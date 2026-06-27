"""Async DNS resolver with integrated caching — FIXED TXT record parsing."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.resolver

from mailtracebox.log.setup import get_logger
from mailtracebox.models.domain import MXRecord
from mailtracebox.services.cache import TtlCache

logger = get_logger("dns")


class DnsResolver:
    """Async DNS resolver with a TTL cache."""

    def __init__(self, cache_ttl: float = 3600.0, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._cache: TtlCache[list[str | MXRecord]] = TtlCache(max_size=500, default_ttl=cache_ttl)

    async def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        """Resolve domain for the given record_type."""
        cache_key = f"dns:{domain}:{record_type}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached  # type: ignore[return-value]

        try:
            loop = asyncio.get_running_loop()
            answers: Any = await loop.run_in_executor(
                None, self._resolver.resolve, domain, record_type,
            )

            if record_type == "TXT":
                results = self._extract_txt(answers)
            else:
                results = [str(r) for r in answers]

            await self._cache.set(cache_key, results)
            return results

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception as exc:
            logger.warning("DNS lookup failed for %s/%s: %s", domain, record_type, exc)
            return []

    @staticmethod
    def _extract_txt(answers: Any) -> list[str]:
        """Extract raw text from TXT record rdata objects.

        dnspython returns TXT records as TXT objects whose str() includes
        zone-file quoting.  We use the strings attribute to get the raw
        bytes and decode them without quotes.
        """
        results: list[str] = []
        for rdata in answers:
            try:
                # rdata.strings is a tuple of bytes
                raw = b"".join(rdata.strings).decode("utf-8", errors="replace")
            except AttributeError:
                raw = str(rdata).strip('"')
            results.append(raw)
        return results

    async def get_mx(self, domain: str) -> list[MXRecord]:
        """Retrieve MX records sorted by priority (lowest first)."""
        cache_key = f"dns:{domain}:MX"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return cached  # type: ignore[return-value]
        try:
            loop = asyncio.get_running_loop()
            answers: Any = await loop.run_in_executor(
                None, self._resolver.resolve, domain, "MX",
            )
            records = sorted(
                [MXRecord(priority=r.preference, host=str(r.exchange).rstrip(".")) for r in answers],
                key=lambda rec: rec.priority,
            )
            await self._cache.set(cache_key, records)
            return records
        except Exception:
            return []

    async def get_txt(self, domain: str) -> list[str]:
        """Retrieve all TXT records for a domain."""
        return await self.resolve(domain, "TXT")

    async def get_spf(self, domain: str) -> str | None:
        """Return the SPF record for domain, or None."""
        records = await self.get_txt(domain)
        for record in records:
            if record.lower().startswith("v=spf1"):
                return record
        return None

    async def get_dmarc(self, domain: str) -> str | None:
        """Return the DMARC record for domain, or None."""
        records = await self.resolve(f"_dmarc.{domain}", "TXT")
        for record in records:
            if "v=dmarc1" in record.lower():
                return record
        return None

    async def close(self) -> None:
        """Clean up resources."""
        await self._cache.clear()
