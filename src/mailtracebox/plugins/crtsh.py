"""Certificate Transparency log search via crt.sh.

Handles 404/502/503 gracefully.  Falls back to CertSpotter when crt.sh
is down.  Deduplicates certificates by subject+issuer to avoid showing
hundreds of identical-looking entries for large domains.
"""

from __future__ import annotations

from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.domain import CertificateInfo
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.crtsh")

_SERVICE_DOWN_CODES = {404, 429, 502, 503}


def _is_hostname_for_domain(hostname: str, domain: str) -> bool:
    """Return True if hostname is the domain itself or a subdomain."""
    hostname = hostname.strip().lower()
    if not hostname or "@" in hostname:
        return False
    bare = hostname[2:] if hostname.startswith("*.") else hostname
    return bare == domain or bare.endswith(f".{domain}")


class CrtShPlugin(BasePlugin):
    """Search Certificate Transparency logs for the target domain."""

    @property
    def name(self) -> str:
        return "crtsh"

    @property
    def description(self) -> str:
        return "Certificate Transparency log search — discovers subdomains and certificates."

    @property
    def version(self) -> str:
        return "1.3.0"

    @property
    def tags(self) -> list[str]:
        return ["certificates", "subdomains", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        domain = context.target_domain
        if not domain:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        # Try crt.sh
        result = await self._query_and_store(domain, http_client, context, "crtsh")
        if result is not None:
            return result

        # Fallback to CertSpotter
        logger.info("crt.sh unavailable — trying CertSpotter fallback")
        result = await self._query_and_store(domain, http_client, context, "certspotter")
        if result is not None:
            return result

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=0,
            warnings=["Both crt.sh and CertSpotter are unavailable right now"],
        )

    async def _query_and_store(
        self,
        domain: str,
        http_client: HttpClient,
        context: Context,
        source: str,
    ) -> PluginResult | None:
        """Query a CT log source, filter, dedup, and store results."""
        if source == "crtsh":
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
        else:
            url = (
                f"https://api.certspotter.com/v1/issuances"
                f"?domain={domain}&include_subdomains=true"
                f"&expand=dns_names&expand=issuer"
            )

        try:
            resp = await http_client.get(url, use_cache=True)

            if resp.status in _SERVICE_DOWN_CODES:
                logger.warning(
                    "%s returned HTTP %d for %s", source, resp.status, domain,
                )
                return None

            if not resp.ok:
                logger.warning(
                    "%s returned HTTP %d for %s", source, resp.status, domain,
                )
                return None

            raw_entries = resp.json_or([])
            if not raw_entries:
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.COMPLETED,
                    items_found=0,
                )

            # Normalize CertSpotter format
            entries: list[dict[str, Any]] = []
            for entry in raw_entries:
                if source == "certspotter":
                    dns_names = entry.get("dns_names", [])
                    issuer = entry.get("issuer", {})
                    entries.append({
                        "common_name": dns_names[0] if dns_names else "",
                        "name_value": "\n".join(dns_names),
                        "issuer_name": issuer.get(
                            "friendly_name", issuer.get("name", ""),
                        ),
                        "serial_number": entry.get("id", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                    })
                else:
                    entries.append(entry)

        except Exception as exc:
            logger.warning("%s query failed for %s: %s", source, domain, exc)
            return None

        # Filter and dedup
        subdomains: set[str] = set()
        seen: set[str] = set()  # dedup key: subject + issuer
        items_found = 0
        total = len(entries)
        skipped = 0
        deduped = 0

        for entry in entries:
            common_name = entry.get("common_name", "")
            name_value = entry.get("name_value", "")
            issuer_name = entry.get("issuer_name", "")

            all_hostnames = [
                h.strip().lower() for h in name_value.split("\n") if h.strip()
            ]
            domain_hostnames = [
                h for h in all_hostnames if _is_hostname_for_domain(h, domain)
            ]
            cn_is_relevant = _is_hostname_for_domain(common_name, domain)

            if not domain_hostnames and not cn_is_relevant:
                skipped += 1
                continue

            # Collect subdomains
            for hostname in domain_hostnames:
                bare = hostname[2:] if hostname.startswith("*.") else hostname
                if "*" not in bare:
                    subdomains.add(bare)

            # Dedup by subject + issuer (not serial, which is unique per cert)
            dedup_key = f"{common_name.strip().lower()}:{issuer_name.strip().lower()}"
            if dedup_key in seen:
                deduped += 1
                continue
            seen.add(dedup_key)

            # Build SAN list from domain-relevant hostnames only
            relevant_sans = list(domain_hostnames)
            if cn_is_relevant:
                cn_lower = common_name.strip().lower()
                if cn_lower not in relevant_sans:
                    relevant_sans = [cn_lower] + relevant_sans

            cert = CertificateInfo(
                subject=common_name,
                issuer=issuer_name,
                serial_number=str(entry.get("serial_number", "")),
                sans=relevant_sans,
                source=source,
                metadata={
                    "not_before_ct": entry.get("not_before", ""),
                    "not_after_ct": entry.get("not_after", ""),
                },
            )
            await context.certificates.add(cert)
            items_found += 1

        if subdomains:
            await context.set_custom("crtsh_subdomains", sorted(subdomains))

        logger.info(
            "%s for %s: %d total, %d skipped (not our domain), "
            "%d deduped, %d unique certs, %d subdomains",
            source, domain, total, skipped, deduped, len(seen), len(subdomains),
        )

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=items_found + len(subdomains),
            confidence=0.95,
        )
