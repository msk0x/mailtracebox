"""WHOIS domain lookup plugin."""

from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.domain import DomainInfo
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.whois_lookup")

_WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "info": "whois.afilias.net",
    "io": "whois.nic.io", "co": "whois.nic.co", "me": "whois.nic.me",
    "dev": "whois.nic.google", "app": "whois.nic.google",
    "uk": "whois.nic.uk", "de": "whois.denic.de", "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl", "eu": "whois.eu",
    "ru": "whois.tcinet.ru", "au": "whois.auda.org.au",
    "ca": "whois.cira.ca", "in": "whois.inregistry.net",
    "xyz": "whois.nic.xyz", "top": "whois.nic.top",
    "online": "whois.nic.online", "site": "whois.nic.site",
    "tech": "whois.nic.tech", "store": "whois.nic.store",
}

_DATE_PATTERNS = [
    r"Creation Date:\s*(.+)", r"Created:\s*(.+)", r"created:\s*(.+)",
    r"Domain Registration Date:\s*(.+)", r"Registration Time:\s*(.+)",
]
_EXPIRY_PATTERNS = [
    r"Registry Expiry Date:\s*(.+)", r"Registrar Registration Expiration Date:\s*(.+)",
    r"Expiry Date:\s*(.+)", r"expires:\s*(.+)", r"Expiration Date:\s*(.+)", r"paid-till:\s*(.+)",
]


class WhoisLookupPlugin(BasePlugin):
    """WHOIS domain intelligence — registrar, dates, name servers, registrant."""

    @property
    def name(self) -> str:
        return "whois_lookup"

    @property
    def description(self) -> str:
        return "WHOIS lookup for domain registrar, dates, name servers, and registrant."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["whois", "domain", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        domain = context.target_domain
        if not domain:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        tld = domain.rsplit(".", 1)[-1].lower()
        server = _WHOIS_SERVERS.get(tld, "whois.iana.org")

        try:
            raw = await self._query_whois(domain, server)
            if not raw:
                return PluginResult(plugin_name=self.name, status=PluginStatus.FAILED, errors=["Empty WHOIS response"])

            data = self._parse_response(raw)

            referral = data.pop("_referral_server", None)
            if referral:
                try:
                    raw2 = await self._query_whois(domain, referral)
                    if raw2:
                        for key, value in self._parse_response(raw2).items():
                            if value and not data.get(key):
                                data[key] = value
                except Exception:
                    pass

            ns_raw = data.get("name_servers", [])
            ns_clean = [ns.strip().lower().rstrip(".") for ns in ns_raw]

            domain_info = DomainInfo(
                domain=domain, registrar=data.get("registrar"),
                registrant=data.get("registrant"),
                registration_date=self._parse_date(data.get("creation_date")),
                expiration_date=self._parse_date(data.get("expiration_date")),
                name_servers=ns_clean, whois_raw=raw[:5000], source="whois_lookup",
            )
            await context.domains.add(domain_info)

            items = sum(1 for v in data.values() if v)
            logger.info(
                "WHOIS for %s: registrar=%s, created=%s, expires=%s, ns=%d",
                domain, data.get("registrar", "?"), data.get("creation_date", "?"),
                data.get("expiration_date", "?"), len(ns_clean),
            )
            return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=items, confidence=0.9)

        except Exception as exc:
            logger.error("WHOIS lookup failed for %s: %s", domain, exc)
            return PluginResult(plugin_name=self.name, status=PluginStatus.FAILED, errors=[f"{type(exc).__name__}: {exc}"])

    async def _query_whois(self, query: str, server: str, port: int = 43) -> str:
        loop = asyncio.get_running_loop()

        def _do_query() -> str:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                sock.connect((server, port))
                sock.sendall(f"{query}\r\n".encode())
                chunks: list[bytes] = []
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        chunks.append(data)
                    except socket.timeout:
                        break
                return b"".join(chunks).decode("utf-8", errors="replace")
            finally:
                sock.close()

        return await loop.run_in_executor(None, _do_query)

    def _parse_response(self, raw: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for pat in [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"]:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                result["registrar"] = m.group(1).strip()
                break
        for pat in _DATE_PATTERNS:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                result["creation_date"] = m.group(1).strip()
                break
        for pat in _EXPIRY_PATTERNS:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                result["expiration_date"] = m.group(1).strip()
                break
        for pat in [r"Registrant Organization:\s*(.+)", r"Registrant:\s*(.+)", r"org-name:\s*(.+)"]:
            m = re.search(pat, raw, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val.lower() not in ("redacted", "n/a", "not disclosed", "data protected"):
                    result["registrant"] = val
                break
        ns = re.findall(r"Name Server:\s*(\S+)", raw, re.IGNORECASE)
        if not ns:
            ns = re.findall(r"nserver:\s*(\S+)", raw, re.IGNORECASE)
        if ns:
            result["name_servers"] = [n.strip().lower().rstrip(".") for n in ns]
        ref = re.search(r"Whois Server:\s*(\S+)", raw, re.IGNORECASE)
        if ref:
            result["_referral_server"] = ref.group(1).strip()
        return result

    @staticmethod
    def _parse_date(date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y"):
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        return None
