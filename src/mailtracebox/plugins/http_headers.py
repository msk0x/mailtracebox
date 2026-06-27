"""HTTP security headers analysis and TLS certificate plugin."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.domain import CertificateInfo
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.http_headers")

_SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "referrer-policy", "permissions-policy", "x-permitted-cross-domain-policies",
]

_TECH_SIGNATURES = {
    "x-powered-by": "server",
    "server": "server",
    "x-aspnet-version": "framework",
    "x-generator": "cms",
}


class HttpHeadersPlugin(BasePlugin):
    """Analyse HTTP response headers and TLS certificates."""

    @property
    def name(self) -> str:
        return "http_headers"

    @property
    def description(self) -> str:
        return "HTTP security headers analysis and TLS certificate information."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["http", "headers", "security", "tls", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        domain = context.target_domain
        if not domain:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        items_found = 0
        errors: list[str] = []

        # HTTP headers probe
        try:
            resp = await http_client.get(f"https://{domain}", use_cache=False)
            if resp.ok:
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                present = [h for h in _SECURITY_HEADERS if h in headers_lower]
                missing = [h for h in _SECURITY_HEADERS if h not in headers_lower]
                techs = [f"{cat}: {headers_lower[hn]}" for hn, cat in _TECH_SIGNATURES.items() if hn in headers_lower]

                await context.set_custom(f"{self.name}_security_headers_present", present)
                await context.set_custom(f"{self.name}_security_headers_missing", missing)
                await context.set_custom(f"{self.name}_technologies", techs)
                items_found += len(present) + len(missing) + len(techs)

                logger.info(
                    "HTTP headers for %s: %d/%d security headers present, %d tech hints",
                    domain, len(present), len(_SECURITY_HEADERS), len(techs),
                )
            else:
                errors.append(f"HTTPS returned status {resp.status}")
        except Exception as exc:
            errors.append(f"HTTPS probe failed: {exc}")

        # TLS certificate
        try:
            cert_info = await self._get_tls_cert(domain)
            if cert_info:
                await context.certificates.add(cert_info)
                items_found += 1
        except Exception as exc:
            errors.append(f"TLS cert check failed: {exc}")

        status = PluginStatus.COMPLETED if items_found > 0 else PluginStatus.FAILED
        return PluginResult(
            plugin_name=self.name, status=status,
            items_found=items_found, errors=errors, confidence=0.8,
        )

    async def _get_tls_cert(self, domain: str) -> CertificateInfo | None:
        """Fetch TLS certificate info using stdlib ssl."""
        def _fetch() -> CertificateInfo | None:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.settimeout(10)
                sock.connect((domain, 443))
                cert = sock.getpeercert()
            if not cert:
                return None
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            sans = [entry[1] for entry in cert.get("subjectAltName", ())]
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return CertificateInfo(
                subject=subject.get("commonName", ""),
                issuer=issuer.get("organizationName", issuer.get("commonName", "")),
                serial_number=cert.get("serialNumber", ""),
                not_before=not_before, not_after=not_after,
                sans=sans, source="http_headers",
            )

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _fetch)
