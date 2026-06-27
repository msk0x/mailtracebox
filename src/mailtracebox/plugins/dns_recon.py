"""DNS, MX, SPF, and DMARC reconnaissance plugin.

Performs passive DNS intelligence gathering using the shared
DnsResolver.  No API keys required — uses public DNS only.
"""

from __future__ import annotations

from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.domain import DomainInfo
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.dns_resolver import DnsResolver
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.dns_recon")


class DnsReconPlugin(BasePlugin):
    """Gather DNS records, MX hosts, SPF, and DMARC for the target domain."""

    @property
    def name(self) -> str:
        return "dns_recon"

    @property
    def description(self) -> str:
        return "DNS, MX, SPF, and DMARC record collection."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["dns", "passive", "mx", "spf", "dmarc"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        domain = context.target_domain
        if not domain:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SKIPPED,
                errors=["No target domain found."],
            )

        resolver = DnsResolver()
        items_found = 0

        try:
            a_records = await resolver.resolve(domain, "A")
            items_found += len(a_records)

            aaaa_records = await resolver.resolve(domain, "AAAA")
            items_found += len(aaaa_records)

            mx_records = await resolver.get_mx(domain)
            items_found += len(mx_records)

            txt_records = await resolver.get_txt(domain)

            spf = await resolver.get_spf(domain)
            dmarc = await resolver.get_dmarc(domain)

            domain_info = DomainInfo(
                domain=domain,
                a_records=a_records,
                aaaa_records=aaaa_records,
                mx_records=mx_records,
                txt_records=txt_records,
                spf_record=spf,
                dmarc_record=dmarc,
                source="dns_recon",
            )

            await context.domains.add(domain_info)

            logger.info(
                "DNS recon for %s: %d A, %d MX, SPF=%s, DMARC=%s",
                domain, len(a_records), len(mx_records),
                "yes" if spf else "no", "yes" if dmarc else "no",
            )

            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.COMPLETED,
                items_found=items_found,
                confidence=0.95,
            )

        except Exception as exc:
            logger.error("DNS recon failed for %s: %s", domain, exc)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        finally:
            await resolver.close()
