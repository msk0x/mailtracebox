"""IP geolocation plugin for discovered mail servers."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.common import ServerInfo
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.dns_resolver import DnsResolver
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.ip_info")


class IpInfoPlugin(BasePlugin):
    """Geolocate and fingerprint mail server IP addresses."""

    @property
    def name(self) -> str:
        return "ip_info"

    @property
    def description(self) -> str:
        return "IP geolocation and ISP lookup for mail server hosts."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def dependencies(self) -> list[str]:
        return ["dns_recon"]

    @property
    def tags(self) -> list[str]:
        return ["ip", "geolocation", "mail", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        domain = context.target_domain
        if not domain:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        mx_hosts = await self._get_mx_hosts(context, domain)
        if not mx_hosts:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED, errors=["No MX records"])

        items_found = 0
        loop = asyncio.get_running_loop()

        for mx_host in mx_hosts:
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, mx_host)
                api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as"
                resp = await http_client.get(api_url, use_cache=True)

                metadata: dict[str, Any] = {"mx_host": mx_host}
                if resp.ok:
                    geo = resp.json_or({})
                    if geo.get("status") == "success":
                        metadata.update({
                            "country": geo.get("country", ""), "region": geo.get("regionName", ""),
                            "city": geo.get("city", ""), "isp": geo.get("isp", ""),
                            "org": geo.get("org", ""), "as": geo.get("as", ""),
                        })

                await context.servers.add(ServerInfo(
                    host=mx_host, ip=ip, port=25, protocol="smtp",
                    source="ip_info", metadata=metadata,
                ))
                items_found += 1
                logger.info("MX %s -> %s (%s, %s)", mx_host, ip, metadata.get("city", "?"), metadata.get("country", "?"))

            except socket.gaierror:
                logger.debug("Could not resolve: %s", mx_host)
            except Exception as exc:
                logger.debug("IP info failed for %s: %s", mx_host, exc)

        return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED, items_found=items_found, confidence=0.95)

    async def _get_mx_hosts(self, context: Context, domain: str) -> list[str]:
        domains = await context.domains.get_all()
        for d in domains:
            if d.domain == domain and d.mx_records:
                return [mx.host for mx in d.mx_records]
        resolver = DnsResolver()
        try:
            return [mx.host for mx in await resolver.get_mx(domain)]
        finally:
            await resolver.close()
