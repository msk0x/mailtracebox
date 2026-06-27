"""SMTP RCPT TO email verification plugin."""

from __future__ import annotations

import asyncio
import smtplib
import uuid
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.dns_resolver import DnsResolver
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.smtp_verify")

_ACCEPT_ALL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "google.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.co.jp", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "protonmail.com", "proton.me", "pm.me",
    "icloud.com", "me.com", "mac.com",
    "aol.com", "aim.com",
    "zoho.com", "zohomail.com",
    "yandex.com", "yandex.ru", "yandex.by", "yandex.kz",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "gmx.com", "gmx.de", "gmx.net",
    "web.de",
    "tutanota.com", "tuta.com",
    "fastmail.com", "fastmail.fm",
})


class SmtpVerifyPlugin(BasePlugin):
    """Verify email existence via SMTP RCPT TO handshake."""

    @property
    def name(self) -> str:
        return "smtp_verify"

    @property
    def description(self) -> str:
        return "SMTP RCPT TO verification — checks if mail server accepts the address."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def dependencies(self) -> list[str]:
        return ["dns_recon"]

    @property
    def tags(self) -> list[str]:
        return ["smtp", "email", "verification", "active"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        email = context.target_email
        domain = context.target_domain
        if not email or not domain:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        mx_hosts = await self._get_mx_hosts(context, domain)
        if not mx_hosts:
            return PluginResult(
                plugin_name=self.name, status=PluginStatus.FAILED,
                errors=[f"No MX records found for {domain}."],
            )

        if domain in _ACCEPT_ALL_DOMAINS:
            logger.info("%s is an accept-all provider — SMTP verification unreliable", domain)
            await context.set_custom("smtp_verify_note", f"{domain} accepts all RCPT TO — low confidence")
            return PluginResult(
                plugin_name=self.name, status=PluginStatus.COMPLETED,
                items_found=1, confidence=0.1,
                warnings=[f"{domain} is an accept-all provider; SMTP result is unreliable"],
            )

        errors: list[str] = []
        for mx_host in mx_hosts:
            try:
                result = await self._verify_on_mx(mx_host, email, domain)
                logger.info("SMTP verify %s on %s: %s", email, mx_host, result.get("status"))
                await context.set_custom("smtp_verify_result", result)

                status = result.get("status", "unknown")
                if status == "accepted":
                    catch_all = await self._check_catch_all(mx_host, domain)
                    await context.set_custom("smtp_verify_catch_all", catch_all)
                    if catch_all:
                        return PluginResult(
                            plugin_name=self.name, status=PluginStatus.COMPLETED,
                            items_found=1, confidence=0.15,
                            warnings=[f"{domain} is catch-all"],
                        )
                    return PluginResult(
                        plugin_name=self.name, status=PluginStatus.COMPLETED,
                        items_found=1, confidence=0.7,
                    )
                elif status == "rejected":
                    return PluginResult(
                        plugin_name=self.name, status=PluginStatus.COMPLETED,
                        items_found=1, confidence=0.9, data={"accepted": False},
                    )
                else:
                    errors.append(f"{mx_host}: {result.get('error', status)}")
            except Exception as exc:
                errors.append(f"{mx_host}: {exc}")

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED if not errors else PluginStatus.FAILED,
            items_found=0, errors=errors,
        )

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

    async def _verify_on_mx(self, mx_host: str, email: str, domain: str) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._smtp_check, mx_host, email, domain)

    def _smtp_check(self, mx_host: str, email: str, domain: str) -> dict[str, Any]:
        """Blocking SMTP verification — runs in a thread executor."""
        result: dict[str, Any] = {"mx_host": mx_host, "status": "unknown", "code": 0}
        server: smtplib.SMTP | None = None
        try:
            server = smtplib.SMTP(mx_host, 25, timeout=15)
            server.ehlo("mailtracebox.local")
            if server.has_extn("starttls"):
                try:
                    server.starttls()
                    server.ehlo("mailtracebox.local")
                except smtplib.SMTPException:
                    pass
            server.mail("test@mailtracebox.local")
            code, message = server.rcpt(email)
            result["code"] = code
            result["response"] = message.decode(errors="replace") if isinstance(message, bytes) else str(message)
            if code == 250:
                result["status"] = "accepted"
            elif code == 252:
                result["status"] = "catch_all_hint"
            elif code in (550, 551, 552, 553):
                result["status"] = "rejected"
            else:
                result["status"] = f"code_{code}"
        except smtplib.SMTPServerDisconnected as exc:
            result["status"] = "disconnected"
            result["error"] = str(exc)
        except smtplib.SMTPConnectError as exc:
            result["status"] = "connection_refused"
            result["error"] = str(exc)
        except TimeoutError:
            result["status"] = "timeout"
            result["error"] = "Connection timed out"
        except OSError as exc:
            result["status"] = "network_error"
            result["error"] = str(exc)
        except Exception as exc:
            result["status"] = "error"
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if server:
                try:
                    server.rset()
                    server.quit()
                except Exception:
                    pass
        return result

    async def _check_catch_all(self, mx_host: str, domain: str) -> bool:
        random_email = f"mailtracebox_{uuid.uuid4().hex[:12]}@{domain}"
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._smtp_check, mx_host, random_email, domain)
        return result.get("code") == 250
