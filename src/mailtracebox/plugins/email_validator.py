"""Email validation and classification plugin."""

from __future__ import annotations

from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.email import EmailAddress
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient
from mailtracebox.utils.validators import (
    is_disposable_domain,
    is_role_account,
    parse_email_parts,
    validate_email,
)

logger = get_logger("plugins.email_validator")


class EmailValidatorPlugin(BasePlugin):
    """Validate, classify, and enrich the target email address."""

    @property
    def name(self) -> str:
        return "email_validator"

    @property
    def description(self) -> str:
        return "Email validation, disposable detection, and role-account classification."

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tags(self) -> list[str]:
        return ["email", "validation", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        if not context.target_email:
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SKIPPED,
                errors=["No target email address."],
            )

        try:
            validated = validate_email(context.target_email)
            local_part, domain = parse_email_parts(validated)

            email = EmailAddress(
                address=validated,
                local_part=local_part,
                domain=domain,
                is_valid=True,
                is_disposable=is_disposable_domain(domain),
                is_role_account=is_role_account(local_part),
                source="email_validator",
                confidence=0.9,
            )

            await context.emails.add(email)

            logger.info(
                "Validated %s: disposable=%s, role=%s",
                validated, email.is_disposable, email.is_role_account,
            )

            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.COMPLETED,
                items_found=1,
                confidence=0.9,
            )

        except Exception as exc:
            logger.error("Email validation failed: %s", exc)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                errors=[f"{type(exc).__name__}: {exc}"],
            )
