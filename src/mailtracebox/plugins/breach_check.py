"""Data breach check plugin via XposedOrNot API.

Queries two endpoints for maximum coverage.
Includes breach risk score in the output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.log.setup import get_logger
from mailtracebox.models.breach import BreachRecord
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient

logger = get_logger("plugins.breach_check")


def _parse_breach_date(raw: str | None) -> datetime | None:
    """Try multiple date formats commonly used in breach databases."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or raw.lower() in ("null", "none", "n/a", ""):
        return None
    for fmt in (
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y",
        "%B %Y",
        "%b %Y",
        "%Y",
    ):
        try:
            return datetime.strptime(raw[:30], fmt)
        except ValueError:
            continue
    return None


class BreachCheckPlugin(BasePlugin):
    """Check email against known data breaches via XposedOrNot."""

    @property
    def name(self) -> str:
        return "breach_check"

    @property
    def description(self) -> str:
        return "Data breach lookup via XposedOrNot (free, no API key)."

    @property
    def version(self) -> str:
        return "1.2.0"

    @property
    def tags(self) -> list[str]:
        return ["breaches", "email", "passive"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        email = context.target_email
        if not email:
            return PluginResult(plugin_name=self.name, status=PluginStatus.SKIPPED)

        # Try breach-analytics endpoint (richer data with risk scores)
        breaches, risk_info = await self._try_breach_analytics(email, http_client)

        # Fall back to check-email endpoint
        if not breaches:
            breaches = await self._try_check_email(email, http_client)

        if breaches:
            items_found = 0
            for breach in breaches:
                await context.breaches.add(breach)
                items_found += 1

            # Store risk info as custom data for display
            if risk_info:
                await context.set_custom("breach_risk_score", risk_info.get("risk_score", ""))
                await context.set_custom("breach_risk_label", risk_info.get("risk_label", ""))

            logger.info("Found %d breaches for %s", items_found, email)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.COMPLETED,
                items_found=items_found,
                confidence=0.9,
            )

        logger.info("No breaches found for %s", email)
        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=0,
        )

    async def _try_breach_analytics(
        self, email: str, http_client: HttpClient,
    ) -> tuple[list[BreachRecord], dict[str, Any]]:
        """Try the /v1/breach-analytics endpoint."""
        url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
        try:
            resp = await http_client.get(url, use_cache=True)
            logger.debug("breach-analytics status=%d", resp.status)

            if not resp.ok:
                return [], {}

            data = resp.json_or({})

            if "Error" in data or "message" in data:
                return [], {}

            # Extract risk info
            risk_info: dict[str, Any] = {}
            metrics = data.get("BreachMetrics", {})
            risk_list = metrics.get("risk", [])
            if risk_list and isinstance(risk_list, list) and len(risk_list) > 0:
                risk_info = risk_list[0] if isinstance(risk_list[0], dict) else {}

            breaches: list[BreachRecord] = []

            # Primary: ExposedBreaches.breaches_details
            exposed = data.get("ExposedBreaches", {})
            breach_details = exposed.get("breaches_details", [])
            if isinstance(breach_details, list):
                for entry in breach_details:
                    record = self._parse_breach_entry(entry)
                    if record:
                        breaches.append(record)

            # Fallback: top-level Breaches key
            if not breaches:
                alt = data.get("Breaches", {})
                alt_details = alt.get("breaches_details", [])
                if isinstance(alt_details, list):
                    for entry in alt_details:
                        record = self._parse_breach_entry(entry)
                        if record:
                            breaches.append(record)

            return breaches, risk_info

        except Exception as exc:
            logger.debug("breach-analytics failed: %s", exc)
            return [], {}

    async def _try_check_email(
        self, email: str, http_client: HttpClient,
    ) -> list[BreachRecord]:
        """Try the /v1/check-email endpoint."""
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            resp = await http_client.get(url, use_cache=True)
            logger.debug("check-email status=%d", resp.status)

            if resp.status == 404 or not resp.ok:
                return []

            data = resp.json_or({})

            if "Error" in data or "message" in data:
                return []

            breaches: list[BreachRecord] = []
            breach_details = data.get("Breaches", {}).get("breaches_details", [])
            if isinstance(breach_details, list):
                for entry in breach_details:
                    record = self._parse_breach_entry(entry)
                    if record:
                        breaches.append(record)

            return breaches

        except Exception as exc:
            logger.debug("check-email failed: %s", exc)
            return []

    def _parse_breach_entry(self, entry: dict[str, Any]) -> BreachRecord | None:
        """Parse a single breach entry into a BreachRecord."""
        if not isinstance(entry, dict):
            return None

        name = entry.get("breach", entry.get("name", ""))
        if not name:
            return None

        # Parse breach date — try multiple field names
        breach_date = None
        for date_field in ("xposed_date", "breach_date", "date", "modified_date"):
            raw_date = entry.get(date_field)
            breach_date = _parse_breach_date(raw_date)
            if breach_date:
                break

        # Parse data classes
        dc_raw = entry.get("xposed_data", entry.get("data_classes", ""))
        if isinstance(dc_raw, str):
            data_classes = [d.strip() for d in dc_raw.replace(";", ",").split(",") if d.strip()]
        elif isinstance(dc_raw, list):
            data_classes = [str(d) for d in dc_raw]
        else:
            data_classes = []

        # Parse record count
        pwn_count = entry.get("xposed_records", entry.get("pwn_count"))
        if isinstance(pwn_count, str):
            try:
                pwn_count = int(pwn_count.replace(",", "").replace(".", ""))
            except ValueError:
                pwn_count = None

        return BreachRecord(
            name=name,
            domain=entry.get("domain", ""),
            breach_date=breach_date,
            pwn_count=pwn_count,
            description=entry.get("details", entry.get("description", "")),
            data_classes=data_classes,
            is_verified=bool(entry.get("verified")),
            source="xposedornot",
            metadata={
                "industry": entry.get("industry", ""),
                "password_risk": entry.get("password_risk", ""),
            },
        )
