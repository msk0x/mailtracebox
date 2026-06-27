"""Orchestration engine — the main entry point for running a scan."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from mailtracebox.config.schema import AppConfig
from mailtracebox.core.context import Context
from mailtracebox.core.plugin_manager import PluginManager
from mailtracebox.log.setup import get_logger
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.models.report import Report, ReportSection
from mailtracebox.services.dns_resolver import DnsResolver
from mailtracebox.services.http_client import HttpClient
from mailtracebox.utils.helpers import utc_now
from mailtracebox.utils.validators import validate_email, validate_domain

logger = get_logger("engine")


class Engine:
    """Top-level scan orchestrator."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._context: Context | None = None
        self._plugin_manager = PluginManager(config)
        self._http_client: HttpClient | None = None
        self._dns_resolver: DnsResolver | None = None

    @property
    def context(self) -> Context:
        if self._context is None:
            raise RuntimeError("No scan has been started.")
        return self._context

    @property
    def plugin_manager(self) -> PluginManager:
        return self._plugin_manager

    async def run(self) -> Report:
        """Execute the full intelligence-gathering pipeline."""
        target = self._config.general.target
        if not target:
            raise ValueError("No target specified.")
        self._validate_target(target)
        self._context = Context(target)
        logger.info("Scan %s started for target: %s", self._context.scan_id, target)
        started = utc_now()
        try:
            await self._init_services()
            await self._plugin_manager.discover()
            await self._plugin_manager.load()
            await self._execute_plugins()
            await self._context.complete()
        except Exception as exc:
            logger.error("Scan failed: %s", exc, exc_info=True)
            if self._context:
                await self._context.complete()
            raise
        finally:
            await self._cleanup()
        report = self._build_report(started)
        logger.info(
            "Scan %s completed in %.1fs — %d plugin(s) executed",
            self._context.scan_id, report.duration_seconds, len(report.plugin_results),
        )
        return report

    async def _init_services(self) -> None:
        self._http_client = HttpClient(self._config.http)
        await self._http_client.__aenter__()
        self._dns_resolver = DnsResolver(cache_ttl=float(self._config.http.dns_cache_ttl))

    async def _cleanup(self) -> None:
        if self._http_client:
            try:
                await self._http_client.close()
            except Exception:
                pass
        for plugin in self._plugin_manager.get_enabled_plugins():
            try:
                await plugin.cleanup()
            except Exception:
                pass

    async def _execute_plugins(self) -> None:
        plugins = self._plugin_manager.get_enabled_plugins()
        total = len(plugins)
        for idx, plugin in enumerate(plugins, 1):
            plugin_config = self._build_plugin_config(plugin)
            plugin_name = plugin.name
            logger.info("[%d/%d] Executing plugin: %s", idx, total, plugin_name)
            started = utc_now()
            result: PluginResult
            try:
                result = await asyncio.wait_for(
                    plugin.execute(self.context, self._http_client, plugin_config),
                    timeout=self._config.plugins.timeout,
                )
                result.started_at = started
                result.completed_at = utc_now()
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
            except asyncio.TimeoutError:
                result = PluginResult(
                    plugin_name=plugin_name, status=PluginStatus.TIMEOUT,
                    started_at=started, completed_at=utc_now(),
                    duration_seconds=self._config.plugins.timeout,
                    errors=[f"Timed out after {self._config.plugins.timeout}s"],
                )
                logger.error("Plugin %s timed out", plugin_name)
            except Exception as exc:
                result = PluginResult(
                    plugin_name=plugin_name, status=PluginStatus.FAILED,
                    started_at=started, completed_at=utc_now(),
                    errors=[f"{type(exc).__name__}: {exc}"],
                )
                logger.error("Plugin %s failed: %s", plugin_name, exc, exc_info=True)
            await self.context.add_plugin_result(result)
            logger.info("[%d/%d] %s -> %s (%.2fs)", idx, total, plugin_name, result.status.value, result.duration_seconds or 0)

    def _build_plugin_config(self, plugin: Any) -> dict[str, Any]:
        config: dict[str, Any] = {}
        env_var = getattr(plugin, "api_key_env_var", None)
        if env_var and env_var in self._config.api_keys:
            config[env_var] = self._config.api_keys[env_var]
        return config

    def _build_report(self, started: datetime) -> Report:
        ctx = self.context
        plugin_results = list(ctx._plugin_results.values())
        completed = ctx.completed_at or utc_now()
        errors = [e.message for e in ctx._errors]
        summary = {
            "target": ctx.target, "scan_id": ctx.scan_id,
            "total_plugins": len(plugin_results),
            "successful": sum(1 for r in plugin_results if r.is_success),
            "failed": sum(1 for r in plugin_results if r.status == PluginStatus.FAILED),
        }
        stats: dict[str, Any] = {}
        if self._http_client:
            hs = self._http_client.stats
            stats["http"] = {
                "requests_made": hs.requests_made, "cache_hits": hs.cache_hits,
                "retries": hs.retries, "errors": hs.errors,
                "total_bytes": hs.total_bytes, "total_time": round(hs.total_time, 3),
            }
        return Report(
            target=ctx.target, scan_id=ctx.scan_id, started_at=started,
            completed_at=completed, duration_seconds=round((completed - started).total_seconds(), 3),
            sections=[ReportSection(title="Summary", content=summary, section_type="summary")],
            summary=summary, statistics=stats, errors=errors, plugin_results=plugin_results,
        )

    @staticmethod
    def _validate_target(target: str) -> None:
        target = target.strip()
        if "@" in target:
            validate_email(target)
        else:
            validate_domain(target)
