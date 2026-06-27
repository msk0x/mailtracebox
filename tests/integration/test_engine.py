"""Integration tests for the orchestration engine.

These tests verify the full scan pipeline with mock plugins — no
real network calls are made.
"""

from __future__ import annotations

from typing import Any

import pytest

from mailtracebox.config.schema import AppConfig
from mailtracebox.core.context import Context
from mailtracebox.core.engine import Engine
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient


class MockPlugin(BasePlugin):
    """A plugin that records calls for assertion."""

    def __init__(self) -> None:
        self.executed = False
        self.received_context: Context | None = None

    @property
    def name(self) -> str:
        return "mock"

    @property
    def description(self) -> str:
        return "Mock plugin for integration tests."

    @property
    def version(self) -> str:
        return "0.0.1"

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        self.executed = True
        self.received_context = context
        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=42,
        )


class FailingPlugin(BasePlugin):
    """A plugin that always raises."""

    @property
    def name(self) -> str:
        return "failing"

    @property
    def description(self) -> str:
        return "Always fails."

    @property
    def version(self) -> str:
        return "0.0.1"

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        raise RuntimeError("Intentional failure for testing")


@pytest.mark.integration
class TestEngineIntegration:
    """End-to-end engine tests."""

    async def test_successful_scan(self) -> None:
        config = AppConfig()
        config.general.target = "test@example.com"
        config.plugins.timeout = 10.0

        engine = Engine(config)
        mock = MockPlugin()
        engine.plugin_manager.register(mock)

        report = await engine.run()

        assert report.target == "test@example.com"
        assert len(report.plugin_results) == 1
        assert report.plugin_results[0].is_success
        assert mock.executed is True
        assert mock.received_context is not None
        assert mock.received_context.target == "test@example.com"

    async def test_failing_plugin_does_not_crash_engine(self) -> None:
        config = AppConfig()
        config.general.target = "test@example.com"
        config.plugins.timeout = 10.0

        engine = Engine(config)
        engine.plugin_manager.register(MockPlugin())
        engine.plugin_manager.register(FailingPlugin())

        report = await engine.run()

        # Both plugins should be in results
        assert len(report.plugin_results) == 2
        statuses = {r.plugin_name: r.status for r in report.plugin_results}
        assert statuses["mock"] == PluginStatus.COMPLETED
        assert statuses["failing"] == PluginStatus.FAILED

    async def test_report_contains_duration(self) -> None:
        config = AppConfig()
        config.general.target = "test@example.com"

        engine = Engine(config)
        engine.plugin_manager.register(MockPlugin())

        report = await engine.run()
        assert report.duration_seconds >= 0

    async def test_context_completes_on_failure(self) -> None:
        config = AppConfig()
        config.general.target = "test@example.com"

        engine = Engine(config)
        engine.plugin_manager.register(FailingPlugin())

        await engine.run()
        assert engine.context.completed_at is not None
