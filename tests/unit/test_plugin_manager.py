"""Tests for the plugin manager."""

from __future__ import annotations

from typing import Any

import pytest

from mailtracebox.config.schema import AppConfig
from mailtracebox.core.context import Context
from mailtracebox.core.plugin_manager import PluginManager
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.plugins.base import BasePlugin
from mailtracebox.services.http_client import HttpClient


class DummyPlugin(BasePlugin):
    """A minimal plugin for testing the manager."""

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def description(self) -> str:
        return "A dummy plugin for testing."

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def tags(self) -> list[str]:
        return ["test"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
            items_found=1,
        )


class DependentPlugin(BasePlugin):
    """A plugin that depends on DummyPlugin."""

    @property
    def name(self) -> str:
        return "dependent"

    @property
    def description(self) -> str:
        return "Depends on dummy."

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def dependencies(self) -> list[str]:
        return ["dummy"]

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.COMPLETED,
        )


class UnavailablePlugin(BasePlugin):
    """A plugin that requires an API key."""

    @property
    def name(self) -> str:
        return "locked"

    @property
    def description(self) -> str:
        return "Needs an API key."

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def api_key_env_var(self) -> str:
        return "LOCKED_API_KEY"

    async def execute(
        self,
        context: Context,
        http_client: HttpClient,
        config: dict[str, Any],
    ) -> PluginResult:
        return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED)


class TestPluginManager:
    """Tests for the PluginManager."""

    def test_register_and_get(self) -> None:
        config = AppConfig()
        mgr = PluginManager(config)
        plugin = DummyPlugin()
        mgr.register(plugin)
        assert mgr.get_plugin("dummy") is plugin
        assert mgr.plugin_count == 1

    def test_register_overwrite_warning(self) -> None:
        config = AppConfig()
        mgr = PluginManager(config)
        mgr.register(DummyPlugin())
        mgr.register(DummyPlugin())  # should warn, not raise
        assert mgr.plugin_count == 1

    async def test_load_filters_unavailable(self) -> None:
        config = AppConfig()
        mgr = PluginManager(config)
        mgr.register(UnavailablePlugin())
        await mgr.load()
        # Without API key, locked should be removed
        assert mgr.get_plugin("locked") is None

    async def test_load_with_api_key(self) -> None:
        config = AppConfig(api_keys={"LOCKED_API_KEY": "secret"})
        mgr = PluginManager(config)
        mgr.register(UnavailablePlugin())
        await mgr.load()
        assert mgr.get_plugin("locked") is not None

    async def test_disabled_plugins(self) -> None:
        config = AppConfig()
        config.plugins.disabled = ["dummy"]
        mgr = PluginManager(config)
        mgr.register(DummyPlugin())
        await mgr.load()
        assert mgr.get_plugin("dummy") is None

    async def test_enabled_plugins_filter(self) -> None:
        config = AppConfig()
        config.plugins.enabled = ["dummy"]
        mgr = PluginManager(config)
        mgr.register(DummyPlugin())
        mgr.register(DependentPlugin())
        await mgr.load()
        assert mgr.get_plugin("dummy") is not None
        assert mgr.get_plugin("dependent") is None

    def test_list_plugins(self) -> None:
        config = AppConfig()
        mgr = PluginManager(config)
        mgr.register(DummyPlugin())
        plugins = mgr.list_plugins()
        assert len(plugins) == 1
        assert plugins[0]["name"] == "dummy"

    async def test_dependency_ordering(self) -> None:
        config = AppConfig()
        mgr = PluginManager(config)
        # Register in reverse order — manager should sort by dependencies
        mgr.register(DependentPlugin())
        mgr.register(DummyPlugin())
        await mgr.load()
        ordered = mgr.get_enabled_plugins()
        names = [p.name for p in ordered]
        # dummy must come before dependent
        assert names.index("dummy") < names.index("dependent")
