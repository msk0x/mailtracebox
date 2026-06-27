"""Plugin discovery, registration, and lifecycle management.

The :class:`PluginManager` dynamically imports plugin modules from the
``mailtracebox.plugins`` package (and any user-supplied directories),
registers every :class:`~mailtracebox.plugins.base.BasePlugin` subclass
it finds, and provides ordered access for the orchestration engine.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

from mailtracebox.config.schema import AppConfig
from mailtracebox.log.setup import get_logger
from mailtracebox.plugins.base import BasePlugin

logger = get_logger("plugin_manager")

_BUILTIN_PLUGINS_PKG = "mailtracebox.plugins"


class PluginManager:
    """Discover, load, and manage intelligence plugins."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._registry: dict[str, type[BasePlugin]] = {}
        self._instances: dict[str, BasePlugin] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover(self) -> int:
        """Scan plugin directories for :class:`BasePlugin` subclasses."""
        count = 0
        count += self._discover_package(_BUILTIN_PLUGINS_PKG)
        for directory in self._config.plugins.directories:
            path = Path(directory)
            if path.is_dir():
                count += self._discover_directory(path)
            else:
                logger.warning("Plugin directory does not exist: %s", directory)
        logger.info("Discovered %d plugin class(es)", count)
        return count

    def _discover_package(self, package_name: str) -> int:
        """Import all modules in a Python package and register plugins."""
        count = 0
        try:
            pkg = importlib.import_module(package_name)
        except ImportError as exc:
            logger.warning("Cannot import plugin package %s: %s", package_name, exc)
            return 0
        pkg_path = Path(pkg.__file__).parent  # type: ignore[arg-type]
        for py_file in sorted(pkg_path.glob("*.py")):
            if py_file.name.startswith("_") or py_file.name == "base.py":
                continue
            module_name = f"{package_name}.{py_file.stem}"
            count += self._load_module(module_name)
        return count

    def _discover_directory(self, directory: Path) -> int:
        """Load standalone plugin files from *directory*."""
        count = 0
        for py_file in sorted(directory.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"mailtracebox._user_plugins.{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                try:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)  # type: ignore[union-attr]
                    count += self._register_from_module(module)
                except Exception as exc:
                    logger.warning("Failed to load plugin file %s: %s", py_file, exc)
        return count

    def _load_module(self, module_name: str) -> int:
        """Import a single module and register any plugins found."""
        try:
            module = importlib.import_module(module_name)
            return self._register_from_module(module)
        except ImportError as exc:
            logger.warning("Cannot import %s: %s", module_name, exc)
            return 0
        except Exception as exc:
            logger.error("Error loading %s: %s", module_name, exc)
            return 0

    def _register_from_module(self, module: Any) -> int:
        """Inspect *module* for BasePlugin subclasses and register them."""
        count = 0
        for attr_name in dir(module):
            attr = getattr(module, attr_name, None)
            if (
                isinstance(attr, type)
                and issubclass(attr, BasePlugin)
                and attr is not BasePlugin
                and not getattr(attr, "__abstractmethods__", None)
            ):
                try:
                    instance = attr()
                    self.register(instance)
                    count += 1
                except Exception as exc:
                    logger.warning("Failed to instantiate plugin %s: %s", attr_name, exc)
        return count

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin instance."""
        name = plugin.name
        if name in self._instances:
            logger.warning("Plugin %r already registered — overwriting", name)
        self._instances[name] = plugin
        self._registry[name] = type(plugin)

    # ------------------------------------------------------------------
    # Loading / filtering
    # ------------------------------------------------------------------

    async def load(self) -> None:
        """Validate and prepare all registered plugins."""
        enabled = set(self._config.plugins.enabled)
        disabled = set(self._config.plugins.disabled)
        api_keys = self._config.api_keys

        for name, plugin in list(self._instances.items()):
            # Explicit disable
            if disabled and name in disabled:
                del self._instances[name]
                continue

            # Explicit enable filter
            if enabled and name not in enabled:
                del self._instances[name]
                continue

            # Build plugin-specific config
            plugin_config = self._build_plugin_config(plugin, api_keys)

            # Check availability
            if not plugin.is_available(plugin_config):
                logger.info(
                    "Plugin %s not available (missing API key?) — skipping", name,
                )
                del self._instances[name]
                continue

            # Validate config
            try:
                valid = await plugin.validate_config(plugin_config)
                if not valid:
                    logger.warning("Plugin %s config validation failed — skipping", name)
                    del self._instances[name]
                    continue
            except Exception as exc:
                logger.warning("Plugin %s validation error: %s", name, exc)
                del self._instances[name]
                continue

        self._loaded = True
        logger.info("Loaded %d plugin(s): %s", len(self._instances), list(self._instances.keys()))

    def _build_plugin_config(
        self, plugin: BasePlugin, api_keys: dict[str, str],
    ) -> dict[str, Any]:
        """Assemble the config dict a plugin receives in ``execute()``."""
        config: dict[str, Any] = {}
        if plugin.api_key_env_var and plugin.api_key_env_var in api_keys:
            config[plugin.api_key_env_var] = api_keys[plugin.api_key_env_var]
        return config

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def get_plugin(self, name: str) -> BasePlugin | None:
        return self._instances.get(name)

    def get_enabled_plugins(self) -> list[BasePlugin]:
        """Return all loaded plugin instances, respecting dependency order."""
        plugins = list(self._instances.values())
        return self._topological_sort(plugins)

    def list_plugins(self) -> list[dict[str, Any]]:
        return [p.to_metadata() for p in self._instances.values()]

    def _topological_sort(self, plugins: list[BasePlugin]) -> list[BasePlugin]:
        """Order plugins so that dependencies are executed first."""
        by_name = {p.name: p for p in plugins}
        visited: set[str] = set()
        result: list[BasePlugin] = []

        def _visit(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            plugin = by_name.get(name)
            if plugin is None:
                return
            for dep in plugin.dependencies:
                if dep in by_name:
                    _visit(dep)
                else:
                    logger.warning(
                        "Plugin %s depends on %s which is not loaded", name, dep,
                    )
            result.append(plugin)

        for p in plugins:
            _visit(p.name)
        return result

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def plugin_count(self) -> int:
        return len(self._instances)
