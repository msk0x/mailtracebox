"""Configuration manager — merges YAML, environment variables, and CLI overrides.

Priority (highest wins):  CLI > Environment > YAML > Defaults.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from mailtracebox.config.schema import AppConfig
from mailtracebox.utils.exceptions import ConfigurationError
from mailtracebox.utils.helpers import deep_merge

logger = logging.getLogger(__name__)


def _find_default_config() -> Path | None:
    """Locate the default config YAML bundled with the package."""
    # 1. Project root (development / editable install)
    candidates = [
        Path(__file__).resolve().parents[3] / "config" / "default.yml",
        # 2. Inside the package itself (installed mode)
        Path(__file__).resolve().parent / "default.yml",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


_DEFAULT_CONFIG_PATH = _find_default_config()


class ConfigManager:
    """Load, merge, and validate configuration from multiple sources."""

    def __init__(self) -> None:
        self._config: AppConfig | None = None
        self._config_file_path: Path | None = None

    def load(
        self,
        config_file: Path | None = None,
        cli_overrides: dict[str, Any] | None = None,
        env_prefix: str = "EMAILRECON_",
    ) -> AppConfig:
        """Build the final AppConfig from all sources."""
        merged: dict[str, Any] = {}

        # 1. Defaults
        default_path = config_file if config_file else _DEFAULT_CONFIG_PATH
        if default_path and default_path.exists():
            merged = self._load_yaml(default_path)
            self._config_file_path = default_path

        # 2. User-specified YAML (if different from default)
        if config_file and config_file != _DEFAULT_CONFIG_PATH and config_file.exists():
            user_data = self._load_yaml(config_file)
            merged = deep_merge(merged, user_data)
            self._config_file_path = config_file

        # 3. Environment variables
        env_data = self._load_env_vars(env_prefix)
        if env_data:
            merged = deep_merge(merged, env_data)

        # 4. CLI overrides (highest priority)
        if cli_overrides:
            merged = deep_merge(merged, cli_overrides)

        # 5. Validate
        try:
            self._config = AppConfig(**merged)
        except Exception as exc:
            raise ConfigurationError(f"Invalid configuration: {exc}") from exc

        logger.debug("Configuration loaded successfully")
        return self._config

    @property
    def config(self) -> AppConfig:
        if self._config is None:
            raise ConfigurationError("Configuration has not been loaded. Call ConfigManager.load() first.")
        return self._config

    @property
    def config_file_path(self) -> Path | None:
        return self._config_file_path

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Failed to parse YAML file {path}: {exc}") from exc

    def _load_env_vars(self, prefix: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
            raw = key[len(prefix):]
            parts = raw.lower().split("_")
            if parts:
                self._set_nested(result, parts, self._parse_env_value(value))
        return result

    @staticmethod
    def _parse_env_value(value: str) -> Any:
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    @staticmethod
    def _set_nested(d: dict[str, Any], keys: list[str], value: Any) -> None:
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = value
