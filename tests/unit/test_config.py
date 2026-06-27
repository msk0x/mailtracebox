"""Tests for the configuration system."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from mailtracebox.config.manager import ConfigManager
from mailtracebox.config.schema import AppConfig, HttpConfig, LoggingConfig
from mailtracebox.utils.exceptions import ConfigurationError


class TestConfigManager:
    """Tests for ConfigManager.load()."""

    def test_defaults_without_file(self) -> None:
        """Loading with no file and no env should produce default config."""
        mgr = ConfigManager()
        config = mgr.load()
        assert isinstance(config, AppConfig)
        assert config.http.timeout == 30.0
        assert config.logging.level == "INFO"
        assert config.plugins.timeout == 60.0

    def test_yaml_override(self, tmp_path: Path) -> None:
        """YAML values should override defaults."""
        cfg_file = tmp_path / "test.yml"
        cfg_file.write_text(yaml.dump({
            "http": {"timeout": 15.0, "max_retries": 5},
            "logging": {"level": "DEBUG"},
        }))
        mgr = ConfigManager()
        config = mgr.load(config_file=cfg_file)
        assert config.http.timeout == 15.0
        assert config.http.max_retries == 5
        assert config.logging.level == "DEBUG"
        # Unset values should retain defaults
        assert config.http.pool_size == 100

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables should override YAML."""
        monkeypatch.setenv("EMAILRECON_HTTP_TIMEOUT", "10")
        monkeypatch.setenv("EMAILRECON_LOGGING_LEVEL", "WARNING")
        mgr = ConfigManager()
        config = mgr.load()
        assert config.http.timeout == 10.0
        assert config.logging.level == "WARNING"

    def test_cli_override_wins(self, tmp_path: Path) -> None:
        """CLI overrides should have highest priority."""
        cfg_file = tmp_path / "test.yml"
        cfg_file.write_text(yaml.dump({"http": {"timeout": 20.0}}))
        mgr = ConfigManager()
        config = mgr.load(
            config_file=cfg_file,
            cli_overrides={"http": {"timeout": 5.0}},
        )
        assert config.http.timeout == 5.0

    def test_env_bool_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMAILRECON_GENERAL_VERBOSE", "true")
        monkeypatch.setenv("EMAILRECON_HTTP_VERIFY_SSL", "false")
        mgr = ConfigManager()
        config = mgr.load()
        assert config.general.verbose is True
        assert config.http.verify_ssl is False

    def test_env_int_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMAILRECON_HTTP_MAX_CONCURRENT", "25")
        mgr = ConfigManager()
        config = mgr.load()
        assert config.http.max_concurrent == 25

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad.yml"
        cfg_file.write_text(": : invalid yaml [")
        mgr = ConfigManager()
        with pytest.raises(ConfigurationError):
            mgr.load(config_file=cfg_file)

    def test_config_property_before_load(self) -> None:
        mgr = ConfigManager()
        with pytest.raises(ConfigurationError, match="not been loaded"):
            _ = mgr.config

    def test_api_keys_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMAILRECON_API_KEYS_SHODAN", "secret123")
        mgr = ConfigManager()
        config = mgr.load()
        assert config.api_keys.get("shodan") == "secret123"


class TestAppConfig:
    """Tests for the AppConfig schema."""

    def test_default_config(self) -> None:
        config = AppConfig()
        assert config.general.target == ""
        assert config.http.max_retries == 3

    def test_get_api_key(self) -> None:
        config = AppConfig(api_keys={"shodan": "key123"})
        assert config.get_api_key("shodan") == "key123"
        assert config.get_api_key("missing") is None


class TestHttpConfig:
    """Tests for the HttpConfig schema."""

    def test_defaults(self) -> None:
        cfg = HttpConfig()
        assert cfg.timeout == 30.0
        assert cfg.verify_ssl is True
        assert cfg.cache_enabled is True
