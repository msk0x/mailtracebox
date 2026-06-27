"""Pydantic schemas for every configuration section."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HttpConfig(BaseModel):
    """HTTP client configuration."""

    timeout: float = 30.0
    connect_timeout: float = 10.0
    max_retries: int = 3
    max_concurrent: int = 10
    pool_size: int = 100
    user_agent: str = "mailtracebox/0.1.0 (OSINT Framework)"
    rate_limit_requests: int = 60
    rate_limit_window: float = 60.0
    cache_enabled: bool = True
    cache_ttl: float = 300.0
    cache_size: int = 1000
    dns_cache_ttl: int = 3600
    verify_ssl: bool = True


class PluginsConfig(BaseModel):
    """Plugin system configuration."""

    enabled: list[str] = Field(default_factory=list)
    disabled: list[str] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)
    timeout: float = 60.0


class LoggingConfig(BaseModel):
    """Logging subsystem configuration."""

    level: str = "INFO"
    file: str | None = None
    format: str = "structured"
    rich_console: bool = True
    log_http: bool = False
    log_plugins: bool = True


class ReportsConfig(BaseModel):
    """Report generation configuration."""

    output_dir: str = "./reports"
    include_raw_data: bool = False
    include_statistics: bool = True
    include_errors: bool = True
    include_timeline: bool = True
    include_confidence: bool = True


class GeneralConfig(BaseModel):
    """Top-level application settings."""

    target: str = ""
    output_format: str = "rich"
    output_file: str | None = None
    verbose: bool = False
    debug: bool = False


class AppConfig(BaseModel):
    """Root configuration — validated representation of the merged config."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    api_keys: dict[str, str] = Field(default_factory=dict)

    def get_api_key(self, env_var: str) -> str | None:
        """Return the API key for env_var, or None if absent."""
        return self.api_keys.get(env_var)
