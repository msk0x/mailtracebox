"""Plugin execution result and metadata models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PluginStatus(str, Enum):
    """Lifecycle status of a plugin execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class PluginMetadata(BaseModel):
    """Static metadata describing a plugin."""

    name: str
    description: str
    version: str
    author: str = ""
    requires_api_key: bool = False
    api_key_env_var: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True


class PluginResult(BaseModel):
    """The result of a single plugin execution."""

    plugin_name: str
    status: PluginStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    items_found: int = 0

    @property
    def is_success(self) -> bool:
        """Return True if the plugin completed without errors."""
        return self.status == PluginStatus.COMPLETED
