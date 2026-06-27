"""Shared base types and lightweight models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ScanError(BaseModel):
    """Represents an error that occurred during a scan."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str
    error_type: str
    message: str
    details: str | None = None
    recoverable: bool = True


class ServerInfo(BaseModel):
    """A network server discovered during reconnaissance."""

    host: str
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    banner: str | None = None
    os_hint: str | None = None
    technologies: list[str] = Field(default_factory=list)
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class RepositoryInfo(BaseModel):
    """A code repository associated with a target."""

    platform: str
    name: str
    url: str
    description: str | None = None
    language: str | None = None
    stars: int | None = None
    forks: int | None = None
    last_updated: datetime | None = None
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentInfo(BaseModel):
    """A document or file reference found during reconnaissance."""

    name: str
    url: str | None = None
    doc_type: str | None = None
    description: str | None = None
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
