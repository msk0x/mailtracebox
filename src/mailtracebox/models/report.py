"""Report output models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mailtracebox.models.plugin import PluginResult


class ReportFormat(str, Enum):
    """Supported report output formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    RICH = "rich"


class ReportSection(BaseModel):
    """A single section within a report."""

    title: str
    content: Any = None
    section_type: str = "text"
    visible: bool = True


class Report(BaseModel):
    """Complete scan report."""

    title: str = "Email Intelligence Report"
    target: str
    scan_id: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    sections: list[ReportSection] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    statistics: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    plugin_results: list[PluginResult] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
