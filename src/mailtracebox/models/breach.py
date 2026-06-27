"""Data breach record model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class BreachRecord(BaseModel):
    """A data breach entry associated with a target."""

    name: str
    domain: str = ""
    breach_date: datetime | None = None
    added_date: datetime | None = None
    modified_date: datetime | None = None
    pwn_count: int | None = None
    description: str | None = None
    data_classes: list[str] = Field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    logo_path: str | None = None
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
