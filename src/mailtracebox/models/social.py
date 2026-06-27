"""Social media profile data model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SocialProfile(BaseModel):
    """A social media profile discovered during reconnaissance."""

    platform: str
    username: str
    url: str = ""
    display_name: str | None = None
    bio: str | None = None
    followers: int | None = None
    following: int | None = None
    posts_count: int | None = None
    verified: bool = False
    profile_image_url: str | None = None
    location: str | None = None
    created_at: datetime | None = None
    source: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
