"""Email address data model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator


class EmailAddress(BaseModel):
    """An email address with associated metadata."""

    address: str
    local_part: str = ""
    domain: str = ""
    is_valid: bool = True
    is_disposable: bool = False
    is_role_account: bool = False
    mx_hosts: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _auto_parse_address(cls, data: Any) -> Any:
        """Derive local_part and domain from address if not provided."""
        if isinstance(data, dict) and "address" in data:
            addr: str = data["address"]
            if "@" in addr and not data.get("local_part"):
                local, domain = addr.rsplit("@", 1)
                data.setdefault("local_part", local)
                data.setdefault("domain", domain)
        return data
