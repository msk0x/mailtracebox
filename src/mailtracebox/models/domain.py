"""Domain and DNS-related data models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MXRecord(BaseModel):
    """A DNS MX record."""

    priority: int
    host: str


class TXTRecord(BaseModel):
    """A DNS TXT record."""

    name: str = ""
    value: str


class CertificateInfo(BaseModel):
    """TLS/SSL certificate information."""

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint_sha256: str = ""
    sans: list[str] = Field(default_factory=list)
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DomainInfo(BaseModel):
    """Comprehensive domain information gathered during reconnaissance."""

    domain: str
    registrar: str | None = None
    registrant: str | None = None
    registration_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    name_servers: list[str] = Field(default_factory=list)
    mx_records: list[MXRecord] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    spf_record: str | None = None
    dmarc_record: str | None = None
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    whois_raw: str | None = None
    ssl_certificate: CertificateInfo | None = None
    technologies: list[str] = Field(default_factory=list)
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
