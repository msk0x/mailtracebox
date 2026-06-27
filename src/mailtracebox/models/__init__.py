"""Pydantic data models for the mailtracebox framework."""

from __future__ import annotations

from mailtracebox.models.breach import BreachRecord
from mailtracebox.models.common import ScanError
from mailtracebox.models.domain import CertificateInfo, DomainInfo, MXRecord
from mailtracebox.models.email import EmailAddress
from mailtracebox.models.plugin import PluginMetadata, PluginResult, PluginStatus
from mailtracebox.models.report import Report, ReportFormat, ReportSection
from mailtracebox.models.social import SocialProfile

__all__ = [
    "BreachRecord", "CertificateInfo", "DomainInfo", "EmailAddress",
    "MXRecord", "PluginMetadata", "PluginResult", "PluginStatus",
    "Report", "ReportFormat", "ReportSection", "ScanError", "SocialProfile",
]
