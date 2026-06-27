"""Tests for Pydantic data models."""

from __future__ import annotations

from datetime import datetime, timezone

from mailtracebox.models.breach import BreachRecord
from mailtracebox.models.domain import CertificateInfo, DomainInfo, MXRecord
from mailtracebox.models.email import EmailAddress
from mailtracebox.models.plugin import PluginResult, PluginStatus
from mailtracebox.models.social import SocialProfile


class TestEmailAddress:
    """Tests for the EmailAddress model."""

    def test_auto_parse_address(self) -> None:
        """local_part and domain should be derived from address automatically."""
        email = EmailAddress(address="Bob@Example.COM")
        assert email.local_part == "Bob"
        assert email.domain == "Example.COM"

    def test_explicit_parts_take_precedence(self) -> None:
        email = EmailAddress(
            address="bob@example.com",
            local_part="robert",
            domain="other.com",
        )
        assert email.local_part == "robert"
        assert email.domain == "other.com"

    def test_serialization_round_trip(self) -> None:
        email = EmailAddress(address="test@example.com", confidence=0.85)
        data = email.model_dump()
        restored = EmailAddress(**data)
        assert restored.address == email.address
        assert restored.confidence == email.confidence

    def test_confidence_bounds(self) -> None:
        email = EmailAddress(address="a@b.com", confidence=0.0)
        assert email.confidence == 0.0
        email = EmailAddress(address="a@b.com", confidence=1.0)
        assert email.confidence == 1.0

    def test_default_values(self) -> None:
        email = EmailAddress(address="a@b.com")
        assert email.is_valid is True
        assert email.is_disposable is False
        assert email.is_role_account is False
        assert email.metadata == {}


class TestDomainInfo:
    """Tests for the DomainInfo model."""

    def test_basic_creation(self) -> None:
        domain = DomainInfo(domain="example.com")
        assert domain.domain == "example.com"
        assert domain.mx_records == []

    def test_mx_records(self) -> None:
        domain = DomainInfo(
            domain="example.com",
            mx_records=[
                MXRecord(priority=10, host="mail.example.com"),
                MXRecord(priority=20, host="mail2.example.com"),
            ],
        )
        assert len(domain.mx_records) == 2
        assert domain.mx_records[0].priority == 10

    def test_serialization(self) -> None:
        domain = DomainInfo(
            domain="test.com",
            a_records=["1.2.3.4"],
            spf_record="v=spf1 -all",
        )
        data = domain.model_dump()
        assert data["domain"] == "test.com"
        assert data["a_records"] == ["1.2.3.4"]


class TestCertificateInfo:
    """Tests for the CertificateInfo model."""

    def test_basic_creation(self) -> None:
        cert = CertificateInfo(
            subject="CN=example.com",
            issuer="Let's Encrypt",
            fingerprint_sha256="abc123",
        )
        assert cert.subject == "CN=example.com"


class TestSocialProfile:
    """Tests for the SocialProfile model."""

    def test_basic_creation(self, sample_social: SocialProfile) -> None:
        assert sample_social.platform == "github"
        assert sample_social.username == "octocat"

    def test_serialization(self, sample_social: SocialProfile) -> None:
        data = sample_social.model_dump()
        assert data["platform"] == "github"


class TestBreachRecord:
    """Tests for the BreachRecord model."""

    def test_basic_creation(self, sample_breach: BreachRecord) -> None:
        assert sample_breach.name == "ExampleBreach"
        assert sample_breach.pwn_count == 1_000_000

    def test_data_classes(self, sample_breach: BreachRecord) -> None:
        assert "Email addresses" in sample_breach.data_classes


class TestPluginResult:
    """Tests for the PluginResult model."""

    def test_success_status(self) -> None:
        result = PluginResult(
            plugin_name="test",
            status=PluginStatus.COMPLETED,
        )
        assert result.is_success is True

    def test_failed_status(self) -> None:
        result = PluginResult(
            plugin_name="test",
            status=PluginStatus.FAILED,
        )
        assert result.is_success is False

    def test_serialization(self) -> None:
        result = PluginResult(
            plugin_name="dns",
            status=PluginStatus.COMPLETED,
            items_found=5,
        )
        data = result.model_dump()
        assert data["plugin_name"] == "dns"
        assert data["items_found"] == 5
