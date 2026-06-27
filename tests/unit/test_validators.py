"""Tests for input validation helpers."""

from __future__ import annotations

import pytest

from mailtracebox.utils.exceptions import ValidationError
from mailtracebox.utils.validators import (
    is_disposable_domain,
    is_role_account,
    parse_email_parts,
    validate_domain,
    validate_email,
)


class TestValidateEmail:
    def test_valid_address(self) -> None:
        assert validate_email("user@example.com") == "user@example.com"

    def test_normalisation(self) -> None:
        assert validate_email("  User@Example.COM  ") == "user@example.com"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_email("")

    def test_no_at_raises(self) -> None:
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("notanemail")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 254"):
            validate_email("a" * 250 + "@b.com")

    def test_dotted_local_part(self) -> None:
        assert validate_email("first.last@example.com") == "first.last@example.com"

    def test_plus_addressing(self) -> None:
        assert validate_email("user+tag@example.com") == "user+tag@example.com"


class TestValidateDomain:
    def test_valid_domain(self) -> None:
        assert validate_domain("example.com") == "example.com"

    def test_normalisation(self) -> None:
        assert validate_domain("  EXAMPLE.COM.  ") == "example.com"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_domain("")

    def test_invalid_chars(self) -> None:
        with pytest.raises(ValidationError, match="Invalid domain"):
            validate_domain("exam ple.com")

    def test_subdomain(self) -> None:
        assert validate_domain("sub.example.com") == "sub.example.com"


class TestParseEmailParts:
    def test_standard(self) -> None:
        local, domain = parse_email_parts("alice@example.com")
        assert local == "alice"
        assert domain == "example.com"


class TestIsRoleAccount:
    def test_role_accounts(self) -> None:
        assert is_role_account("admin") is True
        assert is_role_account("postmaster") is True
        assert is_role_account("noreply") is True
        assert is_role_account("support") is True

    def test_personal_accounts(self) -> None:
        assert is_role_account("alice") is False
        assert is_role_account("john.smith") is False


class TestIsDisposableDomain:
    def test_disposable(self) -> None:
        assert is_disposable_domain("mailinator.com") is True
        assert is_disposable_domain("yopmail.com") is True

    def test_legitimate(self) -> None:
        assert is_disposable_domain("gmail.com") is False
        assert is_disposable_domain("example.com") is False
