"""Shared test fixtures for the mailtracebox test suite."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator

import pytest

from mailtracebox.config.schema import AppConfig, HttpConfig
from mailtracebox.core.context import Context
from mailtracebox.models.breach import BreachRecord
from mailtracebox.models.domain import DomainInfo, MXRecord
from mailtracebox.models.email import EmailAddress
from mailtracebox.models.social import SocialProfile


@pytest.fixture
def sample_email() -> EmailAddress:
    """A reusable sample EmailAddress."""
    return EmailAddress(
        address="alice@example.com",
        local_part="alice",
        domain="example.com",
        source="test",
        confidence=0.9,
    )


@pytest.fixture
def sample_domain() -> DomainInfo:
    """A reusable sample DomainInfo."""
    return DomainInfo(
        domain="example.com",
        registrar="Example Registrar Inc.",
        a_records=["93.184.216.34"],
        mx_records=[MXRecord(priority=10, host="mail.example.com")],
        spf_record="v=spf1 include:_spf.example.com ~all",
        source="test",
    )


@pytest.fixture
def sample_social() -> SocialProfile:
    """A reusable sample SocialProfile."""
    return SocialProfile(
        platform="github",
        username="octocat",
        url="https://github.com/octocat",
        display_name="The Octocat",
        source="test",
    )


@pytest.fixture
def sample_breach() -> BreachRecord:
    """A reusable sample BreachRecord."""
    return BreachRecord(
        name="ExampleBreach",
        domain="example.com",
        breach_date=datetime(2023, 1, 15, tzinfo=timezone.utc),
        pwn_count=1_000_000,
        data_classes=["Email addresses", "Passwords"],
        is_verified=True,
        source="test",
    )


@pytest.fixture
def app_config() -> AppConfig:
    """A default AppConfig for testing."""
    return AppConfig()


@pytest.fixture
def context() -> Context:
    """A fresh Context for a test target."""
    return Context(target="test@example.com")


@pytest.fixture
def http_config() -> HttpConfig:
    """Default HTTP config for testing."""
    return HttpConfig(timeout=5.0, max_retries=1)
