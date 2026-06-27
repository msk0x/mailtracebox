"""Tests for the Context engine and EntityCollection."""

from __future__ import annotations

import asyncio

import pytest

from mailtracebox.core.context import Context, EntityCollection
from mailtracebox.models.email import EmailAddress


class TestEntityCollection:
    """Tests for the generic EntityCollection."""

    async def test_add_and_count(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        e1 = EmailAddress(address="a@b.com")
        e2 = EmailAddress(address="c@d.com")
        assert await coll.add(e1) is True
        assert await coll.add(e2) is True
        assert await coll.count() == 2

    async def test_deduplication(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address.lower())
        e1 = EmailAddress(address="A@B.com")
        e2 = EmailAddress(address="a@b.com")
        assert await coll.add(e1) is True
        assert await coll.add(e2) is False  # duplicate
        assert await coll.count() == 1

    async def test_get_all(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        await coll.add(EmailAddress(address="a@b.com"))
        await coll.add(EmailAddress(address="c@d.com"))
        items = await coll.get_all()
        assert len(items) == 2

    async def test_get_by_key(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        e = EmailAddress(address="a@b.com")
        await coll.add(e)
        found = await coll.get_by_key("a@b.com")
        assert found is not None
        assert found.address == "a@b.com"

    async def test_contains(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        await coll.add(EmailAddress(address="a@b.com"))
        assert await coll.contains("a@b.com") is True
        assert await coll.contains("x@y.com") is False

    async def test_add_many(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        items = [
            EmailAddress(address="a@b.com"),
            EmailAddress(address="c@d.com"),
            EmailAddress(address="a@b.com"),  # duplicate
        ]
        added = await coll.add_many(items)
        assert added == 2
        assert await coll.count() == 2

    async def test_keys(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        await coll.add(EmailAddress(address="a@b.com"))
        keys = await coll.keys()
        assert keys == ["a@b.com"]

    async def test_clear(self) -> None:
        coll = EntityCollection[EmailAddress](key_func=lambda e: e.address)
        await coll.add(EmailAddress(address="a@b.com"))
        await coll.clear()
        assert await coll.count() == 0


class TestContext:
    """Tests for the Context class."""

    def test_target_parsing_email(self) -> None:
        ctx = Context(target="alice@example.com")
        assert ctx.target_email == "alice@example.com"
        assert ctx.target_local == "alice"
        assert ctx.target_domain == "example.com"

    def test_target_parsing_domain(self) -> None:
        ctx = Context(target="example.com")
        assert ctx.target_email == ""
        assert ctx.target_domain == "example.com"

    def test_scan_id_unique(self) -> None:
        ctx1 = Context(target="a@b.com")
        ctx2 = Context(target="a@b.com")
        assert ctx1.scan_id != ctx2.scan_id

    async def test_add_and_get_email(self, context: Context) -> None:
        email = EmailAddress(address="test@example.com")
        added = await context.emails.add(email)
        assert added is True
        count = await context.emails.count()
        assert count == 1

    async def test_plugin_results(self, context: Context) -> None:
        from mailtracebox.models.plugin import PluginResult, PluginStatus

        result = PluginResult(
            plugin_name="test_plugin",
            status=PluginStatus.COMPLETED,
            items_found=3,
        )
        await context.add_plugin_result(result)
        retrieved = await context.get_plugin_result("test_plugin")
        assert retrieved is not None
        assert retrieved.items_found == 3

    async def test_errors(self, context: Context) -> None:
        from mailtracebox.models.common import ScanError

        error = ScanError(source="test", error_type="timeout", message="timed out")
        await context.add_error(error)
        errors = await context.get_errors()
        assert len(errors) == 1
        assert errors[0].source == "test"

    async def test_custom_data(self, context: Context) -> None:
        await context.set_custom("key1", "value1")
        val = await context.get_custom("key1")
        assert val == "value1"
        assert await context.get_custom("missing", "default") == "default"

    async def test_duration(self, context: Context) -> None:
        assert context.duration is not None
        assert context.duration >= 0

    async def test_to_dict(self, context: Context) -> None:
        data = await context.to_dict()
        assert data["target"] == "test@example.com"
        assert "scan_id" in data
        assert "emails" in data
        assert isinstance(data["emails"], list)

    async def test_concurrent_add(self) -> None:
        """EntityCollection must be safe under concurrent writes."""
        ctx = Context(target="test@test.com")

        async def add_email(addr: str) -> None:
            await ctx.emails.add(EmailAddress(address=addr))

        tasks = [add_email(f"user{i}@test.com") for i in range(50)]
        await asyncio.gather(*tasks)
        assert await ctx.emails.count() == 50
