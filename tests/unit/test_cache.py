"""Tests for the TTL cache."""

from __future__ import annotations

import asyncio

import pytest

from mailtracebox.services.cache import TtlCache


class TestTtlCache:
    """Tests for TtlCache."""

    async def test_set_and_get(self) -> None:
        cache: TtlCache[str] = TtlCache(max_size=10, default_ttl=60.0)
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"

    async def test_cache_miss(self) -> None:
        cache: TtlCache[str] = TtlCache()
        result = await cache.get("missing")
        assert result is None

    async def test_ttl_expiration(self) -> None:
        cache: TtlCache[str] = TtlCache(default_ttl=0.1)
        await cache.set("key1", "value1")
        await asyncio.sleep(0.15)
        result = await cache.get("key1")
        assert result is None

    async def test_custom_ttl(self) -> None:
        cache: TtlCache[str] = TtlCache(default_ttl=10.0)
        await cache.set("short", "data", ttl=0.1)
        await asyncio.sleep(0.15)
        assert await cache.get("short") is None

    async def test_lru_eviction(self) -> None:
        cache: TtlCache[str] = TtlCache(max_size=2, default_ttl=60.0)
        await cache.set("a", "1")
        await cache.set("b", "2")
        await cache.set("c", "3")  # should evict "a"
        assert await cache.get("a") is None
        assert await cache.get("b") == "2"
        assert await cache.get("c") == "3"

    async def test_lru_access_refreshes_order(self) -> None:
        cache: TtlCache[str] = TtlCache(max_size=2, default_ttl=60.0)
        await cache.set("a", "1")
        await cache.set("b", "2")
        _ = await cache.get("a")  # touch "a" to make it MRU
        await cache.set("c", "3")  # should evict "b" (LRU)
        assert await cache.get("a") == "1"
        assert await cache.get("b") is None

    async def test_delete(self) -> None:
        cache: TtlCache[str] = TtlCache()
        await cache.set("key", "val")
        assert await cache.delete("key") is True
        assert await cache.get("key") is None
        assert await cache.delete("nonexistent") is False

    async def test_clear(self) -> None:
        cache: TtlCache[str] = TtlCache()
        await cache.set("a", "1")
        await cache.set("b", "2")
        await cache.clear()
        assert await cache.size() == 0

    def test_hit_rate(self) -> None:
        cache: TtlCache[str] = TtlCache()
        assert cache.hit_rate == 0.0

    async def test_stats(self) -> None:
        cache: TtlCache[str] = TtlCache(max_size=5)
        await cache.set("k", "v")
        await cache.get("k")
        await cache.get("missing")
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
