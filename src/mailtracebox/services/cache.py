"""Async-safe TTL cache with LRU eviction."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Generic, TypeVar

from mailtracebox.log.setup import get_logger

logger = get_logger("cache")

T = TypeVar("T")


class TtlCache(Generic[T]):
    """In-memory TTL cache with LRU eviction and async-safe access."""

    def __init__(self, max_size: int = 1000, default_ttl: float = 300.0) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._data: OrderedDict[str, tuple[T, float]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> T | None:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._misses += 1
                return None
            value, expires_at = entry
            if time.monotonic() >= expires_at:
                del self._data[key]
                self._misses += 1
                return None
            self._data.move_to_end(key)
            self._hits += 1
            return value

    async def set(self, key: str, value: T, ttl: float | None = None) -> None:
        async with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            elif len(self._data) >= self._max_size:
                evicted_key, _ = self._data.popitem(last=False)
                logger.debug("Cache evicted key: %s", evicted_key)
            expires_at = time.monotonic() + (ttl if ttl is not None else self._default_ttl)
            self._data[key] = (value, expires_at)

    async def delete(self, key: str) -> bool:
        async with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    async def size(self) -> int:
        async with self._lock:
            return len(self._data)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total else 0.0

    @property
    def stats(self) -> dict[str, int | float]:
        return {
            "size": len(self._data),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 4),
        }
