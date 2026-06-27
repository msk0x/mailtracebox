"""Tests for the token-bucket rate limiter."""

from __future__ import annotations

import asyncio
import time

import pytest

from mailtracebox.services.rate_limiter import TokenBucketRateLimiter


class TestTokenBucketRateLimiter:
    """Tests for TokenBucketRateLimiter."""

    def test_invalid_params(self) -> None:
        with pytest.raises(ValueError, match="Rate"):
            TokenBucketRateLimiter(rate=0, capacity=10)
        with pytest.raises(ValueError, match="Capacity"):
            TokenBucketRateLimiter(rate=1, capacity=0)

    async def test_acquire_single_token(self) -> None:
        limiter = TokenBucketRateLimiter(rate=10, capacity=10)
        await limiter.acquire(1)
        # Should complete immediately

    async def test_acquire_drains_bucket(self) -> None:
        limiter = TokenBucketRateLimiter(rate=10, capacity=5)
        for _ in range(5):
            await limiter.acquire(1)
        # Bucket is now empty — next acquire should block briefly
        start = time.monotonic()
        await limiter.acquire(1)
        elapsed = time.monotonic() - start
        # At rate=10, acquiring 1 token when empty should take ~0.1s
        assert elapsed >= 0.05  # allow some tolerance

    async def test_burst_capacity(self) -> None:
        limiter = TokenBucketRateLimiter(rate=1, capacity=5)
        # Should allow burst of 5 without blocking
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire(1)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # should be near-instant

    async def test_available_tokens(self) -> None:
        limiter = TokenBucketRateLimiter(rate=10, capacity=10)
        assert limiter.available_tokens == 10.0
        await limiter.acquire(3)
        assert limiter.available_tokens <= 7.0 + 0.1  # small margin for timing

    def test_stats(self) -> None:
        limiter = TokenBucketRateLimiter(rate=5, capacity=20)
        stats = limiter.stats
        assert stats["rate"] == 5
        assert stats["capacity"] == 20
