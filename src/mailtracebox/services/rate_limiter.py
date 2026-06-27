"""Token-bucket rate limiter for throttling outbound requests."""

from __future__ import annotations

import asyncio
import time

from mailtracebox.log.setup import get_logger

logger = get_logger("rate_limiter")


class TokenBucketRateLimiter:
    """Async token-bucket rate limiter."""

    def __init__(self, rate: float, capacity: int) -> None:
        if rate <= 0:
            raise ValueError("Rate must be positive.")
        if capacity <= 0:
            raise ValueError("Capacity must be positive.")
        self._rate = rate
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait_time = deficit / self._rate
            logger.debug("Rate limiter: waiting %.3fs for %d token(s)", wait_time, tokens)
            await asyncio.sleep(wait_time)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    @property
    def available_tokens(self) -> float:
        return self._tokens

    @property
    def stats(self) -> dict[str, float | int]:
        return {"rate": self._rate, "capacity": self._capacity, "available_tokens": round(self._tokens, 2)}
