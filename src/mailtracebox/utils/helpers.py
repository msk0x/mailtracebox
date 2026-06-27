"""General-purpose helpers with no domain logic."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

T = TypeVar("T")


def utc_now() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base*.

    For keys present in both, dict values are merged recursively;
    all other types in *override* take precedence.
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def flatten_dict(d: dict[str, Any], prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten a nested dict into dot-separated keys.

    Example::

        {"a": {"b": 1}} -> {"a.b": 1}
    """
    items: dict[str, Any] = {}
    for key, value in d.items():
        new_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key, sep))
        else:
            items[new_key] = value
    return items


def truncate(text: str, max_length: int = 80, suffix: str = "...") -> str:
    """Truncate *text* to *max_length* characters, appending *suffix* if trimmed."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


async def gather_with_concurrency(
    limit: int,
    *coros: Awaitable[T],
) -> list[T]:
    """Run awaitables with a concurrency *limit*.

    Returns results in the order coroutines were passed, not completion order.
    """
    semaphore = asyncio.Semaphore(limit)

    async def _wrapper(coro: Awaitable[T]) -> T:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(_wrapper(c) for c in coros))


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
    **kwargs: Any,
) -> T:
    """Execute an async callable with exponential backoff.

    Parameters
    ----------
    func:
        The async function to call.
    max_retries:
        Maximum number of retry attempts.
    base_delay:
        Initial delay in seconds between retries.
    max_delay:
        Cap on the backoff delay.
    exceptions:
        Tuple of exception types that trigger a retry.
    """
    last_exc: BaseException | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except exceptions as exc:
            last_exc = exc
            if attempt == max_retries:
                break
            delay = min(base_delay * (2 ** attempt), max_delay)
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


def seconds_since(start: float) -> float:
    """Return elapsed seconds since *start* (a ``time.monotonic()`` value)."""
    return round(time.monotonic() - start, 4)
