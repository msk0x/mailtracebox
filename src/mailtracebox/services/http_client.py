"""Async HTTP client with connection pooling, caching, rate limiting, and retries."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

from mailtracebox.config.schema import HttpConfig
from mailtracebox.log.setup import get_logger
from mailtracebox.services.cache import TtlCache
from mailtracebox.services.rate_limiter import TokenBucketRateLimiter
from mailtracebox.utils.exceptions import HttpError

logger = get_logger("http")


@dataclass(frozen=True)
class HttpResponse:
    """Immutable container for an HTTP response."""

    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.body)

    def json_or(self, default: Any = None) -> Any:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, ValueError):
            return default


@dataclass
class HttpStats:
    """Mutable statistics collector for HTTP operations."""

    requests_made: int = 0
    cache_hits: int = 0
    retries: int = 0
    errors: int = 0
    total_bytes: int = 0
    total_time: float = 0.0


class HttpClient:
    """Production-grade async HTTP client."""

    def __init__(self, config: HttpConfig) -> None:
        self._config = config
        self._session: aiohttp.ClientSession | None = None
        self._cache: TtlCache[HttpResponse] = TtlCache(
            max_size=config.cache_size, default_ttl=config.cache_ttl,
        )
        self._rate_limiter = TokenBucketRateLimiter(
            rate=config.rate_limit_requests / config.rate_limit_window,
            capacity=config.rate_limit_requests,
        )
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        self.stats = HttpStats()

    async def __aenter__(self) -> HttpClient:
        connector = aiohttp.TCPConnector(
            limit=self._config.pool_size,
            ttl_dns_cache=self._config.dns_cache_ttl,
            ssl=None if self._config.verify_ssl else False,
        )
        timeout = aiohttp.ClientTimeout(
            total=self._config.timeout, connect=self._config.connect_timeout,
        )
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=timeout,
            headers={"User-Agent": self._config.user_agent},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        await asyncio.sleep(0)

    async def get(
        self, url: str, *, use_cache: bool = True,
        headers: dict[str, str] | None = None, params: dict[str, str] | None = None,
        no_retry: bool = False,
    ) -> HttpResponse:
        """Send a GET request."""
        return await self.request("GET", url, use_cache=use_cache, headers=headers, params=params, no_retry=no_retry)

    async def post(
        self, url: str, *, data: Any = None, json_body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Send a POST request (never cached)."""
        kwargs: dict[str, Any] = {}
        if data is not None:
            kwargs["data"] = data
        if json_body is not None:
            kwargs["json"] = json_body
        if headers:
            kwargs["headers"] = headers
        return await self.request("POST", url, use_cache=False, **kwargs)

    async def request(self, method: str, url: str, *, use_cache: bool = True, no_retry: bool = False, **kwargs: Any) -> HttpResponse:
        """Send an HTTP request with retries, caching, and rate limiting."""
        self._ensure_session()
        if use_cache and method.upper() == "GET":
            cached = await self._cache.get(url)
            if cached is not None:
                self.stats.cache_hits += 1
                logger.debug("Cache HIT: %s", url)
                return cached
        await self._rate_limiter.acquire()
        async with self._semaphore:
            return await self._do_request(method, url, use_cache=use_cache, no_retry=no_retry, **kwargs)

    async def _do_request(self, method: str, url: str, *, use_cache: bool, no_retry: bool = False, **kwargs: Any) -> HttpResponse:
        """Execute the actual HTTP request with retry logic."""
        last_exc: Exception | None = None
        for attempt in range(self._config.max_retries + 1):
            self.stats.requests_made += 1
            start = time.monotonic()
            try:
                assert self._session is not None
                async with self._session.request(method, url, **kwargs) as resp:
                    body = await resp.text()
                    elapsed = time.monotonic() - start
                    self.stats.total_time += elapsed
                    self.stats.total_bytes += len(body)
                    result = HttpResponse(
                        status=resp.status, headers=dict(resp.headers),
                        body=body, url=str(resp.url), elapsed=round(elapsed, 4),
                    )
                    if resp.status == 429:
                        if no_retry:
                            logger.debug("429 for %s — skipping retry (no_retry)", url)
                            return result
                        retry_after = self._parse_retry_after(resp.headers)
                        logger.warning(
                            "429 for %s — retrying in %.1fs (attempt %d/%d)",
                            url, retry_after, attempt + 1, self._config.max_retries,
                        )
                        self.stats.retries += 1
                        await asyncio.sleep(retry_after)
                        continue
                    if use_cache and resp.status == 200 and method.upper() == "GET":
                        await self._cache.set(url, result)
                    logger.debug("%s %s -> %d (%.3fs, %d bytes)", method, url, resp.status, elapsed, len(body))
                    return result
            except asyncio.TimeoutError:
                elapsed = time.monotonic() - start
                self.stats.errors += 1
                last_exc = HttpError(f"Timeout after {elapsed:.1f}s: {method} {url}", url=url)
                logger.warning("Timeout for %s %s (attempt %d/%d)", method, url, attempt + 1, self._config.max_retries)
            except aiohttp.ClientError as exc:
                self.stats.errors += 1
                last_exc = HttpError(f"Client error: {exc} [{method} {url}]", url=url)
                logger.warning("Client error for %s %s: %s (attempt %d/%d)", method, url, exc, attempt + 1, self._config.max_retries)
            if attempt < self._config.max_retries:
                delay = min(2.0 ** attempt, 30.0)
                self.stats.retries += 1
                await asyncio.sleep(delay)
        raise last_exc or HttpError(f"Request failed after retries: {method} {url}", url=url)

    def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            raise RuntimeError("HttpClient session is not open. Use 'async with HttpClient(config) as client:'.")

    @staticmethod
    def _parse_retry_after(headers: dict[str, str]) -> float:
        value = headers.get("Retry-After", headers.get("retry-after", "5"))
        try:
            return max(float(value), 1.0)
        except ValueError:
            return 5.0

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
