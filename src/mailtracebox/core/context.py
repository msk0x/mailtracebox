"""Central intelligence context — the shared data store for a scan."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Generic, TypeVar
from uuid import uuid4

from pydantic import BaseModel

from mailtracebox.models.breach import BreachRecord
from mailtracebox.models.common import ScanError, ServerInfo
from mailtracebox.models.domain import CertificateInfo, DomainInfo
from mailtracebox.models.email import EmailAddress
from mailtracebox.models.plugin import PluginResult
from mailtracebox.models.social import SocialProfile

T = TypeVar("T")


class EntityCollection(Generic[T]):
    """Async-safe, deduplicated collection of reconnaissance entities."""

    def __init__(self, key_func: Callable[[T], str]) -> None:
        self._items: OrderedDict[str, T] = OrderedDict()
        self._key_func = key_func
        self._lock = asyncio.Lock()

    async def add(self, item: T) -> bool:
        async with self._lock:
            key = self._key_func(item)
            if key in self._items:
                return False
            self._items[key] = item
            return True

    async def add_many(self, items: list[T]) -> int:
        count = 0
        for item in items:
            if await self.add(item):
                count += 1
        return count

    async def get_all(self) -> list[T]:
        async with self._lock:
            return list(self._items.values())

    async def get_by_key(self, key: str) -> T | None:
        async with self._lock:
            return self._items.get(key)

    async def count(self) -> int:
        async with self._lock:
            return len(self._items)

    async def contains(self, key: str) -> bool:
        async with self._lock:
            return key in self._items

    async def keys(self) -> list[str]:
        async with self._lock:
            return list(self._items.keys())

    async def clear(self) -> None:
        async with self._lock:
            self._items.clear()


class Context:
    """Central intelligence context for a single scan."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.scan_id = uuid4().hex[:12]
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None

        self.target_email: str = ""
        self.target_local: str = ""
        self.target_domain: str = ""
        self._parse_target(target)

        self.emails: EntityCollection[EmailAddress] = EntityCollection(key_func=lambda e: e.address.lower())
        self.domains: EntityCollection[DomainInfo] = EntityCollection(key_func=lambda d: d.domain.lower())
        self.social_profiles: EntityCollection[SocialProfile] = EntityCollection(key_func=lambda s: f"{s.platform.lower()}:{s.username.lower()}")
        self.breaches: EntityCollection[BreachRecord] = EntityCollection(key_func=lambda b: f"{b.name.lower()}:{b.domain.lower()}")
        self.certificates: EntityCollection[CertificateInfo] = EntityCollection(key_func=lambda c: c.fingerprint_sha256 or c.serial_number)
        self.servers: EntityCollection[ServerInfo] = EntityCollection(key_func=lambda s: f"{s.host}:{s.port or 0}")

        self._plugin_results: dict[str, PluginResult] = {}
        self._plugin_lock = asyncio.Lock()
        self._errors: list[ScanError] = []
        self._errors_lock = asyncio.Lock()
        self._custom: dict[str, Any] = {}
        self._custom_lock = asyncio.Lock()

    def _parse_target(self, target: str) -> None:
        target = target.strip()
        if "@" in target:
            self.target_email = target.lower()
            local, domain = target.rsplit("@", 1)
            self.target_local = local.lower()
            self.target_domain = domain.lower()
        else:
            self.target_domain = target.lower()

    async def add_plugin_result(self, result: PluginResult) -> None:
        async with self._plugin_lock:
            self._plugin_results[result.plugin_name] = result

    async def get_plugin_result(self, name: str) -> PluginResult | None:
        async with self._plugin_lock:
            return self._plugin_results.get(name)

    async def get_all_plugin_results(self) -> list[PluginResult]:
        async with self._plugin_lock:
            return list(self._plugin_results.values())

    async def add_error(self, error: ScanError) -> None:
        async with self._errors_lock:
            self._errors.append(error)

    async def get_errors(self) -> list[ScanError]:
        async with self._errors_lock:
            return list(self._errors)

    async def set_custom(self, key: str, value: Any) -> None:
        async with self._custom_lock:
            self._custom[key] = value

    async def get_custom(self, key: str, default: Any = None) -> Any:
        async with self._custom_lock:
            return self._custom.get(key, default)

    async def get_custom_dict(self) -> dict[str, Any]:
        async with self._custom_lock:
            return dict(self._custom)

    async def complete(self) -> None:
        self.completed_at = datetime.now(timezone.utc)

    @property
    def duration(self) -> float | None:
        end = self.completed_at or datetime.now(timezone.utc)
        return round((end - self.started_at).total_seconds(), 3)

    async def to_dict(self) -> dict[str, Any]:
        def _dump(items: list[Any]) -> list[dict[str, Any]]:
            return [item.model_dump(mode="json") if isinstance(item, BaseModel) else item for item in items]
        return {
            "target": self.target, "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration,
            "target_email": self.target_email, "target_local": self.target_local, "target_domain": self.target_domain,
            "emails": _dump(await self.emails.get_all()),
            "domains": _dump(await self.domains.get_all()),
            "social_profiles": _dump(await self.social_profiles.get_all()),
            "breaches": _dump(await self.breaches.get_all()),
            "certificates": _dump(await self.certificates.get_all()),
            "servers": _dump(await self.servers.get_all()),
            "plugin_results": {n: r.model_dump(mode="json") for n, r in self._plugin_results.items()},
            "errors": _dump(self._errors),
            "custom": dict(self._custom),
        }

    def __repr__(self) -> str:
        return f"<Context target={self.target!r} scan_id={self.scan_id!r}>"
