"""Abstract base class for all mailtracebox plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mailtracebox.core.context import Context
from mailtracebox.models.plugin import PluginResult
from mailtracebox.services.http_client import HttpClient


class BasePlugin(ABC):
    """Contract that every intelligence plugin must fulfil."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def version(self) -> str: ...

    @property
    def author(self) -> str:
        return ""

    @property
    def requires_api_key(self) -> bool:
        return False

    @property
    def api_key_env_var(self) -> str | None:
        return None

    @property
    def dependencies(self) -> list[str]:
        return []

    @property
    def tags(self) -> list[str]:
        return []

    @abstractmethod
    async def execute(self, context: Context, http_client: HttpClient, config: dict[str, Any]) -> PluginResult: ...

    async def validate_config(self, config: dict[str, Any]) -> bool:
        return True

    def is_available(self, config: dict[str, Any]) -> bool:
        if self.requires_api_key and self.api_key_env_var:
            return bool(config.get(self.api_key_env_var))
        return True

    async def cleanup(self) -> None:
        pass

    def to_metadata(self) -> dict[str, Any]:
        return {
            "name": self.name, "description": self.description, "version": self.version,
            "author": self.author, "requires_api_key": self.requires_api_key,
            "api_key_env_var": self.api_key_env_var, "dependencies": self.dependencies,
            "tags": self.tags,
        }

    def __repr__(self) -> str:
        return f"<Plugin {self.name!r} v{self.version}>"
