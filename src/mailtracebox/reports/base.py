"""Abstract base class for report generators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from mailtracebox.config.schema import ReportsConfig
from mailtracebox.core.context import Context


class BaseReporter(ABC):
    @property
    @abstractmethod
    def format_name(self) -> str: ...

    @property
    @abstractmethod
    def file_extension(self) -> str: ...

    @abstractmethod
    def generate(self, context: Context, config: ReportsConfig) -> str: ...

    def save(self, content: str, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
