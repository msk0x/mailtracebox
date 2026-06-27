"""Centralised logging setup."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from mailtracebox.config.schema import LoggingConfig


def setup_logging(config: LoggingConfig) -> None:
    """Configure the root logger based on config."""
    root = logging.getLogger("mailtracebox")
    root.setLevel(getattr(logging, config.level.upper(), logging.INFO))
    root.handlers.clear()

    if config.rich_console:
        rich_handler = RichHandler(
            console=Console(stderr=True),
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            markup=True,
        )
        rich_handler.setLevel(getattr(logging, config.level.upper(), logging.INFO))
        root.addHandler(rich_handler)
    else:
        if config.format == "json":
            formatter = _JsonFormatter()
        else:
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(getattr(logging, config.level.upper(), logging.INFO))
        root.addHandler(stream_handler)

    if config.file:
        file_path = Path(config.file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)

    for noisy in ("aiohttp", "asyncio", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the mailtracebox namespace."""
    return logging.getLogger(f"mailtracebox.{name}")


class _JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        log_entry: dict[str, object] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)
