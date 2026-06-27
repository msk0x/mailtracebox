"""Framework-wide exception hierarchy."""

from __future__ import annotations


class EmailReconError(Exception):
    """Base exception for the mailtracebox framework."""

    def __init__(self, message: str = "", *, details: str | None = None) -> None:
        self.details = details
        super().__init__(message)


class ConfigurationError(EmailReconError):
    """Raised when configuration is invalid or missing."""


class ValidationError(EmailReconError):
    """Raised when input validation fails."""


class PluginError(EmailReconError):
    """Raised when a plugin encounters an unrecoverable error."""

    def __init__(
        self,
        message: str = "",
        *,
        plugin_name: str = "",
        details: str | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        super().__init__(message, details=details)


class PluginTimeoutError(PluginError):
    """Raised when a plugin exceeds its execution timeout."""


class HttpError(EmailReconError):
    """Raised for HTTP-level failures after all retries are exhausted."""

    def __init__(
        self,
        message: str = "",
        *,
        status_code: int | None = None,
        url: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(message)


class RateLimitExceededError(HttpError):
    """Raised when the rate limit is hit and backoff is not possible."""


class CacheError(EmailReconError):
    """Raised when cache operations fail."""


class ReportError(EmailReconError):
    """Raised when report generation fails."""
