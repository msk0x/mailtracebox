"""Input validation helpers."""

from __future__ import annotations

import re

from mailtracebox.utils.exceptions import ValidationError

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.[A-Za-z0-9-]{1,63})*"
    r"\.[A-Za-z]{2,}$"
)

ROLE_PREFIXES = frozenset({
    "abuse", "admin", "administrator", "billing", "compliance",
    "contact", "devnull", "dns", "ftp", "help", "hostmaster",
    "info", "ispfeedback", "ispsupport", "jobs", "list",
    "listmaster", "maildaemon", "mailerdaemon", "marketing",
    "media", "noc", "noreply", "no-reply", "null", "office",
    "operations", "postmaster", "privacy", "registrar",
    "remove", "request", "role", "root", "sales", "security",
    "service", "spam", "subscribe", "support", "sysadmin",
    "tech", "trouble", "undisclosed-recipients", "unsubscribe",
    "usenet", "uucp", "webmaster", "www",
})


def validate_email(address: str) -> str:
    """Validate and normalise an email address."""
    address = address.strip().lower()
    if not address:
        raise ValidationError("Email address must not be empty.")
    if len(address) > 254:
        raise ValidationError(f"Email address exceeds 254 characters: {len(address)}.")
    if not _EMAIL_RE.match(address):
        raise ValidationError(f"Invalid email address syntax: {address!r}")
    return address


def validate_domain(domain: str) -> str:
    """Validate and normalise a domain name."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValidationError("Domain must not be empty.")
    if len(domain) > 253:
        raise ValidationError(f"Domain exceeds 253 characters: {len(domain)}.")
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"Invalid domain syntax: {domain!r}")
    return domain


def parse_email_parts(address: str) -> tuple[str, str]:
    """Split an email address into local-part and domain."""
    validated = validate_email(address)
    local_part, domain = validated.rsplit("@", 1)
    return local_part, domain


def is_role_account(local_part: str) -> bool:
    """Return True if the local-part looks like a role/functional account."""
    return local_part.lower() in ROLE_PREFIXES


def is_disposable_domain(domain: str) -> bool:
    """Heuristic check for known disposable email domains."""
    disposable_suffixes = {
        "mailinator.com", "guerrillamail.com", "tempmail.com",
        "throwaway.email", "yopmail.com", "sharklasers.com",
        "guerrillamailblock.com", "grr.la", "dispostable.com",
        "trashmail.com", "maildrop.cc", "fakeinbox.com",
        "tempail.com", "tempr.email", "discard.email",
    }
    return domain.lower() in disposable_suffixes
