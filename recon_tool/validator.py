"""Domain input validation and scheme stripping."""

import re

__all__ = [
    "UUID_RE",
    "validate_domain",
]

# Shared UUID format regex — used by oidc.py and azure_metadata.py
# to validate tenant IDs before URL interpolation.
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Regex: valid domain has labels separated by dots, TLD at least 2 chars, no spaces
_DOMAIN_RE = re.compile(
    r"^(?!-)"                       # label must not start with hyphen
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"  # one or more labels followed by dot
    r"[a-z]{2,}$"                   # TLD: at least 2 alpha chars
)

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)

# Max raw input length — reject absurdly long strings before any processing.
# Longest realistic domain input is ~260 chars (253 domain + scheme + path).
_MAX_INPUT_LENGTH = 500


def validate_domain(raw_input: str) -> str:
    """Validate and normalize a domain string.

    - Strips leading/trailing whitespace
    - Raises ValueError if empty or whitespace-only
    - Strips http:// or https:// schemes (case-insensitive)
    - Strips trailing slashes and paths after the hostname
    - Validates domain format
    - Returns normalized lowercase domain

    Args:
        raw_input: Raw domain string from user input.

    Returns:
        Normalized lowercase domain string.

    Raises:
        ValueError: If domain is empty, whitespace-only, or invalid format.
    """
    stripped = raw_input.strip()

    if not stripped:
        raise ValueError("A valid domain is required")

    if len(stripped) > _MAX_INPUT_LENGTH:
        raise ValueError(f"Input too long ({len(stripped)} chars, max {_MAX_INPUT_LENGTH})")

    # Strip scheme
    domain = _SCHEME_RE.sub("", stripped)

    # Strip trailing path and slashes (take only the hostname part)
    domain = domain.split("/")[0]

    # Normalize to lowercase
    domain = domain.lower()

    # Strip www. prefix — people paste URLs from browsers, and www.example.com
    # is never the domain you want for tenant/DNS lookups. The zone apex
    # (example.com) is where TXT verification records and MX records live.
    if domain.startswith("www."):
        domain = domain[4:]

    # Validate format
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain format: {raw_input}")

    return domain
