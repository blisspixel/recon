"""Domain input validation and scheme stripping."""

import contextlib
import re

__all__ = [
    "UUID_RE",
    "is_safe_dns_name",
    "strip_control_chars",
    "validate_domain",
]

# Characters allowed in a DNS name recon will display or follow: the
# letter-digit-hyphen alphabet plus dot, underscore (DKIM / SRV
# selectors), and the leading wildcard label. Used to reject SAN values
# and other DNS-derived names that carry control bytes or other non-DNS
# characters before they reach output or further processing.
_SAFE_DNS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-._*")


def is_safe_dns_name(name: str) -> bool:
    """True when *name* contains only DNS-safe characters (case-insensitive)."""
    return bool(name) and all(c in _SAFE_DNS_CHARS for c in name.lower())


# Max length for a sanitized free-text display field (certificate issuer
# or subject name, VMC organization, etc.) pulled from a source recon
# does not control. Long enough for any real CA or company name, short
# enough to bound a hostile payload.
_MAX_DISPLAY_LEN = 200


def strip_control_chars(value: str, max_len: int = _MAX_DISPLAY_LEN) -> str:
    """Remove control characters from an attacker-derived display string and
    bound its length.

    recon renders strings pulled from public sources it does not control
    (certificate issuer and subject names from CT logs, VMC subject fields
    fetched over HTTP) to the operator's terminal and into JSON, markdown,
    and MCP output. Terminal emulators act on C0 / C1 control bytes
    (ESC-introduced ANSI sequences, NUL, CR, LF, BEL), and the rich
    library does not strip ESC, so an unsanitized issuer or subject name
    carrying a raw ESC could move the cursor, recolor, clear the screen,
    or drive OSC escapes. An interior newline also lets such a value
    inject extra lines into the line-oriented output an agent or SIEM
    consumes.

    This removes every C0 control (0x00-0x1F), DEL (0x7F), and C1 control
    (0x80-0x9F), then truncates to *max_len*. Printable content (letters,
    digits, spaces, punctuation, non-control Unicode) is preserved, so a
    legitimate "DigiCert Inc" or "Contoso, Ltd." is unchanged.
    """
    cleaned = "".join(c for c in value if not (ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F))
    return cleaned[:max_len]


# Shared UUID format regex — used by oidc.py and azure_metadata.py
# to validate tenant IDs before URL interpolation.
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Regex: valid domain has labels separated by dots. TLD rules follow labels
# (alphanumeric + hyphens, no leading/trailing hyphen), minimum two chars.
# This accepts Punycode / IDN TLDs like ``xn--p1ai`` (Russian) and
# ``xn--fiqs8s`` (Chinese); the old ``[a-z]{2,}`` TLD pattern rejected
# every IDN as ``Invalid domain format``.
_DOMAIN_RE = re.compile(
    r"^(?!-)"  # label must not start with hyphen
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"  # one or more labels followed by dot
    r"[a-z][a-z0-9-]*[a-z0-9]$"  # TLD: alpha-first (no numeric TLDs), alnum-last, min 2 chars
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

    # Internationalized domain names: convert a raw-Unicode IDN (for
    # example ``münchen.de``) to its ASCII punycode form
    # (``xn--mnchen-3ya.de``) before the format check, so an operator can
    # paste an IDN directly instead of pre-encoding it. Uses the stdlib
    # IDNA codec, so no new dependency. A string the codec cannot encode
    # (empty or oversized labels) raises and falls through to the format
    # check below, which rejects it with the usual clear error. Surfaced by
    # the 2026-05 corpus validation, where a raw-Unicode IDN apex was the
    # only rejected domain in a 200-domain run.
    if not domain.isascii():
        with contextlib.suppress(UnicodeError, ValueError):
            domain = domain.encode("idna").decode("ascii")

    # Validate format
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain format: {raw_input}")

    return domain
