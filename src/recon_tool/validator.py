"""Domain input validation and scheme stripping."""

import contextlib
import re
from urllib.parse import urlsplit

import deal

__all__ = [
    "UUID_RE",
    "host_has_suffix",
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


def host_has_suffix(host: str, suffix: str) -> bool:
    """True when *host* equals *suffix* or is below it in the DNS tree.

    This is the boundary-aware replacement for checks like
    ``"vendor.com" in host``. A value such as ``vendor.com.example.net`` must not
    match ``vendor.com`` because the vendor name is an interior label, not the
    hostname suffix.
    """
    normalized_host = host.lower().rstrip(".")
    normalized_suffix = suffix.lower().rstrip(".")
    return normalized_host == normalized_suffix or normalized_host.endswith(f".{normalized_suffix}")


# Max length for a sanitized free-text display field (certificate issuer
# or subject name, VMC organization, etc.) pulled from a source recon
# does not control. Long enough for any real CA or company name, short
# enough to bound a hostile payload.
_MAX_DISPLAY_LEN = 200

_BIDI_CONTROL_CODEPOINTS = frozenset(
    {
        0x061C,  # Arabic Letter Mark
        0x200E,  # Left-to-Right Mark
        0x200F,  # Right-to-Left Mark
        *range(0x202A, 0x202F),  # embeddings, overrides, and pop formatting
        *range(0x2066, 0x206A),  # directional isolates and pop isolate
    }
)


def _has_no_control_chars(value: str) -> bool:
    """No terminal or bidirectional formatting control survives."""

    return all(
        not (ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F or ord(c) in _BIDI_CONTROL_CODEPOINTS)
        for c in value
    )


@deal.post(_has_no_control_chars)  # pyright: ignore[reportUntypedFunctionDecorator]
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

    This removes every C0 control (0x00-0x1F), DEL (0x7F), C1 control
    (0x80-0x9F), and Unicode bidirectional formatting control, then truncates
    to *max_len*. Ordinary right-to-left letters remain intact; only invisible
    formatting state that can reorder surrounding output is removed.
    """
    cleaned = "".join(
        c
        for c in value
        if not (ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F or ord(c) in _BIDI_CONTROL_CODEPOINTS)
    )
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


def _is_normalized_domain(domain: str) -> bool:
    """A returned domain is lowercase and matches the domain grammar.

    ``validate_domain`` only returns after ``_DOMAIN_RE`` matches the lowercased,
    scheme-stripped, punycode-encoded value, so this postcondition holds on every
    successful return (it does not constrain the ValueError-raising paths).
    """
    return domain == domain.lower() and bool(_DOMAIN_RE.match(domain))


@deal.post(_is_normalized_domain)  # pyright: ignore[reportUntypedFunctionDecorator]
def validate_domain(raw_input: str, *, apex: bool = True) -> str:
    """Validate and normalize a domain string.

    - Strips leading/trailing whitespace
    - Raises ValueError if empty or whitespace-only
    - Strips http:// or https:// schemes (case-insensitive)
    - Strips trailing slashes and paths after the hostname
    - Validates domain format
    - Reduces to the registrable apex (eTLD+1) unless ``apex=False``
    - Returns normalized lowercase domain

    Args:
        raw_input: Raw domain string from user input.
        apex: When True (default), reduce the validated host to its
            registrable domain via the Public Suffix List, so a pasted URL or
            sub-host (``https://mail.acme.co.uk/x``) is analyzed at the apex
            (``acme.co.uk``) where recon's signal lives. This subsumes the old
            special-case ``www.`` strip. Pass False (``recon --exact``) to keep
            the literal host for the narrow "DNS facts about this one host"
            case.

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

    if _SCHEME_RE.match(stripped):
        try:
            domain = urlsplit(stripped).hostname or ""
        except ValueError:
            domain = ""
    else:
        # Bare host input may still include a copied query, fragment, or path.
        domain = re.split(r"[/?#]", stripped, maxsplit=1)[0]
        # ...and a trailing :port, which urlsplit() already strips on the
        # scheme branch. Strip it here too so ``example.com:8443`` normalizes
        # the same way ``https://example.com:8443`` does instead of failing the
        # format check on the stray colon.
        domain = re.sub(r":\d+$", "", domain)

    # Normalize to lowercase
    domain = domain.lower()

    # Strip a trailing root-label dot. An absolute FQDN like "example.com." is a
    # common paste form; dropping the dot normalizes it the same way the scheme,
    # www, and port artifacts above are handled, instead of failing the format
    # check on the stray dot. An all-dots string reduces to "" and still fails.
    domain = domain.rstrip(".")

    # Strip www. prefix — people paste URLs from browsers, and www.example.com
    # is never the domain you want for tenant/DNS lookups. The zone apex
    # (example.com) is where TXT verification records and MX records live. This
    # is independent of apex reduction: even --exact (apex=False) drops www.,
    # because a literal www host is never a meaningful analysis target. Only
    # strip when the remainder is still a valid domain, so a registrable label
    # of ``www`` (e.g. the real domain ``www.com``) is not clobbered to a bare
    # TLD that then fails the format check.
    if domain.startswith("www.") and _DOMAIN_RE.match(domain[4:]):
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
            encoded = domain.encode("idna").decode("ascii")
            # The stdlib idna codec is IDNA2003/nameprep, which is lossy: it maps
            # faß.de to fass.de, straße.de to strasse.de, and folds fullwidth /
            # zero-width characters away, silently changing the registrable domain.
            # Only accept the conversion when it round-trips, so a lossy mapping to
            # a different domain is rejected (it falls through to the format check
            # below) rather than queried as the wrong domain.
            if encoded.encode("ascii").decode("idna") == domain.lower():
                domain = encoded

    # Validate format
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain format: {raw_input}")

    # Reduce to the registrable apex (eTLD+1) so a pasted URL or sub-host is
    # analyzed where recon's signal lives. Imported lazily because constructing
    # the Public Suffix List parses a bundled data file, and callers that pass
    # apex=False (recon --exact) should not pay that cost. to_apex falls back to
    # the validated host when it is already an apex or is itself a public
    # suffix, so the postcondition (lowercase, matches _DOMAIN_RE) still holds.
    if apex:
        from recon_tool.psl import to_apex

        domain = to_apex(domain)

    return domain
