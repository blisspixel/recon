"""Bounded issuer display labels, independent of provider DN formatting."""

from __future__ import annotations

from dataclasses import replace

from recon_tool.models import CertSummary
from recon_tool.validator import strip_control_chars

# Exact display aliases, not certificate or organization authentication.
# https://www.ssl.com/repository/ and https://www.sectigo.com/legal
_ALIASES = {"ssl corporation": "SSL.com", "ssl.com": "SSL.com", "sectigo limited": "Sectigo", "sectigo": "Sectigo"}
_HEX = frozenset("0123456789abcdefABCDEF")


def _attribute_value(value: str) -> str | None:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("#"):
        return None
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "\\":
            if index + 1 == len(value):
                return None
            if index + 2 < len(value) and set(value[index + 1 : index + 3]) <= _HEX:
                decoded.append(int(value[index + 1 : index + 3], 16))
                index += 3
                continue
            index += 1
        decoded.extend(value[index].encode("utf-8", errors="replace"))
        index += 1
    return strip_control_chars(decoded.decode("utf-8", errors="replace")).strip() or None


def issuer_display_name(name: str) -> str:
    """Prefer a DN organization label; retain a provider's short friendly name.

    Parse comma/plus-separated attributes with escapes and quoted values. This
    is a display projection, not full DN validation, issuer identity, or trust.
    Unknown organizations retain their spelling; no generic suffix stripping.
    """
    cleaned = strip_control_chars(name, max_len=2048).strip()
    if "=" not in cleaned:
        return _ALIASES.get(cleaned.casefold(), strip_control_chars(cleaned)) or "Unknown issuer"
    parts: list[str] = []
    start = 0
    escaped = quoted = False
    for index, char in enumerate(cleaned):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in ",+" and not quoted:
            parts.append(cleaned[start:index])
            start = index + 1
    if escaped or quoted:
        return "Unknown issuer"
    parts.append(cleaned[start:])
    organizations: set[str] = set()
    common_names: set[str] = set()
    for part in parts:
        key, separator, raw_value = part.partition("=")
        if not separator or key.strip().upper() not in {"O", "2.5.4.10", "CN", "2.5.4.3"}:
            continue
        value = _attribute_value(raw_value)
        if value is not None:
            bucket = organizations if key.strip().upper() in {"O", "2.5.4.10"} else common_names
            bucket.add(_ALIASES.get(value.casefold(), value))
    labels = organizations or common_names
    return strip_control_chars(" / ".join(sorted(labels))) if labels else "Unknown issuer"


def normalize_cert_summary(summary: CertSummary | None) -> CertSummary | None:
    """Normalize retained display labels without rewriting counts or artifacts."""
    if summary is None:
        return None
    labels = tuple(dict.fromkeys(issuer_display_name(name) for name in summary.top_issuers))
    return replace(summary, top_issuers=labels)
