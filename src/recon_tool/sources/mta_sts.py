"""Bounded RFC 8461 MTA-STS policy admission."""

from __future__ import annotations

import re
from collections.abc import Iterable

MAX_MTA_STS_POLICY_BYTES = 64 * 1024
_MAX_AGE_SECONDS = 31_557_600
_FIELD_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", re.ASCII)
_DOMAIN_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", re.ASCII)
_MAX_AGE_RE = re.compile(r"[0-9]{1,10}", re.ASCII)
_STS_ID_RE = re.compile(r"[A-Za-z0-9]{1,32}", re.ASCII)
_STS_VALUE_RE = re.compile(r"[\x21-\x3a\x3c\x3e-\x7e]+", re.ASCII)
_POLICY_MODES = frozenset({"enforce", "testing", "none"})
_KNOWN_POLICY_FIELDS = frozenset({"version", "mode", "mx", "max_age"})
_VALID_CHARSETS = frozenset({"us-ascii", "utf-8"})


def _valid_mta_sts_record(record: str) -> bool:
    if not record.isascii() or not record.startswith("v=STSv1;"):
        return False
    parts = record.split(";")
    if parts[-1].strip(" \t") == "":
        parts.pop()
    if not parts or parts[0] != "v=STSv1":
        return False
    fields: dict[str, str] = {}
    for part in parts[1:]:
        field, separator, value = part.strip(" \t").partition("=")
        if not separator or _FIELD_NAME_RE.fullmatch(field) is None or _STS_VALUE_RE.fullmatch(value) is None:
            return False
        fields.setdefault(field, value)
    policy_id = fields.get("id")
    return policy_id is not None and _STS_ID_RE.fullmatch(policy_id) is not None


def select_mta_sts_record(records: Iterable[str]) -> str | None:
    """Return the single syntactically eligible RFC 8461 TXT record."""
    candidates = tuple(record for record in records if record.startswith("v=STSv1;"))
    if len(candidates) != 1 or not _valid_mta_sts_record(candidates[0]):
        return None
    return candidates[0]


def is_plain_text_policy(content_type: str | None) -> bool:
    """Return whether an HTTP media type is suitable for an MTA-STS policy."""
    if content_type is None:
        return False
    media_type, *parameters = content_type.split(";")
    if media_type.strip().casefold() != "text/plain":
        return False
    for parameter in parameters:
        name, separator, value = parameter.partition("=")
        if separator and name.strip().casefold() == "charset":
            charset = value.strip().strip('"').casefold()
            if charset not in _VALID_CHARSETS:
                return False
    return True


def _policy_lines(text: str) -> tuple[str, ...] | None:
    """Split only RFC-permitted LF or CRLF records and reject control text."""
    if "\r" in text.replace("\r\n", ""):
        return None
    if any(character not in "\r\n\t" and (ord(character) < 0x20 or ord(character) == 0x7F) for character in text):
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    normalized = tuple(line.removesuffix("\r") for line in lines)
    if not normalized or any(not line or line[:1].isspace() for line in normalized):
        return None
    return normalized


def _valid_mx_pattern(value: str) -> bool:
    """Validate one RFC 8461 MX value in required ASCII A-label form."""
    host = value[2:] if value.startswith("*.") else value
    if not host.isascii() or host.endswith(".") or (value.startswith("*") and not value.startswith("*.")):
        return False
    normalized = host.casefold()
    return len(normalized) <= 253 and all(
        _DOMAIN_LABEL_RE.fullmatch(label) is not None for label in normalized.split(".")
    )


def _valid_extension_value(value: str) -> bool:
    """Validate one RFC extension value after strict UTF-8 decoding."""
    return bool(value) and all(
        character == " " or (ord(character) >= 0x21 and ord(character) != 0x7F) for character in value
    )


def _collect_policy_fields(lines: tuple[str, ...]) -> tuple[dict[str, str], tuple[str, ...]] | None:
    """Collect first-value fields and every repeatable MX pattern."""
    fields: dict[str, str] = {}
    mx_patterns: list[str] = []
    for line in lines:
        field, separator, raw_value = line.rstrip(" \t").partition(":")
        value = raw_value.lstrip(" \t")
        if (
            not separator
            or _FIELD_NAME_RE.fullmatch(field) is None
            or not value
            or (field not in _KNOWN_POLICY_FIELDS and not _valid_extension_value(value))
        ):
            return None
        if field == "mx":
            mx_patterns.append(value)
        else:
            fields.setdefault(field, value)
    return fields, tuple(mx_patterns)


def _validated_policy_mode(fields: dict[str, str], mx_patterns: tuple[str, ...]) -> str | None:
    """Return a mode only when all required RFC 8461 fields are valid."""
    mode = fields.get("mode")
    max_age = fields.get("max_age")
    if fields.get("version") != "STSv1" or mode not in _POLICY_MODES or max_age is None:
        return None
    if _MAX_AGE_RE.fullmatch(max_age) is None or int(max_age) > _MAX_AGE_SECONDS:
        return None
    if (mode != "none" and not mx_patterns) or any(not _valid_mx_pattern(pattern) for pattern in mx_patterns):
        return None
    return mode


def parse_mta_sts_policy(content: bytes) -> str | None:
    """Return the mode of one complete bounded RFC 8461 policy, if valid."""
    if len(content) > MAX_MTA_STS_POLICY_BYTES:
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = _policy_lines(text)
    if lines is None:
        return None
    collected = _collect_policy_fields(lines)
    if collected is None:
        return None
    fields, mx_patterns = collected
    return _validated_policy_mode(fields, mx_patterns)
