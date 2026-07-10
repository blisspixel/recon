"""Deterministic structural limits for JSON text before decoder admission."""

from __future__ import annotations

MAX_JSON_NESTING = 100


def exceeds_json_nesting_limit(text: str, *, maximum: int = MAX_JSON_NESTING) -> bool:
    """Return whether object or array nesting exceeds ``maximum``.

    Brackets inside JSON strings are ignored, including strings with escaped
    quotes and backslashes. Full syntax validation remains the JSON decoder's
    responsibility after this bounded linear scan.
    """
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                return True
        elif char in "]}":
            depth = max(depth - 1, 0)

    return False
