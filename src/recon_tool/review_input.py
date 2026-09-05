"""Pre-collection normalization of caller-owned review coordinates."""

from __future__ import annotations

from recon_tool.validator import strip_control_chars


def normalize_review_coordinate(value: object) -> str:
    """Keep a printable pasted coordinate while trimming surrounding spaces.

    The artifact retains the caller's safe URL or subdomain spelling alongside
    the normalized queried apex. Reject controls and excessive input before
    validation, rate-limit admission, or collection can consume the coordinate.
    """
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("input_coordinate must be 1 to 512 printable characters")
    if strip_control_chars(value, max_len=512) != value:
        raise ValueError("input_coordinate must not contain control characters")
    coordinate = value.strip()
    if not coordinate:
        raise ValueError("input_coordinate must be 1 to 512 printable characters")
    return coordinate
