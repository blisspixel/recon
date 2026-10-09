"""Bounded JSON-object reader shared by MCP client configuration tools."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from recon_tool.json_limits import exceeds_json_nesting_limit, read_bounded_regular_file

MAX_CLIENT_CONFIG_BYTES = 1024 * 1024

JsonObjectState = Literal["missing", "empty", "invalid", "ok"]


@dataclass(frozen=True)
class JsonObjectRead:
    """Result of reading one client configuration file."""

    state: JsonObjectState
    data: dict[str, object] | None
    detail: str


def _parse_json_payload(raw_bytes: bytes) -> tuple[JsonObjectState, dict[str, object] | None, str]:
    try:
        raw = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return "invalid", None, f"is not valid UTF-8 at byte {exc.start}"
    if not raw.strip():
        return "empty", None, "empty file"
    if exceeds_json_nesting_limit(raw):
        return "invalid", None, "JSON is too deeply nested"

    try:
        data = json.loads(raw)
    except Exception as exc:
        if isinstance(exc, json.JSONDecodeError):
            detail = f"not valid JSON ({exc.msg} at line {exc.lineno})"
        elif isinstance(exc, RecursionError):
            detail = "JSON is too deeply nested"
        else:
            detail = "JSON value exceeds supported limits"
        return "invalid", None, detail

    if not isinstance(data, dict):
        return "invalid", None, f"top-level JSON is {type(data).__name__}, not an object"
    return "ok", {str(key): value for key, value in data.items()}, "parsed"


def _check_path_preconditions(path: Path, allow_symlinks: bool) -> tuple[JsonObjectState, str] | None:
    if not allow_symlinks and path.is_symlink():
        return "invalid", "cannot read: JSON file must not be a symbolic link"
    if not path.exists():
        return "missing", "not found"
    if path.is_dir():
        return "invalid", "is a directory, not a config file"
    return None


def read_json_object(path: Path, *, allow_symlinks: bool = True) -> JsonObjectRead:
    """Read a bounded, BOM-tolerant JSON object without leaking parser errors."""
    precondition = _check_path_preconditions(path, allow_symlinks)
    if precondition is not None:
        return JsonObjectRead(precondition[0], None, precondition[1])

    try:
        raw_bytes, _, _ = read_bounded_regular_file(
            path,
            maximum_bytes=MAX_CLIENT_CONFIG_BYTES,
            allow_symlinks=allow_symlinks,
            future_mtime_tolerance_seconds=None,
        )
    except OSError as exc:
        return JsonObjectRead("invalid", None, f"cannot read: {exc}")
    except ValueError as exc:
        detail = "exceeds maximum size of 1 MiB" if "byte limit" in str(exc) else f"cannot read: {exc}"
        return JsonObjectRead("invalid", None, detail)

    state, data, detail = _parse_json_payload(raw_bytes)
    return JsonObjectRead(state, data, detail)
