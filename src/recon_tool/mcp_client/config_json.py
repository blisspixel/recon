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


def read_json_object(path: Path) -> JsonObjectRead:
    """Read a bounded, BOM-tolerant JSON object without leaking parser errors."""
    if not path.exists():
        return JsonObjectRead("missing", None, "not found")
    if path.is_dir():
        return JsonObjectRead("invalid", None, "is a directory, not a config file")

    try:
        raw_bytes, _, _ = read_bounded_regular_file(
            path,
            maximum_bytes=MAX_CLIENT_CONFIG_BYTES,
            allow_symlinks=True,
            future_mtime_tolerance_seconds=None,
        )
    except OSError as exc:
        return JsonObjectRead("invalid", None, f"cannot read: {exc}")
    except ValueError as exc:
        if "byte limit" in str(exc):
            return JsonObjectRead("invalid", None, "exceeds maximum size of 1 MiB")
        return JsonObjectRead("invalid", None, f"cannot read: {exc}")
    try:
        raw = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return JsonObjectRead("invalid", None, f"is not valid UTF-8 at byte {exc.start}")
    if not raw.strip():
        return JsonObjectRead("empty", None, "empty file")
    if exceeds_json_nesting_limit(raw):
        return JsonObjectRead("invalid", None, "JSON is too deeply nested")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return JsonObjectRead(
            "invalid",
            None,
            f"not valid JSON ({exc.msg} at line {exc.lineno})",
        )
    except ValueError:
        return JsonObjectRead("invalid", None, "JSON value exceeds supported limits")
    except RecursionError:
        return JsonObjectRead("invalid", None, "JSON is too deeply nested")
    if not isinstance(data, dict):
        return JsonObjectRead(
            "invalid",
            None,
            f"top-level JSON is {type(data).__name__}, not an object",
        )
    return JsonObjectRead("ok", {str(key): value for key, value in data.items()}, "parsed")
