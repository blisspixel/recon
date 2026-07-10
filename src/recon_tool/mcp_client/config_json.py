"""Bounded JSON-object reader shared by MCP client configuration tools."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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
        with path.open("rb") as handle:
            raw_bytes = handle.read(MAX_CLIENT_CONFIG_BYTES + 1)
    except OSError as exc:
        return JsonObjectRead("invalid", None, f"cannot read: {exc}")

    if len(raw_bytes) > MAX_CLIENT_CONFIG_BYTES:
        return JsonObjectRead(
            "invalid",
            None,
            f"exceeds maximum size of {MAX_CLIENT_CONFIG_BYTES // (1024 * 1024)} MiB",
        )
    try:
        raw = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return JsonObjectRead("invalid", None, f"is not valid UTF-8 at byte {exc.start}")
    if not raw.strip():
        return JsonObjectRead("empty", None, "empty file")

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
