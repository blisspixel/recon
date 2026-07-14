"""Deterministic structural limits for JSON text before decoder admission."""

from __future__ import annotations

import json
import math
import os
import stat
import time
from pathlib import Path
from typing import Any

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


def load_bounded_json_file(
    path: Path,
    *,
    maximum_bytes: int,
    maximum_age_seconds: float | None = None,
    future_mtime_tolerance_seconds: float = 300.0,
) -> tuple[Any, os.stat_result, float]:
    """Decode one stable, regular JSON file without an unbounded path read.

    The descriptor owns both metadata checks and the bounded read, so replacing
    or growing a path after a preliminary stat cannot bypass the byte ceiling.
    Stable symlinks are rejected on every platform, and ``O_NOFOLLOW`` closes
    the open-time race on platforms that provide it. Identity and metadata are
    checked again after the read before parsed content is admitted. Optional
    freshness admission is performed from descriptor metadata before any file
    content is read, avoiding repeated parsing of expired entries. Materially
    future modification times are rejected instead of extending cache life.
    """
    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive")
    if not math.isfinite(future_mtime_tolerance_seconds) or future_mtime_tolerance_seconds < 0:
        raise ValueError("future_mtime_tolerance_seconds must be finite and non-negative")
    if maximum_age_seconds is not None and (
        not math.isfinite(maximum_age_seconds) or maximum_age_seconds < 0
    ):
        raise ValueError("maximum_age_seconds must be finite and non-negative")
    if path.is_symlink():
        raise ValueError("JSON file must not be a symbolic link")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        _require_same_regular_path(path, before)
        if before.st_size > maximum_bytes:
            raise ValueError(f"JSON file exceeds {maximum_bytes}-byte limit")
        age_seconds = time.time() - before.st_mtime
        if not math.isfinite(age_seconds) or age_seconds < -future_mtime_tolerance_seconds:
            raise ValueError("JSON file has an invalid future modification time")
        age_seconds = max(0.0, age_seconds)
        if maximum_age_seconds is not None and age_seconds > maximum_age_seconds:
            raise ValueError("JSON file is older than the permitted maximum age")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum_bytes + 1)
        after = os.fstat(descriptor)
        if len(raw) > maximum_bytes:
            raise ValueError(f"JSON file exceeds {maximum_bytes}-byte limit")
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("JSON file changed while it was being read")
        _require_same_regular_path(path, after)
    finally:
        os.close(descriptor)

    text = raw.decode("utf-8")
    if exceeds_json_nesting_limit(text):
        raise ValueError(f"JSON nesting exceeds {MAX_JSON_NESTING} levels")
    return json.loads(text), after, age_seconds


def _require_same_regular_path(path: Path, opened: os.stat_result) -> None:
    current = path.lstat()
    if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(current.st_mode):
        raise ValueError("JSON path must identify a regular file")
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError("JSON path changed before the read completed")
