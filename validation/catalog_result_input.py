"""Bounded snapshots of supplied maintenance results before reduction."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from pathlib import Path

from recon_tool.json_limits import exceeds_json_nesting_limit, is_json_object, is_object_list, read_bounded_regular_file

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 1024
MAX_ENTRIES = 100_000
MAX_DIRECTORY_DEPTH = 32


def _walk_files(root: Path, *, depth: int = 0, visited: list[int]) -> Iterator[Path]:
    if depth > MAX_DIRECTORY_DEPTH:
        raise ValueError("evaluation directory exceeds depth limit")
    with os.scandir(root) as entries:
        for entry in entries:
            visited[0] += 1
            if visited[0] > MAX_ENTRIES:
                raise ValueError("evaluation directory exceeds entry limit")
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                yield from _walk_files(path, depth=depth + 1, visited=visited)
            elif path.suffix in {".json", ".ndjson"}:
                yield path


def _files(root: Path) -> list[Path]:
    if not root.is_dir():
        return [root]
    candidates: list[Path] = []
    for path in _walk_files(root, visited=[0]):
        candidates.append(path)
        if len(candidates) > MAX_FILES:
            raise ValueError("evaluation exceeds result-file limit")
    ndjson = sorted(path for path in candidates if path.name.startswith("results") and path.suffix == ".ndjson")
    objects = sorted(path for path in candidates if path.name.startswith("results") and path.suffix == ".json")
    return ndjson + objects if ndjson or objects else sorted(path for path in candidates if path.suffix == ".ndjson")


def _decode(text: str) -> object:
    if exceeds_json_nesting_limit(text):
        raise ValueError("evaluation JSON exceeds nesting limit")
    return json.loads(text)


def _records(raw: bytes) -> Iterator[dict[str, object]]:
    text = raw.decode("utf-8")
    if not text.strip():
        return
    try:
        payload = _decode(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            if line.strip():
                item = _decode(line)
                if not is_json_object(item):
                    raise ValueError("evaluation NDJSON record must be an object") from None
                yield item
        return
    if is_json_object(payload):
        yield payload
    elif is_object_list(payload):
        for item in payload:
            if not is_json_object(item):
                raise ValueError("evaluation JSON array records must be objects")
            yield item
    else:
        raise ValueError("evaluation results must contain record objects")


def load_evaluation_results(
    root: Path, *, maximum_records: int, frame: frozenset[str]
) -> tuple[str, list[dict[str, object]]]:
    """Hash and decode the same admitted bytes, rejecting rather than truncating."""
    digest = hashlib.sha256()
    records: list[dict[str, object]] = []
    total = 0
    for path in _files(root):
        remaining = MAX_TOTAL_BYTES - total
        if remaining < 1:
            raise ValueError("evaluation exceeds aggregate byte limit")
        raw, _, _ = read_bounded_regular_file(
            path, maximum_bytes=min(MAX_FILE_BYTES, remaining), future_mtime_tolerance_seconds=None
        )
        total += len(raw)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
        for row in _records(raw):
            domain = row.get("queried_domain", row.get("domain"))
            if len(records) >= maximum_records or not isinstance(domain, str) or domain not in frame:
                raise ValueError("evaluation results exceed or differ from the admitted frame")
            records.append(row)
    return digest.hexdigest(), records
