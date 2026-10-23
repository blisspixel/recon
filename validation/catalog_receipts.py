"""Private durable collection receipts, including honest interrupted counts."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from recon_tool.cli.batch import read_batch_domains
from recon_tool.validator import validate_domain
from validation.prepare_catalog_round import _bounded_read, _reserve_exclusive, _strict_json_object, digest_bytes


def _finite_number(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("maintenance JSON cannot contain non-finite numbers")
    return result


def read_json(path: Path) -> dict[str, object]:
    """Read one bounded, stable JSON object, rejecting duplicate fields."""
    raw = _bounded_read(path, maximum_bytes=1024 * 1024, name="maintenance receipt")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_strict_json_object,
        parse_constant=_finite_number,
        parse_float=_finite_number,
    )
    if not isinstance(value, dict):
        raise ValueError("maintenance receipt must be an object")
    return value


def write_private_blob(path: Path, payload: bytes, *, idempotent: bool = False) -> None:
    """Reserve private immutable bytes and flush them before work continues."""
    try:
        descriptor = _reserve_exclusive(path, kind="maintenance event")
    except ValueError as exc:
        if idempotent and isinstance(exc.__cause__, FileExistsError):
            previous = _bounded_read(path, maximum_bytes=max(1, len(payload)), name="existing maintenance event")
            if previous == payload:
                return
        raise
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def write_private_event(path: Path, value: Mapping[str, object], *, idempotent: bool = False) -> None:
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    write_private_blob(path, payload, idempotent=idempotent)


def validate_frame_bytes(raw: bytes, maximum: int) -> tuple[frozenset[str], str]:
    """Admit normalized frame bytes without expanding or repairing them."""
    import io

    rows = read_batch_domains(io.StringIO(raw.decode("utf-8")))
    if not rows or len(rows) > maximum:
        raise ValueError("maintenance frame is empty or exceeds its namespace budget")
    normalized = [validate_domain(row) for row in rows]
    if rows != normalized or len(set(normalized)) != len(rows):
        raise ValueError("maintenance frame must already be canonical and deduplicated")
    return frozenset(normalized), digest_bytes(raw)


def read_frozen_frame(path: Path, maximum: int) -> tuple[frozenset[str], str]:
    raw = _bounded_read(path, maximum_bytes=8 * 1024 * 1024, name="maintenance frame")
    return validate_frame_bytes(raw, maximum)


def start_recorder(run_dir: Path, descriptor: Mapping[str, object]) -> Callable[[str], None]:
    """Bind starts to this admission before any lookup IO is allowed."""
    root = run_dir / "namespace-starts"
    write_private_event(root / "admission.json", descriptor)

    def record(domain: str) -> None:
        identity = digest_bytes(domain.encode("utf-8"))
        write_private_event(
            root / f"start-{identity}.json",
            {"schema_version": 1, "domain": domain, "started_at": datetime.now(UTC).isoformat()},
        )

    return record


def _durable_starts(root: Path, admitted: int) -> tuple[frozenset[str], set[str]]:
    admission = read_json(root / "admission.json")
    if admission.get("schema_version") != 1 or admission.get("namespace_count") != admitted:
        raise ValueError("start admission differs from the frozen frame")
    frame_path = admission.get("corpus")
    if not isinstance(frame_path, str):
        raise ValueError("start admission has no frozen frame")
    frame, digest = read_frozen_frame(Path(frame_path), admitted)
    if digest != admission.get("frame_sha256"):
        raise ValueError("start admission frame changed")
    recorded: set[str] = set()
    for path in sorted(root.glob("start-*.json")):
        event = read_json(path)
        domain = event.get("domain")
        if event.get("schema_version") != 1 or not isinstance(domain, str) or domain not in frame or domain in recorded:
            raise ValueError("invalid or duplicate durable start receipt")
        if path.name != f"start-{digest_bytes(domain.encode('utf-8'))}.json":
            raise ValueError("start receipt identity differs from filename")
        recorded.add(domain)
    return frame, recorded


def completion_summary(
    run_dir: Path,
    *,
    admitted: int,
    records: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Keep unknown starts distinct from proven unattempted items.

    Historical output without durable starts supplies a lower bound only. A
    valid modern admission proves that every lookup began behind the recorder.
    Validation-error terminals do not establish that collection started.
    """
    terminal: dict[str, bool] = {}
    known_started = set()
    for row in records:
        if len(terminal) >= admitted:
            raise ValueError("collection terminals exceed admitted namespaces")
        domain = row.get("queried_domain", row.get("domain"))
        if not isinstance(domain, str) or not domain:
            raise ValueError("collection terminal has no namespace identity")
        if domain in terminal:
            raise ValueError("duplicate collection terminal")
        terminal[domain] = row.get("record_type") == "error"
        if row.get("error_kind") != "validation":
            known_started.add(domain)
    if len(terminal) > admitted:
        raise ValueError("collection terminals exceed admitted namespaces")
    root = run_dir / "namespace-starts"
    complete = (root / "admission.json").is_file()
    if complete:
        frame, recorded = _durable_starts(root, admitted)
        if not known_started <= recorded or not terminal.keys() <= frame:
            raise ValueError("terminal collection lacks a matching durable start")
        known_started = recorded
    unfinished = admitted - len(terminal)
    unfinished_started = len(known_started - terminal.keys())
    return {
        "admitted": admitted,
        "terminal_success": sum(not error for error in terminal.values()),
        "terminal_error": sum(terminal.values()),
        "unfinished": unfinished,
        "known_started_lower_bound": len(known_started),
        "unfinished_known_started": unfinished_started,
        "unfinished_start_unknown": 0 if complete else unfinished - unfinished_started,
        "known_unattempted": admitted - len(known_started | terminal.keys()) if complete else 0,
        "start_receipts_complete": complete,
    }


def collection_metadata(run_dir: Path, *, admitted: int, records: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Withhold unverifiable accounting without erasing retained results."""
    try:
        completion = {"availability": "available", **completion_summary(run_dir, admitted=admitted, records=records)}
    except (OSError, ValueError, TypeError):
        completion = {"availability": "unavailable", "reason": "invalid_or_unavailable_collection_receipts"}
    metadata: dict[str, object] = {"collection_completion": completion}
    budget_path = run_dir / "collection-budget.json"
    if budget_path.exists():
        try:
            metadata["collection_budget"] = read_json(budget_path)
        except (OSError, ValueError):
            metadata["collection_budget"] = {"availability": "unavailable"}
    return metadata
