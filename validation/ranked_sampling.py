"""Shared, no-network primitives for private ranked-domain sampling."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from recon_tool.validator import validate_domain

MAX_RANKED_SOURCE_BYTES = 128 * 1024 * 1024
MAX_EXCLUDED_ROWS = 10_000


@dataclass(frozen=True, slots=True)
class RankedDomain:
    """One canonical private ranked-source row."""

    rank: int
    domain: str


def digest_bytes(raw: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(raw).hexdigest()


def bounded_stable_read(path: Path, *, maximum_bytes: int, kind: str) -> bytes:
    """Read one bounded regular file and reject replacement during the read."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot read {kind}: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{kind} must be a regular file, not a symbolic link")
    if before.st_size <= 0:
        raise ValueError(f"{kind} is empty")
    if before.st_size > maximum_bytes:
        raise ValueError(f"{kind} exceeds the {maximum_bytes}-byte limit")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"{kind} changed while it was read") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != before.st_size
    ):
        raise ValueError(f"{kind} changed while it was read")
    return raw


def _canonical_domain(value: str) -> str | None:
    try:
        return validate_domain(value)
    except ValueError:
        return None


def read_ranked_source(
    path: Path,
    *,
    expected_rows: int,
) -> tuple[list[RankedDomain], bytes, int, int, int]:
    """Read a contiguous rank/domain CSV without echoing private identifiers."""
    raw = bounded_stable_read(path, maximum_bytes=MAX_RANKED_SOURCE_BYTES, kind="ranked source")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("ranked source is not UTF-8") from exc

    parsed: list[RankedDomain] = []
    seen: set[str] = set()
    normalized_count = 0
    duplicate_count = 0
    invalid_count = 0
    source_rows = 0
    reader = csv.reader(io.StringIO(text, newline=""))
    for physical_row, row in enumerate(reader, start=1):
        if not row or all(not cell.strip() for cell in row):
            continue
        if physical_row == 1 and [cell.strip().casefold() for cell in row] == ["rank", "domain"]:
            continue
        source_rows += 1
        if len(row) != 2:
            raise ValueError(f"ranked source row {physical_row} must have exactly two columns")
        try:
            rank = int(row[0])
        except ValueError as exc:
            raise ValueError(f"ranked source row {physical_row} has an invalid rank") from exc
        if rank != source_rows:
            raise ValueError(f"ranked source row {physical_row} breaks contiguous rank order")
        value = row[1].strip()
        canonical = _canonical_domain(value)
        if canonical is None:
            invalid_count += 1
            continue
        normalized_count += int(value != canonical)
        if canonical in seen:
            duplicate_count += 1
            continue
        seen.add(canonical)
        parsed.append(RankedDomain(rank=rank, domain=canonical))

    if source_rows != expected_rows:
        raise ValueError(f"ranked source has {source_rows} rows; expected exactly {expected_rows}")
    if not parsed:
        raise ValueError("ranked source has no canonical domains")
    return parsed, raw, normalized_count, duplicate_count, invalid_count


def read_exclusions(path: Path) -> tuple[set[str], bytes, int, int, int, int]:
    """Read the bounded development exclusion corpus with aggregate accounting."""
    raw = bounded_stable_read(path, maximum_bytes=8 * 1024 * 1024, kind="development exclusion corpus")
    try:
        # Match ranked sources and generic round inputs: a UTF-8 signature is
        # an encoding marker, not part of the first excluded namespace. Keep
        # raw bytes unchanged so the manifest still commits to the exact file.
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("development exclusion corpus is not UTF-8") from exc

    values = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if len(values) > MAX_EXCLUDED_ROWS:
        raise ValueError(f"development exclusion corpus exceeds {MAX_EXCLUDED_ROWS} rows")
    canonical: list[str] = []
    normalized_count = 0
    invalid_count = 0
    for value in values:
        normalized = _canonical_domain(value)
        if normalized is None:
            invalid_count += 1
            continue
        normalized_count += int(value != normalized)
        canonical.append(normalized)
    duplicate_count = len(canonical) - len(set(canonical))
    unique = set(canonical)
    if not unique:
        raise ValueError("development exclusion corpus has no canonical domains")
    return unique, raw, len(values), normalized_count, duplicate_count, invalid_count


def keyed_rank(key: bytes, context: str, row: RankedDomain) -> tuple[bytes, int, str]:
    """Return the deterministic secret-keyed ordering tuple for one row."""
    message = context.encode("ascii") + b"\0" + row.domain.encode("ascii")
    return hmac.digest(key, message, "sha256"), row.rank, row.domain


def domain_frame_bytes(rows: Sequence[RankedDomain]) -> bytes:
    """Serialize a domain-only frame accepted by catalog-round preparation."""
    return ("\n".join(sorted(row.domain for row in rows)) + "\n").encode("ascii")
