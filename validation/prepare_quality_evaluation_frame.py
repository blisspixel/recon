"""Prepare the private v2.11 evaluation screening frame without network collection.

The public declaration names one archived ranked source and a deterministic
sampling rule. This tool applies that rule locally, excludes the full private
development corpus, and writes only the private frame. Console output contains
aggregate counts and digests, never frame membership.
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import re
import secrets
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from validation.ranked_sampling import (
    RankedDomain,
    bounded_stable_read,
    digest_bytes,
    keyed_rank,
    read_exclusions,
    read_ranked_source,
)
from validation.run_path_safety import validate_private_output_root

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "local",
)
DEFAULT_SAMPLE_SIZE = 2_500
DEFAULT_EXPECTED_SOURCE_ROWS = 1_000_000
DEFAULT_CONTEXT = "v211-screening-frame-20260812-01"
_SAFE_LIST_ID_RE = re.compile(r"^[A-Z0-9]{5}$")
_SAFE_CONTEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_PRIVATE_KEY_RE = re.compile(rb"^[0-9a-f]{64}\n$")


@dataclass(frozen=True, slots=True)
class PreparedFrame:
    """Private membership plus public-safe reproduction metadata."""

    selected: tuple[RankedDomain, ...]
    frame_bytes: bytes
    source_sha256: str
    source_input_rows: int
    source_normalized_rows: int
    source_duplicate_rows_removed: int
    source_invalid_rows_excluded: int
    exclusion_sha256: str
    exclusion_input_rows: int
    exclusion_canonical_rows: int
    exclusion_normalized_rows: int
    exclusion_duplicate_rows_removed: int
    exclusion_invalid_rows_excluded: int
    development_overlap_excluded: int
    eligible_universe_rows: int
    sampling_key_sha256: str
    frame_sha256: str


@dataclass(frozen=True, slots=True)
class FramePreparationConfig:
    """Frozen sampling inputs, with the private key omitted from representations."""

    expected_source_rows: int
    sample_size: int
    sampling_key: bytes = field(repr=False)
    sampling_context: str


def _digest(raw: bytes) -> str:
    return digest_bytes(raw)


def _bounded_read(path: Path, *, maximum_bytes: int, kind: str) -> bytes:
    return bounded_stable_read(path, maximum_bytes=maximum_bytes, kind=kind)


def _read_ranked_source(path: Path, *, expected_rows: int) -> tuple[list[RankedDomain], bytes, int, int, int]:
    return read_ranked_source(path, expected_rows=expected_rows)


def _read_exclusions(path: Path) -> tuple[set[str], bytes, int, int, int, int]:
    return read_exclusions(path)


def _sampling_key(key: bytes, context: str, row: RankedDomain) -> tuple[bytes, int, str]:
    return keyed_rank(key, context, row)


def _frame_bytes(selected: Sequence[RankedDomain]) -> bytes:
    rows = ["rank,domain", *(f"{row.rank},{row.domain}" for row in selected)]
    return ("\n".join(rows) + "\n").encode("ascii")


def prepare_frame(
    ranked_source: Path,
    exclusion_corpus: Path,
    *,
    config: FramePreparationConfig,
) -> PreparedFrame:
    """Return a deterministic private frame and aggregate-safe metadata."""
    if not 1 <= config.sample_size <= config.expected_source_rows:
        raise ValueError("sample size must be within the expected ranked-source size")
    if len(config.sampling_key) != 32:
        raise ValueError("sampling key must contain exactly 32 bytes")
    if not _SAFE_CONTEXT_RE.fullmatch(config.sampling_context):
        raise ValueError("sampling context must be 1-80 letters, digits, dots, underscores, colons, or hyphens")

    ranked, source_raw, normalized, source_duplicates, source_invalid = _read_ranked_source(
        ranked_source,
        expected_rows=config.expected_source_rows,
    )
    excluded, exclusion_raw, exclusion_rows, exclusion_normalized, exclusion_duplicates, exclusion_invalid = (
        _read_exclusions(exclusion_corpus)
    )
    eligible = [row for row in ranked if row.domain not in excluded]
    overlap = len(ranked) - len(eligible)
    if config.sample_size > len(eligible):
        raise ValueError("sample size exceeds the eligible ranked-source universe")
    selected = tuple(
        heapq.nsmallest(
            config.sample_size,
            eligible,
            key=lambda row: _sampling_key(config.sampling_key, config.sampling_context, row),
        )
    )
    rendered = _frame_bytes(selected)
    return PreparedFrame(
        selected=selected,
        frame_bytes=rendered,
        source_sha256=_digest(source_raw),
        source_input_rows=config.expected_source_rows,
        source_normalized_rows=normalized,
        source_duplicate_rows_removed=source_duplicates,
        source_invalid_rows_excluded=source_invalid,
        exclusion_sha256=_digest(exclusion_raw),
        exclusion_input_rows=exclusion_rows,
        exclusion_canonical_rows=len(excluded),
        exclusion_normalized_rows=exclusion_normalized,
        exclusion_duplicate_rows_removed=exclusion_duplicates,
        exclusion_invalid_rows_excluded=exclusion_invalid,
        development_overlap_excluded=overlap,
        eligible_universe_rows=len(eligible),
        sampling_key_sha256=_digest(config.sampling_key),
        frame_sha256=_digest(rendered),
    )


def _private_path(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


def _write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("private frame output already exists; refusing to replace it") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)


def generate_private_sampling_key(path: Path) -> str:
    """Create one private 256-bit key and return only its public commitment."""
    key = secrets.token_bytes(32)
    _write_exclusive(_private_path(path), key.hex().encode("ascii") + b"\n")
    return _digest(key)


def _read_private_sampling_key(path: Path) -> bytes:
    raw = _bounded_read(_private_path(path), maximum_bytes=65, kind="private sampling key")
    if _PRIVATE_KEY_RE.fullmatch(raw) is None:
        raise ValueError("private sampling key must be one lowercase 64-character hexadecimal line")
    return bytes.fromhex(raw.decode("ascii").strip())


def public_summary(frame: PreparedFrame, *, list_id: str, context: str, written: bool) -> dict[str, object]:
    """Return only metadata safe for console output or a public declaration."""
    values = asdict(frame)
    values.pop("selected")
    values.pop("frame_bytes")
    return {
        "schema_version": 1,
        "source": {
            "kind": "tranco-standard-pay-level-top-1m",
            "list_id": list_id,
            "permanent_url": f"https://tranco-list.eu/list/{list_id}/1000000",
            "sha256": values.pop("source_sha256"),
            "input_rows": values.pop("source_input_rows"),
            "normalized_rows": values.pop("source_normalized_rows"),
            "duplicate_rows_removed": values.pop("source_duplicate_rows_removed"),
            "invalid_rows_excluded": values.pop("source_invalid_rows_excluded"),
        },
        "development_exclusion": {
            "sha256": values.pop("exclusion_sha256"),
            "input_rows": values.pop("exclusion_input_rows"),
            "canonical_rows": values.pop("exclusion_canonical_rows"),
            "normalized_rows": values.pop("exclusion_normalized_rows"),
            "duplicate_rows_removed": values.pop("exclusion_duplicate_rows_removed"),
            "invalid_rows_excluded": values.pop("exclusion_invalid_rows_excluded"),
            "ranked_universe_overlap_excluded": values.pop("development_overlap_excluded"),
        },
        "sampling": {
            "eligible_universe_rows": values.pop("eligible_universe_rows"),
            "selected_rows": len(frame.selected),
            "method": "hmac-sha256-rank-without-replacement-v1",
            "context": context,
            "private_key_sha256": values.pop("sampling_key_sha256"),
            "first_stage_inclusion_probability": f"{len(frame.selected)}/{frame.eligible_universe_rows}",
            "frame_sha256": values.pop("frame_sha256"),
        },
        "privacy": {
            "frame_written": written,
            "identifiers_printed": 0,
            "per_domain_rows_printed": 0,
            "network_requests": 0,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate-key", help="create one private sampling key without printing it")
    generate.add_argument("--output", required=True, type=Path)

    prepare = commands.add_parser("prepare", help="preflight or write a frame from a frozen private key")
    prepare.add_argument("--ranked-source", required=True, type=Path)
    prepare.add_argument("--exclude-corpus", required=True, type=Path)
    prepare.add_argument("--output", required=True, type=Path)
    prepare.add_argument("--sampling-key-file", required=True, type=Path)
    prepare.add_argument("--tranco-list-id", required=True)
    prepare.add_argument("--expected-source-rows", type=int, default=DEFAULT_EXPECTED_SOURCE_ROWS)
    prepare.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    prepare.add_argument("--sampling-context", default=DEFAULT_CONTEXT)
    mode = prepare.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--write-private-frame", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "generate-key":
        commitment = generate_private_sampling_key(args.output)
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "private_key_sha256": commitment,
                    "key_bytes": 32,
                    "key_written": True,
                    "key_printed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not _SAFE_LIST_ID_RE.fullmatch(args.tranco_list_id):
        raise ValueError("Tranco list ID must be exactly five uppercase letters or digits")
    output = _private_path(args.output)
    sampling_key = _read_private_sampling_key(args.sampling_key_file)
    frame = prepare_frame(
        _private_path(args.ranked_source),
        _private_path(args.exclude_corpus),
        config=FramePreparationConfig(
            expected_source_rows=args.expected_source_rows,
            sample_size=args.sample_size,
            sampling_key=sampling_key,
            sampling_context=args.sampling_context,
        ),
    )
    if args.write_private_frame:
        _write_exclusive(output, frame.frame_bytes)
    print(
        json.dumps(
            public_summary(
                frame,
                list_id=args.tranco_list_id,
                context=args.sampling_context,
                written=args.write_private_frame,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
