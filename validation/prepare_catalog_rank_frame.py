"""Prepare private, secret-keyed Tranco strata for a catalog rank round.

The input plan, sampling key, selected namespaces, and output paths remain
private. Console output contains aggregate counts and cryptographic commitments
only. This module performs no network requests.
"""

from __future__ import annotations

import argparse
import contextlib
import heapq
import json
import os
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast

from validation.ranked_sampling import (
    bounded_stable_read,
    digest_bytes,
    domain_frame_bytes,
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
SCHEMA_VERSION = 1
EXPECTED_SOURCE_ROWS = 1_000_000
SAMPLING_METHOD = "hmac-sha256-rank-without-replacement-v1"
CANONICAL_BANDS = (
    ("rank-1-1k", 1, 1_000),
    ("rank-1k-10k", 1_001, 10_000),
    ("rank-10k-100k", 10_001, 100_000),
    ("rank-100k-1m", 100_001, 1_000_000),
)
_PLAN_KEYS = frozenset({"schema_version", "private", "source", "development_exclusion", "sampling", "bands"})
_SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$")
_SAFE_CONTEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_PRIVATE_KEY_RE = re.compile(rb"^[0-9a-f]{64}\n$")
_MAX_PLAN_BYTES = 256 * 1024
_MAX_SAMPLE_PER_BAND = 10_000


@dataclass(frozen=True, slots=True)
class RankBandPlan:
    """One frozen popularity band and its equal-allocation discovery quota."""

    id: str
    label: str
    minimum_rank: int
    maximum_rank: int
    sample_size: int


@dataclass(frozen=True, slots=True)
class RankSelectionPlan:
    """Validated private inputs for one catalog rank-strata preparation."""

    source_path: Path
    source_name: str
    source_revision: str
    exclusion_path: Path
    exclusion_rule: str
    sampling_key_path: Path = field(repr=False)
    sampling_context: str
    bands: tuple[RankBandPlan, ...]
    plan_digest_sha256: str


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"rank selection JSON contains duplicate field: {key}")
        result[key] = value
    return result


def _strict_object(value: object, *, name: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{name} must be an object")
    actual = frozenset(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        _fail(f"{name} has invalid fields: {'; '.join(details)}")
    return value


def _text(value: object, *, name: str, minimum: int) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    normalized = " ".join(value.split())
    if len(normalized) < minimum or normalized.casefold() in {"n/a", "none", "tbd", "unknown", "latest"}:
        _fail(f"{name} must be meaningful and at least {minimum} characters")
    return normalized


def _positive_int(value: object, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(f"{name} must be a positive integer")
    return value


def _private_path(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


def _path(plan_path: Path, value: object, *, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{name} must be a non-empty path")
    supplied = Path(value)
    return _private_path(supplied if supplied.is_absolute() else plan_path.parent / supplied)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _read_key(path: Path) -> bytes:
    raw = bounded_stable_read(path, maximum_bytes=65, kind="private sampling key")
    if _PRIVATE_KEY_RE.fullmatch(raw) is None:
        _fail("private sampling key must be one lowercase 64-character hexadecimal line")
    return bytes.fromhex(raw.decode("ascii").strip())


def _validate_bands(value: object) -> tuple[RankBandPlan, ...]:
    if not isinstance(value, list) or len(value) != len(CANONICAL_BANDS):
        _fail("bands must declare the four canonical Tranco rank bands")
    bands: list[RankBandPlan] = []
    sample_sizes: set[int] = set()
    keys = frozenset({"id", "label", "minimum_rank", "maximum_rank", "sample_size"})
    for index, (raw, expected) in enumerate(zip(value, CANONICAL_BANDS, strict=True)):
        item = _strict_object(raw, name=f"bands[{index}]", keys=keys)
        band_id = item["id"]
        if not isinstance(band_id, str) or _SAFE_ID_RE.fullmatch(band_id) is None:
            _fail(f"bands[{index}].id must be a safe lowercase identifier")
        minimum_rank = _positive_int(item["minimum_rank"], name=f"bands[{index}].minimum_rank")
        maximum_rank = _positive_int(item["maximum_rank"], name=f"bands[{index}].maximum_rank")
        if (band_id, minimum_rank, maximum_rank) != expected:
            _fail(f"bands[{index}] must be the canonical {expected[0]} range {expected[1]}-{expected[2]}")
        sample_size = _positive_int(item["sample_size"], name=f"bands[{index}].sample_size")
        if sample_size > _MAX_SAMPLE_PER_BAND:
            _fail(f"bands[{index}].sample_size exceeds the {_MAX_SAMPLE_PER_BAND}-row limit")
        sample_sizes.add(sample_size)
        bands.append(
            RankBandPlan(
                id=band_id,
                label=_text(item["label"], name=f"bands[{index}].label", minimum=5),
                minimum_rank=minimum_rank,
                maximum_rank=maximum_rank,
                sample_size=sample_size,
            )
        )
    if len(sample_sizes) != 1:
        _fail("all rank bands must use the same discovery quota")
    return tuple(bands)


def load_selection_plan(plan_path: Path) -> RankSelectionPlan:
    """Load and validate one exact private rank-selection plan."""
    resolved_plan = _private_path(plan_path)
    raw = bounded_stable_read(resolved_plan, maximum_bytes=_MAX_PLAN_BYTES, kind="rank selection plan")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("rank selection plan must be valid UTF-8 JSON") from exc
    plan = _strict_object(value, name="rank selection plan", keys=_PLAN_KEYS)
    if plan["schema_version"] != SCHEMA_VERSION or plan["private"] is not True:
        _fail(f"rank selection plan must use private schema version {SCHEMA_VERSION}")

    source = _strict_object(
        plan["source"],
        name="source",
        keys=frozenset({"path", "name", "revision", "expected_rows"}),
    )
    expected_rows = _positive_int(source["expected_rows"], name="source.expected_rows")
    if expected_rows != EXPECTED_SOURCE_ROWS:
        _fail(f"source.expected_rows must be {EXPECTED_SOURCE_ROWS}")
    exclusion = _strict_object(
        plan["development_exclusion"],
        name="development_exclusion",
        keys=frozenset({"path", "rule"}),
    )
    sampling = _strict_object(
        plan["sampling"],
        name="sampling",
        keys=frozenset({"key_path", "context", "method"}),
    )
    if sampling["method"] != SAMPLING_METHOD:
        _fail(f"sampling.method must be {SAMPLING_METHOD}")
    context = sampling["context"]
    if not isinstance(context, str) or _SAFE_CONTEXT_RE.fullmatch(context) is None:
        _fail("sampling.context must be a safe 1-80 character domain-separation label")
    return RankSelectionPlan(
        source_path=_path(resolved_plan, source["path"], name="source.path"),
        source_name=_text(source["name"], name="source.name", minimum=3),
        source_revision=_text(source["revision"], name="source.revision", minimum=2),
        exclusion_path=_path(resolved_plan, exclusion["path"], name="development_exclusion.path"),
        exclusion_rule=_text(exclusion["rule"], name="development_exclusion.rule", minimum=20),
        sampling_key_path=_path(resolved_plan, sampling["key_path"], name="sampling.key_path"),
        sampling_context=context,
        bands=_validate_bands(plan["bands"]),
        plan_digest_sha256=digest_bytes(raw),
    )


def prepare_rank_strata(
    plan_path: Path,
    output_directory: Path,
    *,
    prepared_at: str | None = None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Return private stratum payloads and their immutable selection manifest."""
    plan = load_selection_plan(plan_path)
    key = _read_key(plan.sampling_key_path)
    ranked, source_raw, normalized, source_duplicates, source_invalid = read_ranked_source(
        plan.source_path,
        expected_rows=EXPECTED_SOURCE_ROWS,
    )
    excluded, exclusion_raw, exclusion_rows, exclusion_normalized, exclusion_duplicates, exclusion_invalid = (
        read_exclusions(plan.exclusion_path)
    )
    output_root = _private_path(output_directory)
    timestamp = prepared_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("prepared_at must be an ISO-8601 timestamp") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() != UTC.utcoffset(parsed_timestamp):
        _fail("prepared_at must carry the UTC timezone")

    payloads: dict[str, bytes] = {}
    band_rows: list[dict[str, object]] = []
    for band in plan.bands:
        candidates = [
            row for row in ranked if band.minimum_rank <= row.rank <= band.maximum_rank and row.domain not in excluded
        ]
        if band.sample_size > len(candidates):
            _fail(f"{band.id} sample size exceeds its eligible universe")
        selected = tuple(
            heapq.nsmallest(
                band.sample_size,
                candidates,
                key=lambda row, band_id=band.id: keyed_rank(key, f"{plan.sampling_context}:{band_id}", row),
            )
        )
        payload = domain_frame_bytes(selected)
        filename = f"{band.id}.txt"
        payloads[filename] = payload
        source_band_count = sum(band.minimum_rank <= row.rank <= band.maximum_rank for row in ranked)
        band_rows.append(
            {
                "id": band.id,
                "label": band.label,
                "minimum_rank": band.minimum_rank,
                "maximum_rank": band.maximum_rank,
                "source_canonical_rows": source_band_count,
                "development_overlap_excluded": source_band_count - len(candidates),
                "eligible_universe_rows": len(candidates),
                "selected_rows": len(selected),
                "inclusion_probability": f"{len(selected)}/{len(candidates)}",
                "output_path": str(output_root / filename),
                "frame_sha256": digest_bytes(payload),
            }
        )

    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "prepared_at": timestamp,
        "source": {
            "path": str(plan.source_path),
            "name": plan.source_name,
            "revision": plan.source_revision,
            "sha256": digest_bytes(source_raw),
            "input_rows": EXPECTED_SOURCE_ROWS,
            "normalized_rows": normalized,
            "duplicate_rows_removed": source_duplicates,
            "invalid_rows_excluded": source_invalid,
        },
        "development_exclusion": {
            "path": str(plan.exclusion_path),
            "rule": plan.exclusion_rule,
            "sha256": digest_bytes(exclusion_raw),
            "input_rows": exclusion_rows,
            "canonical_rows": len(excluded),
            "normalized_rows": exclusion_normalized,
            "duplicate_rows_removed": exclusion_duplicates,
            "invalid_rows_excluded": exclusion_invalid,
        },
        "sampling": {
            "method": SAMPLING_METHOD,
            "context": plan.sampling_context,
            "private_key_sha256": digest_bytes(key),
            "allocation": "equal-discovery-quota-not-population-weighting",
        },
        "bands": band_rows,
        "plan_digest_sha256": plan.plan_digest_sha256,
        "privacy": {
            "identifiers_printed": 0,
            "per_domain_rows_printed": 0,
            "network_requests": 0,
        },
    }
    manifest["manifest_digest_sha256"] = digest_bytes(_canonical_json(manifest))
    return payloads, manifest


def public_summary(manifest: Mapping[str, object], *, written: bool) -> dict[str, object]:
    """Return aggregate-safe rank-selection metadata for console output."""
    source = cast(Mapping[str, object], manifest["source"])
    exclusion = cast(Mapping[str, object], manifest["development_exclusion"])
    sampling = cast(Mapping[str, object], manifest["sampling"])
    bands = cast(list[dict[str, object]], manifest["bands"])
    return {
        "schema_version": manifest["schema_version"],
        "source": {key: value for key, value in source.items() if key != "path"},
        "development_exclusion": {key: value for key, value in exclusion.items() if key not in {"path", "rule"}},
        "sampling": sampling,
        "bands": [{key: value for key, value in band.items() if key not in {"label", "output_path"}} for band in bands],
        "plan_digest_sha256": manifest["plan_digest_sha256"],
        "manifest_digest_sha256": manifest["manifest_digest_sha256"],
        "privacy": {
            "private_artifacts_written": written,
            "identifiers_printed": 0,
            "per_domain_rows_printed": 0,
            "network_requests": 0,
        },
    }


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("private rank artifact already exists; refusing to replace it") from exc


def write_rank_strata(plan_path: Path, output_directory: Path) -> dict[str, object]:
    """Prepare and exclusively write all private rank-selection artifacts."""
    output_root = _private_path(output_directory)
    payloads, manifest = prepare_rank_strata(plan_path, output_root)
    manifest_name = "rank-selection-manifest.json"
    outputs = {**payloads, manifest_name: json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"}
    output_root.mkdir(parents=True, exist_ok=True)
    owned: list[Path] = []
    descriptors: dict[Path, int] = {}
    try:
        for filename in outputs:
            path = output_root / filename
            descriptors[path] = _reserve(path)
            owned.append(path)
        for filename, payload in outputs.items():
            path = output_root / filename
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in owned:
            with contextlib.suppress(OSError):
                path.unlink()
        raise
    return manifest


def generate_private_sampling_key(path: Path) -> str:
    """Create one private 256-bit key and return only its commitment."""
    output = _private_path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    descriptor = _reserve(output)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key.hex().encode("ascii") + b"\n")
    except Exception:
        with contextlib.suppress(OSError):
            output.unlink()
        raise
    return digest_bytes(key)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate-key", help="create a private sampling key without printing it")
    generate.add_argument("--output", required=True, type=Path)
    prepare = commands.add_parser("prepare", help="preflight or write the four private rank strata")
    prepare.add_argument("--plan", required=True, type=Path)
    prepare.add_argument("--output-directory", required=True, type=Path)
    mode = prepare.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--write-private-strata", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "generate-key":
        commitment = generate_private_sampling_key(args.output)
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
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
    manifest = (
        write_rank_strata(args.plan, args.output_directory)
        if args.write_private_strata
        else prepare_rank_strata(args.plan, args.output_directory)[1]
    )
    print(json.dumps(public_summary(manifest, written=args.write_private_strata), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
