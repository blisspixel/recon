"""Prepare private ccTLD-delegation strata for a catalog regional round.

The source list, mapping, exclusions, sampling key, selected namespaces, and
output paths remain private. Console output contains only aggregate counts,
ccTLD labels, and cryptographic commitments. A ccTLD is a namespace attribute,
not evidence of an organization's location. This module performs no network
requests.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import heapq
import io
import json
import os
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast

from validation.prepare_catalog_round import execution_digest_sha256
from validation.ranked_sampling import (
    RankedDomain,
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
SAMPLING_METHOD = "hmac-sha256-ccTLD-within-m49-region-v1"
CANONICAL_REGIONS = (
    ("africa", "002", "Africa"),
    ("americas", "019", "Americas"),
    ("asia", "142", "Asia"),
    ("europe", "150", "Europe"),
    ("oceania", "009", "Oceania"),
)
MAPPING_COLUMNS = ("tld", "iana_type", "iso_alpha2", "region_code", "region_name")
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "private",
        "question",
        "interpretation_boundary",
        "source",
        "geography",
        "prior_exclusions",
        "sampling",
        "design",
    }
)
_SAFE_CONTEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_TLD_RE = re.compile(r"^[a-z]{2}$")
_ALPHA2_RE = re.compile(r"^[A-Z]{2}$")
_PRIVATE_KEY_RE = re.compile(rb"^[0-9a-f]{64}\n$")
_MAX_PLAN_BYTES = 256 * 1024
_MAX_MAPPING_BYTES = 512 * 1024
_MAX_EXCLUSION_FILES = 64
_MAX_TLDS_PER_REGION = 20
_MAX_SAMPLE_PER_TLD = 2_000


@dataclass(frozen=True, slots=True)
class RegionDesign:
    """One canonical UN M49 region and its equal ccTLD discovery quota."""

    id: str
    code: str
    name: str


@dataclass(frozen=True, slots=True)
class ExclusionSource:
    """One prior corpus excluded before regional selection."""

    path: Path
    rule: str


@dataclass(frozen=True, slots=True)
class RegionSelectionPlan:
    """Validated private inputs for one ccTLD-delegation selection."""

    question: str
    interpretation_boundary: str
    source_path: Path
    source_name: str
    source_revision: str
    expected_source_rows: int
    mapping_path: Path
    mapping_name: str
    mapping_revision: str
    expected_mapping_rows: int
    exclusions: tuple[ExclusionSource, ...]
    sampling_key_path: Path = field(repr=False)
    sampling_context: str = ""
    regions: tuple[RegionDesign, ...] = ()
    tlds_per_region: int = 0
    sample_size_per_tld: int = 0
    plan_digest_sha256: str = ""


@dataclass(frozen=True, slots=True)
class TldRegion:
    """One exact ASCII ccTLD to UN M49 region mapping."""

    tld: str
    iso_alpha2: str
    region_code: str
    region_name: str


@dataclass(frozen=True, slots=True)
class SelectionContext:
    """Immutable inputs shared by every regional stratum selection."""

    eligible: Mapping[str, Sequence[RankedDomain]]
    source_counts: Mapping[str, int]
    mapping: Mapping[str, TldRegion]
    plan: RegionSelectionPlan
    key: bytes = field(repr=False)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"regional selection JSON contains duplicate field: {key}")
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


def _positive_int(value: object, *, name: str, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        _fail(f"{name} exceeds the {maximum}-row limit")
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


def _load_regions(value: object) -> tuple[RegionDesign, ...]:
    if not isinstance(value, list) or len(value) != len(CANONICAL_REGIONS):
        _fail("design.regions must declare the five canonical UN M49 regions")
    regions: list[RegionDesign] = []
    keys = frozenset({"id", "code", "name"})
    for index, (raw, expected) in enumerate(zip(value, CANONICAL_REGIONS, strict=True)):
        item = _strict_object(raw, name=f"design.regions[{index}]", keys=keys)
        actual = (item["id"], item["code"], item["name"])
        if actual != expected:
            _fail(f"design.regions[{index}] must be canonical region {expected[0]} ({expected[1]})")
        regions.append(RegionDesign(*expected))
    return tuple(regions)


def _load_exclusions(plan_path: Path, value: object) -> tuple[ExclusionSource, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_EXCLUSION_FILES:
        _fail(f"prior_exclusions must contain 1-{_MAX_EXCLUSION_FILES} entries")
    keys = frozenset({"path", "rule"})
    exclusions: list[ExclusionSource] = []
    seen: set[Path] = set()
    for index, raw in enumerate(value):
        item = _strict_object(raw, name=f"prior_exclusions[{index}]", keys=keys)
        path = _path(plan_path, item["path"], name=f"prior_exclusions[{index}].path")
        if path in seen:
            _fail("prior_exclusions paths must be unique")
        seen.add(path)
        exclusions.append(
            ExclusionSource(
                path=path,
                rule=_text(item["rule"], name=f"prior_exclusions[{index}].rule", minimum=20),
            )
        )
    return tuple(exclusions)


def load_selection_plan(plan_path: Path) -> RegionSelectionPlan:
    """Load and validate one exact private regional-selection plan."""
    resolved_plan = _private_path(plan_path)
    raw = bounded_stable_read(resolved_plan, maximum_bytes=_MAX_PLAN_BYTES, kind="regional selection plan")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("regional selection plan must be valid UTF-8 JSON") from exc
    plan = _strict_object(value, name="regional selection plan", keys=_PLAN_KEYS)
    if plan["schema_version"] != SCHEMA_VERSION or plan["private"] is not True:
        _fail(f"regional selection plan must use private schema version {SCHEMA_VERSION}")

    source = _strict_object(
        plan["source"],
        name="source",
        keys=frozenset({"path", "name", "revision", "expected_rows"}),
    )
    geography = _strict_object(
        plan["geography"],
        name="geography",
        keys=frozenset({"path", "name", "revision", "expected_rows"}),
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
    design = _strict_object(
        plan["design"],
        name="design",
        keys=frozenset({"regions", "tlds_per_region", "sample_size_per_tld"}),
    )
    return RegionSelectionPlan(
        question=_text(plan["question"], name="question", minimum=20),
        interpretation_boundary=_text(
            plan["interpretation_boundary"],
            name="interpretation_boundary",
            minimum=40,
        ),
        source_path=_path(resolved_plan, source["path"], name="source.path"),
        source_name=_text(source["name"], name="source.name", minimum=3),
        source_revision=_text(source["revision"], name="source.revision", minimum=2),
        expected_source_rows=_positive_int(source["expected_rows"], name="source.expected_rows"),
        mapping_path=_path(resolved_plan, geography["path"], name="geography.path"),
        mapping_name=_text(geography["name"], name="geography.name", minimum=10),
        mapping_revision=_text(geography["revision"], name="geography.revision", minimum=10),
        expected_mapping_rows=_positive_int(geography["expected_rows"], name="geography.expected_rows"),
        exclusions=_load_exclusions(resolved_plan, plan["prior_exclusions"]),
        sampling_key_path=_path(resolved_plan, sampling["key_path"], name="sampling.key_path"),
        sampling_context=context,
        regions=_load_regions(design["regions"]),
        tlds_per_region=_positive_int(
            design["tlds_per_region"],
            name="design.tlds_per_region",
            maximum=_MAX_TLDS_PER_REGION,
        ),
        sample_size_per_tld=_positive_int(
            design["sample_size_per_tld"],
            name="design.sample_size_per_tld",
            maximum=_MAX_SAMPLE_PER_TLD,
        ),
        plan_digest_sha256=digest_bytes(raw),
    )


def _read_mapping(plan: RegionSelectionPlan) -> tuple[dict[str, TldRegion], bytes]:
    raw = bounded_stable_read(plan.mapping_path, maximum_bytes=_MAX_MAPPING_BYTES, kind="ccTLD region mapping")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
    except UnicodeDecodeError as exc:
        raise ValueError("ccTLD region mapping is not UTF-8") from exc
    if tuple(reader.fieldnames or ()) != MAPPING_COLUMNS:
        _fail("ccTLD region mapping has an invalid header")
    mapping: dict[str, TldRegion] = {}
    known_regions = {(region.code, region.name) for region in plan.regions}
    for physical_row, row in enumerate(reader, start=2):
        if None in row or any(value is None for value in row.values()):
            _fail(f"ccTLD region mapping row {physical_row} has an invalid column count")
        tld = cast(str, row["tld"])
        alpha2 = cast(str, row["iso_alpha2"])
        code = cast(str, row["region_code"])
        name = cast(str, row["region_name"])
        if _TLD_RE.fullmatch(tld) is None or _ALPHA2_RE.fullmatch(alpha2) is None:
            _fail(f"ccTLD region mapping row {physical_row} has an invalid code")
        if tld != alpha2.casefold():
            _fail(f"ccTLD region mapping row {physical_row} is not an exact ISO alpha-2 match")
        if row["iana_type"] != "country-code":
            _fail(f"ccTLD region mapping row {physical_row} is not IANA country-code data")
        if (code, name) not in known_regions:
            _fail(f"ccTLD region mapping row {physical_row} has an unsupported UN M49 region")
        if tld in mapping:
            _fail(f"ccTLD region mapping row {physical_row} duplicates a TLD")
        mapping[tld] = TldRegion(tld, alpha2, code, name)
    if len(mapping) != plan.expected_mapping_rows:
        _fail(f"ccTLD region mapping has {len(mapping)} rows; expected exactly {plan.expected_mapping_rows}")
    if not mapping:
        _fail("ccTLD region mapping has no eligible rows")
    return mapping, raw


def _read_prior_exclusions(plan: RegionSelectionPlan) -> tuple[set[str], list[dict[str, object]]]:
    combined: set[str] = set()
    reports: list[dict[str, object]] = []
    for exclusion in plan.exclusions:
        values, raw, rows, normalized, duplicates, invalid = read_exclusions(exclusion.path)
        new_rows = len(values - combined)
        combined.update(values)
        reports.append(
            {
                "path": str(exclusion.path),
                "rule": exclusion.rule,
                "sha256": digest_bytes(raw),
                "input_rows": rows,
                "canonical_rows": len(values),
                "new_union_rows": new_rows,
                "normalized_rows": normalized,
                "duplicate_rows_removed": duplicates,
                "invalid_rows_excluded": invalid,
            }
        )
    return combined, reports


def _select_region(
    region: RegionDesign,
    context: SelectionContext,
) -> tuple[bytes, dict[str, object]]:
    region_tlds = sorted(
        (
            (tld, rows)
            for tld, rows in context.eligible.items()
            if rows and context.mapping[tld].region_code == region.code
        ),
        key=lambda item: (-len(item[1]), item[0]),
    )
    qualified = [(tld, rows) for tld, rows in region_tlds if len(rows) >= context.plan.sample_size_per_tld]
    if len(qualified) < context.plan.tlds_per_region:
        _fail(f"region {region.id} has fewer than {context.plan.tlds_per_region} eligible ccTLD strata")
    selected_tlds = qualified[: context.plan.tlds_per_region]
    selected_rows: list[RankedDomain] = []
    tld_reports: list[dict[str, object]] = []
    for tld, rows in selected_tlds:
        selected = heapq.nsmallest(
            context.plan.sample_size_per_tld,
            rows,
            key=lambda row, current=tld: keyed_rank(
                context.key,
                f"{context.plan.sampling_context}:{region.id}:{current}",
                row,
            ),
        )
        selected_rows.extend(selected)
        tld_reports.append(
            {
                "tld": tld,
                "source_canonical_rows": int(context.source_counts.get(tld, 0)),
                "prior_overlap_excluded": int(context.source_counts.get(tld, 0)) - len(rows),
                "eligible_universe_rows": len(rows),
                "selected_rows": len(selected),
                "inclusion_probability": f"{len(selected)}/{len(rows)}",
            }
        )
    payload = domain_frame_bytes(selected_rows)
    return payload, {
        "id": region.id,
        "code": region.code,
        "name": region.name,
        "eligible_ccTLDs": len(qualified),
        "selected_ccTLDs": tld_reports,
        "selected_rows": len(selected_rows),
        "frame_sha256": digest_bytes(payload),
    }


def prepare_region_strata(
    plan_path: Path,
    output_directory: Path,
    *,
    prepared_at: str | None = None,
) -> tuple[dict[str, bytes], dict[str, object]]:
    """Return private regional payloads and their immutable selection manifest."""
    plan = load_selection_plan(plan_path)
    key = _read_key(plan.sampling_key_path)
    ranked, source_raw, normalized, source_duplicates, source_invalid = read_ranked_source(
        plan.source_path,
        expected_rows=plan.expected_source_rows,
    )
    mapping, mapping_raw = _read_mapping(plan)
    excluded, exclusion_reports = _read_prior_exclusions(plan)
    _private_path(output_directory)
    timestamp = prepared_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("prepared_at must be an ISO-8601 timestamp") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() != UTC.utcoffset(parsed_timestamp):
        _fail("prepared_at must carry the UTC timezone")

    source_counts: Counter[str] = Counter()
    eligible: defaultdict[str, list[RankedDomain]] = defaultdict(list)
    mapped_rows = 0
    for row in ranked:
        tld = row.domain.rsplit(".", maxsplit=1)[-1]
        if tld not in mapping:
            continue
        mapped_rows += 1
        source_counts[tld] += 1
        if row.domain not in excluded:
            eligible[tld].append(row)

    selection_context = SelectionContext(eligible, source_counts, mapping, plan, key)
    payloads: dict[str, bytes] = {}
    region_reports: list[dict[str, object]] = []
    for region in plan.regions:
        payload, report = _select_region(region, selection_context)
        payloads[f"{region.id}.txt"] = payload
        region_reports.append(report)

    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "prepared_at": timestamp,
        "question": plan.question,
        "interpretation_boundary": plan.interpretation_boundary,
        "source": {
            "path": str(plan.source_path),
            "name": plan.source_name,
            "revision": plan.source_revision,
            "sha256": digest_bytes(source_raw),
            "input_rows": plan.expected_source_rows,
            "normalized_rows": normalized,
            "duplicate_rows_removed": source_duplicates,
            "invalid_rows_excluded": source_invalid,
            "mapped_ccTLD_rows": mapped_rows,
        },
        "geography": {
            "path": str(plan.mapping_path),
            "name": plan.mapping_name,
            "revision": plan.mapping_revision,
            "sha256": digest_bytes(mapping_raw),
            "mapping_rows": len(mapping),
            "rule": "exact ASCII two-letter IANA country-code TLD and UN M49 ISO-alpha2 intersection",
        },
        "prior_exclusions": exclusion_reports,
        "prior_exclusion_union_rows": len(excluded),
        "sampling": {
            "method": SAMPLING_METHOD,
            "context": plan.sampling_context,
            "private_key_sha256": digest_bytes(key),
            "ccTLD_selection": "largest eligible universes per UN M49 region; lexical tie break",
            "allocation": "equal-discovery-quota-not-population-weighting",
            "tlds_per_region": plan.tlds_per_region,
            "sample_size_per_tld": plan.sample_size_per_tld,
        },
        "implementation": {"execution_sha256": execution_digest_sha256()},
        "regions": region_reports,
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
    """Return aggregate-safe regional-selection metadata for console output."""
    source = cast(Mapping[str, object], manifest["source"])
    geography = cast(Mapping[str, object], manifest["geography"])
    exclusions = cast(list[dict[str, object]], manifest["prior_exclusions"])
    return {
        "schema_version": manifest["schema_version"],
        "question": manifest["question"],
        "interpretation_boundary": manifest["interpretation_boundary"],
        "source": {key: value for key, value in source.items() if key != "path"},
        "geography": {key: value for key, value in geography.items() if key != "path"},
        "prior_exclusions": [
            {key: value for key, value in report.items() if key not in {"path", "rule"}} for report in exclusions
        ],
        "prior_exclusion_union_rows": manifest["prior_exclusion_union_rows"],
        "sampling": manifest["sampling"],
        "implementation": manifest["implementation"],
        "regions": manifest["regions"],
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
        raise ValueError("private regional artifact already exists; refusing to replace it") from exc


def write_region_strata(plan_path: Path, output_directory: Path) -> dict[str, object]:
    """Prepare and exclusively write all private regional artifacts."""
    output_root = _private_path(output_directory)
    payloads, manifest = prepare_region_strata(plan_path, output_root)
    manifest_name = "region-selection-manifest" + "." + "json"
    outputs = {
        **payloads,
        manifest_name: json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    }
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--write-private-strata", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = (
        write_region_strata(args.plan, args.output_directory)
        if args.write_private_strata
        else prepare_region_strata(args.plan, args.output_directory)[1]
    )
    print(json.dumps(public_summary(manifest, written=args.write_private_strata), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
