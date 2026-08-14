"""Score a frozen vendor-seed round without exposing holdout members.

This reducer treats provider-controlled customer evidence as a relationship
label. A matching recon slug is independent public-DNS corroboration. A silent
row is not a false negative because a provider relationship does not guarantee
that any catalog-readable record is published on the bounded namespace. The
public output therefore reports corroboration yield, not recall or precision.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

from recon_tool.fingerprints import load_fingerprints
from validation import catalog_baseline
from validation.prepare_catalog_round import (
    REPO_ROOT,
    RoundStratumMembership,
    execution_digest_sha256,
    load_round_manifest,
    load_round_membership,
)
from validation.prepare_vendor_seed_round import LABEL_BASIS, METRIC, MIN_PROVIDER_ROWS
from validation.ranked_sampling import bounded_stable_read, digest_bytes
from validation.run_path_safety import validate_private_output_root
from validation.stratify_catalog_round import partition_round_records

PRIVATE_OUTPUT_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = "1.0"
_MAX_CONTRACT_BYTES = 2 * 1024 * 1024
_CLAIM_BOUNDARY = (
    "Provider-controlled customer evidence labels a relationship, not publication of a specific DNS record. "
    "Observed silence is not a false negative; this aggregate is not recall, precision, prevalence, or a "
    "population estimate."
)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _private_output(path: Path) -> Path:
    return validate_private_output_root(path, repo_root=REPO_ROOT, allowed_roots=PRIVATE_OUTPUT_ROOTS)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            _fail(f"vendor-seed JSON contains duplicate field: {key}")
        value[key] = child
    return value


def _read_json(path: Path, *, kind: str) -> tuple[dict[str, Any], bytes]:
    raw = bounded_stable_read(path.resolve(strict=False), maximum_bytes=_MAX_CONTRACT_BYTES, kind=kind)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{kind} must contain one JSON object")
    return value, raw


def _catalog_by_slug() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for fingerprint in load_fingerprints():
        row = result.setdefault(fingerprint.slug, {"names": set(), "record_types": set()})
        cast(set[str], row["names"]).add(fingerprint.name)
        cast(set[str], row["record_types"]).update(rule.type for rule in fingerprint.detections)
    return result


def _source_contract_digest(contract: Mapping[str, Any]) -> str:
    supplied = contract.get("contract_digest_sha256")
    if not isinstance(supplied, str):
        _fail("vendor source contract has no digest")
    payload = dict(contract)
    del payload["contract_digest_sha256"]
    actual = hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).hexdigest()
    if supplied != actual:
        _fail("vendor source contract digest mismatch")
    return supplied


def _provider_contracts(contract: Mapping[str, Any]) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    providers = contract.get("providers")
    if not isinstance(providers, list) or not providers:
        _fail("vendor source contract has no provider strata")
    typed_providers: list[dict[str, object]] = []
    by_slug: dict[str, dict[str, object]] = {}
    for row in providers:
        if not isinstance(row, dict) or not isinstance(row.get("slug"), str):
            _fail("vendor source contract contains a malformed provider")
        slug = row["slug"]
        if slug in by_slug:
            _fail("vendor source contract contains duplicate provider slugs")
        if row.get("label_basis") != LABEL_BASIS:
            _fail(f"provider {slug} uses an unsupported label basis")
        count = row.get("member_count")
        record_types = row.get("record_types")
        if not isinstance(count, int) or isinstance(count, bool) or count < MIN_PROVIDER_ROWS:
            _fail(f"provider {slug} does not meet the public minimum stratum size")
        if (
            not isinstance(record_types, list)
            or not record_types
            or any(not isinstance(item, str) for item in record_types)
        ):
            _fail(f"provider {slug} has no valid record-type contract")
        typed_row = cast(dict[str, object], row)
        typed_providers.append(typed_row)
        by_slug[slug] = typed_row
    return typed_providers, by_slug


def _validate_source_contract(
    contract: Mapping[str, Any],
    *,
    manifest: Mapping[str, object],
    memberships: Sequence[RoundStratumMembership],
) -> dict[str, dict[str, object]]:
    if contract.get("schema_version") != 1 or contract.get("private") is not True:
        _fail("vendor source contract must use private schema version 1")
    if contract.get("label_basis") != LABEL_BASIS or contract.get("metric") != METRIC:
        _fail("vendor source contract label basis or metric is unsupported")
    digest = _source_contract_digest(contract)
    source = manifest.get("source")
    if not isinstance(source, dict) or f"source-contract-sha256={digest}" not in str(source.get("revision", "")):
        _fail("round manifest does not bind the vendor source contract")
    providers, by_slug = _provider_contracts(contract)
    if [membership.id for membership in memberships] != [str(row["slug"]) for row in providers]:
        _fail("vendor source contract order does not match frozen round strata")
    for membership in memberships:
        provider = by_slug[membership.id]
        if provider["member_count"] != len(membership.domains):
            _fail(f"provider {membership.id} source and round counts differ")
        rendered = ("\n".join(sorted(membership.domains)) + "\n").encode("ascii")
        if provider.get("member_digest_sha256") != digest_bytes(rendered):
            _fail(f"provider {membership.id} membership digest mismatch")
    return by_slug


def _validate_pooled_aggregate(
    pooled: Mapping[str, Any],
    *,
    manifest: Mapping[str, object],
    results_digest: str,
    records_total: int,
) -> None:
    catalog_baseline.assert_aggregate_safe(pooled)
    if pooled.get("aggregate_only") is not True:
        _fail("pooled catalog baseline is not marked aggregate-only")
    if pooled.get("results_digest_sha256") != results_digest:
        _fail("pooled catalog baseline results digest does not match the vendor-seed results")
    if pooled.get("records_total") != records_total:
        _fail("pooled catalog baseline record count does not match the vendor-seed results")
    contract = pooled.get("round_contract")
    if not isinstance(contract, dict):
        _fail("pooled catalog baseline has no round contract")
    if contract.get("manifest_digest_sha256") != manifest.get("manifest_digest_sha256"):
        _fail("pooled catalog baseline does not reference the frozen vendor-seed manifest")
    if contract.get("implementation") != manifest.get("implementation"):
        _fail("pooled catalog baseline implementation commitment does not match the vendor-seed manifest")


def _wilson_95(successes: int, total: int) -> tuple[float | None, float | None]:
    if total == 0:
        return None, None
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)


def _slug_list(record: Mapping[str, Any]) -> set[str]:
    raw = record.get("slugs", [])
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        _fail("vendor-seed result has a malformed slugs field")
    return set(raw)


def _availability(record: Mapping[str, Any], expected_types: set[str]) -> str:
    summaries = record.get("dns_catalog_summary")
    if not isinstance(summaries, list):
        return "unmeasured"
    relevant: list[str] = []
    for row in summaries:
        if not isinstance(row, dict) or row.get("record_type") not in expected_types:
            continue
        value = row.get("availability")
        relevant.append(value if isinstance(value, str) else "unmeasured")
    if any(value in {"available", "partial"} for value in relevant):
        return "measured"
    if any(value == "unavailable" for value in relevant):
        return "unavailable"
    return "unmeasured"


def _provider_result(
    membership: RoundStratumMembership,
    records: Sequence[Mapping[str, Any]],
    *,
    provider: Mapping[str, object],
    catalog: Mapping[str, dict[str, object]],
) -> dict[str, object]:
    slug = membership.id
    catalog_row = catalog.get(slug)
    if catalog_row is None:
        _fail(f"frozen provider slug is absent from the current catalog: {slug}")
    expected_types = set(cast(list[str], provider["record_types"]))
    current_types = cast(set[str], catalog_row["record_types"])
    if expected_types != current_types:
        _fail(f"provider {slug} catalog record types changed after the source contract froze")
    counts = {"corroborated": 0, "observed_silent": 0, "unavailable": 0, "unmeasured": 0, "error": 0}
    for record in records:
        if record.get("record_type") == "error":
            counts["error"] += 1
            continue
        if slug in _slug_list(record):
            counts["corroborated"] += 1
            continue
        availability = _availability(record, expected_types)
        if availability == "measured":
            counts["observed_silent"] += 1
        else:
            counts[availability] += 1
    measurable = counts["corroborated"] + counts["observed_silent"]
    low, high = _wilson_95(counts["corroborated"], measurable)
    rate = round(counts["corroborated"] / measurable, 6) if measurable else None
    names = sorted(cast(set[str], catalog_row["names"]))
    return {
        "provider_slug": slug,
        "provider_names": names,
        "label_basis": LABEL_BASIS,
        "expected_record_types": sorted(expected_types),
        "frame_count": len(membership.domains),
        "measurable_count": measurable,
        **counts,
        "corroboration_rate": rate,
        "wilson_95_low": low,
        "wilson_95_high": high,
    }


def _reducer_digest() -> str:
    paths = [
        REPO_ROOT / "validation" / "catalog_baseline.py",
        REPO_ROOT / "validation" / "evaluate_vendor_seed_round.py",
        REPO_ROOT / "validation" / "prepare_catalog_round.py",
        REPO_ROOT / "validation" / "prepare_vendor_seed_round.py",
        REPO_ROOT / "validation" / "stratify_catalog_round.py",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "uv.lock",
    ]
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(REPO_ROOT).as_posix().encode("utf-8")
        raw = bounded_stable_read(path, maximum_bytes=32 * 1024 * 1024, kind="vendor-seed reducer input")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def evaluate_vendor_seed(
    *,
    results_path: Path,
    round_plan_path: Path,
    round_manifest_path: Path,
    source_contract_path: Path,
    pooled_aggregate_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a disclosure-safe aggregate and a private execution manifest."""
    manifest = load_round_manifest(round_manifest_path)
    if manifest.get("round_kind") != "vendor-seed":
        _fail("vendor-seed evaluator requires a vendor-seed round manifest")
    budget = manifest.get("promotion_budget")
    if not isinstance(budget, dict) or budget.get("metric") != METRIC:
        _fail("vendor-seed round manifest does not freeze the supported metric")
    memberships = load_round_membership(round_plan_path, manifest)
    if any(len(membership.domains) < MIN_PROVIDER_ROWS for membership in memberships):
        _fail(f"every public provider stratum requires at least {MIN_PROVIDER_ROWS} rows")
    source_contract, source_raw = _read_json(source_contract_path, kind="vendor source contract")
    provider_contracts = _validate_source_contract(
        source_contract,
        manifest=manifest,
        memberships=memberships,
    )
    records_by_stratum, result_files = partition_round_records(results_path, memberships)
    records_total = sum(len(records) for records in records_by_stratum)
    results_digest = catalog_baseline.digest_result_files(result_files)
    pooled, pooled_raw = _read_json(pooled_aggregate_path, kind="pooled catalog baseline")
    _validate_pooled_aggregate(
        pooled,
        manifest=manifest,
        results_digest=results_digest,
        records_total=records_total,
    )
    catalog = _catalog_by_slug()
    provider_results = [
        _provider_result(
            membership,
            records,
            provider=provider_contracts[membership.id],
            catalog=catalog,
        )
        for membership, records in zip(memberships, records_by_stratum, strict=True)
    ]
    frame_counts = [cast(int, row["frame_count"]) for row in provider_results]
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    revision, dirty = catalog_baseline.repository_revision()
    public: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "aggregate_only": True,
        "generated_at": generated_at,
        "round_kind": "vendor-seed",
        "label_basis": LABEL_BASIS,
        "metric": METRIC,
        "claim_boundary": _CLAIM_BOUNDARY,
        "provider_count": len(provider_results),
        "records_total": records_total,
        "results_digest_sha256": results_digest,
        "pooled_aggregate_sha256": digest_bytes(pooled_raw),
        "source_contract_digest_sha256": source_contract["contract_digest_sha256"],
        "observation_contract": catalog_baseline.public_round_contract(cast(dict[str, Any], manifest)),
        "reducer": {
            "code_revision": revision,
            "working_tree_dirty": dirty,
            "digest_sha256": _reducer_digest(),
            "current_execution_digest_sha256": execution_digest_sha256(),
            "network_requests": 0,
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "providers": provider_results,
    }
    catalog_baseline.assert_aggregate_safe(public)
    private_manifest = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "generated_at": generated_at,
        "results_path": str(results_path.resolve(strict=False)),
        "round_plan_path": str(round_plan_path.resolve(strict=False)),
        "round_manifest_path": str(round_manifest_path.resolve(strict=False)),
        "source_contract_path": str(source_contract_path.resolve(strict=False)),
        "pooled_aggregate_path": str(pooled_aggregate_path.resolve(strict=False)),
        "source_contract_file_sha256": digest_bytes(source_raw),
        "pooled_aggregate_sha256": digest_bytes(pooled_raw),
        "results_digest_sha256": results_digest,
        "provider_counts": frame_counts,
        "reducer_digest_sha256": public["reducer"]["digest_sha256"],
    }
    return public, private_manifest


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("vendor-seed output already exists; refusing to replace it") from exc


def write_outputs(output_dir: Path, public: Mapping[str, Any], private_manifest: Mapping[str, Any]) -> None:
    """Exclusively write the aggregate and private execution manifest."""
    root = _private_output(output_dir.resolve(strict=False))
    root.mkdir(parents=True, exist_ok=True)
    outputs = {
        root / "vendor-seed-aggregate.json": public,
        root / "vendor-seed-manifest.json": private_manifest,
    }
    descriptors: dict[Path, int] = {}
    owned: list[Path] = []
    try:
        for path in outputs:
            descriptors[path] = _reserve(path)
            owned.append(path)
        for path, value in outputs.items():
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in owned:
            with contextlib.suppress(OSError):
                path.unlink()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Complete ignored private result file or run.")
    parser.add_argument("--round-plan", required=True, type=Path, help="Frozen private round plan.")
    parser.add_argument("--round-manifest", required=True, type=Path, help="Frozen private round manifest.")
    parser.add_argument("--source-contract", required=True, type=Path, help="Frozen private vendor source contract.")
    parser.add_argument("--pooled-aggregate", required=True, type=Path, help="Scan-produced pooled catalog aggregate.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Ignored private output directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        public, private_manifest = evaluate_vendor_seed(
            results_path=args.input,
            round_plan_path=args.round_plan,
            round_manifest_path=args.round_manifest,
            source_contract_path=args.source_contract,
            pooled_aggregate_path=args.pooled_aggregate,
        )
        write_outputs(args.output_dir, public, private_manifest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "provider_count": public["provider_count"],
                "records_total": public["records_total"],
                "results_digest_sha256": public["results_digest_sha256"],
                "reducer_digest_sha256": public["reducer"]["digest_sha256"],
                "identifiers_printed": 0,
                "network_requests": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
