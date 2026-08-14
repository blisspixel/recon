"""Freeze and verify a prior-sample catalog drift contract.

The generic catalog-round manifest binds the future collection. This module
adds the comparison half required by a drift round: the exact prior result,
its catalog and collection regime, the eligible prior rows, and the rule for
separating retained observation-summary changes from interpretation changes.
All paths and target identifiers remain in ignored private workspaces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from recon_tool.validator import validate_domain
from validation import catalog_baseline
from validation.prepare_catalog_round import (
    canonical_frame_rows,
    canonical_json_digest,
    catalog_digest_sha256,
    execution_digest_sha256,
    load_round_frame_rows,
    load_round_manifest,
)
from validation.run_path_safety import validate_private_output_root

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = 1
OBSERVATION_FIELDS = (
    "availability",
    "opportunity_count",
    "observed_count",
    "truncated",
)
OUTCOME_PRECEDENCE = ("unmeasured", "unavailable", "changed", "no_change")
_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "private",
        "prepared_at",
        "prior",
        "current",
        "comparison",
        "contract_digest_sha256",
    }
)
_PRIOR_KEYS = frozenset(
    {
        "run_path",
        "results_path",
        "aggregate_path",
        "round_kind",
        "collected_at",
        "code_revision",
        "results_digest_sha256",
        "aggregate_digest_sha256",
        "catalog_digest_sha256",
        "execution_digest_sha256",
        "records_total",
        "eligible_records",
        "excluded_error_records",
        "ct_enabled",
        "concurrency",
    }
)
_CURRENT_KEYS = frozenset(
    {
        "round_manifest_path",
        "round_manifest_digest_sha256",
        "frame_digest_sha256",
        "frame_count",
        "catalog_digest_sha256",
        "execution_digest_sha256",
    }
)
_COMPARISON_KEYS = frozenset(
    {
        "observation_fields",
        "outcome_precedence",
        "classification_comparison",
    }
)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _private_path(path: Path) -> Path:
    return validate_private_output_root(path, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)


def _strict_object(value: object, *, name: str, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{name} must be an object")
    actual = frozenset(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        _fail(f"{name} has invalid fields: {'; '.join(details)}")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_json_object(path: Path, *, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} must be readable UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{name} must be a JSON object")
    return value


def _prior_result_path(prior_run: Path) -> Path:
    for filename in ("results.ndjson", "results.json"):
        candidate = prior_run / filename
        if candidate.is_file():
            return candidate
    _fail("prior run has no results.ndjson or results.json")


def _prior_frame(prior_results: Path) -> tuple[bytes, int, int]:
    eligible: set[str] = set()
    records_total = 0
    excluded_errors = 0
    for index, record in enumerate(catalog_baseline.iter_result_records(prior_results), start=1):
        records_total += 1
        if record.get("record_type") == "error":
            excluded_errors += 1
            continue
        domain = record.get("queried_domain")
        if not isinstance(domain, str):
            _fail(f"prior result row {index} has no canonical queried domain")
        try:
            canonical = validate_domain(domain)
        except ValueError as exc:
            raise ValueError(f"prior result row {index} has a malformed queried domain") from exc
        if canonical != domain:
            _fail(f"prior result row {index} is not a canonical registrable apex")
        if canonical in eligible:
            _fail("prior results contain duplicate eligible namespaces")
        eligible.add(canonical)
    if not eligible:
        _fail("prior results have no eligible measured rows")
    frame = ("\n".join(sorted(eligible)) + "\n").encode("ascii")
    canonical_frame_rows(frame)
    return frame, records_total, excluded_errors


def derive_prior_frame(prior_run: Path) -> tuple[bytes, dict[str, Any]]:
    """Return the canonical eligible prior frame and disclosure-safe metadata."""
    resolved_run = _private_path(prior_run)
    results_path = _prior_result_path(resolved_run)
    aggregate_path = resolved_run / "catalog-aggregate.json"
    meta_path = resolved_run / "meta.json"
    if not aggregate_path.is_file() or not meta_path.is_file():
        _fail("prior run must include catalog-aggregate.json and meta.json")
    aggregate = _read_json_object(aggregate_path, name="prior aggregate")
    meta = _read_json_object(meta_path, name="prior scan metadata")
    if meta.get("batch_completed") is not True or meta.get("batch_timed_out") is True:
        _fail("prior run must be complete and must not have timed out")
    if meta.get("ct_enabled") is not False:
        _fail("prior drift baseline must have CT disabled")
    frame, records_total, excluded_errors = _prior_frame(results_path)
    expected_total = aggregate.get("records_total")
    expected_errors = aggregate.get("error_records", excluded_errors)
    if expected_total != records_total or expected_errors != excluded_errors:
        _fail("prior aggregate record accounting does not match the retained result")
    result_files = catalog_baseline.result_files(results_path)
    results_digest = catalog_baseline.digest_result_files(result_files)
    if aggregate.get("results_digest_sha256") != results_digest:
        _fail("prior aggregate result digest does not match the retained result")
    catalog = aggregate.get("catalog")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("digest_sha256"), str):
        _fail("prior aggregate has no catalog digest")
    code_revision = aggregate.get("code_revision")
    if not isinstance(code_revision, str) or len(code_revision) != 40:
        _fail("prior aggregate has no exact code revision")
    round_contract = aggregate.get("round_contract")
    prior_execution_digest: str | None = None
    if isinstance(round_contract, dict):
        implementation = round_contract.get("implementation")
        if isinstance(implementation, dict) and isinstance(implementation.get("execution_digest_sha256"), str):
            prior_execution_digest = implementation["execution_digest_sha256"]
    concurrency = meta.get("concurrency")
    if not isinstance(concurrency, int) or isinstance(concurrency, bool) or concurrency < 1:
        _fail("prior scan metadata has no valid concurrency")
    collected_at = meta.get("scan_started_utc")
    if not isinstance(collected_at, str) or not collected_at:
        _fail("prior scan metadata has no collection timestamp")
    return frame, {
        "run_path": str(resolved_run),
        "results_path": str(results_path.resolve()),
        "aggregate_path": str(aggregate_path.resolve()),
        "round_kind": str(aggregate.get("round_kind", meta.get("round_kind", "baseline"))),
        "collected_at": collected_at,
        "code_revision": code_revision,
        "results_digest_sha256": results_digest,
        "aggregate_digest_sha256": _sha256_bytes(aggregate_path.read_bytes()),
        "catalog_digest_sha256": catalog["digest_sha256"],
        "execution_digest_sha256": prior_execution_digest,
        "records_total": records_total,
        "eligible_records": records_total - excluded_errors,
        "excluded_error_records": excluded_errors,
        "ct_enabled": False,
        "concurrency": concurrency,
    }


def build_drift_contract(
    prior_run: Path,
    round_manifest_path: Path,
    *,
    prepared_at: str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Build a private comparison contract and its exact eligible frame."""
    frame_bytes, prior = derive_prior_frame(prior_run)
    resolved_manifest = _private_path(round_manifest_path)
    manifest = load_round_manifest(resolved_manifest)
    if manifest.get("round_kind") != "drift":
        _fail("drift comparison requires a drift round manifest")
    manifest_rows = load_round_frame_rows(manifest)
    if frame_bytes != ("\n".join(manifest_rows) + "\n").encode("ascii"):
        _fail("drift round frame does not match the eligible prior result rows")
    implementation = manifest.get("implementation")
    frame = manifest.get("frame")
    if not isinstance(implementation, dict) or not isinstance(frame, dict):
        _fail("drift round manifest implementation or frame is malformed")
    timestamp = prepared_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    contract: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "prepared_at": timestamp,
        "prior": prior,
        "current": {
            "round_manifest_path": str(resolved_manifest),
            "round_manifest_digest_sha256": manifest["manifest_digest_sha256"],
            "frame_digest_sha256": frame["digest_sha256"],
            "frame_count": frame["count"],
            "catalog_digest_sha256": implementation["catalog_digest_sha256"],
            "execution_digest_sha256": implementation["execution_digest_sha256"],
        },
        "comparison": {
            "observation_fields": list(OBSERVATION_FIELDS),
            "outcome_precedence": list(OUTCOME_PRECEDENCE),
            "classification_comparison": "only_when_catalog_and_interpretation_digests_match",
        },
    }
    contract["contract_digest_sha256"] = canonical_json_digest(contract)
    return frame_bytes, contract


def load_drift_contract(path: Path) -> dict[str, Any]:
    """Load and structurally validate one private drift comparison contract."""
    resolved = _private_path(path)
    contract = _strict_object(
        _read_json_object(resolved, name="drift contract"), name="drift contract", keys=_CONTRACT_KEYS
    )
    if contract["schema_version"] != SCHEMA_VERSION or contract["private"] is not True:
        _fail(f"drift contract must use private schema version {SCHEMA_VERSION}")
    supplied_digest = contract.get("contract_digest_sha256")
    digest_payload = dict(contract)
    del digest_payload["contract_digest_sha256"]
    if supplied_digest != canonical_json_digest(digest_payload):
        _fail("drift contract digest mismatch")
    _strict_object(contract["prior"], name="drift contract prior", keys=_PRIOR_KEYS)
    _strict_object(contract["current"], name="drift contract current", keys=_CURRENT_KEYS)
    comparison = _strict_object(contract["comparison"], name="drift contract comparison", keys=_COMPARISON_KEYS)
    if comparison["observation_fields"] != list(OBSERVATION_FIELDS):
        _fail("drift contract observation fields do not match the supported comparison")
    if comparison["outcome_precedence"] != list(OUTCOME_PRECEDENCE):
        _fail("drift contract outcome precedence does not match the supported comparison")
    if comparison["classification_comparison"] != "only_when_catalog_and_interpretation_digests_match":
        _fail("drift contract classification comparison rule is unsupported")
    return contract


def verify_drift_contract(
    path: Path,
    *,
    round_manifest_path: Path,
    compare_to: Path,
) -> dict[str, Any]:
    """Verify the comparison contract, prior result, and future frame binding."""
    contract = load_drift_contract(path)
    prior = contract["prior"]
    current = contract["current"]
    resolved_compare = _private_path(compare_to)
    if resolved_compare != Path(prior["run_path"]).resolve(strict=False):
        _fail("drift --compare-to path does not match the frozen prior run")
    resolved_manifest = _private_path(round_manifest_path)
    if resolved_manifest != Path(current["round_manifest_path"]).resolve(strict=False):
        _fail("drift round manifest path does not match the frozen comparison contract")
    manifest = load_round_manifest(resolved_manifest)
    if manifest.get("manifest_digest_sha256") != current["round_manifest_digest_sha256"]:
        _fail("drift round manifest digest does not match the comparison contract")
    frame_bytes, derived_prior = derive_prior_frame(resolved_compare)
    for key in _PRIOR_KEYS:
        expected_value = derived_prior[key]
        supplied_value = prior[key]
        if key in {"run_path", "results_path", "aggregate_path"}:
            matches = Path(str(expected_value)).resolve(strict=False) == Path(str(supplied_value)).resolve(strict=False)
        else:
            matches = expected_value == supplied_value
        if not matches:
            _fail(f"drift prior {key} does not match the retained prior run")
    if _sha256_bytes(frame_bytes) != current["frame_digest_sha256"]:
        _fail("drift prior frame digest does not match the comparison contract")
    if len(canonical_frame_rows(frame_bytes)) != current["frame_count"]:
        _fail("drift prior frame count does not match the comparison contract")
    if current["catalog_digest_sha256"] != catalog_digest_sha256():
        _fail("drift contract catalog digest does not match the current catalog")
    if current["execution_digest_sha256"] != execution_digest_sha256():
        _fail("drift contract execution digest does not match the current implementation")
    return contract


def write_drift_contract(
    prior_run: Path,
    round_manifest_path: Path,
    output_path: Path,
    *,
    prepared_at: str | None = None,
) -> dict[str, Any]:
    """Write one immutable private drift comparison contract."""
    resolved_output = _private_path(output_path)
    if resolved_output.exists():
        _fail("drift contract already exists; refusing to replace it")
    _, contract = build_drift_contract(prior_run, round_manifest_path, prepared_at=prepared_at)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(resolved_output, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(contract, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except BaseException:
        resolved_output.unlink(missing_ok=True)
        raise
    return contract


def write_prior_frame(prior_run: Path, output_path: Path) -> dict[str, Any]:
    """Write the canonical eligible prior frame without printing identifiers."""
    resolved_output = _private_path(output_path)
    if resolved_output.exists():
        _fail("prior drift frame already exists; refusing to replace it")
    frame, metadata = derive_prior_frame(prior_run)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(resolved_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(frame)
    except BaseException:
        resolved_output.unlink(missing_ok=True)
        raise
    return {
        "prior_round_kind": metadata["round_kind"],
        "prior_collected_at": metadata["collected_at"],
        "prior_results_digest_sha256": metadata["results_digest_sha256"],
        "prior_catalog_digest_sha256": metadata["catalog_digest_sha256"],
        "prior_records_total": metadata["records_total"],
        "frame_count": metadata["eligible_records"],
        "excluded_error_records": metadata["excluded_error_records"],
        "frame_digest_sha256": _sha256_bytes(frame),
    }


def public_drift_commitments(contract: dict[str, Any]) -> dict[str, Any]:
    """Return the identifier-free commitments suitable for a public declaration."""
    prior = contract["prior"]
    current = contract["current"]
    return {
        "schema_version": contract["schema_version"],
        "prior_round_kind": prior["round_kind"],
        "prior_collected_at": prior["collected_at"],
        "prior_code_revision": prior["code_revision"],
        "prior_results_digest_sha256": prior["results_digest_sha256"],
        "prior_catalog_digest_sha256": prior["catalog_digest_sha256"],
        "prior_execution_digest_sha256": prior["execution_digest_sha256"],
        "prior_records_total": prior["records_total"],
        "frame_count": prior["eligible_records"],
        "excluded_error_records": prior["excluded_error_records"],
        "ct_enabled": prior["ct_enabled"],
        "concurrency": prior["concurrency"],
        "frame_digest_sha256": current["frame_digest_sha256"],
        "round_manifest_digest_sha256": current["round_manifest_digest_sha256"],
        "current_catalog_digest_sha256": current["catalog_digest_sha256"],
        "current_execution_digest_sha256": current["execution_digest_sha256"],
        "observation_fields": contract["comparison"]["observation_fields"],
        "outcome_precedence": contract["comparison"]["outcome_precedence"],
        "classification_comparison": contract["comparison"]["classification_comparison"],
        "contract_digest_sha256": contract["contract_digest_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-run", type=Path, required=True)
    parser.add_argument("--round-manifest", type=Path)
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output", type=Path, help="Write the frozen private comparison contract.")
    outputs.add_argument("--output-frame", type=Path, help="Extract the canonical eligible prior frame only.")
    parser.add_argument("--public", action="store_true", help="Print identifier-free commitments only.")
    args = parser.parse_args()
    if args.output_frame is not None:
        public = write_prior_frame(args.prior_run, args.output_frame)
        if args.public:
            print(json.dumps(public, indent=2, sort_keys=True))
        return 0
    if args.round_manifest is None:
        parser.error("--round-manifest is required with --output")
    contract = write_drift_contract(args.prior_run, args.round_manifest, args.output)
    if args.public:
        print(json.dumps(public_drift_commitments(contract), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
