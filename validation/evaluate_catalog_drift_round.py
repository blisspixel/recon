"""Reduce a frozen catalog drift comparison to disclosure-safe aggregates."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from validation import catalog_baseline
from validation.prepare_catalog_drift_round import (
    OBSERVATION_FIELDS,
    OUTCOME_PRECEDENCE,
    PRIVATE_ROOTS,
    REPO_ROOT,
    load_drift_contract,
    public_drift_commitments,
    verify_drift_contract,
)
from validation.prepare_catalog_round import load_round_frame_rows, load_round_manifest
from validation.run_path_safety import validate_private_output_root

SCHEMA_VERSION = 1
_MEASURED = frozenset({"available", "partial"})


@dataclass(frozen=True)
class _DriftInputs:
    contract: dict[str, Any]
    manifest: dict[str, Any]
    expected: set[str]
    prior_records: dict[str, dict[str, Any]]
    current_records: dict[str, dict[str, Any]]
    current_results_path: Path
    maximum_regression: float


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _private_path(path: Path) -> Path:
    return validate_private_output_root(path, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)


def _results_path(run: Path) -> Path:
    resolved = _private_path(run)
    if resolved.is_file():
        return resolved
    for filename in ("results.ndjson", "results.json"):
        candidate = resolved / filename
        if candidate.is_file():
            return candidate
    _fail("drift result path has no results.ndjson or results.json")


def _result_digest(path: Path) -> str:
    return catalog_baseline.digest_result_files(catalog_baseline.result_files(path))


def _records_by_namespace(path: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(catalog_baseline.iter_result_records(path), start=1):
        field = "domain" if record.get("record_type") == "error" else "queried_domain"
        namespace = record.get(field)
        if not isinstance(namespace, str) or not namespace:
            _fail(f"drift result row {index} has no namespace identity")
        if namespace in records:
            _fail("drift result contains a duplicate namespace")
        records[namespace] = record
    return records


def _summary_by_type(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    summaries = record.get("dns_catalog_summary")
    if not isinstance(summaries, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in summaries:
        if not isinstance(row, dict):
            continue
        record_type = row.get("record_type")
        if isinstance(record_type, str) and record_type in catalog_baseline.RECORD_TYPES:
            if record_type in result:
                _fail("drift result contains duplicate catalog summary types")
            result[record_type] = row
    return result


def _availability(row: dict[str, Any] | None) -> str:
    if row is None:
        return "unmeasured"
    value = row.get("availability")
    return value if isinstance(value, str) and value in {*_MEASURED, "unavailable", "unmeasured"} else "unmeasured"


def _observation_signature(row: dict[str, Any]) -> tuple[object, ...]:
    values: list[object] = []
    for field in OBSERVATION_FIELDS:
        value = row.get(field)
        if field in {"opportunity_count", "observed_count"}:
            value = value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        elif field == "truncated":
            value = bool(value)
        values.append(value)
    return tuple(values)


def _outcome(before: dict[str, Any] | None, after: dict[str, Any] | None) -> str:
    before_availability = _availability(before)
    after_availability = _availability(after)
    if before_availability not in _MEASURED or after_availability == "unmeasured":
        return "unmeasured"
    if after_availability == "unavailable":
        return "unavailable"
    if after is None or before is None:
        return "unmeasured"
    if _observation_signature(before) != _observation_signature(after):
        return "changed"
    return "no_change"


def _nonnegative_int(row: dict[str, Any] | None, field: str) -> int:
    if row is None:
        return 0
    value = row.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _highest_precedence(outcomes: list[str]) -> str:
    for outcome in OUTCOME_PRECEDENCE:
        if outcome in outcomes:
            return outcome
    _fail("drift comparison produced no namespace outcome")


def _slugs(record: dict[str, Any]) -> set[str]:
    values = record.get("slugs")
    return {value for value in values if isinstance(value, str)} if isinstance(values, list) else set()


def _load_after_aggregate(after_run: Path, results_path: Path) -> dict[str, Any]:
    aggregate_path = (
        after_run / "catalog-aggregate.json" if after_run.is_dir() else results_path.parent / "catalog-aggregate.json"
    )
    if not aggregate_path.is_file():
        _fail("drift run has no catalog-aggregate.json")
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("drift run aggregate must be readable UTF-8 JSON") from exc
    if not isinstance(aggregate, dict) or aggregate.get("round_kind") != "drift":
        _fail("drift run aggregate is missing or has the wrong round kind")
    if aggregate.get("results_digest_sha256") != _result_digest(results_path):
        _fail("drift run aggregate result digest does not match its result rows")
    return aggregate


def _load_drift_inputs(contract_path: Path, after_run: Path) -> _DriftInputs:
    frozen = load_drift_contract(contract_path)
    contract = verify_drift_contract(
        contract_path,
        round_manifest_path=Path(frozen["current"]["round_manifest_path"]),
        compare_to=Path(frozen["prior"]["run_path"]),
    )
    prior = contract["prior"]
    current = contract["current"]
    manifest = load_round_manifest(Path(current["round_manifest_path"]))
    expected = set(load_round_frame_rows(manifest))
    prior_records = {
        key: value for key, value in _records_by_namespace(Path(prior["results_path"])).items() if key in expected
    }
    current_results_path = _results_path(after_run)
    current_records = _records_by_namespace(current_results_path)
    if set(prior_records) != expected:
        _fail("eligible prior rows do not exactly match the frozen drift frame")
    if set(current_records) != expected:
        _fail("current drift rows do not exactly match the frozen drift frame")

    after_aggregate = _load_after_aggregate(_private_path(after_run), current_results_path)
    round_contract = after_aggregate.get("round_contract")
    if (
        not isinstance(round_contract, dict)
        or round_contract.get("manifest_digest_sha256") != current["round_manifest_digest_sha256"]
    ):
        _fail("drift run aggregate does not match the frozen round manifest")

    promotion_budget = manifest.get("promotion_budget")
    if not isinstance(promotion_budget, dict):
        _fail("drift manifest has no promotion budget")
    maximum_regression = promotion_budget.get("maximum_regression")
    if not isinstance(maximum_regression, (int, float)) or isinstance(maximum_regression, bool):
        _fail("drift manifest has an invalid regression budget")
    return _DriftInputs(
        contract=contract,
        manifest=manifest,
        expected=expected,
        prior_records=prior_records,
        current_records=current_records,
        current_results_path=current_results_path,
        maximum_regression=float(maximum_regression),
    )


def _empty_type_counters() -> dict[str, Counter[str]]:
    return {record_type: Counter() for record_type in catalog_baseline.RECORD_TYPES}


def _empty_outcome_counter() -> Counter[str]:
    counts: Counter[str] = Counter()
    for outcome in OUTCOME_PRECEDENCE:
        counts[outcome] = 0
    return counts


def _accumulate_observation_outcomes(
    inputs: _DriftInputs,
) -> tuple[dict[str, Counter[str]], dict[str, Counter[str]], dict[str, Counter[str]], Counter[str]]:
    type_outcomes = {record_type: _empty_outcome_counter() for record_type in catalog_baseline.RECORD_TYPES}
    before_totals = _empty_type_counters()
    after_totals = _empty_type_counters()
    namespace_outcomes = _empty_outcome_counter()
    for namespace in sorted(inputs.expected):
        before_summaries = _summary_by_type(inputs.prior_records[namespace])
        current_record = inputs.current_records[namespace]
        after_summaries = {} if current_record.get("record_type") == "error" else _summary_by_type(current_record)
        row_outcomes: list[str] = []
        for record_type in catalog_baseline.RECORD_TYPES:
            before_row = before_summaries.get(record_type)
            after_row = after_summaries.get(record_type)
            outcome = _outcome(before_row, after_row)
            type_outcomes[record_type][outcome] += 1
            row_outcomes.append(outcome)
            for field in ("opportunity_count", "observed_count"):
                before_totals[record_type][field] += _nonnegative_int(before_row, field)
                after_totals[record_type][field] += _nonnegative_int(after_row, field)
            before_totals[record_type]["partial"] += int(_availability(before_row) == "partial")
            after_totals[record_type]["partial"] += int(_availability(after_row) == "partial")
            before_totals[record_type]["truncated"] += int(bool(before_row and before_row.get("truncated")))
            after_totals[record_type]["truncated"] += int(bool(after_row and after_row.get("truncated")))
        namespace_outcomes[_highest_precedence(row_outcomes)] += 1
    return type_outcomes, before_totals, after_totals, namespace_outcomes


def _accumulate_classification_outcomes(
    inputs: _DriftInputs,
) -> tuple[Counter[str], int, int]:
    outcomes: Counter[str] = Counter({"changed": 0, "no_change": 0, "unmeasured": 0})
    added_assignments = 0
    removed_assignments = 0
    for namespace in sorted(inputs.expected):
        before = inputs.prior_records[namespace]
        after = inputs.current_records[namespace]
        if before.get("record_type") == "error" or after.get("record_type") == "error":
            outcomes["unmeasured"] += 1
            continue
        before_slugs = _slugs(before)
        after_slugs = _slugs(after)
        if before_slugs == after_slugs:
            outcomes["no_change"] += 1
            continue
        outcomes["changed"] += 1
        added_assignments += len(after_slugs - before_slugs)
        removed_assignments += len(before_slugs - after_slugs)
    return outcomes, added_assignments, removed_assignments


def _record_type_results(
    type_outcomes: dict[str, Counter[str]],
    before_totals: dict[str, Counter[str]],
    after_totals: dict[str, Counter[str]],
    maximum_regression: float,
) -> tuple[dict[str, Any], list[str]]:
    results: dict[str, Any] = {}
    regressions: list[str] = []
    delta_fields = ("opportunity_count", "observed_count", "partial", "truncated")
    for record_type in catalog_baseline.RECORD_TYPES:
        before_observed = before_totals[record_type]["observed_count"]
        after_observed = after_totals[record_type]["observed_count"]
        change_rate = round((after_observed - before_observed) / before_observed, 6) if before_observed else None
        exceeded = change_rate is not None and change_rate < -maximum_regression
        if exceeded:
            regressions.append(record_type)
        results[record_type] = {
            "outcomes": dict(type_outcomes[record_type]),
            "before": dict(before_totals[record_type]),
            "after": dict(after_totals[record_type]),
            "deltas": {
                field: after_totals[record_type][field] - before_totals[record_type][field] for field in delta_fields
            },
            "observed_count_change_rate": change_rate,
            "regression_budget_exceeded": exceeded,
        }
    return results, regressions


def _classification_result(inputs: _DriftInputs) -> dict[str, Any]:
    prior = inputs.contract["prior"]
    current = inputs.contract["current"]
    catalogs_comparable = prior["catalog_digest_sha256"] == current["catalog_digest_sha256"]
    interpretations_comparable = (
        isinstance(prior["execution_digest_sha256"], str)
        and prior["execution_digest_sha256"] == current["execution_digest_sha256"]
    )
    comparable = catalogs_comparable and interpretations_comparable
    outcomes, added, removed = (
        _accumulate_classification_outcomes(inputs)
        if comparable
        else (Counter({"changed": 0, "no_change": 0, "unmeasured": 0}), 0, 0)
    )
    status = (
        "comparable"
        if comparable
        else "not_comparable_catalog_changed"
        if not catalogs_comparable
        else "not_comparable_interpretation_changed"
    )
    return {
        "status": status,
        "prior_catalog_digest_sha256": prior["catalog_digest_sha256"],
        "current_catalog_digest_sha256": current["catalog_digest_sha256"],
        "prior_execution_digest_sha256": prior["execution_digest_sha256"],
        "current_execution_digest_sha256": current["execution_digest_sha256"],
        "namespace_outcomes": dict(outcomes) if comparable else None,
        "added_assignments": added if comparable else None,
        "removed_assignments": removed if comparable else None,
    }


def evaluate_drift_round(
    contract_path: Path,
    after_run: Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Verify both runs and return one target-free drift aggregate."""
    inputs = _load_drift_inputs(contract_path, after_run)
    type_outcomes, before_totals, after_totals, namespace_outcomes = _accumulate_observation_outcomes(inputs)
    record_types, regression_types = _record_type_results(
        type_outcomes,
        before_totals,
        after_totals,
        inputs.maximum_regression,
    )
    aggregate = {
        "schema_version": SCHEMA_VERSION,
        "aggregate_only": True,
        "round_kind": "drift",
        "generated_at": generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "commitments": public_drift_commitments(inputs.contract),
        "results": {
            "prior_results_digest_sha256": inputs.contract["prior"]["results_digest_sha256"],
            "current_results_digest_sha256": _result_digest(inputs.current_results_path),
            "frame_count": len(inputs.expected),
        },
        "namespace_outcomes": dict(namespace_outcomes),
        "record_types": record_types,
        "classification_comparison": _classification_result(inputs),
        "decision": {
            "catalog_promotion_authorized": False,
            "regression_budget_exceeded": bool(regression_types),
            "regression_record_type_count": len(regression_types),
            "review_required": bool(regression_types)
            or namespace_outcomes["changed"] > 0
            or namespace_outcomes["unavailable"] > 0
            or namespace_outcomes["unmeasured"] > 0,
        },
        "interpretation_limits": {
            "no_change_scope": "retained per-path observation summaries only",
            "causal_attribution": False,
            "independent_coverage": False,
            "population_estimate": False,
        },
    }
    catalog_baseline.assert_aggregate_safe(aggregate)
    return aggregate


def write_drift_aggregate(contract_path: Path, after_run: Path, output_path: Path) -> dict[str, Any]:
    """Write one immutable disclosure-safe drift aggregate."""
    resolved_output = _private_path(output_path)
    if resolved_output.exists():
        _fail("drift aggregate already exists; refusing to replace it")
    aggregate = evaluate_drift_round(contract_path, after_run)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(resolved_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(aggregate, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except BaseException:
        resolved_output.unlink(missing_ok=True)
        raise
    return aggregate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    aggregate = write_drift_aggregate(args.contract, args.after, args.output)
    print(
        "drift aggregate: "
        f"{aggregate['results']['frame_count']} rows, "
        f"{aggregate['namespace_outcomes']['changed']} changed, "
        f"{aggregate['namespace_outcomes']['unavailable']} unavailable, "
        f"{aggregate['namespace_outcomes']['unmeasured']} unmeasured"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
