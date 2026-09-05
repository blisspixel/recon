"""Evaluate additive catalog rules against one frozen observation set.

Live replay checks whether a complete collection still works with the proposed
catalog. This evaluator answers the separate fixed-observation question: how would the
specified candidate rules classify the exact observations retained by the
baseline run? It reads only the private, already collected diagnostics and
emits aggregate counts and commitments. It performs no network requests.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from recon_tool.fingerprints import DetectionRule, load_builtin_fingerprints  # noqa: E402
from recon_tool.validator import host_has_suffix, is_domain_shaped  # noqa: E402
from validation import catalog_baseline  # noqa: E402
from validation.prepare_catalog_round import (  # noqa: E402
    catalog_digest_sha256,
    load_round_manifest,
    load_round_membership,
)
from validation.ranked_sampling import bounded_stable_read  # noqa: E402
from validation.run_path_safety import validate_private_output_root  # noqa: E402
from validation.stratify_catalog_round import partition_round_records  # noqa: E402

SCHEMA_VERSION = "1.0"
SUPPORTED_TYPES = frozenset({"cname_target", "mx", "ns", "spf"})
PRIVATE_OUTPUT_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
_MAX_POOLED_AGGREGATE_BYTES = 32 * 1024 * 1024
_MIN_PUBLIC_STRATUM_ROWS = 20
_DNS_PATTERN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9])?$", re.ASCII)


@dataclass(frozen=True, slots=True)
class CandidateRule:
    """One referenced, dated rule selected for counterfactual evaluation."""

    slug: str
    record_type: str
    pattern: str


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_candidate_rules(slugs: Sequence[str]) -> tuple[CandidateRule, ...]:
    """Load exact supported built-in rules for a unique, non-empty selection.

    Operator-local and ephemeral rules do not belong to the reviewed source
    catalog committed by the report. Whole-fingerprint conjunctions cannot be
    evaluated from individual retained unclassified observations, so reject
    them instead of reporting a partial rule match as promotion acceptance.
    """
    requested = tuple(slugs)
    if not requested or any(not slug for slug in requested):
        _fail("at least one non-empty candidate slug is required")
    if len(requested) != len(set(requested)):
        _fail("candidate slugs must be unique")

    found: set[str] = set()
    rules: list[CandidateRule] = []
    for fingerprint in load_builtin_fingerprints():
        if fingerprint.slug not in requested:
            continue
        if fingerprint.match_mode != "any":
            _fail(f"candidate {fingerprint.slug} uses unsupported counterfactual match_mode {fingerprint.match_mode}")
        found.add(fingerprint.slug)
        for rule in fingerprint.detections:
            _validate_candidate_rule(fingerprint.slug, rule)
            rules.append(CandidateRule(fingerprint.slug, rule.type, rule.pattern.lower().rstrip(".")))
    missing = sorted(set(requested) - found)
    if missing:
        _fail(f"candidate slugs are absent from the current catalog: {', '.join(missing)}")
    if not rules:
        _fail("candidate selection contains no rules")
    return tuple(sorted(set(rules), key=lambda item: (item.record_type, -len(item.pattern), item.slug, item.pattern)))


def _candidate_rules_digest(rules: Sequence[CandidateRule]) -> str:
    """Commit the exact evaluated rules independently of canonical YAML bytes."""
    canonical = sorted(set(rules), key=lambda item: (item.slug, item.record_type, item.pattern))
    raw = json.dumps([asdict(rule) for rule in canonical], sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _validate_candidate_rule(slug: str, rule: DetectionRule) -> None:
    if rule.type not in SUPPORTED_TYPES:
        _fail(f"candidate {slug} uses unsupported counterfactual record type {rule.type}")
    if not is_domain_shaped(rule.pattern) and _DNS_PATTERN_RE.fullmatch(rule.pattern) is None:
        _fail(f"candidate {slug} must use a DNS-label suffix pattern")
    if not rule.reference.startswith("https://"):
        _fail(f"candidate {slug} has no HTTPS reference")
    if not rule.verified:
        _fail(f"candidate {slug} has no review date")


def _matched_slugs(record_type: str, value: str, rules: Sequence[CandidateRule]) -> frozenset[str]:
    host = value.strip().lower().split()[-1].rstrip(".") if value.strip() else ""
    if not host:
        return frozenset()
    matching = [rule for rule in rules if rule.record_type == record_type and host_has_suffix(host, rule.pattern)]
    if not matching:
        return frozenset()
    if record_type == "spf":
        return frozenset(rule.slug for rule in matching)
    longest = max(len(rule.pattern) for rule in matching)
    return frozenset(rule.slug for rule in matching if len(rule.pattern) == longest)


def _added_counts(
    records: Sequence[Mapping[str, Any]],
    rules: Sequence[CandidateRule],
) -> tuple[Counter[str], Counter[tuple[str, str]]]:
    by_type: Counter[str] = Counter()
    by_rule: Counter[tuple[str, str]] = Counter()
    for record in records:
        observations = record.get("unclassified_dns_observations")
        if not isinstance(observations, list):
            continue
        seen: set[tuple[str, str, str]] = set()
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            raw_record_type = observation.get("record_type")
            raw_owner = observation.get("owner")
            raw_value = observation.get("value")
            if not isinstance(raw_record_type, str) or not isinstance(raw_owner, str) or not isinstance(raw_value, str):
                continue
            record_type, owner, value = raw_record_type, raw_owner, raw_value
            identity = (record_type, owner, value)
            if identity in seen:
                continue
            seen.add(identity)
            matched = _matched_slugs(record_type, value, rules)
            if not matched:
                continue
            by_type[record_type] += 1
            for slug in matched:
                by_rule[(slug, record_type)] += 1
    return by_type, by_rule


def _rate(classified: int, observed: int) -> float | None:
    return round(classified / observed, 6) if observed else None


def _type_rows(
    baseline: Mapping[str, Any],
    added: Mapping[str, int],
    *,
    minimum_improvement: float,
    maximum_regression: float,
) -> dict[str, dict[str, Any]]:
    baseline_types = baseline.get("record_types")
    if not isinstance(baseline_types, dict):
        _fail("baseline aggregate has no typed accounting")
    rows: dict[str, dict[str, Any]] = {}
    for record_type in catalog_baseline.RECORD_TYPES:
        before = baseline_types.get(record_type)
        if not isinstance(before, dict):
            _fail(f"baseline aggregate is missing {record_type} accounting")
        observed = int(before.get("observed_count", 0))
        classified = int(before.get("classified_count", 0))
        uplift = int(added.get(record_type, 0))
        if uplift < 0 or classified + uplift > observed:
            _fail(f"counterfactual {record_type} classified count exceeds retained observations")
        before_rate = _rate(classified, observed)
        after_rate = _rate(classified + uplift, observed)
        # Decide from the retained counts, not rounded presentation values.
        # Subtracting rounded rates can move an uplift across a frozen gate.
        exact_delta = uplift / observed if observed else 0.0
        delta = round(exact_delta, 6)
        affected = uplift > 0
        rows[record_type] = {
            "baseline_observed_count": observed,
            "baseline_classified_count": classified,
            "counterfactual_added_classified": uplift,
            "counterfactual_classified_count": classified + uplift,
            "baseline_classified_rate": before_rate,
            "counterfactual_classified_rate": after_rate,
            "classified_rate_delta": delta,
            "affected": affected,
            "meets_minimum_improvement": not affected or exact_delta >= minimum_improvement,
            "within_regression_budget": exact_delta >= -maximum_regression,
        }
    return rows


def evaluate_partitioned_records(
    records_by_stratum: Sequence[Sequence[dict[str, Any]]],
    rules: Sequence[CandidateRule],
    *,
    min_count: int,
    min_distinct_namespaces: int,
    minimum_improvement: float,
    maximum_regression: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate candidate rules against fixed observations by stratum and pooled."""
    strata: list[dict[str, Any]] = []
    pooled_records: list[dict[str, Any]] = []
    pooled_by_rule: Counter[tuple[str, str]] = Counter()
    for stratum_index, stratum_records in enumerate(records_by_stratum):
        records = list(stratum_records)
        pooled_records.extend(records)
        baseline, _ = catalog_baseline.aggregate_records(
            records,
            min_count=min_count,
            min_distinct_namespaces=min_distinct_namespaces,
            max_samples=0,
        )
        by_type, by_rule = _added_counts(records, rules)
        pooled_by_rule.update(by_rule)
        strata.append(
            {
                "stratum_index": stratum_index,
                "records_total": len(records),
                "record_types": _type_rows(
                    baseline,
                    by_type,
                    minimum_improvement=minimum_improvement,
                    maximum_regression=maximum_regression,
                ),
            }
        )

    pooled_baseline, _ = catalog_baseline.aggregate_records(
        pooled_records,
        min_count=min_count,
        min_distinct_namespaces=min_distinct_namespaces,
        max_samples=0,
    )
    pooled_by_type, _ = _added_counts(pooled_records, rules)
    pooled_types = _type_rows(
        pooled_baseline,
        pooled_by_type,
        minimum_improvement=minimum_improvement,
        maximum_regression=maximum_regression,
    )
    candidate_matches: list[dict[str, Any]] = [
        {"slug": slug, "record_type": record_type, "added_classified": count}
        for (slug, record_type), count in sorted(pooled_by_rule.items())
    ]
    matched_slugs = {str(row["slug"]) for row in candidate_matches if int(row["added_classified"]) > 0}
    requested_slugs = {rule.slug for rule in rules}
    decision = {
        "decision_scope": "pooled-classification-diagnostic",
        "policy_text_status": "not_evaluated",
        "candidate_match_counts": candidate_matches,
        "all_candidate_slugs_observed": matched_slugs == requested_slugs,
        "all_affected_types_meet_minimum": all(
            row["meets_minimum_improvement"] for row in pooled_types.values() if row["affected"]
        ),
        "all_types_within_regression_budget": all(row["within_regression_budget"] for row in pooled_types.values()),
    }
    decision["accepted"] = (
        bool(decision["all_candidate_slugs_observed"])
        and bool(decision["all_affected_types_meet_minimum"])
        and bool(decision["all_types_within_regression_budget"])
    )
    return strata, {"record_types": pooled_types, "decision": decision}


def _read_pooled(path: Path) -> dict[str, Any]:
    raw = bounded_stable_read(
        path.resolve(strict=False),
        maximum_bytes=_MAX_POOLED_AGGREGATE_BYTES,
        kind="pooled catalog aggregate",
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("pooled catalog aggregate must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail("pooled catalog aggregate must contain one object")
    catalog_baseline.assert_aggregate_safe(value)
    return value


def _evaluator_digest() -> str:
    paths = (
        REPO_ROOT / "validation" / "catalog_baseline.py",
        REPO_ROOT / "validation" / "evaluate_catalog_promotions.py",
        REPO_ROOT / "validation" / "prepare_catalog_round.py",
        REPO_ROOT / "validation" / "stratify_catalog_round.py",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "uv.lock",
    )
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(REPO_ROOT).as_posix().encode("utf-8")
        raw = bounded_stable_read(path, maximum_bytes=32 * 1024 * 1024, kind="evaluator input")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def evaluate_catalog_promotions(
    *,
    results_path: Path,
    round_plan_path: Path,
    round_manifest_path: Path,
    pooled_aggregate_path: Path,
    candidate_slugs: Sequence[str],
) -> dict[str, Any]:
    """Return a disclosure-safe, fixed-observation promotion evaluation."""
    manifest = load_round_manifest(round_manifest_path)
    memberships = load_round_membership(round_plan_path, manifest)
    if any(len(membership.domains) < _MIN_PUBLIC_STRATUM_ROWS for membership in memberships):
        _fail(f"public promotion output requires at least {_MIN_PUBLIC_STRATUM_ROWS} rows in every stratum")
    records_by_stratum, result_files = partition_round_records(results_path, memberships)
    results_digest = catalog_baseline.digest_result_files(result_files)
    pooled = _read_pooled(pooled_aggregate_path)
    if pooled.get("results_digest_sha256") != results_digest:
        _fail("pooled catalog aggregate does not bind the supplied results")
    if pooled.get("records_total") != sum(len(records) for records in records_by_stratum):
        _fail("pooled catalog aggregate record count does not match the supplied results")
    contract = pooled.get("round_contract")
    if not isinstance(contract, dict) or contract.get("manifest_digest_sha256") != manifest.get(
        "manifest_digest_sha256"
    ):
        _fail("pooled catalog aggregate does not bind the frozen round manifest")

    thresholds = cast(dict[str, int], manifest["thresholds"])
    budget = cast(dict[str, float], manifest["promotion_budget"])
    rules = load_candidate_rules(candidate_slugs)
    strata, pooled_result = evaluate_partitioned_records(
        records_by_stratum,
        rules,
        min_count=int(thresholds["minimum_occurrences"]),
        min_distinct_namespaces=int(thresholds["minimum_distinct_namespaces"]),
        minimum_improvement=float(budget["minimum_improvement"]),
        maximum_regression=float(budget["maximum_regression"]),
    )
    revision, dirty = catalog_baseline.repository_revision()
    public = {
        "schema_version": SCHEMA_VERSION,
        "aggregate_only": True,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "method": "fixed-observation-additive-counterfactual-v1",
        "records_total": sum(len(records) for records in records_by_stratum),
        "results_digest_sha256": results_digest,
        "round_contract": catalog_baseline.public_round_contract(cast(dict[str, Any], manifest)),
        "candidate_catalog_digest_sha256": catalog_digest_sha256(),
        "candidate_rules_digest_sha256": _candidate_rules_digest(rules),
        "evaluator": {
            "code_revision": revision,
            "working_tree_dirty": dirty,
            "digest_sha256": _evaluator_digest(),
            "network_requests": 0,
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "strata": strata,
        "pooled": pooled_result,
    }
    catalog_baseline.assert_aggregate_safe(public)
    return public


def _write_output(path: Path, public: Mapping[str, Any]) -> None:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_OUTPUT_ROOTS)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("promotion evaluation output already exists; refusing to replace it") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(public, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        with contextlib.suppress(OSError):
            resolved.unlink()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Private baseline result file or run directory.")
    parser.add_argument("--round-plan", required=True, type=Path, help="Original frozen private round plan.")
    parser.add_argument("--round-manifest", required=True, type=Path, help="Original frozen private round manifest.")
    parser.add_argument("--pooled-aggregate", required=True, type=Path, help="Baseline pooled aggregate.")
    parser.add_argument("--candidate-slug", action="append", required=True, help="Current candidate slug; repeatable.")
    parser.add_argument("--output", required=True, type=Path, help="Exclusive aggregate output in a private workspace.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        public = evaluate_catalog_promotions(
            results_path=args.input,
            round_plan_path=args.round_plan,
            round_manifest_path=args.round_manifest,
            pooled_aggregate_path=args.pooled_aggregate,
            candidate_slugs=args.candidate_slug,
        )
        _write_output(args.output, public)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "records_total": public["records_total"],
                "accepted": public["pooled"]["decision"]["accepted"],
                "decision_scope": public["pooled"]["decision"]["decision_scope"],
                "policy_text_status": public["pooled"]["decision"]["policy_text_status"],
                "results_digest_sha256": public["results_digest_sha256"],
                "evaluator_digest_sha256": public["evaluator"]["digest_sha256"],
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
