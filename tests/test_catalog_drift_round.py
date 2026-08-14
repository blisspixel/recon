"""Tests for the fail-closed prior-sample catalog drift protocol."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from validation import catalog_baseline
from validation import evaluate_catalog_drift_round as evaluator
from validation import prepare_catalog_drift_round as drift
from validation.prepare_catalog_round import (
    SCHEMA_VERSION as ROUND_SCHEMA_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]
from validation.prepare_catalog_round import (
    canonical_json_digest,
    catalog_digest_sha256,
    digest_bytes,
    execution_digest_sha256,
)


def _summary(*, changed_type: str | None = None, unavailable_type: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record_type in catalog_baseline.RECORD_TYPES:
        unavailable = record_type == unavailable_type
        changed = record_type == changed_type
        rows.append(
            {
                "record_type": record_type,
                "availability": "unavailable" if unavailable else "available",
                "opportunity_count": 0 if unavailable else 1,
                "observed_count": 0 if unavailable else 2 if changed else 1,
                "classified_count": 0 if unavailable else 1,
                "unclassified_count": 0 if unavailable else int(changed),
                "truncated": False,
            }
        )
    return rows


def _write_prior_run(
    tmp_path: Path,
    *,
    prior_catalog: str = "0" * 64,
    prior_execution: str | None = None,
) -> Path:
    run = tmp_path / "prior"
    run.mkdir()
    results = run / "results.ndjson"
    records = [
        {"queried_domain": "alpha.invalid", "dns_catalog_summary": _summary(), "record_type": "tenant_info"},
        {"queried_domain": "beta.invalid", "dns_catalog_summary": _summary(), "record_type": "tenant_info"},
        {"domain": "bad input", "record_type": "error", "error_kind": "validation"},
    ]
    results.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    result_digest = catalog_baseline.digest_result_files([results])
    (run / "catalog-aggregate.json").write_text(
        json.dumps(
            {
                "round_kind": "baseline",
                "records_total": 3,
                "error_records": 1,
                "results_digest_sha256": result_digest,
                "catalog": {"digest_sha256": prior_catalog},
                "code_revision": "1" * 40,
                "round_contract": {"implementation": {"execution_digest_sha256": prior_execution}}
                if prior_execution is not None
                else None,
            }
        ),
        encoding="utf-8",
    )
    (run / "meta.json").write_text(
        json.dumps(
            {
                "batch_completed": True,
                "batch_timed_out": False,
                "ct_enabled": False,
                "concurrency": 4,
                "scan_started_utc": "2026-07-17T20:27:53Z",
                "round_kind": "baseline",
            }
        ),
        encoding="utf-8",
    )
    return run


def _write_round_manifest(tmp_path: Path, frame: bytes) -> Path:
    frame_path = tmp_path / "frame.txt"
    frame_path.write_bytes(frame)
    manifest: dict[str, Any] = {
        "schema_version": ROUND_SCHEMA_VERSION,
        "private": True,
        "round_id": "catalog-drift-2026-08",
        "round_kind": "drift",
        "question": "Which retained bounded-path observation summaries changed since the prior sample?",
        "prepared_at": "2026-08-14T04:00:00Z",
        "source": {"name": "prior frozen sample", "revision": "2026-07-17", "digest_sha256": "2" * 64},
        "frame": {
            "path": str(frame_path.resolve()),
            "digest_sha256": digest_bytes(frame),
            "count": 2,
        },
        "strata": [{"id": "prior", "label": "prior measured sample", "count": 2}],
        "policies": {
            "exclusions": "Exclude historical validation-error rows before re-observation.",
            "overlap": "reject",
        },
        "collection": {"ct_enabled": False, "direct_probes_enabled": False},
        "thresholds": {"minimum_occurrences": 3, "minimum_distinct_namespaces": 2},
        "promotion_budget": {
            "metric": "observed count by bounded record type",
            "minimum_improvement": 0.01,
            "maximum_regression": 0.01,
            "decision_rule": "Do not promote from drift; review any observed-count decline beyond one percent.",
        },
        "implementation": {
            "catalog_digest_sha256": catalog_digest_sha256(),
            "execution_digest_sha256": execution_digest_sha256(),
        },
        "plan_digest_sha256": "3" * 64,
    }
    manifest["manifest_digest_sha256"] = canonical_json_digest(manifest)
    path = tmp_path / "round-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _write_contract(
    tmp_path: Path,
    *,
    prior_catalog: str = "0" * 64,
    prior_execution: str | None = None,
) -> tuple[Path, Path, Path]:
    prior = _write_prior_run(tmp_path, prior_catalog=prior_catalog, prior_execution=prior_execution)
    frame, metadata = drift.derive_prior_frame(prior)
    assert metadata["eligible_records"] == 2
    manifest = _write_round_manifest(tmp_path, frame)
    contract_path = tmp_path / "drift-contract.json"
    drift.write_drift_contract(
        prior,
        manifest,
        contract_path,
        prepared_at="2026-08-14T04:05:00Z",
    )
    return prior, manifest, contract_path


def _write_after_run(tmp_path: Path, manifest_path: Path) -> Path:
    run = tmp_path / "after"
    run.mkdir()
    results = run / "results.ndjson"
    records = [
        {
            "queried_domain": "alpha.invalid",
            "dns_catalog_summary": _summary(changed_type="txt"),
            "record_type": "tenant_info",
        },
        {
            "queried_domain": "beta.invalid",
            "dns_catalog_summary": _summary(unavailable_type="mx"),
            "record_type": "tenant_info",
        },
    ]
    results.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (run / "catalog-aggregate.json").write_text(
        json.dumps(
            {
                "round_kind": "drift",
                "results_digest_sha256": catalog_baseline.digest_result_files([results]),
                "round_contract": {"manifest_digest_sha256": manifest["manifest_digest_sha256"]},
            }
        ),
        encoding="utf-8",
    )
    return run


def test_contract_binds_prior_frame_and_public_commitments(tmp_path: Path) -> None:
    prior, manifest, contract_path = _write_contract(tmp_path)

    contract = drift.verify_drift_contract(
        contract_path,
        round_manifest_path=manifest,
        compare_to=prior,
    )
    public = drift.public_drift_commitments(contract)

    assert public["prior_records_total"] == 3
    assert public["frame_count"] == 2
    assert public["excluded_error_records"] == 1
    assert public["observation_fields"] == list(drift.OBSERVATION_FIELDS)
    assert all("path" not in key for key in public)
    assert "alpha.invalid" not in json.dumps(public)


def test_prior_frame_writer_is_exclusive_and_returns_only_safe_metadata(tmp_path: Path) -> None:
    prior = _write_prior_run(tmp_path)
    frame_path = tmp_path / "prior-frame.txt"

    public = drift.write_prior_frame(prior, frame_path)

    assert frame_path.read_bytes() == b"alpha.invalid\nbeta.invalid\n"
    assert public["frame_count"] == 2
    assert public["excluded_error_records"] == 1
    assert "alpha.invalid" not in json.dumps(public)
    with pytest.raises(ValueError, match="already exists"):
        drift.write_prior_frame(prior, frame_path)


def test_contract_rejects_wrong_prior_and_retained_result_mutation(tmp_path: Path) -> None:
    prior, manifest, contract_path = _write_contract(tmp_path)
    wrong = tmp_path / "wrong"
    wrong.mkdir()

    with pytest.raises(ValueError, match="compare-to path"):
        drift.verify_drift_contract(contract_path, round_manifest_path=manifest, compare_to=wrong)

    with (prior / "results.ndjson").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"queried_domain": "gamma.invalid", "dns_catalog_summary": _summary()}) + "\n")
    with pytest.raises(ValueError, match=r"record accounting|result digest"):
        drift.verify_drift_contract(contract_path, round_manifest_path=manifest, compare_to=prior)


def test_evaluator_separates_changed_unavailable_and_catalog_interpretation(tmp_path: Path) -> None:
    _, manifest, contract_path = _write_contract(tmp_path)
    after = _write_after_run(tmp_path, manifest)

    aggregate = evaluator.evaluate_drift_round(
        contract_path,
        after,
        generated_at="2026-08-14T05:00:00Z",
    )

    catalog_baseline.assert_aggregate_safe(aggregate)
    assert aggregate["namespace_outcomes"] == {
        "unmeasured": 0,
        "unavailable": 1,
        "changed": 1,
        "no_change": 0,
    }
    assert aggregate["record_types"]["txt"]["outcomes"]["changed"] == 1
    assert aggregate["record_types"]["mx"]["outcomes"]["unavailable"] == 1
    assert aggregate["classification_comparison"]["status"] == "not_comparable_catalog_changed"
    assert aggregate["classification_comparison"]["namespace_outcomes"] is None
    assert aggregate["decision"]["catalog_promotion_authorized"] is False
    assert aggregate["decision"]["review_required"] is True
    assert aggregate["interpretation_limits"]["independent_coverage"] is False


def test_evaluator_rejects_incomplete_after_frame(tmp_path: Path) -> None:
    _, manifest, contract_path = _write_contract(tmp_path)
    after = _write_after_run(tmp_path, manifest)
    lines = (after / "results.ndjson").read_text(encoding="utf-8").splitlines()
    (after / "results.ndjson").write_text(lines[0] + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exactly match the frozen drift frame"):
        evaluator.evaluate_drift_round(contract_path, after)


def test_evaluator_compares_classifications_only_under_equal_catalog_digest(tmp_path: Path) -> None:
    _, manifest, contract_path = _write_contract(
        tmp_path,
        prior_catalog=catalog_digest_sha256(),
        prior_execution=execution_digest_sha256(),
    )
    after = _write_after_run(tmp_path, manifest)

    aggregate = evaluator.evaluate_drift_round(contract_path, after)

    comparison = aggregate["classification_comparison"]
    assert comparison["status"] == "comparable"
    assert comparison["namespace_outcomes"] == {"changed": 0, "no_change": 2, "unmeasured": 0}
    assert comparison["added_assignments"] == 0
    assert comparison["removed_assignments"] == 0


def test_evaluator_withholds_classification_when_interpretation_digest_is_missing(tmp_path: Path) -> None:
    _, manifest, contract_path = _write_contract(tmp_path, prior_catalog=catalog_digest_sha256())
    after = _write_after_run(tmp_path, manifest)

    comparison = evaluator.evaluate_drift_round(contract_path, after)["classification_comparison"]

    assert comparison["status"] == "not_comparable_interpretation_changed"
    assert comparison["namespace_outcomes"] is None


def test_scan_cli_requires_explicit_prior_contract_and_compare() -> None:
    from validation import scan

    args = argparse.Namespace(
        finalize_existing=None,
        ct_retry_from=None,
        timeout=10.0,
        max_runtime=None,
        json_array=False,
        round_kind="drift",
        round_manifest=Path("manifest.json"),
        drift_prior_contract=None,
        compare_to=None,
        no_compare=False,
    )
    with pytest.raises(ValueError, match="drift-prior-contract"):
        scan._validate_cli_options(args)

    args.drift_prior_contract = Path("prior-contract.json")
    with pytest.raises(ValueError, match="explicit --compare-to"):
        scan._validate_cli_options(args)


def test_non_drift_round_rejects_prior_contract() -> None:
    from validation import scan

    args = argparse.Namespace(
        finalize_existing=None,
        ct_retry_from=None,
        timeout=10.0,
        max_runtime=None,
        json_array=False,
        round_kind="rank",
        round_manifest=Path("manifest.json"),
        drift_prior_contract=Path("prior-contract.json"),
        compare_to=None,
        no_compare=False,
    )
    with pytest.raises(ValueError, match="only for 'drift'"):
        scan._validate_cli_options(args)


def test_public_declaration_pins_frozen_contract_and_active_docs() -> None:
    declaration = (ROOT / "docs" / "catalog-drift-round-declaration.md").read_text(encoding="utf-8")
    validation_readme = (ROOT / "validation" / "README.md").read_text(encoding="utf-8")
    active_docs = [
        (ROOT / "ROADMAP.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "catalog-strategy.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "strategic-gap-audit.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "engineering-refinement-plan.md").read_text(encoding="utf-8"),
    ]

    assert "5,199" in declaration
    assert "39655fc31713302803d37a17345f30f3b2a8253da082e3c47509db25e16db7ed" in declaration
    assert "75592b94714d418b1512a2ec89cd9d6ac5efbfac51b4704976597d4d9ed81b78" in declaration
    assert "5e08515cd9a0c36d3dd147b572e84e3eb4a03bfdcbab02a4a1c4da81913708e3" in declaration
    assert "only when both the catalog and" in declaration
    assert "--drift-prior-contract" in validation_readme
    assert "--compare-to" in validation_readme
    for document in active_docs:
        assert "5,199" in document
        assert "protected main" in document
