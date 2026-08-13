"""Tests for disclosure-safe, membership-bound catalog stratification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from validation import catalog_baseline, stratify_catalog_round
from validation.prepare_catalog_round import SCHEMA_VERSION, prepare_catalog_round


def _fixture(tmp_path: Path, *, rows_per_stratum: int = 20) -> tuple[Path, Path, Path, Path, list[str]]:
    private = tmp_path / "private"
    private.mkdir(parents=True)
    domains = [f"private-member-{index}.invalid" for index in range(rows_per_stratum * 4)]
    strata = []
    for index in range(4):
        source = private / f"stratum-{index}.txt"
        start = index * rows_per_stratum
        source.write_text("\n".join(domains[start : start + rows_per_stratum]) + "\n", encoding="utf-8")
        strata.append(
            {
                "id": f"private-stratum-{index}",
                "label": f"Private stratum label {index}",
                "input": source.name,
            }
        )
    plan = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "round_id": "private-stratified-round",
        "round_kind": "rank",
        "question": "Do independent private strata expose different typed catalog gaps?",
        "source": {"name": "Private ranked fixture", "revision": "fixture-revision"},
        "strata": strata,
        "policies": {"exclusions": "Exclude every prior development namespace.", "overlap": "reject"},
        "collection": {"ct_enabled": False, "direct_probes_enabled": False},
        "thresholds": {"minimum_occurrences": 2, "minimum_distinct_namespaces": 2},
        "promotion_budget": {
            "metric": "classified opportunity share by record type",
            "minimum_improvement": 0.01,
            "maximum_regression": 0.0,
            "decision_rule": "Promote only independently documented rules with zero protected regression.",
        },
    }
    plan_path = private / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    frame_path = private / "frame.txt"
    frame, manifest = prepare_catalog_round(
        plan_path,
        frame_path,
        prepared_at="2026-08-13T12:00:00Z",
    )
    frame_path.write_bytes(frame)
    manifest_path = private / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    results_path = private / "results.ndjson"
    result_rows = []
    for index, domain in enumerate(domains):
        result_rows.append(
            {
                "queried_domain": domain,
                "partial": index == 1,
                "degraded_sources": ["dns:txt"] if index == 1 else [],
                "dns_catalog_summary": [
                    {
                        "record_type": "txt",
                        "availability": "partial" if index == 1 else "available",
                        "opportunity_count": 1,
                        "observed_count": 1,
                        "classified_count": index % 2,
                        "unclassified_count": 1 - (index % 2),
                        "truncated": False,
                    }
                ],
                "unclassified_dns_observations": [],
            }
        )
    results_path.write_text("".join(json.dumps(row) + "\n" for row in result_rows), encoding="utf-8")
    results_digest = catalog_baseline.digest_result_files([results_path])
    pooled = {
        "schema_version": catalog_baseline.SCHEMA_VERSION,
        "aggregate_only": True,
        "records_total": len(result_rows),
        "results_digest_sha256": results_digest,
        "round_contract": catalog_baseline.public_round_contract(manifest),
    }
    pooled_path = private / "catalog-aggregate.json"
    pooled_path.write_text(json.dumps(pooled), encoding="utf-8")
    return plan_path, manifest_path, results_path, pooled_path, domains


def _reduce(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    plan, manifest, results, pooled, domains = _fixture(tmp_path)
    public, private, private_manifest = stratify_catalog_round.reduce_strata(
        results_path=results,
        round_plan_path=plan,
        round_manifest_path=manifest,
        pooled_aggregate_path=pooled,
    )
    return public, private, private_manifest, domains


def test_reducer_emits_complete_ordered_strata_without_private_text(tmp_path: Path) -> None:
    public, private, private_manifest, domains = _reduce(tmp_path)
    rendered = json.dumps(public, sort_keys=True)

    assert public["records_total"] == 80
    assert [row["stratum_index"] for row in public["strata"]] == [0, 1, 2, 3]
    assert all(row["frame_count"] == 20 and row["complete"] is True for row in public["strata"])
    assert all(row["aggregate"]["records_total"] == 20 for row in public["strata"])
    assert public["strata"][0]["aggregate"]["partial_records"] == 1
    assert "private-stratum" not in rendered
    assert "Private stratum label" not in rendered
    assert all(domain not in rendered for domain in domains)
    assert private["strata"][0]["stratum_id"] == "private-stratum-0"
    assert private_manifest["stratum_counts"] == [20, 20, 20, 20]


def test_reducer_rejects_incomplete_duplicate_and_outside_results(tmp_path: Path) -> None:
    plan, manifest, results, pooled, _ = _fixture(tmp_path)
    original = results.read_text(encoding="utf-8").splitlines()

    results.write_text("\n".join(original[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requires the complete frozen frame"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )

    results.write_text("\n".join([*original, original[0]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate frozen-frame"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )

    outside = json.loads(original[0])
    outside["queried_domain"] = "outside.invalid"
    results.write_text("\n".join([json.dumps(outside), *original[1:]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not belong"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )


def test_reducer_rejects_plan_source_and_pooled_commitment_drift(tmp_path: Path) -> None:
    plan, manifest, results, pooled, _ = _fixture(tmp_path)
    plan_value = json.loads(plan.read_text(encoding="utf-8"))
    plan_value["question"] = "A different post-collection question that must not be accepted."
    plan.write_text(json.dumps(plan_value), encoding="utf-8")
    with pytest.raises(ValueError, match="plan digest"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )

    plan, manifest, results, pooled, _ = _fixture(tmp_path / "unsafe-pooled")
    pooled_value = json.loads(pooled.read_text(encoding="utf-8"))
    pooled_value["queried_domain"] = "private-target.invalid"
    pooled.write_text(json.dumps(pooled_value), encoding="utf-8")
    with pytest.raises(ValueError, match="forbidden key"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )

    plan, manifest, results, pooled, _ = _fixture(tmp_path / "source")
    (plan.parent / "stratum-0.txt").write_text("changed.invalid\nsecond.invalid\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source digest"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )

    plan, manifest, results, pooled, _ = _fixture(tmp_path / "pooled")
    pooled_value = json.loads(pooled.read_text(encoding="utf-8"))
    pooled_value["results_digest_sha256"] = "0" * 64
    pooled.write_text(json.dumps(pooled_value), encoding="utf-8")
    with pytest.raises(ValueError, match="results digest"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )


def test_public_stratification_rejects_small_strata(tmp_path: Path) -> None:
    plan, manifest, results, pooled, _ = _fixture(tmp_path, rows_per_stratum=2)

    with pytest.raises(ValueError, match="at least 20 rows"):
        stratify_catalog_round.reduce_strata(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
        )


def test_exclusive_output_write_preserves_existing_artifact(tmp_path: Path) -> None:
    public, private, private_manifest, _ = _reduce(tmp_path)
    output = tmp_path / "private" / "output"
    output.mkdir()
    existing = output / "catalog-stratified-gaps.json"
    existing.write_text("operator-owned", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to replace"):
        stratify_catalog_round.write_stratified_outputs(output, public, private, private_manifest)

    assert existing.read_text(encoding="utf-8") == "operator-owned"
    assert not (output / "catalog-stratified-aggregate.json").exists()
    assert not (output / "catalog-stratified-manifest.json").exists()


def test_cli_prints_counts_and_commitments_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan, manifest, results, pooled, domains = _fixture(tmp_path)
    output = tmp_path / "private" / "output"

    assert (
        stratify_catalog_round.main(
            [
                "--input",
                str(results),
                "--round-plan",
                str(plan),
                "--round-manifest",
                str(manifest),
                "--pooled-aggregate",
                str(pooled),
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out

    assert all(domain not in rendered for domain in domains)
    assert "private-stratum" not in rendered
    assert json.loads(rendered)["identifiers_printed"] == 0
    assert (output / "catalog-stratified-aggregate.json").is_file()


def test_negative_max_samples_returns_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plan, manifest, results, pooled, _ = _fixture(tmp_path)

    assert (
        stratify_catalog_round.main(
            [
                "--input",
                str(results),
                "--round-plan",
                str(plan),
                "--round-manifest",
                str(manifest),
                "--pooled-aggregate",
                str(pooled),
                "--output-dir",
                str(tmp_path / "private" / "output"),
                "--max-samples",
                "-1",
            ]
        )
        == 2
    )
    assert "max_samples must be non-negative" in capsys.readouterr().err
