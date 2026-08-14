"""Tests for the frozen, disclosure-safe vendor-seed round contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from validation import (
    archive_vendor_seed_sources,
    catalog_baseline,
    evaluate_vendor_seed_round,
    prepare_vendor_seed_round,
)

ROOT = Path(__file__).resolve().parents[1]


def _members(prefix: str, source_id: str, count: int = 20) -> list[dict[str, str]]:
    return [{"domain": f"{prefix}-{index}.invalid", "source_id": source_id} for index in range(count)]


def _dossier(tmp_path: Path, *, provider_rows: int = 20) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    webflow_archive = tmp_path / "archives" / "webflow" / "webflow-cases.html"
    shopify_archive = tmp_path / "archives" / "shopify" / "shopify-cases.html"
    webflow_archive.parent.mkdir(parents=True)
    shopify_archive.parent.mkdir(parents=True)
    webflow_archive.write_text("frozen provider-controlled Webflow source", encoding="utf-8")
    shopify_archive.write_text("frozen provider-controlled Shopify source", encoding="utf-8")
    (tmp_path / "excluded.txt").write_text("development.invalid\nprior-observation.invalid\n", encoding="utf-8")
    receipt: dict[str, object] = {
        "schema_version": 1,
        "private": True,
        "source_set_id": "vendor-seed-source-set-2026-08",
        "purpose": "Archive exact provider-controlled evidence before freezing the disjoint vendor-seed frame.",
        "retrieved_at": "2026-08-13T12:00:00Z",
        "plan_digest_sha256": "1" * 64,
        "implementation_digest_sha256": "2" * 64,
        "acquisition_policy": archive_vendor_seed_sources._acquisition_policy(),
        "providers": [
            {
                "slug": "webflow",
                "allowed_domains": ["webflow.com"],
                "sources": [
                    {
                        "id": "webflow-cases",
                        "url": "https://webflow.com/customers",
                        "retrieved_at": "2026-08-13T12:00:00Z",
                        "media_type": "text/html",
                        "archive": "archives/webflow/webflow-cases.html",
                        "archive_bytes": webflow_archive.stat().st_size,
                        "archive_digest_sha256": hashlib.sha256(webflow_archive.read_bytes()).hexdigest(),
                    }
                ],
            },
            {
                "slug": "shopify",
                "allowed_domains": ["shopify.com"],
                "sources": [
                    {
                        "id": "shopify-cases",
                        "url": "https://www.shopify.com/case-studies",
                        "retrieved_at": "2026-08-13T12:00:00Z",
                        "media_type": "text/html",
                        "archive": "archives/shopify/shopify-cases.html",
                        "archive_bytes": shopify_archive.stat().st_size,
                        "archive_digest_sha256": hashlib.sha256(shopify_archive.read_bytes()).hexdigest(),
                    }
                ],
            },
        ],
        "totals": {
            "provider_count": 2,
            "source_count": 2,
            "archive_bytes": webflow_archive.stat().st_size + shopify_archive.stat().st_size,
            "selected_target_requests": 0,
        },
    }
    (tmp_path / "source-plan.json").write_text("frozen synthetic source plan", encoding="utf-8")
    receipt["plan_digest_sha256"] = hashlib.sha256((tmp_path / "source-plan.json").read_bytes()).hexdigest()
    receipt["implementation_digest_sha256"] = archive_vendor_seed_sources._implementation_digest()
    receipt["receipt_digest_sha256"] = archive_vendor_seed_sources._receipt_digest(receipt)
    (tmp_path / "source-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    dossier = {
        "schema_version": 2,
        "private": True,
        "round_id": "vendor-seed-2026-08",
        "question": (
            "How often does recon independently corroborate provider relationships on a disjoint "
            "provider-controlled customer-evidence holdout?"
        ),
        "source_name": "Provider-controlled customer evidence",
        "source_revision": "retrieved-2026-08-13",
        "source_receipt": "source-receipt.json",
        "providers": [
            {
                "slug": "webflow",
                "label_basis": "provider-relationship",
                "sources": [
                    {
                        "id": "webflow-cases",
                        "url": "https://webflow.com/customers",
                        "retrieved_at": "2026-08-13T12:00:00Z",
                        "archive": "archives/webflow/webflow-cases.html",
                    }
                ],
                "members": _members("webflow-private", "webflow-cases", provider_rows),
            },
            {
                "slug": "shopify",
                "label_basis": "provider-relationship",
                "sources": [
                    {
                        "id": "shopify-cases",
                        "url": "https://www.shopify.com/case-studies",
                        "retrieved_at": "2026-08-13T12:00:00Z",
                        "archive": "archives/shopify/shopify-cases.html",
                    }
                ],
                "members": _members("shopify-private", "shopify-cases", provider_rows),
            },
        ],
        "exclusions": [{"id": "prior-work", "input": "excluded.txt"}],
        "collection": {"ct_enabled": False, "direct_probes_enabled": False},
        "thresholds": {"minimum_occurrences": 2, "minimum_distinct_namespaces": 2},
        "promotion_budget": {
            "metric": "provider-relationship corroboration rate",
            "minimum_improvement": 0.01,
            "maximum_regression": 0.0,
            "decision_rule": (
                "Publish each provider outcome without treating observed silence as a false negative or "
                "using it to tune the evaluated rules."
            ),
        },
    }
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(dossier), encoding="utf-8")
    return path


def _write_contract(tmp_path: Path, *, provider_rows: int = 20) -> Path:
    output = tmp_path / "contract"
    prepare_vendor_seed_round.write_vendor_seed_round(_dossier(tmp_path, provider_rows=provider_rows), output)
    return output


def _availability_rows(record_types: list[str], availability: str) -> list[dict[str, object]]:
    return [
        {
            "record_type": record_type,
            "availability": availability,
            "opportunity_count": 1,
            "observed_count": 0,
            "classified_count": 0,
            "unclassified_count": 0,
            "truncated": False,
        }
        for record_type in record_types
    ]


def _results(contract: Path) -> tuple[Path, list[str], Path]:
    source_contract = json.loads((contract / "source-contract.json").read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []
    domains: list[str] = []
    for provider in source_contract["providers"]:
        slug = provider["slug"]
        expected_types = provider["record_types"]
        provider_domains = (contract / "sources" / f"{slug}.txt").read_text(encoding="ascii").splitlines()
        domains.extend(provider_domains)
        for index, domain in enumerate(provider_domains):
            if slug == "webflow" and index == 19:
                rows.append({"record_type": "error", "domain": domain, "error_kind": "timeout"})
                continue
            availability = "unavailable" if index in {17, 18} else "available"
            if slug == "shopify" and index in {18, 19}:
                availability = "unmeasured"
            match_limit = 8 if slug == "webflow" else 10
            rows.append(
                {
                    "queried_domain": domain,
                    "slugs": [slug] if index < match_limit else [],
                    "partial": availability == "unavailable",
                    "degraded_sources": ["dns"] if availability == "unavailable" else [],
                    "dns_catalog_summary": _availability_rows(expected_types, availability),
                    "unclassified_dns_observations": [],
                }
            )
    path = contract / "results.ndjson"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    manifest = json.loads((contract / "round-manifest.json").read_text(encoding="utf-8"))
    pooled = {
        "aggregate_only": True,
        "records_total": len(rows),
        "results_digest_sha256": catalog_baseline.digest_result_files([path]),
        "round_contract": catalog_baseline.public_round_contract(manifest),
    }
    pooled_path = contract / "catalog-aggregate.json"
    pooled_path.write_text(json.dumps(pooled), encoding="utf-8")
    return path, domains, pooled_path


def _evaluate(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], list[str], Path]:
    contract = _write_contract(tmp_path)
    results, domains, pooled = _results(contract)
    public, private = evaluate_vendor_seed_round.evaluate_vendor_seed(
        results_path=results,
        round_plan_path=contract / "round-plan.json",
        round_manifest_path=contract / "round-manifest.json",
        source_contract_path=contract / "source-contract.json",
        pooled_aggregate_path=pooled,
    )
    return public, private, domains, contract


def test_preparer_freezes_sources_exclusions_and_generic_round(tmp_path: Path) -> None:
    contract = _write_contract(tmp_path)
    source = json.loads((contract / "source-contract.json").read_text(encoding="utf-8"))
    manifest = json.loads((contract / "round-manifest.json").read_text(encoding="utf-8"))

    assert source["label_basis"] == "provider-relationship"
    assert source["metric"] == "provider-relationship corroboration rate"
    assert source["target_network_requests"] == 0
    assert source["exclusion_union_count"] == 2
    assert len(source["exclusion_union_digest_sha256"]) == 64
    assert [row["slug"] for row in source["providers"]] == ["webflow", "shopify"]
    assert all(row["member_count"] == 20 for row in source["providers"])
    assert manifest["round_kind"] == "vendor-seed"
    assert manifest["frame"]["count"] == 40
    assert [row["id"] for row in manifest["strata"]] == ["webflow", "shopify"]
    assert "source-contract-sha256=" in manifest["source"]["revision"]


def test_preparer_rejects_overlap_small_strata_and_unsupported_metric(tmp_path: Path) -> None:
    dossier_path = _dossier(tmp_path)
    dossier = cast(dict[str, Any], json.loads(dossier_path.read_text(encoding="utf-8")))
    dossier["providers"][0]["members"][0]["domain"] = "development.invalid"
    dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    with pytest.raises(ValueError, match="overlaps a frozen exclusion"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(dossier_path, tmp_path / "overlap")

    with pytest.raises(ValueError, match="at least 20"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(
            _dossier(tmp_path / "small", provider_rows=19), tmp_path / "small-output"
        )

    metric_path = _dossier(tmp_path / "metric")
    metric = cast(dict[str, Any], json.loads(metric_path.read_text(encoding="utf-8")))
    metric["promotion_budget"]["metric"] = "recall"
    metric_path.write_text(json.dumps(metric), encoding="utf-8")
    with pytest.raises(ValueError, match="provider-relationship corroboration rate"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(metric_path, tmp_path / "metric-output")

    duplicate_path = _dossier(tmp_path / "duplicate")
    duplicate_raw = duplicate_path.read_text(encoding="utf-8").replace(
        '"schema_version": 2,',
        '"schema_version": 2, "schema_version": 2,',
        1,
    )
    duplicate_path.write_text(duplicate_raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate field: schema_version"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(duplicate_path, tmp_path / "duplicate-output")


def test_preparer_rejects_source_receipt_or_archive_substitution(tmp_path: Path) -> None:
    dossier_path = _dossier(tmp_path)
    dossier = cast(dict[str, Any], json.loads(dossier_path.read_text(encoding="utf-8")))
    dossier["providers"][0]["sources"][0]["url"] = "https://www.webflow.com/customers"
    dossier_path.write_text(json.dumps(dossier), encoding="utf-8")
    with pytest.raises(ValueError, match="metadata does not match"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(dossier_path, tmp_path / "metadata-output")

    dossier_path = _dossier(tmp_path / "archive")
    archive = tmp_path / "archive" / "archives" / "webflow" / "webflow-cases.html"
    archive.write_text("substituted source bytes", encoding="utf-8")
    with pytest.raises(ValueError, match="archive does not match"):
        prepare_vendor_seed_round.prepare_vendor_seed_round(dossier_path, tmp_path / "archive-output")


def test_reducer_reports_corroboration_without_target_identifiers(tmp_path: Path) -> None:
    public, private, domains, _ = _evaluate(tmp_path)
    rendered = json.dumps(public, sort_keys=True)
    by_slug = {row["provider_slug"]: row for row in public["providers"]}

    assert public["provider_count"] == 2
    assert public["records_total"] == 40
    assert public["metric"] == "provider-relationship corroboration rate"
    assert "not recall" in public["claim_boundary"]
    assert by_slug["webflow"]["corroborated"] == 8
    assert by_slug["webflow"]["observed_silent"] == 9
    assert by_slug["webflow"]["unavailable"] == 2
    assert by_slug["webflow"]["error"] == 1
    assert by_slug["webflow"]["measurable_count"] == 17
    assert by_slug["webflow"]["corroboration_rate"] == pytest.approx(8 / 17, abs=1e-6)
    assert by_slug["shopify"]["corroborated"] == 10
    assert by_slug["shopify"]["observed_silent"] == 7
    assert by_slug["shopify"]["unmeasured"] == 2
    assert by_slug["shopify"]["unavailable"] == 1
    assert all(domain not in rendered for domain in domains)
    assert "webflow.com/customers" not in rendered
    assert "shopify.com/case-studies" not in rendered
    assert private["provider_counts"] == [20, 20]


def test_reducer_rejects_source_contract_and_catalog_contract_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _write_contract(tmp_path)
    results, _, pooled = _results(contract)
    source_path = contract / "source-contract.json"
    source = cast(dict[str, Any], json.loads(source_path.read_text(encoding="utf-8")))
    source["providers"][0]["record_types"] = ["txt"]
    source_path.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        evaluate_vendor_seed_round.evaluate_vendor_seed(
            results_path=results,
            round_plan_path=contract / "round-plan.json",
            round_manifest_path=contract / "round-manifest.json",
            source_contract_path=source_path,
            pooled_aggregate_path=pooled,
        )

    contract = _write_contract(tmp_path / "catalog-drift")
    results, _, pooled = _results(contract)
    actual_catalog = evaluate_vendor_seed_round._catalog_by_slug()
    drifted_catalog = {slug: dict(row) for slug, row in actual_catalog.items()}
    drifted_catalog["webflow"] = {
        **drifted_catalog["webflow"],
        "record_types": {"txt"},
    }

    def catalog_with_drift() -> dict[str, dict[str, object]]:
        return drifted_catalog

    monkeypatch.setattr(evaluate_vendor_seed_round, "_catalog_by_slug", catalog_with_drift)
    with pytest.raises(ValueError, match="catalog record types changed"):
        evaluate_vendor_seed_round.evaluate_vendor_seed(
            results_path=results,
            round_plan_path=contract / "round-plan.json",
            round_manifest_path=contract / "round-manifest.json",
            source_contract_path=contract / "source-contract.json",
            pooled_aggregate_path=pooled,
        )


def test_reducer_rejects_incomplete_results(tmp_path: Path) -> None:
    contract = _write_contract(tmp_path)
    results, _, pooled = _results(contract)
    lines = results.read_text(encoding="utf-8").splitlines()
    results.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requires the complete frozen frame"):
        evaluate_vendor_seed_round.evaluate_vendor_seed(
            results_path=results,
            round_plan_path=contract / "round-plan.json",
            round_manifest_path=contract / "round-manifest.json",
            source_contract_path=contract / "source-contract.json",
            pooled_aggregate_path=pooled,
        )


def test_reducer_rejects_pooled_aggregate_not_bound_to_results(tmp_path: Path) -> None:
    contract = _write_contract(tmp_path)
    results, _, pooled = _results(contract)
    pooled_value = json.loads(pooled.read_text(encoding="utf-8"))
    pooled_value["results_digest_sha256"] = "0" * 64
    pooled.write_text(json.dumps(pooled_value), encoding="utf-8")

    with pytest.raises(ValueError, match="results digest does not match"):
        evaluate_vendor_seed_round.evaluate_vendor_seed(
            results_path=results,
            round_plan_path=contract / "round-plan.json",
            round_manifest_path=contract / "round-manifest.json",
            source_contract_path=contract / "source-contract.json",
            pooled_aggregate_path=pooled,
        )


def test_reducer_rejects_malformed_slugs(tmp_path: Path) -> None:
    contract = _write_contract(tmp_path)

    results, _, pooled = _results(contract)
    rows = [json.loads(line) for line in results.read_text(encoding="utf-8").splitlines()]
    first_success = next(row for row in rows if row.get("record_type") != "error")
    first_success["slugs"] = "webflow"
    results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    pooled_value = json.loads(pooled.read_text(encoding="utf-8"))
    pooled_value["results_digest_sha256"] = catalog_baseline.digest_result_files([results])
    pooled.write_text(json.dumps(pooled_value), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed slugs"):
        evaluate_vendor_seed_round.evaluate_vendor_seed(
            results_path=results,
            round_plan_path=contract / "round-plan.json",
            round_manifest_path=contract / "round-manifest.json",
            source_contract_path=contract / "source-contract.json",
            pooled_aggregate_path=pooled,
        )


def test_cli_writes_exclusively_and_prints_only_safe_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    contract = _write_contract(tmp_path)
    results, domains, pooled = _results(contract)
    output = tmp_path / "output"
    args = [
        "--input",
        str(results),
        "--round-plan",
        str(contract / "round-plan.json"),
        "--round-manifest",
        str(contract / "round-manifest.json"),
        "--source-contract",
        str(contract / "source-contract.json"),
        "--pooled-aggregate",
        str(pooled),
        "--output-dir",
        str(output),
    ]

    assert evaluate_vendor_seed_round.main(args) == 0
    rendered = capsys.readouterr().out
    assert all(domain not in rendered for domain in domains)
    assert json.loads(rendered)["identifiers_printed"] == 0
    assert (output / "vendor-seed-aggregate.json").is_file()
    assert evaluate_vendor_seed_round.main(args) == 2
    assert "refusing to replace" in capsys.readouterr().err


def test_current_docs_keep_vendor_seed_boundary_and_next_operation_aligned() -> None:
    declaration = (ROOT / "docs" / "catalog-vendor-seed-round-declaration.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    strategy = (ROOT / "docs" / "catalog-strategy.md").read_text(encoding="utf-8")
    validation_readme = (ROOT / "validation" / "README.md").read_text(encoding="utf-8")
    active = "\n".join((declaration, roadmap, strategy, validation_readme))

    assert "bounded source acquisition" in declaration
    assert "private pre-collection contract frozen" in declaration
    assert "33-row disjoint HubSpot" in active
    assert "zero target requests" in active
    assert "37bb3e9f2609b9f4470d637d60f42077593169522b117af9660ac3058516728b" in declaration
    assert "target\ncollection has not started" in declaration
    assert "provider-relationship corroboration rate" in " ".join(declaration.split())
    assert "not recall" in active
    assert "vendor-seed recall" not in active.casefold()
    assert "archive_vendor_seed_sources.py" in validation_readme
    assert "prepare_vendor_seed_round.py" in validation_readme
    assert "evaluate_vendor_seed_round.py" in validation_readme
    assert "catalog-vendor-seed-round-declaration.md" in roadmap
