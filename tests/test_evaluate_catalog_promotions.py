"""Tests for fixed-observation catalog promotion evaluation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from recon_tool import fingerprints
from recon_tool.fingerprints import DetectionRule, Fingerprint
from validation import catalog_baseline
from validation.evaluate_catalog_promotions import (
    CandidateRule,
    _candidate_rules_digest,
    _matched_slugs,
    _type_rows,
    evaluate_catalog_promotions,
    evaluate_partitioned_records,
    load_candidate_rules,
    main,
)
from validation.prepare_catalog_round import SCHEMA_VERSION, prepare_catalog_round


def _record(*, mx: str = "", ns: str = "", spf: str = "", cname_target: str = "") -> dict[str, object]:
    values = {"mx": mx, "ns": ns, "spf": spf, "cname_target": cname_target}
    observations = [
        {"record_type": record_type, "owner": "@", "value": value} for record_type, value in values.items() if value
    ]
    summaries = []
    for record_type in catalog_baseline.RECORD_TYPES:
        observed = int(bool(values.get(record_type)))
        summaries.append(
            {
                "record_type": record_type,
                "availability": "available",
                "opportunity_count": 1,
                "observed_count": observed,
                "classified_count": 0,
                "unclassified_count": observed,
                "truncated": False,
            }
        )
    return {
        "queried_domain": "fixture.invalid",
        "partial": False,
        "degraded_sources": [],
        "dns_catalog_summary": summaries,
        "unclassified_dns_observations": observations,
    }


def test_candidate_rules_are_referenced_dated_and_exact() -> None:
    rules = load_candidate_rules(("cloudflare-email-routing", "alibaba-dns", "alibaba-alb", "yandex-360"))

    assert {(rule.slug, rule.record_type, rule.pattern) for rule in rules} == {
        ("cloudflare-email-routing", "mx", "mx.cloudflare.net"),
        ("cloudflare-email-routing", "spf", "_spf.mx.cloudflare.net"),
        ("alibaba-dns", "ns", "alidns.com"),
        ("alibaba-alb", "cname_target", "alb.aliyuncsslbintl.com"),
        ("yandex-360", "mx", "mx.yandex.net"),
        ("yandex-360", "spf", "_spf.yandex.net"),
    }


def test_candidate_rule_loading_rejects_missing_or_duplicate_slugs() -> None:
    with pytest.raises(ValueError, match="at least one"):
        load_candidate_rules(())
    with pytest.raises(ValueError, match="unique"):
        load_candidate_rules(("yandex-360", "yandex-360"))
    with pytest.raises(ValueError, match="absent"):
        load_candidate_rules(("missing-candidate",))


def _synthetic_fingerprint(*, match_mode: str = "any") -> Fingerprint:
    return Fingerprint(
        name="Synthetic Vendor",
        slug="synthetic-vendor",
        category="Email & Communication",
        confidence="high",
        m365=False,
        match_mode=match_mode,
        detections=tuple(
            DetectionRule(
                type=record_type,
                pattern=pattern,
                reference="https://vendor.example/docs",
                verified="2026-08-01",
            )
            for record_type, pattern in (("mx", "mail.vendor.invalid"), ("ns", "dns.vendor.invalid"))
        ),
    )


def test_candidate_rule_loading_rejects_whole_fingerprint_conjunctions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "validation.evaluate_catalog_promotions.load_builtin_fingerprints",
        lambda: (_synthetic_fingerprint(match_mode="all"),),
    )

    with pytest.raises(ValueError, match="unsupported counterfactual match_mode all"):
        load_candidate_rules(("synthetic-vendor",))


def test_candidate_rule_loading_excludes_operator_and_ephemeral_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_catalog = (*fingerprints.load_builtin_fingerprints(), _synthetic_fingerprint())
    monkeypatch.setattr(fingerprints._cache_state, "fingerprints", runtime_catalog)

    assert any(fingerprint.slug == "synthetic-vendor" for fingerprint in fingerprints.load_fingerprints())
    with pytest.raises(ValueError, match="absent from the current catalog"):
        load_candidate_rules(("synthetic-vendor",))


def test_candidate_rules_digest_is_order_independent_and_binds_exact_rules() -> None:
    rules = (
        CandidateRule("synthetic", "mx", "mail.vendor.invalid"),
        CandidateRule("synthetic", "ns", "dns.vendor.invalid"),
    )
    digest = _candidate_rules_digest(rules)

    assert _candidate_rules_digest((*reversed(rules), rules[0])) == digest
    assert _candidate_rules_digest(rules[:1]) != digest
    for replacement in (
        CandidateRule("different", "mx", "mail.vendor.invalid"),
        CandidateRule("synthetic", "spf", "mail.vendor.invalid"),
        CandidateRule("synthetic", "mx", "other.vendor.invalid"),
    ):
        assert _candidate_rules_digest((replacement, rules[1])) != digest


def test_suffix_matching_rejects_lookalikes_and_keeps_longest_host_rule() -> None:
    rules = (
        CandidateRule("broad", "mx", "example.net"),
        CandidateRule("specific", "mx", "mx.example.net"),
    )

    assert _matched_slugs("mx", "route.mx.example.net", rules) == {"specific"}
    assert _matched_slugs("mx", "route.mx.example.net.attacker.invalid", rules) == set()
    assert _matched_slugs("mx", "", rules) == set()


@pytest.mark.parametrize(
    ("classified", "minimum", "expected"),
    [(0, 0.3333332, True), (1, 0.3333335, False), (2, 0.3333335, False), (1, 1 / 3, True)],
)
def test_promotion_threshold_uses_unrounded_count_ratio(classified: int, minimum: float, expected: bool) -> None:
    baseline = {
        "record_types": {
            kind: {"observed_count": 3 if kind == "mx" else 0, "classified_count": classified if kind == "mx" else 0}
            for kind in catalog_baseline.RECORD_TYPES
        }
    }

    rows = _type_rows(baseline, {"mx": 1}, minimum_improvement=minimum, maximum_regression=0.0)

    assert rows["mx"]["classified_rate_delta"] == 0.333333
    assert rows["mx"]["meets_minimum_improvement"] is expected
    assert rows["mx"]["within_regression_budget"] is True


@pytest.mark.parametrize(("minimum", "expected"), [(0.3333332, True), (0.3333335, False)])
def test_acceptance_uses_unrounded_uplift(minimum: float, expected: bool) -> None:
    records = [_record(mx=f"tenant{index}.vendor.invalid") for index in range(3)]
    rules = (CandidateRule("synthetic", "mx", "tenant0.vendor.invalid"),)

    _, pooled = evaluate_partitioned_records(
        [records],
        rules,
        min_count=1,
        min_distinct_namespaces=1,
        minimum_improvement=minimum,
        maximum_regression=0.0,
    )

    assert pooled["decision"]["accepted"] is expected


def test_counterfactual_uses_fixed_denominators_and_zero_regression() -> None:
    rules = (
        CandidateRule("cloudflare-email-routing", "mx", "mx.cloudflare.net"),
        CandidateRule("alibaba-dns", "ns", "alidns.com"),
        CandidateRule("alibaba-alb", "cname_target", "alb.aliyuncsslbintl.com"),
        CandidateRule("yandex-360", "mx", "mx.yandex.net"),
        CandidateRule("yandex-360", "spf", "_spf.yandex.net"),
    )
    records = [
        _record(
            mx="route1.mx.cloudflare.net",
            ns="vip3.alidns.com",
            spf="_spf.yandex.net",
            cname_target="fixture.eu-central-1.alb.aliyuncsslbintl.com",
        ),
        _record(mx="mx.yandex.net"),
    ]

    strata, pooled = evaluate_partitioned_records(
        [records],
        rules,
        min_count=1,
        min_distinct_namespaces=1,
        minimum_improvement=0.1,
        maximum_regression=0.0,
    )

    assert strata[0]["record_types"]["mx"]["counterfactual_added_classified"] == 2
    assert pooled["record_types"]["mx"]["baseline_observed_count"] == 2
    assert pooled["record_types"]["mx"]["counterfactual_classified_rate"] == 1.0
    assert pooled["record_types"]["txt"]["classified_rate_delta"] == 0.0
    assert pooled["decision"]["all_candidate_slugs_observed"] is True
    assert pooled["decision"]["accepted"] is True


def test_counterfactual_fails_when_a_candidate_is_unobserved_or_below_budget() -> None:
    rules = (
        CandidateRule("observed", "mx", "mx.example.net"),
        CandidateRule("unobserved", "ns", "ns.example.net"),
    )
    records = [_record(mx="mx.example.net"), _record(mx="unmatched.invalid")]

    _strata, pooled = evaluate_partitioned_records(
        [records],
        rules,
        min_count=1,
        min_distinct_namespaces=1,
        minimum_improvement=0.6,
        maximum_regression=0.0,
    )

    assert pooled["record_types"]["mx"]["classified_rate_delta"] == 0.5
    assert pooled["decision"]["all_candidate_slugs_observed"] is False
    assert pooled["decision"]["all_affected_types_meet_minimum"] is False
    assert pooled["decision"]["accepted"] is False


def test_public_shape_has_no_target_fields(tmp_path: Path) -> None:
    rules = (CandidateRule("observed", "mx", "mx.example.net"),)
    _strata, pooled = evaluate_partitioned_records(
        [[_record(mx="mx.example.net")]],
        rules,
        min_count=1,
        min_distinct_namespaces=1,
        minimum_improvement=0.1,
        maximum_regression=0.0,
    )

    catalog_baseline.assert_aggregate_safe(pooled)
    rendered = json.dumps(pooled)
    assert "fixture.invalid" not in rendered
    assert "mx.example.net" not in rendered
    assert tmp_path.exists()


def _bound_fixture(
    tmp_path: Path,
    *,
    rows_per_stratum: int = 20,
    metric: str = "classified opportunity share by record type",
    decision_rule: str = "Promote referenced candidates only when fixed-observation uplift is positive.",
) -> tuple[Path, Path, Path, Path, list[str]]:
    private = tmp_path / "private"
    private.mkdir(parents=True)
    domains = [f"counterfactual-{index}.invalid" for index in range(rows_per_stratum * 4)]
    strata = []
    for index in range(4):
        source = private / f"stratum-{index}.txt"
        start = index * rows_per_stratum
        source.write_text("\n".join(domains[start : start + rows_per_stratum]) + "\n", encoding="utf-8")
        strata.append({"id": f"stratum-{index}", "label": f"Private stratum {index}", "input": source.name})
    plan = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "round_id": "counterfactual-fixture",
        "round_kind": "rank",
        "question": "Does one referenced candidate improve the fixed observation baseline?",
        "source": {"name": "Private counterfactual fixture", "revision": "fixture-v1"},
        "strata": strata,
        "policies": {"exclusions": "Exclude every development namespace.", "overlap": "reject"},
        "collection": {"ct_enabled": False, "direct_probes_enabled": False},
        "thresholds": {"minimum_occurrences": 2, "minimum_distinct_namespaces": 2},
        "promotion_budget": {
            "metric": metric,
            "minimum_improvement": 0.001,
            "maximum_regression": 0.0,
            "decision_rule": decision_rule,
        },
    }
    plan_path = private / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    frame_path = private / "frame.txt"
    frame, manifest = prepare_catalog_round(plan_path, frame_path, prepared_at="2026-08-13T18:00:00Z")
    frame_path.write_bytes(frame)
    manifest_path = private / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    rows = []
    for domain in domains:
        rows.append(
            {
                "queried_domain": domain,
                "partial": False,
                "degraded_sources": [],
                "dns_catalog_summary": [
                    {
                        "record_type": "mx",
                        "availability": "available",
                        "opportunity_count": 1,
                        "observed_count": 1,
                        "classified_count": 0,
                        "unclassified_count": 1,
                        "truncated": False,
                    }
                ],
                "unclassified_dns_observations": [
                    {"record_type": "mx", "owner": "@", "value": "route1.mx.cloudflare.net"}
                ],
            }
        )
    results_path = private / "results.ndjson"
    results_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    results_digest = catalog_baseline.digest_result_files([results_path])
    pooled_path = private / "catalog-aggregate.json"
    pooled_path.write_text(
        json.dumps(
            {
                "schema_version": catalog_baseline.SCHEMA_VERSION,
                "aggregate_only": True,
                "records_total": len(rows),
                "results_digest_sha256": results_digest,
                "round_contract": catalog_baseline.public_round_contract(manifest),
            }
        ),
        encoding="utf-8",
    )
    return plan_path, manifest_path, results_path, pooled_path, domains


def test_end_to_end_evaluation_binds_inputs_and_omits_members(tmp_path: Path) -> None:
    plan, manifest, results, pooled, domains = _bound_fixture(tmp_path)

    public = evaluate_catalog_promotions(
        results_path=results,
        round_plan_path=plan,
        round_manifest_path=manifest,
        pooled_aggregate_path=pooled,
        candidate_slugs=("cloudflare-email-routing",),
    )

    rendered = json.dumps(public, sort_keys=True)
    assert public["records_total"] == 80
    assert public["pooled"]["decision"]["accepted"] is True
    assert public["pooled"]["decision"]["decision_scope"] == "pooled-classification-diagnostic"
    assert public["pooled"]["decision"]["policy_text_status"] == "not_evaluated"
    assert public["pooled"]["record_types"]["mx"]["counterfactual_added_classified"] == 80
    assert public["candidate_rules_digest_sha256"] == _candidate_rules_digest(
        load_candidate_rules(("cloudflare-email-routing",))
    )
    assert all(domain not in rendered for domain in domains)
    assert "route1.mx.cloudflare.net" not in rendered
    catalog_baseline.assert_aggregate_safe(public)


def test_policy_text_is_preserved_but_not_reported_as_evaluated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    metric = "Independent provider confirmation count"
    decision_rule = "Do not promote until a curator verifies independent provider confirmation."
    plan, manifest, results, pooled, _domains = _bound_fixture(tmp_path, metric=metric, decision_rule=decision_rule)
    output = tmp_path / "evaluation.json"

    assert (
        main(
            [
                "--input",
                str(results),
                "--round-plan",
                str(plan),
                "--round-manifest",
                str(manifest),
                "--pooled-aggregate",
                str(pooled),
                "--candidate-slug",
                "cloudflare-email-routing",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    public = json.loads(output.read_text(encoding="utf-8"))
    summary = json.loads(capsys.readouterr().out)
    budget = json.loads(manifest.read_text(encoding="utf-8"))["promotion_budget"]
    assert budget["metric"] == metric
    assert budget["decision_rule"] == decision_rule
    encoded_budget = json.dumps(budget, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    assert public["round_contract"]["promotion_budget_digest_sha256"] == hashlib.sha256(encoded_budget).hexdigest()
    assert metric not in json.dumps(public)
    assert decision_rule not in json.dumps(public)
    for decision in (public["pooled"]["decision"], summary):
        assert decision["accepted"] is True
        assert decision["decision_scope"] == "pooled-classification-diagnostic"
        assert decision["policy_text_status"] == "not_evaluated"


def test_acceptance_does_not_claim_per_candidate_recurrence() -> None:
    _, pooled = evaluate_partitioned_records(
        [[_record(mx="vendor.invalid")]],
        (CandidateRule("synthetic", "mx", "vendor.invalid"),),
        min_count=100,
        min_distinct_namespaces=100,
        minimum_improvement=0.1,
        maximum_regression=0.0,
    )

    assert pooled["decision"]["accepted"] is True
    assert pooled["decision"]["candidate_match_counts"] == [
        {"slug": "synthetic", "record_type": "mx", "added_classified": 1}
    ]
    assert pooled["decision"]["decision_scope"] == "pooled-classification-diagnostic"
    assert pooled["decision"]["policy_text_status"] == "not_evaluated"


def test_end_to_end_evaluation_rejects_small_strata_and_unbound_aggregate(tmp_path: Path) -> None:
    plan, manifest, results, pooled, _domains = _bound_fixture(tmp_path / "small", rows_per_stratum=2)
    with pytest.raises(ValueError, match="at least 20 rows"):
        evaluate_catalog_promotions(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
            candidate_slugs=("cloudflare-email-routing",),
        )

    plan, manifest, results, pooled, _domains = _bound_fixture(tmp_path / "digest")
    pooled_value = json.loads(pooled.read_text(encoding="utf-8"))
    pooled_value["results_digest_sha256"] = "0" * 64
    pooled.write_text(json.dumps(pooled_value), encoding="utf-8")
    with pytest.raises(ValueError, match="bind the supplied results"):
        evaluate_catalog_promotions(
            results_path=results,
            round_plan_path=plan,
            round_manifest_path=manifest,
            pooled_aggregate_path=pooled,
            candidate_slugs=("cloudflare-email-routing",),
        )
