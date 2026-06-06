"""Tests for recon_tool.cohort_summary, the in-core v2.1 cohort summary.

Pins the statistics and the honest behaviors: the missing-not-at-random
observability split (declarative signals observable when DNS resolved, hideable
claims observable only when their node fired non-sparse), the three-number
prevalence, posterior-mass aggregation, compositional concentration, and the
edge cases that must not crash (empty cohort, no fusion, single domain).
"""

from __future__ import annotations

from typing import Any

from recon_tool.cohort_summary import (
    build_summary_document,
    extract_signals,
    hhi,
    normalized_entropy,
    summarize_cohort,
    wilson_interval,
)


def _rec(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "provider": None,
        "dmarc_policy": None,
        "mta_sts_mode": None,
        "email_gateway": None,
        "cloud_instance": None,
        "slugs": [],
        "degraded_sources": [],
        "posterior_observations": [],
    }
    base.update(kw)
    return base


def _node(
    name: str, posterior: float, low: float, high: float, *, sparse: bool = False, fired: bool = True
) -> dict[str, Any]:
    return {
        "name": name,
        "posterior": posterior,
        "interval_low": low,
        "interval_high": high,
        "evidence_used": (["slug:x"] if fired else []),
        "sparse": sparse,
    }


def test_wilson_empty_denominator_uninformative() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_brackets_estimate() -> None:
    low, high = wilson_interval(6, 10)
    assert 0.0 <= low < 0.6 < high <= 1.0


def test_entropy_and_hhi_extremes() -> None:
    assert normalized_entropy([8]) == 0.0
    assert hhi([8]) == 1.0
    assert normalized_entropy([4, 4]) == 1.0
    assert abs(hhi([4, 4]) - 0.5) < 1e-9


def test_extract_signals_observability_split() -> None:
    visible = _rec(dmarc_policy="reject", posterior_observations=[_node("m365_tenant", 0.9, 0.8, 0.95)])
    sig = extract_signals(visible)
    assert sig["dmarc_reject"] is True
    assert sig["m365_tenant"] is True

    hidden = _rec(posterior_observations=[_node("m365_tenant", 0.2, 0.05, 0.5, sparse=True, fired=False)])
    assert extract_signals(hidden)["m365_tenant"] is None  # hideable, not observable

    degraded = _rec(dmarc_policy="reject", degraded_sources=["dns"])
    assert extract_signals(degraded)["dmarc_reject"] is None  # DNS down


def test_build_summary_document_shape() -> None:
    recs = [
        _rec(
            provider="Microsoft 365",
            dmarc_policy="reject",
            cloud_instance="Azure",
            posterior_observations=[_node("m365_tenant", 0.9, 0.84, 0.96)],
        )
        for _ in range(5)
    ]
    doc = build_summary_document(recs, "c", attempted=8)
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.1"
    assert doc["n"] == 5
    assert doc["observability"]["attempted"] == 8
    assert doc["observability"]["resolution_rate"] == 0.625
    assert doc["mix"]["provider"]["shares"] == {"Microsoft 365": 1.0}
    assert doc["mix"]["provider"]["hhi"] == 1.0
    assert doc["prevalence"]["dmarc_reject"]["observed_rate"] == 1.0


def test_empty_cohort_does_not_crash() -> None:
    doc = build_summary_document([], "empty")
    assert doc["n"] == 0
    assert doc["observability"]["resolution_rate"] is None
    assert doc["prevalence"]["m365_tenant"]["observed_rate"] is None
    assert doc["posterior_claims"] == {}
    assert doc["mix"]["provider"]["shares"] == {}


def test_no_fusion_cohort() -> None:
    # No posteriors (--no-fusion): posterior_claims empty, hideable claims not
    # observable, declarative signals still reported.
    recs = [_rec(provider="Microsoft 365", dmarc_policy="reject") for _ in range(4)]
    doc = build_summary_document(recs)
    assert doc["posterior_claims"] == {}
    assert doc["prevalence"]["m365_tenant"]["observability_fraction"] == 0.0
    assert doc["prevalence"]["dmarc_reject"]["observed_rate"] == 1.0


def test_single_domain_warns() -> None:
    doc = build_summary_document([_rec(provider="Google Workspace", dmarc_policy="none")])
    assert doc["n"] == 1
    assert doc["small_n_warning"] is True


def test_summarize_cohort_has_no_envelope() -> None:
    # The blocks-only function is reused per group by the downstream reducer.
    blocks = summarize_cohort([_rec(provider="Microsoft 365")], "g")
    assert "record_type" not in blocks
    assert set(blocks) == {"label", "n", "small_n_warning", "observability", "prevalence", "posterior_claims", "mix"}


def test_document_contract() -> None:
    # Pins the full v2.1 cohort_summary shape (the stable downstream contract).
    recs = [
        _rec(
            provider="Microsoft 365",
            dmarc_policy="reject",
            cloud_instance="Azure",
            posterior_observations=[_node("m365_tenant", 0.9, 0.84, 0.96)],
        )
        for _ in range(12)
    ]
    doc = build_summary_document(recs, attempted=20)
    assert set(doc) >= {
        "record_type", "schema_version", "disclaimer", "suppression_policy",
        "label", "n", "small_n_warning", "observability", "prevalence", "posterior_claims", "mix",
    }
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.1"
    assert set(doc["observability"]) == {
        "attempted", "resolved", "resolution_rate", "dns_resolved", "degraded_source_rate", "mean_sparse_share",
    }
    signals = ("dmarc_reject", "dmarc_enforcing", "mta_sts_enforce",
               "email_gateway_present", "m365_tenant", "google_workspace")
    for sig in signals:
        assert set(doc["prevalence"][sig]) == {
            "positives", "observable_n", "observed_rate", "observed_rate_interval_80",
            "lower_bound_over_cohort", "observability_fraction",
        }
    assert set(doc["posterior_claims"]["m365_tenant"]) == {
        "expected_prevalence", "high_confidence_share", "mean_interval_width", "sparse_share",
    }
    assert set(doc["mix"]) == {"provider", "cloud"}
    for dim in ("provider", "cloud"):
        assert set(doc["mix"][dim]) == {"shares", "normalized_entropy", "hhi", "categorized_n"}
