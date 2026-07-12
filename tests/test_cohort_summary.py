"""Tests for recon_tool.cohort_summary's compatible 2.1 and opt-in 2.2 contracts.

Pins the statistics and the honest behaviors: declarative public-claim rates
only after a successful observation opportunity, model support coverage for
hideable claims, model-score aggregation, compositional concentration, and the
edge cases that must not crash (empty cohort, no fusion, single domain).
"""

from __future__ import annotations

import io
from typing import Any

import pytest
from rich.console import Console

from recon_tool.claim_contract import (
    DMARC_EFFECTIVE_POLICY_FIELD,
    DMARC_REJECT_CLAIM_STATE_FIELD,
    ClaimState,
)
from recon_tool.cohort_summary import (
    build_summary_document,
    extract_signals,
    hhi,
    normalized_entropy,
    render_cohort_summary,
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
    if base["dmarc_policy"] in {"none", "quarantine", "reject"} and "evidence" not in base:
        base["evidence"] = [
            {
                "source_type": "DMARC",
                "raw_value": f"v=DMARC1; p={base['dmarc_policy']}",
                "rule_name": "DMARC",
                "slug": "dmarc",
            }
        ]
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
    sig = extract_signals(visible, schema_version="2.2")
    assert sig["dmarc_reject"] is True
    assert sig["m365_tenant"] is True

    hidden = _rec(posterior_observations=[_node("m365_tenant", 0.2, 0.05, 0.5, sparse=True, fired=False)])
    assert extract_signals(hidden, schema_version="2.2")["m365_tenant"] is None  # hideable, not observable

    degraded = _rec(dmarc_policy="reject", degraded_sources=["dns"])
    assert extract_signals(degraded, schema_version="2.2")["dmarc_reject"] is None  # DNS down

    scalar_only = _rec(dmarc_policy="reject")
    assert extract_signals(scalar_only, schema_version="2.2")["dmarc_reject"] is True
    assert (
        build_summary_document([scalar_only], schema_version="2.2")["prevalence"]["dmarc_reject"]["metric_kind"]
        == "atemporal_explicit_policy_rate"
    )
    scalar_without_lineage = dict(scalar_only)
    scalar_without_lineage.pop("evidence")
    assert extract_signals(scalar_without_lineage, schema_version="2.2")["dmarc_reject"] is None

    defaulted_none = _rec(
        dmarc_policy="none",
        evidence=[
            {
                "source_type": "DMARC",
                "raw_value": "v=DMARC1; rua=mailto:dmarc@example.com",
                "rule_name": "DMARC",
                "slug": "dmarc",
            }
        ],
    )
    assert extract_signals(defaulted_none, schema_version="2.2")["dmarc_reject"] is None

    empty = _rec()
    assert extract_signals(empty, schema_version="2.2")["dmarc_reject"] is None
    assert extract_signals(empty, schema_version="2.2")["dmarc_enforcing"] is None

    inconsistent = _rec(
        dmarc_policy="none",
        **{DMARC_REJECT_CLAIM_STATE_FIELD: ClaimState.SUPPORTED.value},
    )
    assert extract_signals(inconsistent, schema_version="2.2")["dmarc_reject"] is False
    assert extract_signals(inconsistent, schema_version="2.2")["dmarc_enforcing"] is False


def test_contract_and_atemporal_dmarc_modes_do_not_fall_back_into_each_other() -> None:
    raw_only = _rec(dmarc_policy="reject")
    strict = extract_signals(
        raw_only,
        schema_version="2.2",
        dmarc_contract_scoped=True,
    )
    assert strict["dmarc_reject"] is None
    assert strict["dmarc_enforcing"] is None

    transient_only = _rec(
        dmarc_policy="reject",
        evidence=[],
        **{
            DMARC_REJECT_CLAIM_STATE_FIELD: ClaimState.SUPPORTED.value,
            DMARC_EFFECTIVE_POLICY_FIELD: "reject",
        },
    )
    assert extract_signals(transient_only, schema_version="2.2")["dmarc_reject"] is None
    strict = extract_signals(
        transient_only,
        schema_version="2.2",
        dmarc_contract_scoped=True,
    )
    assert strict["dmarc_reject"] is True
    assert strict["dmarc_enforcing"] is True


@pytest.mark.parametrize(
    ("record", "enforcing"),
    [
        ("v=DMARC1; p=quarantine; t=y", False),
        ("v=DMARC1; p=reject; t=y", True),
        ("v=DMARC1; p=quarantine; pct=50", False),
        ("v=DMARC1; p=quarantine; t=y ", True),
        ("v=DMARC1; p=quarantine; pct=50 ", True),
        (f"v=DMARC1; p=quarantine; pct={'0' * 5000}", True),
        ("v=DMARC1; p=quarantine; pct=0000", True),
    ],
)
def test_atemporal_enforcement_uses_raw_bound_effective_policy(record: str, enforcing: bool) -> None:
    policy = "reject" if "p=reject" in record else "quarantine"
    result = extract_signals(
        _rec(
            dmarc_policy=policy,
            evidence=[
                {
                    "source_type": "DMARC",
                    "raw_value": record,
                    "rule_name": "DMARC",
                    "slug": "dmarc",
                }
            ],
        ),
        schema_version="2.2",
    )
    assert result["dmarc_reject"] is (policy == "reject")
    assert result["dmarc_enforcing"] is enforcing


@pytest.mark.parametrize(
    ("marker", "unavailable"),
    [
        ("dns", {"dmarc_reject", "dmarc_enforcing", "mta_sts_enforce", "email_gateway_present"}),
        ("dns_records", {"dmarc_reject", "dmarc_enforcing", "mta_sts_enforce", "email_gateway_present"}),
        ("dns:dmarc", {"dmarc_reject", "dmarc_enforcing"}),
        ("dns:mta_sts", {"mta_sts_enforce"}),
        ("http:mta_sts_policy", {"mta_sts_enforce"}),
        ("detector:email_security", {"dmarc_reject", "dmarc_enforcing", "mta_sts_enforce"}),
        ("dns:mx", {"email_gateway_present"}),
        ("detector:mx", {"email_gateway_present"}),
    ],
)
def test_extract_signals_masks_only_degraded_collection_channels(marker: str, unavailable: set[str]) -> None:
    signals = extract_signals(
        _rec(
            dmarc_policy="reject",
            mta_sts_mode="enforce",
            email_gateway="Proofpoint",
            degraded_sources=[marker],
        ),
        schema_version="2.2",
    )

    observed = {"dmarc_reject", "dmarc_enforcing", "mta_sts_enforce", "email_gateway_present"} - unavailable
    assert all(signals[name] is None for name in unavailable)
    assert all(signals[name] is True for name in observed)


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
    doc = build_summary_document(recs, "c", attempted=8, schema_version="2.2")
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.2"
    assert doc["n"] == 5
    assert doc["observability"]["attempted"] == 8
    assert doc["observability"]["resolution_rate"] == 0.625
    assert doc["mix"]["provider"]["shares"] == {"Microsoft 365": 1.0}
    assert doc["mix"]["provider"]["hhi"] == 1.0
    assert doc["prevalence"]["dmarc_reject"]["observed_rate"] == 1.0


def test_v21_default_preserves_released_denominators_and_metric_kinds() -> None:
    records = [
        _rec(dmarc_policy="reject", mta_sts_mode="enforce", email_gateway="Proofpoint"),
        _rec(),
    ]

    doc = build_summary_document(records)

    assert doc["schema_version"] == "2.1"
    assert doc["prevalence"]["dmarc_reject"]["observable_n"] == 2
    assert doc["prevalence"]["dmarc_reject"]["observed_rate"] == 0.5
    assert doc["prevalence"]["dmarc_reject"]["metric_kind"] == "authoritative_observed_rate"
    assert doc["prevalence"]["mta_sts_enforce"]["observable_n"] == 2
    assert doc["prevalence"]["email_gateway_present"]["metric_kind"] == "authoritative_observed_rate"


def test_v22_scopes_mta_sts_and_rejects_incompatible_contract_mode() -> None:
    doc = build_summary_document(
        [_rec(mta_sts_mode="enforce"), _rec()],
        schema_version="2.2",
    )
    metric = doc["prevalence"]["mta_sts_enforce"]
    assert metric["metric_kind"] == "scoped_observed_rate"
    assert metric["observable_n"] == 1
    assert metric["observed_rate"] == 1.0

    with pytest.raises(ValueError, match=r"requires cohort schema 2\.2"):
        build_summary_document(
            [],
            schema_version="2.1",
            dmarc_contract_scoped=True,
        )


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
    # Pins the full opt-in v2.2 cohort_summary shape.
    recs = [
        _rec(
            provider="Microsoft 365",
            dmarc_policy="reject",
            cloud_instance="Azure",
            posterior_observations=[_node("m365_tenant", 0.9, 0.84, 0.96)],
        )
        for _ in range(12)
    ]
    doc = build_summary_document(recs, attempted=20, schema_version="2.2")
    assert set(doc) >= {
        "record_type",
        "schema_version",
        "disclaimer",
        "suppression_policy",
        "label",
        "n",
        "small_n_warning",
        "observability",
        "prevalence",
        "posterior_claims",
        "mix",
    }
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.2"
    assert set(doc["observability"]) == {
        "attempted",
        "resolved",
        "resolution_rate",
        "dns_resolved",
        "degraded_source_rate",
        "mean_sparse_share",
    }
    signals = (
        "dmarc_reject",
        "dmarc_enforcing",
        "mta_sts_enforce",
        "email_gateway_present",
        "m365_tenant",
        "google_workspace",
    )
    for sig in signals:
        assert set(doc["prevalence"][sig]) == {
            "positives",
            "observable_n",
            "observed_rate",
            "observed_rate_interval_80",
            "lower_bound_over_cohort",
            "observability_fraction",
            "metric_kind",
            "model_evidence_n",
            "support_coverage",
            "unresolved_share",
        }
    assert set(doc["posterior_claims"]["m365_tenant"]) == {
        "expected_prevalence",
        "high_confidence_share",
        "mean_model_score",
        "high_score_share",
        "mean_interval_width",
        "sparse_share",
        "observed_n",
    }
    assert set(doc["mix"]) == {"provider", "cloud"}
    for dim in ("provider", "cloud"):
        assert set(doc["mix"][dim]) == {"shares", "normalized_entropy", "hhi", "categorized_n"}


# --- 2.1.1 hardening regressions ---


def test_mix_order_deterministic_under_ties() -> None:
    # Tied counts must order identically regardless of input order (count desc,
    # then key ascending), not by non-deterministic insertion order.
    a = [_rec(provider="Microsoft 365"), _rec(provider="Google Workspace")] * 3
    b = [_rec(provider="Google Workspace"), _rec(provider="Microsoft 365")] * 3
    sa = list(build_summary_document(a)["mix"]["provider"]["shares"])
    sb = list(build_summary_document(b)["mix"]["provider"]["shares"])
    assert sa == sb == ["Google Workspace", "Microsoft 365"]


def test_wilson_clamps_positives_over_n() -> None:
    low, high = wilson_interval(15, 10)  # positives > n must not raise
    assert 0.0 <= low <= high <= 1.0


def test_resolution_rate_never_exceeds_one() -> None:
    recs = [_rec(provider="Microsoft 365") for _ in range(5)]
    doc = build_summary_document(recs, attempted=2)  # attempted < resolved (bad input)
    assert doc["observability"]["resolution_rate"] == 1.0
    assert doc["observability"]["attempted"] == 5


def test_malformed_posteriors_do_not_crash_or_poison_json() -> None:
    import json
    import math as _m

    # None, non-numeric, NaN/inf, and an inverted interval must coerce safely.
    recs = [
        _rec(
            posterior_observations=[
                {
                    "name": "m365_tenant",
                    "posterior": None,
                    "interval_low": 0.5,
                    "interval_high": 0.2,
                    "evidence_used": ["slug:x"],
                    "sparse": False,
                }
            ]
        ),
        _rec(
            posterior_observations=[
                {
                    "name": "m365_tenant",
                    "posterior": "high",
                    "interval_low": float("nan"),
                    "interval_high": float("inf"),
                    "evidence_used": ["slug:x"],
                    "sparse": False,
                }
            ]
        ),
    ]
    doc = build_summary_document(recs)
    claim = doc["posterior_claims"]["m365_tenant"]
    assert 0.0 <= claim["expected_prevalence"] <= 1.0
    assert claim["mean_interval_width"] >= 0.0  # inverted interval never goes negative
    assert _m.isfinite(claim["expected_prevalence"])
    assert claim["mean_model_score"] == claim["expected_prevalence"]
    assert _m.isfinite(claim["mean_interval_width"])
    assert "NaN" not in json.dumps(doc)  # no bare NaN tokens in the JSON


def test_hideable_model_support_is_not_reported_as_prevalence() -> None:
    recs = [
        _rec(posterior_observations=[_node("m365_tenant", 0.9, 0.8, 0.95)]),
        _rec(posterior_observations=[_node("m365_tenant", 0.3, 0.1, 0.6)]),
        _rec(),
    ]

    metric = build_summary_document(recs)["prevalence"]["m365_tenant"]

    assert metric["metric_kind"] == "model_support_coverage"
    assert metric["model_evidence_n"] == 2
    assert metric["support_coverage"] == 0.3333
    assert metric["unresolved_share"] == 0.6667
    assert metric["observed_rate"] is None
    assert metric["lower_bound_over_cohort"] is None
    assert metric["observable_n"] == 0

    gateway = build_summary_document(
        [_rec(email_gateway="Proofpoint"), _rec(email_gateway=None)],
        schema_version="2.2",
    )["prevalence"]["email_gateway_present"]
    assert gateway["metric_kind"] == "model_support_coverage"
    assert gateway["support_coverage"] == 0.5
    assert gateway["observed_rate"] is None


def test_malformed_record_fields_do_not_crash() -> None:
    # Non-list posterior_observations / degraded_sources / slugs from arbitrary
    # JSON must coerce to empty rather than raise.
    recs = [
        {
            "provider": "Microsoft 365",
            "dmarc_policy": "reject",
            "cloud_instance": None,
            "mta_sts_mode": None,
            "email_gateway": None,
            "posterior_observations": 5,
            "degraded_sources": "dns",
            "slugs": "x",
        }
    ]
    doc = build_summary_document(recs, schema_version="2.2")  # must not raise
    assert doc["n"] == 1
    assert doc["posterior_claims"] == {}
    assert doc["observability"]["dns_resolved"] == 0
    assert doc["prevalence"]["dmarc_reject"]["observable_n"] == 0


def test_unhashable_posterior_name_is_skipped() -> None:
    # A malformed record with a list/dict name must be skipped, not raise
    # TypeError when used as a dict key.
    recs = [
        _rec(
            posterior_observations=[
                {
                    "name": ["m365_tenant"],
                    "posterior": 0.9,
                    "interval_low": 0.8,
                    "interval_high": 0.95,
                    "evidence_used": ["x"],
                    "sparse": False,
                },
                {
                    "name": "m365_tenant",
                    "posterior": 0.92,
                    "interval_low": 0.85,
                    "interval_high": 0.97,
                    "evidence_used": ["x"],
                    "sparse": False,
                },
            ]
        )
    ]
    doc = build_summary_document(recs)  # must not raise
    assert "m365_tenant" in doc["posterior_claims"]  # the valid string-named entry counts


def test_panel_strips_control_chars_from_record_strings() -> None:
    # A hostile cloud_instance (influenceable via OIDC discovery) must not inject
    # terminal escapes into the operator's panel.
    recs = [_rec(provider="Microsoft 365", cloud_instance="evil\x1b[31mred\x07") for _ in range(3)]
    console = Console(file=io.StringIO(), width=82, force_terminal=False)
    console.print(render_cohort_summary(build_summary_document(recs)))
    out = console.file.getvalue()
    assert "\x1b" not in out
    assert "\x07" not in out
