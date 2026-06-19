from __future__ import annotations

import json

import pytest

from validation.render_calibration_memo import main as memo_main
from validation.render_calibration_memo import render_memo, validate_public_payload

REFERENCE_SINGLE = {
    "mode": "single",
    "n": 30,
    "full": {
        "n": 30,
        "base_rate_enforcing": 0.6,
        "brier": 0.08,
        "log_score": 0.24,
        "ece": 0.04,
        "agreement_rate": 0.9,
    },
    "held_out": {
        "n": 30,
        "base_rate_enforcing": 0.6,
        "brier": 0.23,
        "log_score": 0.67,
        "ece": 0.18,
        "agreement_rate": 0.57,
    },
}

TENANCY_SINGLE = {
    "mode": "single",
    "counts": {
        "resolved": 30,
        "resolve_failed": 0,
        "no_dns_channel": 0,
        "m365_positive": 18,
        "m365_negative": 12,
        "m365_unlabeled": 0,
        "m365_conflict": 0,
        "gws_attested": 4,
    },
    "m365_dns_only": {
        "n": 30,
        "base_rate_enforcing": 0.6,
        "brier": 0.2,
        "log_score": 0.55,
        "ece": 0.12,
        "agreement_rate": 0.7,
    },
    "m365_full": {
        "n": 30,
        "base_rate_enforcing": 0.6,
        "brier": 0.03,
        "log_score": 0.11,
        "ece": 0.02,
        "agreement_rate": 0.97,
    },
    "gws_one_sided": {
        "n": 4,
        "threshold": 0.5,
        "recall": 0.75,
        "recall_wilson80": [0.41, 0.93],
        "posterior_quartiles": [0.51, 0.63, 0.81],
    },
}

CONFORMAL_SINGLE = {
    "mode": "single",
    "node": "email_security_policy_enforcing",
    "construction": "split_conformal",
    "summary": {
        "n": 30.0,
        "trials": 20.0,
        "target_coverage": 0.9,
        "mean_coverage": 0.93,
        "min_coverage": 0.87,
        "mean_set_size": 1.21,
    },
}


def test_render_memo_includes_aggregate_sections_only() -> None:
    memo = render_memo(
        title="Aggregate Calibration Validation Memo",
        reference=REFERENCE_SINGLE,
        tenancy=TENANCY_SINGLE,
        conformal=CONFORMAL_SINGLE,
    )

    assert "Email Policy Reference Calibration" in memo
    assert "Tenancy Provider Corroboration" in memo
    assert "Conformal Coverage" in memo
    assert "30" in memo
    assert "apexes" in memo.lower()
    assert "tenant IDs" in memo
    assert "contoso" not in memo.lower()
    assert "fabrikam" not in memo.lower()


def test_validate_public_payload_rejects_target_fields() -> None:
    with pytest.raises(ValueError, match="queried_domain"):
        validate_public_payload("reference", {"queried_domain": "nonfiction.example.org"})
    with pytest.raises(ValueError, match="tenant_id"):
        validate_public_payload("tenancy", {"tenant_id": "00000000-0000-0000-0000-000000000000"})


def test_validate_public_payload_rejects_domain_values_under_other_keys() -> None:
    with pytest.raises(ValueError, match="target-looking domain"):
        validate_public_payload("reference", {"source": "private-corpus.example"})


def test_validate_public_payload_rejects_unsuppressed_small_strata() -> None:
    payload = {
        "mode": "stratified",
        "full": {
            "min_cell": 10,
            "pooled": {"n": 13},
            "strata": {
                "tiny": {"n": 3, "ece": 0.1},
                "large": {"n": 10, "ece": 0.2},
            },
        },
    }
    with pytest.raises(ValueError, match="not suppressed"):
        validate_public_payload("reference", payload)


def test_validate_public_payload_allows_suppressed_small_strata() -> None:
    payload = {
        "mode": "stratified",
        "full": {
            "min_cell": 10,
            "pooled": {"n": 13},
            "strata": {
                "tiny": {"n": 3, "suppressed": True},
                "large": {"n": 10, "ece": 0.2},
            },
        },
    }
    validate_public_payload("reference", payload)


def test_main_writes_memo_from_json_inputs(tmp_path) -> None:
    reference = tmp_path / "reference.json"
    tenancy = tmp_path / "tenancy.json"
    conformal = tmp_path / "conformal.json"
    output = tmp_path / "memo.md"
    reference.write_text(json.dumps(REFERENCE_SINGLE), encoding="utf-8")
    tenancy.write_text(json.dumps(TENANCY_SINGLE), encoding="utf-8")
    conformal.write_text(json.dumps(CONFORMAL_SINGLE), encoding="utf-8")

    rc = memo_main(
        [
            "--reference",
            str(reference),
            "--tenancy",
            str(tenancy),
            "--conformal",
            str(conformal),
            "--output",
            str(output),
        ]
    )

    assert rc == 0
    text = output.read_text(encoding="utf-8")
    assert "Disclosure Controls" in text
    assert "Conformal Coverage" in text
