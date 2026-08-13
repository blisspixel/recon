"""Structural-identifiability checks for the frozen v2.11 M365 arms."""

from __future__ import annotations

import json

import pytest

from validation.quality_arm_identifiability import (
    DNS_EVIDENCE_TYPES,
    evaluate_state,
    main,
    run_audit,
)


def test_exhaustive_audit_proves_candidate_cannot_beat_baseline() -> None:
    report = run_audit()

    assert report["network_requests"] == 0
    assert report["private_rows_read"] == 0
    assert report["enumerated_states"] == 64
    relationships = report["arm_relationships"]
    assert relationships["a1_equals_a0_all_states"] is True
    assert relationships["a2_equals_a3_all_states"] is True
    assert relationships["a3_implies_a0_all_states"] is True
    assert relationships["candidate_only_state_count"] == 0
    assert relationships["baseline_only_state_count"] == 3
    assert relationships["baseline_only_evidence_types"] == [["TXT"], ["SPF"], ["TXT", "SPF"]]
    assert len(relationships["a1_possible_scores"]) == 24
    assert min(relationships["a1_possible_scores"]) == 0.6
    assert max(relationships["a1_possible_scores"]) == 0.9394
    assert report["decision_consequence"] == {
        "candidate_only_positive_discordance_b_is_always_zero": True,
        "benefit_lower_bound_can_clear_zero": False,
        "live_ablation_identifies_fusion_benefit": False,
        "collection_disposition": "cancel-before-contact",
    }


@pytest.mark.parametrize("source_type", DNS_EVIDENCE_TYPES)
def test_each_abstract_state_uses_shipped_role_semantics(source_type: str) -> None:
    state = evaluate_state((source_type,))

    assert state.a0_supported is True
    assert state.a1_supported is True
    assert state.role_signal_observed is (source_type in {"MX", "DKIM", "CNAME", "SRV"})
    assert state.a2_supported is state.role_signal_observed
    assert state.a3_supported is state.role_signal_observed


def test_empty_state_abstains_in_every_arm() -> None:
    state = evaluate_state(())

    assert state.a0_supported is False
    assert state.a1_supported is False
    assert state.a2_supported is False
    assert state.a3_supported is False
    assert state.a1_score is None
    assert state.a3_posterior == 0.3


def test_state_validation_rejects_duplicates_and_reordering() -> None:
    with pytest.raises(ValueError, match="unique and follow the frozen order"):
        evaluate_state(("MX", "TXT"))
    with pytest.raises(ValueError, match="unique and follow the frozen order"):
        evaluate_state(("TXT", "TXT"))


def test_cli_emits_aggregate_json_only(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    report = json.loads(capsys.readouterr().out)

    assert report["scope"] == "v2.11-m365-dns-arm-structural-identifiability"
    assert "domain" not in json.dumps(report).casefold()
