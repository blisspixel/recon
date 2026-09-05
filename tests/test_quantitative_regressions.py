"""Synthetic arithmetic regressions, not population or security validation."""

from __future__ import annotations

import itertools
import json
import math
from dataclasses import replace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from recon_tool.cohort_summary import build_summary_document, hhi, normalized_entropy, shannon_entropy
from recon_tool.exposure_models import DMARC_COMPONENT_ID
from recon_tool.exposure_scoring import compute_exposure_index
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.server.posture_simulation import simulate_fixes


@pytest.mark.parametrize("scale", [1e-300, 1.0, 1e308])
def test_concentration_preserves_equal_mix_under_finite_scaling(scale: float) -> None:
    counts = [scale, scale]
    assert shannon_entropy(counts) == pytest.approx(1.0)
    assert normalized_entropy(counts) == pytest.approx(1.0)
    assert hhi(counts) == pytest.approx(0.5)


def test_concentration_extreme_finite_imbalance_and_integer_counts() -> None:
    # The tiny category's fraction underflows, not the large category's total.
    counts = [1e308, 1e-300]
    assert shannon_entropy(counts) == pytest.approx(0.0)
    assert normalized_entropy(counts) == pytest.approx(0.0)
    assert hhi(counts) == pytest.approx(1.0)
    # Python integers can represent exact counts beyond the float range.
    assert hhi([10**400, 10**400]) == pytest.approx(0.5)
    assert shannon_entropy([10**400, 10**400]) == pytest.approx(1.0)


def test_concentration_matches_hand_computable_unequal_mix_in_every_order() -> None:
    expected_entropy = -0.25 * math.log2(0.25) - 0.75 * math.log2(0.75)
    for counts in itertools.permutations([0.0, 1e307, 3e307]):
        assert shannon_entropy(counts) == pytest.approx(expected_entropy)
        assert normalized_entropy(counts) == pytest.approx(expected_entropy)
        assert hhi(counts) == pytest.approx(0.25**2 + 0.75**2)


@pytest.mark.parametrize("counts", [[], [0.0, -1.0], [float("nan"), 0.0]])
def test_concentration_retains_empty_and_nonpositive_input_semantics(counts: list[float]) -> None:
    assert shannon_entropy(counts) == 0.0
    assert normalized_entropy(counts) == 0.0
    assert hhi(counts) == 0.0


@pytest.mark.parametrize("counts", [[math.inf], [math.inf, 1.0], [0.0, math.inf]])
def test_unbounded_positive_concentration_counts_fail_explicitly(counts: list[float]) -> None:
    for metric in (shannon_entropy, normalized_entropy, hhi):
        with pytest.raises(ValueError, match="must be finite"):
            metric(counts)


@pytest.mark.parametrize(
    ("low", "high", "posterior", "expected_width"),
    [
        (-1e308, 1e308, 0.5, 1.0),
        (0.0, 1e308, 0.5, 1.0),
        (1e308, -1e308, 0.5, 0.0),
        (0.0, 10**400, 10**400, 0.0),
        (0.0, "1e999", None, 0.0),
        (0.2, 0.8, 0.5, 0.6),
    ],
)
def test_external_cohort_numeric_values_cannot_poison_summary_json(
    low: Any, high: Any, posterior: Any, expected_width: float
) -> None:
    row = {
        "posterior_observations": [
            {
                "name": "m365_tenant",
                "posterior": posterior,
                "interval_low": low,
                "interval_high": high,
                "sparse": False,
                "evidence_used": ["synthetic"],
            }
        ]
    }
    # Exercise the arbitrary-JSON boundary, including very large valid integers.
    rows = json.loads(json.dumps([row, row], allow_nan=False))
    result = build_summary_document(rows)
    metrics = result["posterior_claims"]["m365_tenant"]
    assert metrics["mean_interval_width"] == pytest.approx(expected_width)
    assert 0.0 <= metrics["mean_model_score"] <= 1.0
    assert metrics["observed_n"] == 2
    json.dumps(result, allow_nan=False)


def _dmarc_info(policy: str, pct: int | None, testing: bool = False) -> TenantInfo:
    raw = f"v=DMARC1; p={policy}"
    if pct is not None:
        raw += f"; pct={pct}"
    if testing:
        raw += "; t=y"
    return TenantInfo(
        tenant_id=None,
        display_name="alpha.invalid",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        services=("DMARC",),
        slugs=("dmarc",),
        dmarc_policy=policy,
        dmarc_pct=pct,
        dmarc_testing=testing,
        evidence=(EvidenceRecord("DMARC", raw, "DMARC", "dmarc"),),
    )


@pytest.mark.parametrize(
    ("policy", "pct", "testing"),
    [("reject", 0, False), ("reject", 50, True), ("quarantine", 0, False), ("quarantine", 100, True)],
)
@pytest.mark.parametrize("supply_ledger", [False, True])
def test_quarantine_fix_uses_effective_component_value_not_nominal_policy(
    policy: str, pct: int | None, testing: bool, supply_ledger: bool
) -> None:
    info = _dmarc_info(policy, pct, testing)
    current = compute_exposure_index(info)
    original_evidence = info.evidence
    assert current.score_floor == 0
    applied, state = simulate_fixes(
        ["dmarc quarantine", "dmarc quarantine"], info, current.components if supply_ledger else ()
    )
    hypothetical = replace(
        info,
        dmarc_policy=state.dmarc,
        dmarc_pct=state.dmarc_pct,
        dmarc_testing=state.dmarc_testing,
        evidence=tuple(state.evidence),
    )
    simulated = compute_exposure_index(hypothetical, hypothetical_components=frozenset(state.hypothetical_components))
    assert applied == ["DMARC policy set to quarantine"]
    assert simulated.score_floor == 12
    component = next(c for c in simulated.components if c.component_id == DMARC_COMPONENT_ID)
    assert component.state == "hypothetical_value"
    assert component.awarded_points == 12
    assert state.dmarc_pct is None
    assert state.dmarc_testing is False
    assert info.evidence == original_evidence


@pytest.mark.parametrize(
    ("policy", "pct", "testing"),
    [("reject", 100, False), ("reject", 50, False), ("reject", 100, True), ("quarantine", 100, False)],
)
def test_quarantine_fix_never_downgrades_an_exact_sufficient_component(
    policy: str, pct: int | None, testing: bool
) -> None:
    info = _dmarc_info(policy, pct, testing)
    current = compute_exposure_index(info)
    for ledger in ((), current.components):
        applied, state = simulate_fixes(["dmarc quarantine"], info, ledger)
        assert applied == []
        assert state.hypothetical_components == set()
        assert state.evidence == list(info.evidence)
        assert state.dmarc == policy
        assert state.dmarc_pct == pct
        assert state.dmarc_testing is testing


@pytest.mark.asyncio
async def test_public_simulation_reports_the_correct_hypothetical_delta(monkeypatch: pytest.MonkeyPatch) -> None:
    from recon_tool.server import app as server_app
    from recon_tool.server.posture import simulate_hardening

    info = _dmarc_info("reject", 0)
    resolve = AsyncMock(return_value=(info, []))
    monkeypatch.setattr(server_app, "resolve_or_cache", resolve)
    result = await simulate_hardening("alpha.invalid", ["DMARC quarantine"])
    assert result["current_score"] == 0
    assert result["simulated_score"] == 12
    assert result["score_delta"] == 12
    assert result["applied_fixes"] == ["DMARC policy set to quarantine"]
    component = next(
        c for c in result["simulated_observability"]["components"] if c["component_id"] == DMARC_COMPONENT_ID
    )
    assert component["state"] == "hypothetical_value"
    assert component["awarded_points"] == 12
    resolve.assert_awaited_once_with("alpha.invalid")
