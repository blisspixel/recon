"""Tests for --confidence-mode strict (v0.11).

Strict mode drops hedging qualifiers on dense-evidence targets. Sparse-data
output is never touched — the invariant "never overclaim when evidence is
thin" stays load-bearing.
"""

from __future__ import annotations

from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.strict_mode import (
    STRICT_SOURCE_THRESHOLD,
    apply_strict_mode,
    should_apply_strict,
)


def _info(
    sources: tuple[str, ...] = ("oidc_discovery", "userrealm", "dns_records", "google_identity"),
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> TenantInfo:
    return TenantInfo(
        tenant_id="t1",
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=confidence,
        sources=sources,
    )


class TestShouldApplyStrict:
    def test_gate_high_confidence_three_plus_sources(self) -> None:
        info = _info(sources=("a", "b", "c"), confidence=ConfidenceLevel.HIGH)
        assert should_apply_strict(info, "strict") is True

    def test_gate_high_confidence_two_sources_blocks(self) -> None:
        info = _info(sources=("a", "b"), confidence=ConfidenceLevel.HIGH)
        assert should_apply_strict(info, "strict") is False

    def test_gate_medium_confidence_blocks(self) -> None:
        info = _info(sources=("a", "b", "c", "d"), confidence=ConfidenceLevel.MEDIUM)
        assert should_apply_strict(info, "strict") is False

    def test_gate_low_confidence_blocks(self) -> None:
        info = _info(sources=("a", "b", "c", "d"), confidence=ConfidenceLevel.LOW)
        assert should_apply_strict(info, "strict") is False

    def test_hedged_mode_never_applies_strict(self) -> None:
        info = _info(sources=("a", "b", "c", "d"), confidence=ConfidenceLevel.HIGH)
        assert should_apply_strict(info, "hedged") is False

    def test_threshold_constant(self) -> None:
        """Threshold matches the same bar as ConfidenceLevel.HIGH in merger."""
        assert STRICT_SOURCE_THRESHOLD == 3


class TestApplyStrictMode:
    def test_drops_indicators_qualifier(self) -> None:
        result = apply_strict_mode(("M365 E3+ indicators (Intune enrolled)",))
        assert result == ("M365 E3+ (Intune enrolled)",)

    def test_drops_likely_qualifier(self) -> None:
        result = apply_strict_mode(("Federated identity (likely ADFS/Okta/Ping — enterprise SSO)",))
        assert "(likely" not in result[0]
        assert "Federated identity" in result[0]

    def test_drops_indicators_observed_compound(self) -> None:
        result = apply_strict_mode(("Federated identity indicators observed (likely Okta)",))
        assert "indicators" not in result[0]
        assert "observed" not in result[0]
        assert "likely" not in result[0]

    def test_drops_observed_parenthetical(self) -> None:
        result = apply_strict_mode(("Dual provider insight here (observed)",))
        assert "(observed)" not in result[0]

    def test_preserves_factual_scores(self) -> None:
        """The email security score is factual — strict mode doesn't touch it."""
        text = "Email security 4/5 strong (DMARC reject, DKIM, SPF strict, MTA-STS)"
        result = apply_strict_mode((text,))
        assert result == (text,)

    def test_preserves_direct_insights(self) -> None:
        """Already-direct insights pass through unchanged."""
        text = "AI Adoption: OpenAI, Anthropic"
        result = apply_strict_mode((text,))
        assert result == (text,)

    def test_transforms_likely_azure_china(self) -> None:
        result = apply_strict_mode(("Likely Azure China 21Vianet tenant (cloud_instance=partner.microsoftonline.cn)",))
        assert "Likely" not in result[0]
        assert "Azure China 21Vianet tenant" in result[0]

    def test_collapses_double_spaces(self) -> None:
        """Replacements must not leave double spaces behind."""
        # "indicators (" → " (" creates a single space; ensure no leftover doubles
        result = apply_strict_mode(("Service indicators   (detail)",))
        assert "   " not in result[0]

    def test_empty_tuple(self) -> None:
        assert apply_strict_mode(()) == ()
