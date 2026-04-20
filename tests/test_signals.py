"""Tests for signal loading, validation, and evaluation."""

from __future__ import annotations

from recon_tool.models import SignalContext
from recon_tool.signals import evaluate_signals, load_signals


def _ctx(slugs: set[str], dmarc_policy: str | None = None) -> SignalContext:
    """Helper to build a SignalContext from a slug set."""
    return SignalContext(detected_slugs=frozenset(slugs), dmarc_policy=dmarc_policy)


class TestLoadSignals:
    def test_loads_builtin_signals(self):
        signals = load_signals()
        assert len(signals) > 0
        names = {s.name for s in signals}
        assert "AI Adoption" in names
        assert "High GTM Maturity" in names

    def test_all_signals_have_required_fields(self):
        for signal in load_signals():
            assert signal.name
            # Signals must have either candidates, metadata, or requires_signals
            assert signal.candidates or signal.metadata or signal.requires_signals


class TestEvaluateSignals:
    def test_ai_adoption_fires(self):
        results = evaluate_signals(_ctx({"openai"}))
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_ai_adoption_fires_anthropic(self):
        results = evaluate_signals(_ctx({"anthropic"}))
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_ai_adoption_fires_mistral(self):
        results = evaluate_signals(_ctx({"mistral"}))
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_ai_adoption_fires_perplexity(self):
        results = evaluate_signals(_ctx({"perplexity"}))
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_gtm_maturity_needs_two(self):
        # One tool shouldn't fire
        results = evaluate_signals(_ctx({"hubspot"}))
        names = {r.name for r in results}
        assert "High GTM Maturity" not in names

        # Two tools should fire
        results = evaluate_signals(_ctx({"hubspot", "outreach"}))
        names = {r.name for r in results}
        assert "High GTM Maturity" in names

    def test_modern_collaboration_needs_three(self):
        results = evaluate_signals(_ctx({"slack", "notion"}))
        names = {r.name for r in results}
        assert "Modern Collaboration" not in names

        results = evaluate_signals(_ctx({"slack", "notion", "miro"}))
        names = {r.name for r in results}
        assert "Modern Collaboration" in names

    def test_no_matches_returns_empty(self):
        results = evaluate_signals(_ctx({"nonexistent-slug"}))
        assert results == []

    def test_matched_slugs_included(self):
        results = evaluate_signals(_ctx({"openai", "anthropic"}))
        ai_signal = next(r for r in results if r.name == "AI Adoption")
        assert "openai" in ai_signal.matched
        assert "anthropic" in ai_signal.matched

    def test_description_included_when_present(self):
        results = evaluate_signals(_ctx({"openai"}))
        ai_signal = next(r for r in results if r.name == "AI Adoption")
        assert ai_signal.description
        assert len(ai_signal.description) > 0

    # ── Composite signals (Layer 2) ─────────────────────────────────────

    def test_digital_transformation_needs_four(self):
        results = evaluate_signals(_ctx({"openai", "slack", "notion"}))
        names = {r.name for r in results}
        assert "Digital Transformation" not in names

        results = evaluate_signals(_ctx({"openai", "slack", "notion", "vercel"}))
        names = {r.name for r in results}
        assert "Digital Transformation" in names

    def test_sales_led_growth(self):
        results = evaluate_signals(_ctx({"salesforce", "outreach", "6sense"}))
        names = {r.name for r in results}
        assert "Sales-Led Growth" in names

    def test_product_led_growth(self):
        results = evaluate_signals(_ctx({"mixpanel", "pendo", "intercom"}))
        names = {r.name for r in results}
        assert "Product-Led Growth" in names

    def test_multi_layer_security_tooling(self):
        results = evaluate_signals(_ctx({"okta", "crowdstrike", "proofpoint", "jamf"}))
        names = {r.name for r in results}
        assert "Multi-Layer Security Tooling" in names

    def test_heavy_outbound_stack(self):
        results = evaluate_signals(_ctx({"sendgrid", "mailchimp"}))
        names = {r.name for r in results}
        assert "Heavy Outbound Stack" in names

    # ── Consistency checks (Layer 3) ────────────────────────────────────

    def test_gateway_without_dmarc_fires_when_no_enforcement(self):
        """Gateway present + DMARC none = inconsistency signal fires."""
        results = evaluate_signals(_ctx({"proofpoint"}, dmarc_policy="none"))
        names = {r.name for r in results}
        assert "Security Gap — Gateway Without DMARC Enforcement" in names

    def test_gateway_without_dmarc_fires_when_dmarc_missing(self):
        """Gateway present + no DMARC at all = inconsistency signal fires."""
        results = evaluate_signals(_ctx({"mimecast"}, dmarc_policy=None))
        names = {r.name for r in results}
        assert "Security Gap — Gateway Without DMARC Enforcement" in names

    def test_gateway_with_dmarc_reject_does_not_fire(self):
        """Gateway present + DMARC reject = no inconsistency."""
        results = evaluate_signals(_ctx({"proofpoint"}, dmarc_policy="reject"))
        names = {r.name for r in results}
        assert "Security Gap — Gateway Without DMARC Enforcement" not in names

    def test_gateway_with_dmarc_quarantine_does_not_fire(self):
        """Gateway present + DMARC quarantine = no inconsistency."""
        results = evaluate_signals(_ctx({"trendmicro"}, dmarc_policy="quarantine"))
        names = {r.name for r in results}
        assert "Security Gap — Gateway Without DMARC Enforcement" not in names


class TestReloadFingerprints:
    def test_reload_clears_caches(self):
        from recon_tool.fingerprints import load_fingerprints, reload_fingerprints

        # Load once to populate cache
        fps1 = load_fingerprints()
        # Reload clears cache
        reload_fingerprints()
        # Load again — should work (reloads from disk)
        fps2 = load_fingerprints()
        assert len(fps2) == len(fps1)
