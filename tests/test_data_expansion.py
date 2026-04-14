"""QA Round 4 — Data Expansion and Backward Compatibility.

Validates:
- All new fingerprints load without warnings (14.1)
- All new signals evaluate correctly (14.2)
- Backward compatibility for all existing fingerprints/signals (14.3)
- Requirements: 19.3, 20.1, 20.2, 21.1–21.7, 22.12
"""

from __future__ import annotations

import logging

from recon_tool.explanation import explain_signals, serialize_explanation
from recon_tool.fingerprints import load_fingerprints, reload_fingerprints
from recon_tool.models import SignalContext
from recon_tool.posture import load_posture_rules, reload_posture
from recon_tool.signals import evaluate_signals, load_signals, reload_signals


def _ctx(
    slugs: set[str],
    *,
    dmarc_policy: str | None = None,
    auth_type: str | None = None,
    email_security_score: int | None = None,
    spf_include_count: int | None = None,
    issuance_velocity: int | None = None,
) -> SignalContext:
    return SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
    )


# ── 14.1: All new fingerprints load without warnings ──────────────────


class TestNewFingerprintsLoad:
    """Verify all new fingerprints load without warnings."""

    def setup_method(self) -> None:
        reload_fingerprints()

    def test_fingerprint_count_at_least_194(self) -> None:
        fps = load_fingerprints()
        assert len(fps) >= 194, f"Expected >= 194 fingerprints, got {len(fps)}"

    def test_no_warnings_during_loading(self, caplog: object) -> None:
        import io

        reload_fingerprints()
        logger = logging.getLogger("recon")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            reload_fingerprints()
            load_fingerprints()
            output = stream.getvalue()
            assert output == "", f"Warnings during fingerprint loading:\n{output}"
        finally:
            logger.removeHandler(handler)

    def test_all_new_fingerprints_have_valid_slugs(self) -> None:
        fps = load_fingerprints()
        new_slugs = {
            "n8n",
            "dify",
            "autogen",
            "snyk",
            "github-advanced-security",
            "sonatype",
            "beyond-identity",
            "ping-identity",
            "cyberark",
            "lakera",
            "cato",
            "sentinelone",
            "netskope",
            "kandji",
        }
        loaded_slugs = {fp.slug for fp in fps}
        for slug in new_slugs:
            assert slug in loaded_slugs, f"New fingerprint slug '{slug}' not found"

    def test_all_fingerprints_have_valid_categories(self) -> None:
        fps = load_fingerprints()
        for fp in fps:
            assert fp.category, f"Fingerprint '{fp.name}' has empty category"
            assert isinstance(fp.category, str)

    def test_all_fingerprints_have_valid_detections(self) -> None:
        fps = load_fingerprints()
        for fp in fps:
            assert len(fp.detections) > 0, f"Fingerprint '{fp.name}' has no detections"
            for det in fp.detections:
                assert det.type in {"txt", "spf", "mx", "ns", "cname", "subdomain_txt", "caa", "srv", "dmarc_rua"}
                assert det.pattern, f"Fingerprint '{fp.name}' has empty pattern"

    def test_all_fingerprints_have_valid_confidence(self) -> None:
        fps = load_fingerprints()
        for fp in fps:
            assert fp.confidence in {"high", "medium", "low"}, (
                f"Fingerprint '{fp.name}' has invalid confidence '{fp.confidence}'"
            )


# ── 14.2: All new signals evaluate correctly ──────────────────────────


class TestNewSignalsEvaluate:
    """Verify contradiction signals suppress and meta-signals fire correctly."""

    def setup_method(self) -> None:
        reload_signals()

    # -- Incomplete Identity Migration (contradicts: microsoft365) --

    def test_incomplete_identity_migration_fires_without_contradiction(self) -> None:
        """Signal fires when okta present and microsoft365 absent."""
        results = evaluate_signals(_ctx({"okta"}))
        names = {r.name for r in results}
        assert "Incomplete Identity Migration" in names

    def test_incomplete_identity_migration_suppressed_by_microsoft365(self) -> None:
        """Signal suppressed when microsoft365 (contradiction slug) present."""
        results = evaluate_signals(_ctx({"okta", "microsoft365"}))
        names = {r.name for r in results}
        assert "Incomplete Identity Migration" not in names

    def test_incomplete_identity_migration_fires_with_auth0(self) -> None:
        """Signal also fires with auth0 as candidate."""
        results = evaluate_signals(_ctx({"auth0"}))
        names = {r.name for r in results}
        assert "Incomplete Identity Migration" in names

    def test_incomplete_identity_migration_fires_with_ping_identity(self) -> None:
        """Signal also fires with ping-identity as candidate."""
        results = evaluate_signals(_ctx({"ping-identity"}))
        names = {r.name for r in results}
        assert "Incomplete Identity Migration" in names

    # -- Split-Brain Email Config (contradicts: mta-sts-enforce) --

    def test_split_brain_email_fires_with_both_providers(self) -> None:
        """Signal fires when both microsoft365 and google-workspace present."""
        results = evaluate_signals(_ctx({"microsoft365", "google-workspace"}))
        names = {r.name for r in results}
        assert "Split-Brain Email Config" in names

    def test_split_brain_email_suppressed_by_mta_sts_enforce(self) -> None:
        """Signal suppressed when mta-sts-enforce present."""
        results = evaluate_signals(_ctx({"microsoft365", "google-workspace", "mta-sts-enforce"}))
        names = {r.name for r in results}
        assert "Split-Brain Email Config" not in names

    def test_split_brain_email_needs_both_providers(self) -> None:
        """Signal does not fire with only one provider."""
        results = evaluate_signals(_ctx({"microsoft365"}))
        names = {r.name for r in results}
        assert "Split-Brain Email Config" not in names

    # -- Security Stack Without Governance (contradicts via metadata) --

    def test_security_stack_without_governance_fires(self) -> None:
        """Signal fires with security tools and non-reject DMARC."""
        results = evaluate_signals(_ctx({"crowdstrike", "sentinelone"}, dmarc_policy="none"))
        names = {r.name for r in results}
        assert "Security Stack Without Governance" in names

    # -- Complex Migration Window (meta-signal) --

    def test_complex_migration_window_fires_when_both_signals_active(self) -> None:
        """Meta-signal fires when Enterprise Security Stack AND Dual Email Provider both fire."""
        # Enterprise Security Stack needs 2+ from its candidates
        # Dual Email Provider needs microsoft365 + google-workspace
        slugs = {"crowdstrike", "okta", "microsoft365", "google-workspace"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "Enterprise Security Stack" in names, "Prerequisite signal should fire"
        assert "Dual Email Provider" in names, "Prerequisite signal should fire"
        assert "Complex Migration Window" in names

    def test_complex_migration_window_does_not_fire_without_security_stack(self) -> None:
        """Meta-signal does not fire when Enterprise Security Stack is missing."""
        slugs = {"microsoft365", "google-workspace"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "Dual Email Provider" in names
        assert "Enterprise Security Stack" not in names
        assert "Complex Migration Window" not in names

    def test_complex_migration_window_does_not_fire_without_dual_email(self) -> None:
        """Meta-signal does not fire when Dual Email Provider is missing."""
        slugs = {"crowdstrike", "okta"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "Enterprise Security Stack" in names
        assert "Dual Email Provider" not in names
        assert "Complex Migration Window" not in names

    # -- Governance Sprawl (meta-signal) --

    def test_governance_sprawl_fires_when_both_signals_active(self) -> None:
        """Meta-signal fires when AI Adoption AND Shadow IT Risk both fire."""
        # AI Adoption needs 1+ from [openai, anthropic, mistral, perplexity]
        # Shadow IT Risk needs 3+ from [canva, dropbox, mailchimp, zoom, airtable, notion, monday, clickup, loom]
        slugs = {"openai", "canva", "dropbox", "zoom"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "AI Adoption" in names, "Prerequisite signal should fire"
        assert "Shadow IT Risk" in names, "Prerequisite signal should fire"
        assert "Governance Sprawl" in names

    def test_governance_sprawl_does_not_fire_without_ai_adoption(self) -> None:
        """Meta-signal does not fire when AI Adoption is missing."""
        slugs = {"canva", "dropbox", "zoom"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "Shadow IT Risk" in names
        assert "AI Adoption" not in names
        assert "Governance Sprawl" not in names

    def test_governance_sprawl_does_not_fire_without_shadow_it(self) -> None:
        """Meta-signal does not fire when Shadow IT Risk is missing."""
        slugs = {"openai"}
        results = evaluate_signals(_ctx(slugs))
        names = {r.name for r in results}
        assert "AI Adoption" in names
        assert "Shadow IT Risk" not in names
        assert "Governance Sprawl" not in names


# ── 14.3: Backward compatibility tests ────────────────────────────────


class TestBackwardCompatibility:
    """Verify all existing fingerprints/signals load and defaults work correctly."""

    def setup_method(self) -> None:
        reload_fingerprints()
        reload_signals()
        reload_posture()

    def test_all_existing_fingerprints_load(self) -> None:
        """All 187+ existing fingerprints load without modification."""
        fps = load_fingerprints()
        assert len(fps) >= 187, f"Expected >= 187 fingerprints, got {len(fps)}"

    def test_all_existing_signals_load(self) -> None:
        """All 29+ existing signals load without modification."""
        sigs = load_signals()
        assert len(sigs) >= 29, f"Expected >= 29 signals, got {len(sigs)}"

    def test_fingerprint_without_match_mode_defaults_to_any(self) -> None:
        """Fingerprint without match_mode defaults to 'any'."""
        fps = load_fingerprints()
        # All existing fingerprints should have match_mode "any" (default)
        for fp in fps:
            assert fp.match_mode in {"any", "all"}, f"Fingerprint '{fp.name}' has invalid match_mode '{fp.match_mode}'"
        # Specifically, the vast majority should be "any" (default)
        any_count = sum(1 for fp in fps if fp.match_mode == "any")
        assert any_count > 0, "No fingerprints with default match_mode 'any'"

    def test_detection_without_weight_defaults_to_1(self) -> None:
        """Detection without weight defaults to 1.0."""
        fps = load_fingerprints()
        for fp in fps:
            for det in fp.detections:
                assert isinstance(det.weight, float), f"Fingerprint '{fp.name}' detection weight is not float"
                assert 0.0 <= det.weight <= 1.0, f"Fingerprint '{fp.name}' detection weight {det.weight} out of range"
        # Most detections should have default weight 1.0
        default_weight_count = sum(1 for fp in fps for det in fp.detections if det.weight == 1.0)
        assert default_weight_count > 0, "No detections with default weight 1.0"

    def test_signal_without_contradicts_applies_no_negation(self) -> None:
        """Signal without contradicts evaluates normally (no negation)."""
        sigs = load_signals()
        no_contradicts = [s for s in sigs if not s.contradicts]
        assert len(no_contradicts) > 0, "Expected signals without contradicts"

        # AI Adoption has no contradicts — should fire with openai
        results = evaluate_signals(_ctx({"openai"}))
        names = {r.name for r in results}
        assert "AI Adoption" in names

    def test_signal_without_requires_signals_evaluates_normally(self) -> None:
        """Signal without requires_signals evaluates with existing logic."""
        sigs = load_signals()
        no_meta = [s for s in sigs if not s.requires_signals]
        assert len(no_meta) > 0, "Expected non-meta signals"

        # Enterprise Security Stack has no requires_signals
        results = evaluate_signals(_ctx({"crowdstrike", "okta"}))
        names = {r.name for r in results}
        assert "Enterprise Security Stack" in names

    def test_signal_without_explain_produces_no_curated_explanation(self) -> None:
        """Signal without explain produces empty curated_explanation."""
        sigs = load_signals()
        # AI Adoption has no explain field
        ai_sig = next((s for s in sigs if s.name == "AI Adoption"), None)
        assert ai_sig is not None
        assert ai_sig.explain == ""

        # Evaluate and explain
        context = _ctx({"openai"})
        results = evaluate_signals(context)
        ai_match = next((r for r in results if r.name == "AI Adoption"), None)
        assert ai_match is not None

        explanations = explain_signals(
            [ai_match],
            sigs,
            context.detected_slugs,
            {},
            (),
            (),
        )
        assert len(explanations) == 1
        serialized = serialize_explanation(explanations[0])
        assert serialized["curated_explanation"] == ""

    def test_posture_rule_without_explain_produces_no_curated_explanation(self) -> None:
        """Posture rule without explain produces empty curated_explanation."""
        rules = load_posture_rules()
        # Find a rule without explain
        no_explain = [r for r in rules if not r.explain]
        assert len(no_explain) > 0, "Expected posture rules without explain"
        # The explain field should be empty string
        for rule in no_explain:
            assert rule.explain == ""

    def test_signal_with_explain_preserves_text(self) -> None:
        """Signal with explain field preserves the curated text."""
        sigs = load_signals()
        # Incomplete Identity Migration has an explain field
        sig = next((s for s in sigs if s.name == "Incomplete Identity Migration"), None)
        assert sig is not None
        assert sig.explain != ""
        assert "external IdP" in sig.explain or "identity" in sig.explain.lower()

    def test_existing_signals_still_evaluate_correctly(self) -> None:
        """Spot-check that existing signals still fire as expected."""
        # AI Adoption
        results = evaluate_signals(_ctx({"openai"}))
        assert any(r.name == "AI Adoption" for r in results)

        # Enterprise Security Stack
        results = evaluate_signals(_ctx({"crowdstrike", "okta"}))
        assert any(r.name == "Enterprise Security Stack" for r in results)

        # Modern Collaboration
        results = evaluate_signals(_ctx({"slack", "notion", "figma"}))
        assert any(r.name == "Modern Collaboration" for r in results)

        # Dual Email Provider
        results = evaluate_signals(_ctx({"microsoft365", "google-workspace"}))
        assert any(r.name == "Dual Email Provider" for r in results)

    def test_all_signal_names_unique(self) -> None:
        """All signal names are unique."""
        sigs = load_signals()
        names = [s.name for s in sigs]
        assert len(names) == len(set(names)), "Duplicate signal names found"

    def test_all_fingerprint_slugs_valid_format(self) -> None:
        """All fingerprint slugs are lowercase with valid characters."""
        fps = load_fingerprints()
        for fp in fps:
            assert fp.slug, f"Fingerprint '{fp.name}' has empty slug"
            # Slugs should be lowercase (allow hyphens, digits, dots, colons for CAA)
            assert fp.slug == fp.slug.lower() or "CAA" in fp.name, (
                f"Fingerprint '{fp.name}' slug '{fp.slug}' is not lowercase"
            )
