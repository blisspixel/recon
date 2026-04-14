"""v0.9.0 — QA Round 4: Negative-Space Analysis.

Validates:
- evaluate_absence_signals() core logic (14.1)
- Built-in expected_counterparts definitions (14.2)
- Absence signal integration in merger pipeline (14.3)
- Absence explanation records (14.4)
- Property 2: Absence Signal Biconditional (14.5)
- Requirements: 6.1–6.5, 7.1–7.6, 8.1–8.3
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.absence import evaluate_absence_signals
from recon_tool.explanation import explain_signals
from recon_tool.fingerprints import load_fingerprints, reload_fingerprints
from recon_tool.models import ExplanationRecord, SignalContext
from recon_tool.signals import Signal, SignalMatch, evaluate_signals, load_signals, reload_signals

# ── Helpers ───────────────────────────────────────────────────────────


def _make_signal(
    name: str,
    *,
    candidates: tuple[str, ...] = (),
    min_matches: int = 1,
    expected_counterparts: tuple[str, ...] = (),
) -> Signal:
    """Create a minimal Signal for testing."""
    return Signal(
        name=name,
        category="Test",
        confidence="medium",
        description=f"Test signal {name}",
        candidates=candidates,
        min_matches=min_matches,
        expected_counterparts=expected_counterparts,
    )


def _make_match(name: str, matched: tuple[str, ...] = ()) -> SignalMatch:
    """Create a minimal SignalMatch for testing."""
    return SignalMatch(
        name=name,
        category="Test",
        confidence="medium",
        matched=matched,
        description=f"Test match {name}",
    )


# ── 14.1: evaluate_absence_signals() ─────────────────────────────────


class TestEvaluateAbsenceSignals:
    """Verify evaluate_absence_signals() core logic."""

    def test_all_counterparts_present_no_absence(self) -> None:
        """Signal with expected_counterparts where all present → no absence signal."""
        sig = _make_signal(
            "Contoso Security Stack",
            candidates=("crowdstrike", "okta"),
            expected_counterparts=("proofpoint", "mimecast"),
        )
        match = _make_match("Contoso Security Stack", matched=("crowdstrike", "okta"))
        detected = frozenset({"crowdstrike", "okta", "proofpoint", "mimecast"})

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 0

    def test_some_counterparts_absent_fires(self) -> None:
        """Signal with expected_counterparts where some absent → absence signal fires."""
        sig = _make_signal(
            "Contoso Security Stack",
            candidates=("crowdstrike", "okta"),
            expected_counterparts=("proofpoint", "mimecast"),
        )
        match = _make_match("Contoso Security Stack", matched=("crowdstrike", "okta"))
        detected = frozenset({"crowdstrike", "okta", "proofpoint"})  # mimecast absent

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 1
        assert result[0].category == "Absence"
        assert "mimecast" in result[0].matched

    def test_empty_counterparts_no_evaluation(self) -> None:
        """Signal with empty expected_counterparts → no absence evaluation."""
        sig = _make_signal(
            "Contoso Basic Signal",
            candidates=("crowdstrike",),
            expected_counterparts=(),
        )
        match = _make_match("Contoso Basic Signal", matched=("crowdstrike",))
        detected = frozenset({"crowdstrike"})

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 0

    def test_parent_not_fired_no_absence(self) -> None:
        """Parent signal did not fire → no absence signal regardless of counterpart presence."""
        sig = _make_signal(
            "Contoso Security Stack",
            candidates=("crowdstrike", "okta"),
            expected_counterparts=("proofpoint", "mimecast"),
        )
        # No match for this signal — parent did not fire
        detected = frozenset({"something-else"})

        result = evaluate_absence_signals([], (sig,), detected)
        assert len(result) == 0

    def test_absence_signal_category(self) -> None:
        """Absence signal has category='Absence'."""
        sig = _make_signal(
            "Fabrikam AI Stack",
            candidates=("openai",),
            expected_counterparts=("lakera",),
        )
        match = _make_match("Fabrikam AI Stack", matched=("openai",))
        detected = frozenset({"openai"})  # lakera absent

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 1
        assert result[0].category == "Absence"

    def test_absence_signal_hedged_language(self) -> None:
        """Absence signal description uses hedged language ('not observed', 'may indicate')."""
        sig = _make_signal(
            "Northwind Traders Security",
            candidates=("crowdstrike",),
            expected_counterparts=("proofpoint",),
        )
        match = _make_match("Northwind Traders Security", matched=("crowdstrike",))
        detected = frozenset({"crowdstrike"})

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 1
        assert "not observed" in result[0].description
        assert "may indicate" in result[0].description

    def test_multiple_missing_counterparts(self) -> None:
        """Multiple missing counterparts → all listed in matched tuple."""
        sig = _make_signal(
            "Contoso Full Stack",
            candidates=("crowdstrike",),
            expected_counterparts=("proofpoint", "mimecast", "barracuda"),
        )
        match = _make_match("Contoso Full Stack", matched=("crowdstrike",))
        detected = frozenset({"crowdstrike"})  # all counterparts absent

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 1
        assert set(result[0].matched) == {"proofpoint", "mimecast", "barracuda"}

    def test_absence_signal_name_format(self) -> None:
        """Absence signal name follows '{parent} — Missing Counterparts' pattern."""
        sig = _make_signal(
            "Contoso AI",
            candidates=("openai",),
            expected_counterparts=("lakera",),
        )
        match = _make_match("Contoso AI", matched=("openai",))
        detected = frozenset({"openai"})

        result = evaluate_absence_signals([match], (sig,), detected)
        assert len(result) == 1
        assert result[0].name == "Contoso AI \u2014 Missing Counterparts"


# ── 14.2: Built-in expected_counterparts definitions ──────────────────


class TestBuiltInExpectedCounterparts:
    """Verify built-in expected_counterparts definitions in signals.yaml."""

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def test_at_least_two_signals_have_counterparts(self) -> None:
        """At least 2 signals have expected_counterparts populated.

        Counterparts should be limited to signals where the listed slugs are
        truly complementary (expected to co-occur), not competing alternatives.
        See A2 audit: Enterprise Security Stack, Enterprise IT Maturity, and
        DMARC Governance Investment had counterparts pointing at competing
        vendors; those entries were removed to avoid false-positive absence
        gaps.
        """
        signals = load_signals()
        with_counterparts = [s for s in signals if s.expected_counterparts]
        assert len(with_counterparts) >= 2, (
            f"Expected 2+ signals with expected_counterparts, found {len(with_counterparts)}: "
            f"{[s.name for s in with_counterparts]}"
        )

    def test_all_referenced_slugs_exist_in_fingerprints(self) -> None:
        """All slugs referenced in expected_counterparts exist in loaded fingerprints."""
        signals = load_signals()
        fps = load_fingerprints()
        all_fp_slugs = {fp.slug for fp in fps}

        missing: list[tuple[str, str]] = []
        for sig in signals:
            for slug in sig.expected_counterparts:
                if slug not in all_fp_slugs:
                    missing.append((sig.name, slug))

        assert len(missing) == 0, f"Signals reference non-existent fingerprint slugs: {missing}"

    def test_enterprise_it_maturity_no_competing_vendor_counterparts(self) -> None:
        """Enterprise IT Maturity should not list competing vendors as counterparts.

        Regression guard for A2: the previous design listed jamf/kandji,
        crowdstrike/sentinelone, and proofpoint/mimecast as expected
        counterparts, which generated false-positive "Missing Counterparts"
        signals when the org picked one of each pair. Those are alternatives,
        not complements, so the entire expected_counterparts entry was
        removed.
        """
        signals = load_signals()
        eit = [s for s in signals if s.name == "Enterprise IT Maturity"]
        assert len(eit) == 1
        assert eit[0].expected_counterparts == ()

    def test_ai_adoption_counterparts(self) -> None:
        """AI Adoption lists governance and identity slugs."""
        signals = load_signals()
        ai = [s for s in signals if s.name == "AI Adoption"]
        assert len(ai) == 1
        counterparts = set(ai[0].expected_counterparts)
        assert "lakera" in counterparts
        assert "okta" in counterparts

    def test_agentic_ai_infrastructure_counterparts(self) -> None:
        """Agentic AI Infrastructure lists supply-chain slugs."""
        signals = load_signals()
        agentic = [s for s in signals if s.name == "Agentic AI Infrastructure"]
        assert len(agentic) == 1
        counterparts = set(agentic[0].expected_counterparts)
        assert "cosign-attestation" in counterparts
        assert "snyk" in counterparts

    def test_enterprise_security_stack_no_competing_gateway_counterparts(self) -> None:
        """Enterprise Security Stack should not list competing gateways as counterparts.

        Regression guard for A2: Proofpoint/Mimecast/Barracuda are alternatives
        to each other, not complementary tools. Listing them produced noise
        like "Missing Counterparts: proofpoint, mimecast, barracuda" when an
        org was already using one of them. Removed.
        """
        signals = load_signals()
        ess = [s for s in signals if s.name == "Enterprise Security Stack"]
        assert len(ess) == 1
        assert ess[0].expected_counterparts == ()


# ── 14.3: Absence signal integration in merger pipeline ───────────────


class TestAbsenceSignalMergerIntegration:
    """Verify absence signals appear in merger pipeline output."""

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def test_absence_signals_in_output(self) -> None:
        """Absence signals appear in final signals output alongside standard signals."""
        # Simulate AI Adoption firing (openai detected) but no governance slugs
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        standard_signals = evaluate_signals(ctx)

        # Verify AI Adoption fired
        ai_adoption = [s for s in standard_signals if s.name == "AI Adoption"]
        assert len(ai_adoption) == 1

        # Run absence evaluation
        all_signal_defs = load_signals()
        absence_signals = evaluate_absence_signals(standard_signals, all_signal_defs, ctx.detected_slugs)

        # Absence signal should fire for AI Adoption missing counterparts
        ai_absence = [s for s in absence_signals if "AI Adoption" in s.name]
        assert len(ai_absence) == 1
        assert ai_absence[0].category == "Absence"

    def test_absence_insights_generated(self) -> None:
        """Absence insights generated for missing counterparts via build_insights_with_signals."""
        from recon_tool.merger import build_insights_with_signals

        insights = build_insights_with_signals(
            services=set(),
            slugs={"openai"},
            auth_type=None,
            dmarc_policy=None,
            domain_count=0,
        )

        # Should contain an absence insight mentioning missing counterparts
        absence_insights = [i for i in insights if "Missing Counterparts" in i]
        assert len(absence_insights) >= 1

    def test_no_absence_when_all_counterparts_present(self) -> None:
        """No absence signals when all counterparts are present."""
        # AI Adoption with all counterparts present
        ctx = SignalContext(detected_slugs=frozenset({"openai", "lakera", "okta", "cyberark", "beyond-identity"}))
        standard_signals = evaluate_signals(ctx)
        all_signal_defs = load_signals()
        absence_signals = evaluate_absence_signals(standard_signals, all_signal_defs, ctx.detected_slugs)

        ai_absence = [s for s in absence_signals if "AI Adoption" in s.name]
        assert len(ai_absence) == 0


# ── 14.4: Absence explanation records ─────────────────────────────────


class TestAbsenceExplanationRecords:
    """Verify --explain produces ExplanationRecord for absence signals."""

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def test_explain_produces_explanation_record(self) -> None:
        """--explain with absence signal produces ExplanationRecord with parent signal info."""
        # Fire AI Adoption (openai detected, no governance slugs)
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        standard_signals = evaluate_signals(ctx)
        all_signal_defs = load_signals()
        absence_signals = evaluate_absence_signals(standard_signals, all_signal_defs, ctx.detected_slugs)

        all_matches = standard_signals + absence_signals

        # Generate explanations
        records = explain_signals(
            signal_matches=all_matches,
            signals=all_signal_defs,
            context_detected_slugs=ctx.detected_slugs,
            context_metadata={},
            evidence=(),
            detection_scores=(),
        )

        # Find the absence explanation
        absence_recs = [r for r in records if "Missing Counterparts" in r.item_name]
        assert len(absence_recs) >= 1

        rec = absence_recs[0]
        assert isinstance(rec, ExplanationRecord)
        assert rec.item_type == "signal"
        # fired_rules should reference the parent signal
        assert any("AI Adoption" in rule for rule in rec.fired_rules)
        # confidence_derivation should mention absence
        assert "absence" in rec.confidence_derivation.lower() or "Absence" in rec.confidence_derivation
        # weakening_conditions should mention detecting the missing slugs
        assert len(rec.weakening_conditions) > 0
        assert any("slug" in w.lower() or "suppress" in w.lower() for w in rec.weakening_conditions)

    def test_explain_absence_has_curated_explanation(self) -> None:
        """Absence explanation record has curated_explanation from the absence signal description."""
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        standard_signals = evaluate_signals(ctx)
        all_signal_defs = load_signals()
        absence_signals = evaluate_absence_signals(standard_signals, all_signal_defs, ctx.detected_slugs)
        all_matches = standard_signals + absence_signals

        records = explain_signals(
            signal_matches=all_matches,
            signals=all_signal_defs,
            context_detected_slugs=ctx.detected_slugs,
            context_metadata={},
            evidence=(),
            detection_scores=(),
        )

        absence_recs = [r for r in records if "Missing Counterparts" in r.item_name]
        assert len(absence_recs) >= 1
        # curated_explanation should contain the hedged description
        assert "not observed" in absence_recs[0].curated_explanation


# ── 14.5: Property 2 — Absence Signal Biconditional (PBT) ────────────
# Feature: intelligence-amplification, Property 2: Absence Signal Biconditional
# **Validates: Requirements 6.1, 6.2, 6.5**

# Strategy: pool of slugs to draw from
_SLUG_POOL = [
    "openai",
    "anthropic",
    "crowdstrike",
    "okta",
    "proofpoint",
    "mimecast",
    "lakera",
    "snyk",
    "jamf",
    "kandji",
    "sentinelone",
    "cosign-attestation",
    "beyond-identity",
    "cyberark",
    "barracuda",
    "slack",
    "notion",
    "figma",
    "datadog",
    "github",
]


@st.composite
def absence_scenario(
    draw: st.DrawFn,
) -> tuple[
    list[Signal],
    list[SignalMatch],
    frozenset[str],
]:
    """Generate random Signal definitions, fired matches, and detected slugs.

    Returns (all_signals, fired_matches, detected_slugs).
    """
    # Pick a random subset of slugs for the pool
    pool = draw(st.lists(st.sampled_from(_SLUG_POOL), min_size=2, max_size=10, unique=True))

    # Generate 1-3 signal definitions
    n_signals = draw(st.integers(min_value=1, max_value=3))
    signals: list[Signal] = []
    matches: list[SignalMatch] = []

    for i in range(n_signals):
        # Pick candidates from pool
        n_candidates = draw(st.integers(min_value=1, max_value=min(3, len(pool))))
        candidates = tuple(
            draw(st.lists(st.sampled_from(pool), min_size=n_candidates, max_size=n_candidates, unique=True))
        )

        # Pick expected_counterparts from pool (may overlap with candidates)
        n_counterparts = draw(st.integers(min_value=0, max_value=min(4, len(pool))))
        counterparts = tuple(
            draw(st.lists(st.sampled_from(pool), min_size=n_counterparts, max_size=n_counterparts, unique=True))
        )

        sig_name = f"TestSignal_{i}"
        sig = Signal(
            name=sig_name,
            category="Test",
            confidence="medium",
            description=f"Test signal {i}",
            candidates=candidates,
            min_matches=1,
            expected_counterparts=counterparts,
        )
        signals.append(sig)

        # Decide whether this signal fires
        should_fire = draw(st.booleans())
        if should_fire:
            matches.append(
                SignalMatch(
                    name=sig_name,
                    category="Test",
                    confidence="medium",
                    matched=candidates[:1],
                    description=f"Test match {i}",
                )
            )

    # Generate detected_slugs — random subset of pool
    detected = frozenset(draw(st.lists(st.sampled_from(pool), min_size=0, max_size=len(pool), unique=True)))

    return signals, matches, detected


class TestProperty2AbsenceSignalBiconditional:
    """Hypothesis PBT for Absence Signal Biconditional.

    For any signal with non-empty expected_counterparts that fires,
    and any detected_slugs: absence fires iff >=1 counterpart absent.
    When all counterparts present → no absence signal.
    When parent did not fire → no absence signal.
    """

    @given(scenario=absence_scenario())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_absence_fires_iff_counterpart_absent_and_parent_fired(
        self,
        scenario: tuple[list[Signal], list[SignalMatch], frozenset[str]],
    ) -> None:
        """Absence fires iff (parent fired AND >=1 counterpart missing)."""
        all_signals, fired_matches, detected_slugs = scenario

        result = evaluate_absence_signals(fired_matches, tuple(all_signals), detected_slugs)

        fired_names = {m.name for m in fired_matches}

        for sig in all_signals:
            absence_for_sig = [r for r in result if r.name == f"{sig.name} \u2014 Missing Counterparts"]

            parent_fired = sig.name in fired_names
            has_counterparts = len(sig.expected_counterparts) > 0
            missing = [slug for slug in sig.expected_counterparts if slug not in detected_slugs]
            has_missing = len(missing) > 0

            if parent_fired and has_counterparts and has_missing:
                # Absence SHOULD fire
                assert len(absence_for_sig) == 1, (
                    f"Expected absence signal for '{sig.name}' "
                    f"(parent fired, counterparts={sig.expected_counterparts}, "
                    f"detected={detected_slugs}, missing={missing})"
                )
                assert absence_for_sig[0].category == "Absence"
                assert set(absence_for_sig[0].matched) == set(missing)
            else:
                # Absence should NOT fire
                assert len(absence_for_sig) == 0, (
                    f"Unexpected absence signal for '{sig.name}' "
                    f"(parent_fired={parent_fired}, has_counterparts={has_counterparts}, "
                    f"has_missing={has_missing})"
                )

    @given(scenario=absence_scenario())
    @settings(max_examples=100)
    def test_all_counterparts_present_no_absence(
        self,
        scenario: tuple[list[Signal], list[SignalMatch], frozenset[str]],
    ) -> None:
        """When all counterparts present → no absence signal for that parent."""
        all_signals, fired_matches, _ = scenario

        # Force all counterparts to be present
        all_counterpart_slugs: set[str] = set()
        for sig in all_signals:
            all_counterpart_slugs.update(sig.expected_counterparts)
        detected_slugs = frozenset(all_counterpart_slugs | {s for m in fired_matches for s in m.matched})

        result = evaluate_absence_signals(fired_matches, tuple(all_signals), detected_slugs)
        assert len(result) == 0, (
            f"Expected no absence signals when all counterparts present, got {[r.name for r in result]}"
        )

    @given(scenario=absence_scenario())
    @settings(max_examples=100)
    def test_parent_not_fired_no_absence(
        self,
        scenario: tuple[list[Signal], list[SignalMatch], frozenset[str]],
    ) -> None:
        """When parent did not fire → no absence signal."""
        all_signals, _, detected_slugs = scenario

        # Pass empty fired_matches — no parent fired
        result = evaluate_absence_signals([], tuple(all_signals), detected_slugs)
        assert len(result) == 0, f"Expected no absence signals when no parent fired, got {[r.name for r in result]}"
