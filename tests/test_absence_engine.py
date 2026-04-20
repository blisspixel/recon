"""Negative-space (absence engine) analysis tests.

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
from recon_tool.signals import Signal, SignalMatch, load_signals, reload_signals

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

    def test_no_builtin_counterparts(self) -> None:
        """No built-in signals use expected_counterparts.

        The mechanism remains available for user-customised signals in
        ~/.recon/signals.yaml, but every built-in counterpart list has
        been retired. History:
        - A2 audit removed Enterprise Security Stack, Enterprise IT
          Maturity, and DMARC Governance Investment — those lists named
          competing vendors, producing false-positive absence gaps.
        - Validation-driven audit removed AI Adoption and Agentic AI
          Infrastructure — those lists were vendor recommendations
          (Lakera, Okta, CyberArk, Cosign, Snyk) whose absence does not
          constitute a defect. They fired on every AI-adopting target
          as presumptuous "you should also have…" commentary.
        """
        signals = load_signals()
        with_counterparts = [s for s in signals if s.expected_counterparts]
        assert with_counterparts == [], (
            f"No built-in signals should declare expected_counterparts; found {[s.name for s in with_counterparts]}"
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

    def test_multi_layer_security_tooling_no_competing_vendor_counterparts(self) -> None:
        """Multi-Layer Security Tooling (formerly Enterprise IT Maturity)
        should not list competing vendors as counterparts.

        Regression guard for A2: the previous design listed jamf/kandji,
        crowdstrike/sentinelone, and proofpoint/mimecast as expected
        counterparts, which generated false-positive "Missing Counterparts"
        signals when the org picked one of each pair. Those are alternatives,
        not complements, so the entire expected_counterparts entry was
        removed. The signal was also renamed in v1.0.2 to drop the
        judgmental "maturity" framing.
        """
        signals = load_signals()
        mlst = [s for s in signals if s.name == "Multi-Layer Security Tooling"]
        assert len(mlst) == 1
        assert mlst[0].expected_counterparts == ()

    def test_ai_adoption_has_no_counterparts(self) -> None:
        # Removed: the list (lakera/okta/cyberark/beyond-identity) was a
        # vendor recommendation, not an observable counterpart relationship.
        signals = load_signals()
        ai = [s for s in signals if s.name == "AI Adoption"]
        assert len(ai) == 1
        assert ai[0].expected_counterparts == ()

    def test_agentic_ai_infrastructure_has_no_counterparts(self) -> None:
        # Removed: cosign-attestation/snyk absence does not constitute a
        # defect observable from DNS.
        signals = load_signals()
        agentic = [s for s in signals if s.name == "Agentic AI Infrastructure"]
        assert len(agentic) == 1
        assert agentic[0].expected_counterparts == ()

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
    """Verify the absence-signal mechanism works end-to-end.

    No built-in signals currently declare expected_counterparts (see
    TestBuiltInExpectedCounterparts), so these tests drive the
    mechanism with a custom Signal fixture rather than production YAML.
    That keeps the tests validating behavior of the evaluator instead
    of the contents of signals.yaml.
    """

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def test_absence_signals_fire_on_signal_with_counterparts(self) -> None:
        parent = _make_signal(
            "Test Parent",
            candidates=("openai",),
            min_matches=1,
            expected_counterparts=("lakera", "okta"),
        )
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        parent_match = _make_match("Test Parent", matched=("openai",))
        absence_signals = evaluate_absence_signals([parent_match], (parent,), ctx.detected_slugs)

        absences = [s for s in absence_signals if "Test Parent" in s.name]
        assert len(absences) == 1
        assert absences[0].category == "Absence"

    def test_no_absence_when_all_counterparts_present(self) -> None:
        parent = _make_signal(
            "Test Parent",
            candidates=("openai",),
            min_matches=1,
            expected_counterparts=("lakera", "okta"),
        )
        ctx = SignalContext(detected_slugs=frozenset({"openai", "lakera", "okta"}))
        parent_match = _make_match("Test Parent", matched=("openai",))
        absence_signals = evaluate_absence_signals([parent_match], (parent,), ctx.detected_slugs)

        absences = [s for s in absence_signals if "Test Parent" in s.name]
        assert len(absences) == 0

    def test_builtin_signals_produce_no_absence_insights(self) -> None:
        # Regression guard: because no built-in signals declare
        # expected_counterparts, build_insights_with_signals must never
        # produce "Missing Counterparts" lines on production data.
        from recon_tool.merger import build_insights_with_signals

        insights = build_insights_with_signals(
            services=set(),
            slugs={"openai", "anthropic", "crewai-aid"},
            auth_type=None,
            dmarc_policy=None,
            domain_count=0,
        )

        absence_insights = [i for i in insights if "Missing Counterparts" in i]
        assert absence_insights == []


# ── 14.4: Absence explanation records ─────────────────────────────────


class TestAbsenceExplanationRecords:
    """Verify --explain produces ExplanationRecord for absence signals."""

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def test_explain_produces_explanation_record(self) -> None:
        # Uses a fixture signal with counterparts since no built-in signal
        # declares expected_counterparts.
        parent = _make_signal(
            "Test Parent",
            candidates=("openai",),
            min_matches=1,
            expected_counterparts=("lakera", "okta"),
        )
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        parent_match = _make_match("Test Parent", matched=("openai",))
        absence_signals = evaluate_absence_signals([parent_match], (parent,), ctx.detected_slugs)

        all_matches = [parent_match, *absence_signals]

        records = explain_signals(
            signal_matches=all_matches,
            signals=(parent,),
            context_detected_slugs=ctx.detected_slugs,
            context_metadata={},
            evidence=(),
            detection_scores=(),
        )

        absence_recs = [r for r in records if "Missing Counterparts" in r.item_name]
        assert len(absence_recs) >= 1

        rec = absence_recs[0]
        assert isinstance(rec, ExplanationRecord)
        assert rec.item_type == "signal"
        assert any("Test Parent" in rule for rule in rec.fired_rules)
        assert "absence" in rec.confidence_derivation.lower() or "Absence" in rec.confidence_derivation
        assert len(rec.weakening_conditions) > 0
        assert any("slug" in w.lower() or "suppress" in w.lower() for w in rec.weakening_conditions)

    def test_explain_absence_has_curated_explanation(self) -> None:
        # Uses a fixture signal with counterparts since no built-in signal
        # declares expected_counterparts.
        parent = _make_signal(
            "Test Parent",
            candidates=("openai",),
            min_matches=1,
            expected_counterparts=("lakera", "okta"),
        )
        ctx = SignalContext(detected_slugs=frozenset({"openai"}))
        parent_match = _make_match("Test Parent", matched=("openai",))
        absence_signals = evaluate_absence_signals([parent_match], (parent,), ctx.detected_slugs)
        all_matches = [parent_match, *absence_signals]

        records = explain_signals(
            signal_matches=all_matches,
            signals=(parent,),
            context_detected_slugs=ctx.detected_slugs,
            context_metadata={},
            evidence=(),
            detection_scores=(),
        )

        absence_recs = [r for r in records if "Missing Counterparts" in r.item_name]
        assert len(absence_recs) >= 1
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
