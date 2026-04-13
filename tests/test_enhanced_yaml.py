"""QA Round 1 — Enhanced YAML Engine tests.

Unit tests and Hypothesis property-based tests for:
- match_mode: all enforcement (2.1)
- contradicts suppression (2.2)
- meta-signal evaluation (2.3)
- detection weight parsing and weighted scoring (2.4)
- explain field on Signal and _PostureRule (2.5)
- PBT Property 2: Signal Contradiction Suppression (2.6)
- PBT Property 3: match_mode: all Enforcement (2.7)
- PBT Property 4: Detection Weight Monotonicity (2.8)
- PBT Property 5: Meta-Signal Biconditional Evaluation (2.9)

All examples use fictional companies (Contoso, Northwind, Fabrikam).
"""

from __future__ import annotations

from unittest.mock import patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.fingerprints import (
    DetectionRule,
    Fingerprint,
    _validate_fingerprint,  # pyright: ignore[reportPrivateUsage]
)
from recon_tool.merger import compute_detection_scores
from recon_tool.models import EvidenceRecord, SignalContext
from recon_tool.posture import _validate_and_build_rule  # pyright: ignore[reportPrivateUsage]
from recon_tool.signals import (
    Signal,
    _evaluate_single_signal,  # pyright: ignore[reportPrivateUsage]
    _validate_and_build_signal,  # pyright: ignore[reportPrivateUsage]
    _validate_meta_signals,  # pyright: ignore[reportPrivateUsage]
    evaluate_signals,
)
from recon_tool.sources.dns import _DetectionCtx  # pyright: ignore[reportPrivateUsage]


def _ctx(slugs: set[str], **kwargs: object) -> SignalContext:
    """Helper to build a SignalContext from a slug set."""
    return SignalContext(detected_slugs=frozenset(slugs), **kwargs)  # pyright: ignore[reportCallIssue, reportArgumentType]


# ── 2.1 Unit tests for match_mode: all enforcement ─────────────────────


class TestMatchModeAll:
    """Task 2.1: match_mode: all enforcement tests.

    Requirements: 8.1, 8.2, 8.4, 8.5, 22.4
    """

    def test_match_mode_all_all_detections_match(self) -> None:
        """Fingerprint with match_mode: all where all detections match → detection produced."""
        fp = Fingerprint(
            name="Contoso Platform",
            slug="contoso-platform",
            category="SaaS",
            confidence="high",
            m365=False,
            match_mode="all",
            detections=(
                DetectionRule(type="txt", pattern="^contoso-verify="),
                DetectionRule(type="cname", pattern="login.contoso.com"),
            ),
        )

        ctx = _DetectionCtx()
        ctx.add("Contoso Platform", "contoso-platform", source_type="TXT", raw_value="contoso-verify=abc")
        ctx.record_fp_match("contoso-platform", "txt", "^contoso-verify=")
        ctx.record_fp_match("contoso-platform", "cname", "login.contoso.com")

        with patch("recon_tool.sources.dns.load_fingerprints", return_value=(fp,)):
            ctx.enforce_match_mode_all()

        assert "contoso-platform" in ctx.slugs
        assert "Contoso Platform" in ctx.services

    def test_match_mode_all_one_detection_fails(self) -> None:
        """Fingerprint with match_mode: all where one detection fails → no detection."""
        fp = Fingerprint(
            name="Contoso Platform",
            slug="contoso-platform",
            category="SaaS",
            confidence="high",
            m365=False,
            match_mode="all",
            detections=(
                DetectionRule(type="txt", pattern="^contoso-verify="),
                DetectionRule(type="cname", pattern="login.contoso.com"),
            ),
        )

        ctx = _DetectionCtx()
        ctx.add("Contoso Platform", "contoso-platform", source_type="TXT", raw_value="contoso-verify=abc")
        # Only record one of two detections
        ctx.record_fp_match("contoso-platform", "txt", "^contoso-verify=")

        with patch("recon_tool.sources.dns.load_fingerprints", return_value=(fp,)):
            ctx.enforce_match_mode_all()

        assert "contoso-platform" not in ctx.slugs
        assert "Contoso Platform" not in ctx.services

    def test_match_mode_any_single_match_produces_detection(self) -> None:
        """Fingerprint with match_mode: any (default) → single match produces detection."""
        fp = Fingerprint(
            name="Northwind Analytics",
            slug="northwind-analytics",
            category="Analytics",
            confidence="medium",
            m365=False,
            match_mode="any",
            detections=(
                DetectionRule(type="txt", pattern="^northwind-verify="),
                DetectionRule(type="cname", pattern="track.northwind.com"),
            ),
        )

        ctx = _DetectionCtx()
        ctx.add("Northwind Analytics", "northwind-analytics", source_type="TXT", raw_value="northwind-verify=xyz")
        ctx.record_fp_match("northwind-analytics", "txt", "^northwind-verify=")

        with patch("recon_tool.sources.dns.load_fingerprints", return_value=(fp,)):
            ctx.enforce_match_mode_all()

        # match_mode: any — single match is enough
        assert "northwind-analytics" in ctx.slugs
        assert "Northwind Analytics" in ctx.services

    def test_invalid_match_mode_skips_fingerprint(self, caplog: object) -> None:
        """Invalid match_mode value → warning logged, fingerprint skipped."""
        fp_dict = {
            "name": "Fabrikam Widget",
            "slug": "fabrikam-widget",
            "category": "SaaS",
            "confidence": "high",
            "match_mode": "invalid_mode",
            "detections": [{"type": "txt", "pattern": "^fabrikam="}],
        }
        result = _validate_fingerprint(fp_dict, "test")
        assert result is None


# ── 2.2 Unit tests for contradicts suppression ─────────────────────────


class TestContradictsSuppression:
    """Task 2.2: contradicts suppression tests.

    Requirements: 7.1, 7.3, 7.4, 22.3
    """

    def test_contradiction_slug_present_suppresses_signal(self) -> None:
        """Signal with contradicts where contradiction slug present → signal suppressed."""
        signal = Signal(
            name="Incomplete Migration",
            category="Consistency",
            confidence="medium",
            description="Possible incomplete migration",
            candidates=("okta",),
            min_matches=1,
            contradicts=("microsoft365",),
        )
        context = _ctx({"okta", "microsoft365"})
        result = _evaluate_single_signal(signal, context)
        assert result is None

    def test_no_contradiction_slug_fires_normally(self) -> None:
        """Signal with contradicts where no contradiction slug present → signal fires."""
        signal = Signal(
            name="Incomplete Migration",
            category="Consistency",
            confidence="medium",
            description="Possible incomplete migration",
            candidates=("okta",),
            min_matches=1,
            contradicts=("microsoft365",),
        )
        context = _ctx({"okta", "auth0"})
        result = _evaluate_single_signal(signal, context)
        assert result is not None
        assert result.name == "Incomplete Migration"

    def test_empty_contradicts_unchanged_behavior(self) -> None:
        """Signal with empty contradicts → existing behavior unchanged."""
        signal = Signal(
            name="AI Tooling",
            category="AI",
            confidence="high",
            description="AI tools detected",
            candidates=("openai",),
            min_matches=1,
            contradicts=(),
        )
        context = _ctx({"openai", "microsoft365"})
        result = _evaluate_single_signal(signal, context)
        assert result is not None

    def test_invalid_contradicts_entries_rejected(self) -> None:
        """Invalid contradicts entries → warning logged, signal skipped."""
        result = _validate_and_build_signal({"name": "Bad Signal", "requires": {"any": ["a"]}, "contradicts": [123]}, 0)
        assert result is None

        result = _validate_and_build_signal(
            {"name": "Bad Signal", "requires": {"any": ["a"]}, "contradicts": ["ok", ""]}, 0
        )
        assert result is None


# ── 2.3 Unit tests for meta-signal evaluation ──────────────────────────


class TestMetaSignalEvaluation:
    """Task 2.3: meta-signal evaluation tests.

    Requirements: 10.1, 10.3, 10.4, 10.5, 10.7, 22.6
    """

    def _make_signals(self) -> tuple[Signal, ...]:
        """Create a set of test signals including a meta-signal."""
        sig_a = Signal(
            name="Enterprise Security Stack",
            category="Security",
            confidence="high",
            description="Enterprise security detected",
            candidates=("crowdstrike", "zscaler", "okta"),
            min_matches=2,
        )
        sig_b = Signal(
            name="Dual Email Provider",
            category="Email",
            confidence="medium",
            description="Dual email providers detected",
            candidates=("microsoft365", "google-workspace"),
            min_matches=2,
        )
        meta = Signal(
            name="Complex Migration Window",
            category="Composite",
            confidence="medium",
            description="Complex migration in progress",
            candidates=(),
            min_matches=0,
            requires_signals=("Enterprise Security Stack", "Dual Email Provider"),
        )
        return (sig_a, sig_b, meta)

    def test_meta_signal_fires_when_all_refs_fired(self) -> None:
        """Meta-signal fires when all referenced signals fired in pass 1."""
        signals = self._make_signals()
        context = _ctx({"crowdstrike", "zscaler", "okta", "microsoft365", "google-workspace"})

        with patch("recon_tool.signals.load_signals", return_value=signals):
            results = evaluate_signals(context)

        names = {r.name for r in results}
        assert "Complex Migration Window" in names

    def test_meta_signal_does_not_fire_when_ref_missing(self) -> None:
        """Meta-signal does not fire when a referenced signal is missing."""
        signals = self._make_signals()
        # Only Enterprise Security Stack can fire, not Dual Email Provider
        context = _ctx({"crowdstrike", "zscaler", "okta"})

        with patch("recon_tool.signals.load_signals", return_value=signals):
            results = evaluate_signals(context)

        names = {r.name for r in results}
        assert "Enterprise Security Stack" in names
        assert "Complex Migration Window" not in names

    def test_meta_signal_with_additional_conditions(self) -> None:
        """Meta-signal with additional slug/metadata conditions — all must hold."""
        sig_a = Signal(
            name="Sig A",
            category="Test",
            confidence="high",
            description="",
            candidates=("slug-a",),
            min_matches=1,
        )
        # Meta-signal requires Sig A AND has its own slug requirement
        meta = Signal(
            name="Meta With Slugs",
            category="Composite",
            confidence="medium",
            description="",
            candidates=("extra-slug",),
            min_matches=1,
            requires_signals=("Sig A",),
        )

        # Missing extra-slug → meta should not fire
        context_missing = _ctx({"slug-a"})
        with patch("recon_tool.signals.load_signals", return_value=(sig_a, meta)):
            results = evaluate_signals(context_missing)
        names = {r.name for r in results}
        assert "Meta With Slugs" not in names

        # With extra-slug → meta should fire
        context_full = _ctx({"slug-a", "extra-slug"})
        with patch("recon_tool.signals.load_signals", return_value=(sig_a, meta)):
            results = evaluate_signals(context_full)
        names = {r.name for r in results}
        assert "Meta With Slugs" in names

    def test_meta_signal_referencing_nonexistent_signal_skipped(self, caplog: object) -> None:
        """Meta-signal referencing non-existent signal → warning, skipped at load time."""
        sig_a = Signal(
            name="Sig A",
            category="Test",
            confidence="high",
            description="",
            candidates=("slug-a",),
            min_matches=1,
        )
        meta = Signal(
            name="Bad Meta",
            category="Composite",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
            requires_signals=("Nonexistent Signal",),
        )
        validated = _validate_meta_signals([sig_a, meta])
        names = {s.name for s in validated}
        assert "Bad Meta" not in names
        assert "Sig A" in names

    def test_meta_signal_referencing_another_meta_skipped(self, caplog: object) -> None:
        """Meta-signal referencing another meta-signal → warning, skipped (cycle prevention)."""
        sig_a = Signal(
            name="Sig A",
            category="Test",
            confidence="high",
            description="",
            candidates=("slug-a",),
            min_matches=1,
        )
        meta_a = Signal(
            name="Meta A",
            category="Composite",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
            requires_signals=("Sig A",),
        )
        meta_b = Signal(
            name="Meta B",
            category="Composite",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
            requires_signals=("Meta A",),
        )
        validated = _validate_meta_signals([sig_a, meta_a, meta_b])
        names = {s.name for s in validated}
        assert "Meta B" not in names
        assert "Meta A" in names
        assert "Sig A" in names


# ── 2.4 Unit tests for detection weight parsing and weighted scoring ───


class TestDetectionWeight:
    """Task 2.4: detection weight parsing and weighted scoring tests.

    Requirements: 9.1, 9.2, 9.3, 9.5, 22.5
    """

    def test_weight_parsed_correctly(self) -> None:
        """Weight parsed correctly from YAML."""
        fp_dict = {
            "name": "Contoso CDN",
            "slug": "contoso-cdn",
            "category": "CDN",
            "confidence": "high",
            "detections": [{"type": "cname", "pattern": "cdn.contoso.com", "weight": 0.7}],
        }
        fp = _validate_fingerprint(fp_dict, "test")
        assert fp is not None
        assert fp.detections[0].weight == 0.7

    def test_weight_defaults_to_1_when_omitted(self) -> None:
        """Weight defaults to 1.0 when omitted."""
        fp_dict = {
            "name": "Contoso CDN",
            "slug": "contoso-cdn",
            "category": "CDN",
            "confidence": "high",
            "detections": [{"type": "cname", "pattern": "cdn.contoso.com"}],
        }
        fp = _validate_fingerprint(fp_dict, "test")
        assert fp is not None
        assert fp.detections[0].weight == 1.0

    def test_out_of_range_weight_defaults_to_1(self) -> None:
        """Out-of-range weight → warning, defaults to 1.0."""
        fp_dict = {
            "name": "Contoso CDN",
            "slug": "contoso-cdn",
            "category": "CDN",
            "confidence": "high",
            "detections": [{"type": "cname", "pattern": "cdn.contoso.com", "weight": 2.5}],
        }
        fp = _validate_fingerprint(fp_dict, "test")
        assert fp is not None
        assert fp.detections[0].weight == 1.0

        # Negative weight
        fp_dict["detections"] = [{"type": "cname", "pattern": "cdn.contoso.com", "weight": -0.5}]
        fp = _validate_fingerprint(fp_dict, "test")
        assert fp is not None
        assert fp.detections[0].weight == 1.0

    def test_weighted_detection_scores_computation(self) -> None:
        """Weighted detection_scores computation with explicit weights dict."""
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="contoso-verify=abc", rule_name="Contoso", slug="contoso"),
            EvidenceRecord(source_type="CNAME", raw_value="login.contoso.com", rule_name="Contoso", slug="contoso"),
            EvidenceRecord(source_type="MX", raw_value="mx.fabrikam.com", rule_name="Fabrikam", slug="fabrikam"),
        )
        weights = {
            ("contoso", "TXT"): 0.3,
            ("contoso", "CNAME"): 0.9,
            ("fabrikam", "MX"): 1.0,
        }
        scores = compute_detection_scores(evidence, weights=weights)
        score_dict = dict(scores)
        # contoso: 0.3 + 0.9 = 1.2 → < 1.5 → "low"
        assert score_dict["contoso"] == "low"
        # fabrikam: 1.0 → < 1.5 → "low"
        assert score_dict["fabrikam"] == "low"

    def test_weighted_scores_high_threshold(self) -> None:
        """Weighted scores reach 'high' when sum >= 2.5."""
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="v1", rule_name="R", slug="s"),
            EvidenceRecord(source_type="CNAME", raw_value="v2", rule_name="R", slug="s"),
            EvidenceRecord(source_type="MX", raw_value="v3", rule_name="R", slug="s"),
        )
        weights = {
            ("s", "TXT"): 1.0,
            ("s", "CNAME"): 0.9,
            ("s", "MX"): 0.8,
        }
        scores = compute_detection_scores(evidence, weights=weights)
        score_dict = dict(scores)
        # 1.0 + 0.9 + 0.8 = 2.7 >= 2.5 → "high"
        assert score_dict["s"] == "high"


# ── 2.5 Unit tests for explain field on Signal and _PostureRule ────────


class TestExplainField:
    """Task 2.5: explain field on Signal and _PostureRule tests.

    Requirements: 18.1, 18.2, 18.4, 22.13
    """

    def test_explain_parsed_on_signal(self) -> None:
        """explain parsed and stored on Signal dataclass."""
        result = _validate_and_build_signal(
            {
                "name": "Contoso Signal",
                "requires": {"any": ["contoso"]},
                "explain": "Contoso integration indicates enterprise deployment",
            },
            0,
        )
        assert result is not None
        assert result.explain == "Contoso integration indicates enterprise deployment"

    def test_explain_parsed_on_posture_rule(self) -> None:
        """explain parsed and stored on _PostureRule dataclass."""
        rule_dict = {
            "name": "Contoso Observation",
            "category": "infrastructure",
            "salience": "medium",
            "template": "Contoso infrastructure detected",
            "condition": {"slugs_any": ["contoso"]},
            "explain": "Contoso infrastructure suggests enterprise hosting",
        }
        result = _validate_and_build_rule(rule_dict, 0)
        assert result is not None
        assert result.explain == "Contoso infrastructure suggests enterprise hosting"

    def test_explain_defaults_to_empty_on_signal(self) -> None:
        """Omitted explain defaults to empty string on Signal."""
        result = _validate_and_build_signal(
            {"name": "Minimal Signal", "requires": {"any": ["slug-a"]}},
            0,
        )
        assert result is not None
        assert result.explain == ""

    def test_explain_defaults_to_empty_on_posture_rule(self) -> None:
        """Omitted explain defaults to empty string on _PostureRule."""
        rule_dict = {
            "name": "Minimal Rule",
            "category": "email",
            "salience": "low",
            "template": "Minimal observation",
            "condition": {"slugs_any": ["slug-a"]},
        }
        result = _validate_and_build_rule(rule_dict, 0)
        assert result is not None
        assert result.explain == ""

    def test_non_string_explain_defaults_to_empty_on_signal(self) -> None:
        """Non-string explain defaults to empty string on Signal."""
        result = _validate_and_build_signal(
            {"name": "Bad Explain", "requires": {"any": ["a"]}, "explain": 42},
            0,
        )
        assert result is not None
        assert result.explain == ""

    def test_non_string_explain_defaults_to_empty_on_posture_rule(self) -> None:
        """Non-string explain defaults to empty string on _PostureRule."""
        rule_dict = {
            "name": "Bad Explain Rule",
            "category": "email",
            "salience": "low",
            "template": "Observation",
            "condition": {"slugs_any": ["slug-a"]},
            "explain": 999,
        }
        result = _validate_and_build_rule(rule_dict, 0)
        assert result is not None
        assert result.explain == ""


# ── 2.6 PBT Property 2: Signal Contradiction Suppression ───────────────


# Strategies for PBTs
_slug_alphabet = st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789-")
_slug_st = st.text(alphabet=_slug_alphabet, min_size=1, max_size=15).filter(
    lambda s: s[0].isalnum() and s[-1].isalnum()
)

_signal_name_st = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    min_size=1,
    max_size=25,
).filter(lambda s: s.strip() == s and len(s) > 0)


class TestPBTContradictionSuppression:
    """PBT Property 2: Signal Contradiction Suppression.

    For any signal with non-empty contradicts and any context where
    a contradiction slug is present, evaluate_signals() shall not
    include that signal.

    **Validates: Requirements 7.1, 7.3**
    """

    @given(
        candidate_slugs=st.lists(_slug_st, min_size=1, max_size=5),
        contradict_slugs=st.lists(_slug_st, min_size=1, max_size=3),
        extra_slugs=st.lists(_slug_st, min_size=0, max_size=3),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_contradiction_suppression(
        self,
        candidate_slugs: list[str],
        contradict_slugs: list[str],
        extra_slugs: list[str],
    ) -> None:
        """Signal with contradicts is suppressed when any contradiction slug is present."""
        signal = Signal(
            name="Test Contradiction Signal",
            category="Test",
            confidence="medium",
            description="Test signal",
            candidates=tuple(candidate_slugs),
            min_matches=1,
            contradicts=tuple(contradict_slugs),
        )

        # Build context that includes at least one contradiction slug + all candidates
        detected = set(candidate_slugs) | set(extra_slugs)
        # Add at least one contradiction slug
        detected.add(contradict_slugs[0])

        context = _ctx(detected)

        with patch("recon_tool.signals.load_signals", return_value=(signal,)):
            results = evaluate_signals(context)

        signal_names = {r.name for r in results}
        assert "Test Contradiction Signal" not in signal_names

    @given(
        candidate_slugs=st.lists(_slug_st, min_size=1, max_size=5),
        contradict_slugs=st.lists(_slug_st, min_size=1, max_size=3),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_no_contradiction_fires_normally(
        self,
        candidate_slugs: list[str],
        contradict_slugs: list[str],
    ) -> None:
        """Signal fires when no contradiction slug is present and candidates match."""
        # Ensure no overlap between candidates and contradicts
        contradict_set = set(contradict_slugs)
        clean_candidates = [s for s in candidate_slugs if s not in contradict_set]
        if not clean_candidates:
            clean_candidates = ["unique-candidate-slug"]

        signal = Signal(
            name="Test Normal Signal",
            category="Test",
            confidence="medium",
            description="Test signal",
            candidates=tuple(clean_candidates),
            min_matches=1,
            contradicts=tuple(contradict_slugs),
        )

        # Context has candidates but NO contradiction slugs
        detected = set(clean_candidates)
        # Ensure no contradiction slug is present
        detected -= contradict_set

        if not detected:
            detected = {"unique-candidate-slug"}

        context = _ctx(detected)

        with patch("recon_tool.signals.load_signals", return_value=(signal,)):
            results = evaluate_signals(context)

        signal_names = {r.name for r in results}
        assert "Test Normal Signal" in signal_names


# ── 2.7 PBT Property 3: match_mode: all Enforcement ────────────────────


class TestPBTMatchModeAll:
    """PBT Property 3: match_mode: all Enforcement.

    For any fingerprint with match_mode: all and any set of DNS records
    where at least one detection fails, no detection result is produced.

    **Validates: Requirements 8.1, 8.2, 8.5**
    """

    @given(
        num_detections=st.integers(min_value=2, max_value=5),
        missing_index=st.integers(min_value=0, max_value=4),
    )
    @settings(max_examples=100)
    def test_partial_match_no_detection(
        self,
        num_detections: int,
        missing_index: int,
    ) -> None:
        """Fingerprint with match_mode: all and partial matches → no detection."""
        missing_index = missing_index % num_detections

        detections = tuple(DetectionRule(type="txt", pattern=f"^pattern-{i}=") for i in range(num_detections))
        fp = Fingerprint(
            name="Contoso Multi",
            slug="contoso-multi",
            category="SaaS",
            confidence="high",
            m365=False,
            match_mode="all",
            detections=detections,
        )

        ctx = _DetectionCtx()
        ctx.add("Contoso Multi", "contoso-multi", source_type="TXT", raw_value="test")

        # Record all detections EXCEPT the missing one
        for i in range(num_detections):
            if i != missing_index:
                ctx.record_fp_match("contoso-multi", "txt", f"^pattern-{i}=")

        with patch("recon_tool.sources.dns.load_fingerprints", return_value=(fp,)):
            ctx.enforce_match_mode_all()

        assert "contoso-multi" not in ctx.slugs

    @given(
        num_detections=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_full_match_produces_detection(
        self,
        num_detections: int,
    ) -> None:
        """Fingerprint with match_mode: all and all matches → detection produced."""
        detections = tuple(DetectionRule(type="txt", pattern=f"^pattern-{i}=") for i in range(num_detections))
        fp = Fingerprint(
            name="Contoso Full",
            slug="contoso-full",
            category="SaaS",
            confidence="high",
            m365=False,
            match_mode="all",
            detections=detections,
        )

        ctx = _DetectionCtx()
        ctx.add("Contoso Full", "contoso-full", source_type="TXT", raw_value="test")

        # Record ALL detections
        for i in range(num_detections):
            ctx.record_fp_match("contoso-full", "txt", f"^pattern-{i}=")

        with patch("recon_tool.sources.dns.load_fingerprints", return_value=(fp,)):
            ctx.enforce_match_mode_all()

        assert "contoso-full" in ctx.slugs


# ── 2.8 PBT Property 4: Detection Weight Monotonicity ──────────────────


class TestPBTDetectionWeightMonotonicity:
    """PBT Property 4: Detection Weight Monotonicity.

    Weighted detection score is monotonically non-decreasing with respect
    to sum of weights; adding higher-weight evidence never decreases score.

    **Validates: Requirements 9.2, 9.5**
    """

    @given(
        base_weights=st.lists(
            st.floats(min_value=0.01, max_value=1.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=5,
        ),
        extra_weight=st.floats(min_value=0.01, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=100)
    def test_adding_evidence_never_decreases_score(
        self,
        base_weights: list[float],
        extra_weight: float,
    ) -> None:
        """Adding higher-weight evidence never decreases score."""
        slug = "test-slug"
        source_types = ["TXT", "CNAME", "MX", "NS", "SPF", "CAA"]

        # Build base evidence with distinct source types
        base_evidence: list[EvidenceRecord] = []
        base_weight_map: dict[tuple[str, str], float] = {}
        for i, w in enumerate(base_weights):
            if i >= len(source_types):
                break
            st_name = source_types[i]
            base_evidence.append(EvidenceRecord(source_type=st_name, raw_value=f"v{i}", rule_name="R", slug=slug))
            base_weight_map[(slug, st_name)] = w

        base_scores = compute_detection_scores(tuple(base_evidence), weights=base_weight_map)

        # Add one more evidence record with a new source type
        next_idx = len(base_evidence)
        if next_idx < len(source_types):
            new_st = source_types[next_idx]
            extended_evidence = base_evidence + [
                EvidenceRecord(source_type=new_st, raw_value="extra", rule_name="R", slug=slug)
            ]
            extended_weights = dict(base_weight_map)
            extended_weights[(slug, new_st)] = extra_weight

            extended_scores = compute_detection_scores(tuple(extended_evidence), weights=extended_weights)

            # Map score labels to numeric values for comparison
            score_order = {"low": 0, "medium": 1, "high": 2}
            base_score_val = score_order.get(dict(base_scores).get(slug, "low"), 0)
            ext_score_val = score_order.get(dict(extended_scores).get(slug, "low"), 0)

            assert ext_score_val >= base_score_val


# ── 2.9 PBT Property 5: Meta-Signal Biconditional Evaluation ───────────


class TestPBTMetaSignalBiconditional:
    """PBT Property 5: Meta-Signal Biconditional Evaluation.

    Meta-signal fires iff all referenced signals fired in pass 1
    AND all other conditions satisfied.

    **Validates: Requirements 10.1, 10.4, 10.5**
    """

    @given(
        num_required=st.integers(min_value=1, max_value=4),
        all_fire=st.booleans(),
    )
    @settings(max_examples=100)
    def test_meta_signal_biconditional(
        self,
        num_required: int,
        all_fire: bool,
    ) -> None:
        """Meta-signal fires iff all referenced signals fired in pass 1."""
        # Create required non-meta signals
        required_signals: list[Signal] = []
        all_slugs: set[str] = set()
        for i in range(num_required):
            slug = f"req-slug-{i}"
            all_slugs.add(slug)
            required_signals.append(
                Signal(
                    name=f"Required Signal {i}",
                    category="Test",
                    confidence="high",
                    description="",
                    candidates=(slug,),
                    min_matches=1,
                )
            )

        # Create meta-signal referencing all required signals
        meta = Signal(
            name="Test Meta Signal",
            category="Composite",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
            requires_signals=tuple(s.name for s in required_signals),
        )

        if all_fire:
            # All required slugs present → all required signals fire → meta fires
            context = _ctx(all_slugs)
        else:
            # Remove one slug so one required signal doesn't fire
            partial_slugs = set(list(all_slugs)[:-1]) if len(all_slugs) > 1 else set()
            context = _ctx(partial_slugs)

        all_signals = tuple(required_signals) + (meta,)
        with patch("recon_tool.signals.load_signals", return_value=all_signals):
            results = evaluate_signals(context)

        result_names = {r.name for r in results}

        if all_fire:
            assert "Test Meta Signal" in result_names
        else:
            assert "Test Meta Signal" not in result_names

    @given(
        has_extra_slug=st.booleans(),
    )
    @settings(max_examples=100)
    def test_meta_signal_with_additional_slug_condition(
        self,
        has_extra_slug: bool,
    ) -> None:
        """Meta-signal with requires_signals AND requires.any — both must hold."""
        base_signal = Signal(
            name="Base Signal",
            category="Test",
            confidence="high",
            description="",
            candidates=("base-slug",),
            min_matches=1,
        )
        meta = Signal(
            name="Conditional Meta",
            category="Composite",
            confidence="medium",
            description="",
            candidates=("extra-condition-slug",),
            min_matches=1,
            requires_signals=("Base Signal",),
        )

        slugs = {"base-slug"}
        if has_extra_slug:
            slugs.add("extra-condition-slug")

        context = _ctx(slugs)
        with patch("recon_tool.signals.load_signals", return_value=(base_signal, meta)):
            results = evaluate_signals(context)

        result_names = {r.name for r in results}

        if has_extra_slug:
            assert "Conditional Meta" in result_names
        else:
            assert "Conditional Meta" not in result_names
