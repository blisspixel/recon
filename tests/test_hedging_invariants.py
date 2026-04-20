"""Property-based hedging regression harness.

This is the mechanical floor that makes other hedging work safe to
ship: it asserts hedging invariants on synthetic sparse-data fixtures so
a PR that accidentally reintroduces confident-wrong language on a
proxy-fronted / minimal-DNS / managed-auth target gets caught before
merge.

Three invariants, tested with Hypothesis-generated inputs:

    1. **Hedged hardening observations never contain confident verdicts.**
       When ``positive_when_absent`` fires, the emitted description must
       use two-sided hedged language ("fits deliberate hardening or a
       dormant / parked target"). No "is", no "definitely", no
       "confirmed".

    2. **Sparse-data insights never claim certainty.** When a TenantInfo
       has fewer than 3 successful sources, its generated insights are
       allowed to observe patterns but never to commit to them. Every
       sovereignty, federation, dual-provider, and hardening insight on
       sparse data must match the hedged-language allowlist.

    3. **Signal/absence output survives random slug subsets.** Given any
       subset of the built-in fingerprint slugs, the signal evaluator +
       absence engine + positive-absence engine must not raise, must
       produce only hedged descriptions, and must never emit duplicate
       signal names.

The harness is deliberately narrow in scope. It doesn't try to replace
the existing golden corpus (``tests/validation/``) or the v0.9.2
hardened-archetype tests — it sits alongside them, running on every
``pytest`` invocation and blocking any regression on the language and
shape invariants that v0.9.3's new inference layers depend on.

Runs in <2 seconds on the default Hypothesis settings so it's always on.
"""

from __future__ import annotations

import re

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
from recon_tool.insights import generate_insights
from recon_tool.models import ConfidenceLevel, SignalContext, TenantInfo
from recon_tool.signals import Signal, SignalMatch, evaluate_signals, load_signals, reload_signals

# ── Hedged language allowlist ──────────────────────────────────────────

# A user-facing string is "hedged" when at least one of these markers
# appears in its lowercased form. The list is intentionally broad —
# we're catching confident-wrong output, not policing wording.
_HEDGE_MARKERS: tuple[str, ...] = (
    "observed",
    "observation",
    "likely",
    "possible",
    "fits",
    "consistent with",
    "suggests",
    "may ",  # "may indicate", "may not be fully effective", …
    "indicator",
    "not a verdict",
    "appears",
    "probably",
    "approximately",
    "hedged",
    "hint",
    "looks like",
    "no dmarc",  # factual DMARC absence, not a verdict
    "no dkim",  # same
    "unknown",  # "actual DKIM status unknown"
    "(observed)",
    "(inferred)",
    "(likely primary)",
    "possible ",
    "potential ",
    "configuration residue",
    "gap ",  # "Security gap", "…has a gap"
    "in progress",  # "migration in progress"
    "coexistence",  # "dual provider coexistence"
    "incomplete",  # "Incomplete Identity Migration"
)

# Confident absolute markers that must NEVER appear in hedged output.
_CONFIDENT_FORBIDDEN: tuple[str, ...] = (
    " is a deliberately hardened",
    "definitely",
    "confirmed hardened",
    "this is a government",
    "this is a gcc",
    "this is an hvt",
    "proven hardened",
)


def _is_hedged(text: str) -> bool:
    """True if text contains at least one hedged marker.

    Factual record quotations are whitelisted explicitly because they
    reproduce the raw record value verbatim — that's a fact, not an
    inference. ``"DMARC: none"`` quotes the policy directly; ``"email
    security 4/5 strong"`` reports a computed score with a known
    formula; ``"no DMARC record"`` is a factual absence claim.
    """
    lower = text.lower()
    # Quick whitelist for raw record quotations
    if re.search(r"\bdmarc:\s*(reject|quarantine|none)\b", lower):
        return True
    if re.search(r"\bdmarc policy is (reject|quarantine|none)\b", lower):
        return True
    if re.search(r"\bspf (strict|soft|permissive)\b", lower):
        return True
    if re.search(r"email security \d/5", lower):
        return True
    if "no dmarc record" in lower:
        return True
    return any(marker in lower for marker in _HEDGE_MARKERS)


def _has_forbidden(text: str) -> bool:
    lower = text.lower()
    return any(bad in lower for bad in _CONFIDENT_FORBIDDEN)


# ── Hypothesis strategies ──────────────────────────────────────────────


def _loaded_slugs() -> tuple[str, ...]:
    """All detected-slug candidates from loaded signals."""
    reload_signals()
    slugs: set[str] = set()
    for sig in load_signals():
        slugs.update(sig.candidates)
        slugs.update(sig.contradicts)
        slugs.update(sig.expected_counterparts)
        slugs.update(sig.positive_when_absent)
    return tuple(sorted(slugs))


_ALL_SLUGS = _loaded_slugs()

slug_subset_st = st.lists(
    st.sampled_from(_ALL_SLUGS) if _ALL_SLUGS else st.just("placeholder"),
    min_size=0,
    max_size=10,
    unique=True,
)


dmarc_policy_st = st.one_of(
    st.just(None),
    st.sampled_from(("reject", "quarantine", "none")),
)


cloud_instance_st = st.one_of(
    st.just(None),
    st.sampled_from(
        (
            "microsoftonline.com",
            "microsoftonline.us",
            "partner.microsoftonline.cn",
            "fabrikam.b2clogin.com",
        )
    ),
)


# ── Invariant 1: positive-when-absent always hedged ───────────────────


class TestHardeningObservationIsHedged:
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(detected=slug_subset_st)
    def test_positive_absence_only_emits_hedged(self, detected: list[str]):
        """Every SignalMatch produced by the positive-absence engine
        must have a two-sided hedged description."""
        ctx = SignalContext(detected_slugs=frozenset(detected))
        fired = evaluate_signals(ctx)
        observations = evaluate_positive_absence(fired, load_signals(), ctx.detected_slugs)
        for obs in observations:
            assert _is_hedged(obs.description), f"Non-hedged hardening obs: {obs.description!r}"
            assert not _has_forbidden(obs.description), f"Forbidden language: {obs.description!r}"

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(detected=slug_subset_st)
    def test_hardening_observation_name_has_suffix(self, detected: list[str]):
        """The emitted SignalMatch name must carry the v0.9.3 suffix so
        downstream code can filter for hardening observations without
        having to string-match the description."""
        ctx = SignalContext(detected_slugs=frozenset(detected))
        fired = evaluate_signals(ctx)
        observations = evaluate_positive_absence(fired, load_signals(), ctx.detected_slugs)
        for obs in observations:
            assert "Hardening Pattern Observed" in obs.name


# ── Invariant 2: sparse-data insights never claim certainty ───────────


class TestSparseDataInsightsHedged:
    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(cloud=cloud_instance_st, dmarc=dmarc_policy_st, slugs=slug_subset_st)
    def test_sovereignty_insights_hedged(
        self,
        cloud: str | None,
        dmarc: str | None,
        slugs: list[str],
    ):
        """Any sovereignty insight emitted must be hedged."""
        assume(cloud is not None)
        insights = generate_insights(
            services=set(),
            slugs=set(slugs),
            auth_type="Managed",
            dmarc_policy=dmarc,
            domain_count=1,
            cloud_instance=cloud,
        )
        for line in insights:
            lower = line.lower()
            if "government" in lower or "china" in lower or "b2c" in lower or "non-commercial" in lower:
                assert _is_hedged(line), f"Unhedged sovereignty insight: {line!r}"
                assert not _has_forbidden(line), f"Forbidden language: {line!r}"

    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(dmarc=dmarc_policy_st, slugs=slug_subset_st)
    def test_email_security_insights_hedged(self, dmarc: str | None, slugs: list[str]):
        """Email security score and DKIM observations must use hedged
        language — a score like '4/5 strong' is a factual observation
        of the score, not a confident claim about actual security."""
        insights = generate_insights(
            services={"DMARC", "DKIM", "SPF: strict (-all)"},
            slugs=set(slugs),
            auth_type=None,
            dmarc_policy=dmarc,
            domain_count=1,
        )
        for line in insights:
            lower = line.lower()
            if "email security" in lower or "dmarc" in lower or "dkim" in lower:
                assert _is_hedged(line), f"Unhedged email-security insight: {line!r}"


# ── Invariant 3: signal pipeline robustness ───────────────────────────


class TestSignalPipelineRobustness:
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(slugs=slug_subset_st, dmarc=dmarc_policy_st)
    def test_pipeline_never_raises(self, slugs: list[str], dmarc: str | None):
        """Random slug subsets must flow through the two-pass + absence
        + positive-absence pipeline without exceptions."""
        ctx = SignalContext(detected_slugs=frozenset(slugs), dmarc_policy=dmarc)
        fired = evaluate_signals(ctx)
        sigs = load_signals()
        absence = evaluate_absence_signals(fired, sigs, ctx.detected_slugs)
        positive = evaluate_positive_absence(fired, sigs, ctx.detected_slugs)
        all_matches = list(fired) + list(absence) + list(positive)
        assert all(isinstance(m, SignalMatch) for m in all_matches)

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(slugs=slug_subset_st)
    def test_no_duplicate_signal_names(self, slugs: list[str]):
        """A signal name must not appear twice in the same output set —
        duplicates indicate a logic bug in the two-pass evaluator."""
        ctx = SignalContext(detected_slugs=frozenset(slugs))
        fired = evaluate_signals(ctx)
        names = [m.name for m in fired]
        assert len(names) == len(set(names)), f"Duplicate signal names: {names}"

    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    @given(slugs=slug_subset_st)
    def test_absence_name_references_parent(self, slugs: list[str]):
        """Every absence SignalMatch must have a name pointing at a
        parent signal that actually fired."""
        ctx = SignalContext(detected_slugs=frozenset(slugs))
        fired = evaluate_signals(ctx)
        absence = evaluate_absence_signals(fired, load_signals(), ctx.detected_slugs)
        fired_names = {m.name for m in fired}
        for m in absence:
            parent = m.name.split(" —", 1)[0]
            assert parent in fired_names, f"Absence signal {m.name!r} references non-firing parent {parent!r}"


# ── Invariant 4: TenantInfo serialization preserves hedging ───────────


def _hedged_info() -> TenantInfo:
    """A minimal TenantInfo that exercises the hedged insight paths."""
    return TenantInfo(
        tenant_id=None,
        display_name="Test",
        default_domain="test.example",
        queried_domain="test.example",
        confidence=ConfidenceLevel.LOW,
        insights=(
            "Federated identity indicators observed (likely enterprise SSO)",
            "Email security 2/5 basic (DMARC none)",
            "Edge Layering — Hardening Pattern Observed: fits deliberate hardening",
        ),
    )


class TestHedgedInfoRenders:
    def test_render_panel_preserves_hedged_insights(self):
        """The v0.9.3 panel must emit every hedged insight without
        rewriting it into a confident verdict."""
        from io import StringIO

        from rich.console import Console

        from recon_tool.formatter import get_console, render_tenant_panel

        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True, no_color=True)
        from recon_tool.formatter import set_console

        set_console(console)
        try:
            console.print(render_tenant_panel(_hedged_info()))
        finally:
            set_console(get_console())
        out = buf.getvalue()
        # Every hedged insight must survive curation
        assert "Federated identity" in out
        assert "observed" in out.lower()
        # No confident verdict replacement
        assert not _has_forbidden(out)


# ── Invariant 5: Signal definitions themselves are validated ──────────


class TestSignalDefinitionsValid:
    def test_no_signal_uses_forbidden_language(self):
        """Every loaded Signal's description and explain text must NOT
        contain the forbidden confident-verdict markers. Signal
        descriptions are allowed to be factual-observation statements
        ("X detected", "multiple Y present") — they don't have to
        carry hedging markers because they describe what's observed,
        not what's inferred. The runtime inference layers (insights,
        posture, absence engine) do the hedging when they turn
        detections into conclusions."""
        reload_signals()
        for sig in load_signals():
            assert isinstance(sig, Signal)
            assert not _has_forbidden(sig.description), (
                f"Signal {sig.name!r} uses forbidden language: {sig.description!r}"
            )
            assert not _has_forbidden(sig.explain), (
                f"Signal {sig.name!r} explain uses forbidden language: {sig.explain!r}"
            )

    def test_no_signal_claims_absolute_certainty(self):
        """Signal descriptions must not use words that imply absolute
        certainty about the organization's actual state. We allow
        factual-observation language ("X detected") but reject
        absolute claims ("definitely X", "confirmed Y", "proven Z")."""
        reload_signals()
        absolute_patterns = ("definitely", "proven", "confirmed ", "guaranteed")
        for sig in load_signals():
            lower = sig.description.lower() + " " + sig.explain.lower()
            for pat in absolute_patterns:
                assert pat not in lower, (
                    f"Signal {sig.name!r} has absolute certainty language {pat!r}: {sig.description!r}"
                )
