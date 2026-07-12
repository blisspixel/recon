"""Posture MCP tools: analyze, exposure, gaps, compare, hypothesis, simulate.

Extracted from server.py (docs/roadmap.md god-file track, app-sharing variant).
Registers its tools on the shared ``mcp`` instance imported from
``recon_tool.server.app``; the server facade imports this module to trigger
registration and re-exports the tool functions for the test surface. Imports
``recon_tool.server.app`` and ``recon_tool.server.runtime``; never the reverse.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass
from typing import Literal, cast

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from typing_extensions import TypedDict

from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.server import app as server_app
from recon_tool.server.app import mcp
from recon_tool.server.runtime import (
    log_structured,
)
from recon_tool.validator import strip_control_chars

logger = logging.getLogger("recon")

HypothesisLikelihood = Literal["unresolved"]
HypothesisConfidence = Literal["high", "medium", "low"]


class HypothesisAssessmentResult(TypedDict):
    domain: str
    hypothesis: str
    likelihood: HypothesisLikelihood
    supporting_signals: list[str]
    contradicting_signals: list[str]
    missing_evidence: list[str]
    confidence: HypothesisConfidence
    disclaimer: str


class SimulatedGapSummary(TypedDict):
    category: str
    severity: str
    observation: str
    recommendation: str


class HardeningSimulationResult(TypedDict):
    domain: str
    current_score: int
    simulated_score: int
    score_delta: int
    applied_fixes: list[str]
    remaining_gaps: list[SimulatedGapSummary]
    disclaimer: str


class EvidenceReferenceSummary(TypedDict):
    source_type: str
    raw_value: str
    rule_name: str
    slug: str


class ObservabilitySummary(TypedDict):
    score_is_lower_bound: bool
    unconfirmable_absent_points: int
    score_ceiling: int
    unavailable_controls: list[str]
    note: str


class EmailPostureSummary(TypedDict):
    dmarc_policy: str | None
    dkim_configured: bool
    spf_strict: bool
    mta_sts_mode: str | None
    email_gateway: str | None
    bimi_configured: bool
    email_security_score: int
    evidence: list[EvidenceReferenceSummary]


class IdentityPostureSummary(TypedDict):
    auth_type: str | None
    identity_provider: str | None
    google_auth_type: str | None
    google_idp_name: str | None
    evidence: list[EvidenceReferenceSummary]


class InfrastructureFootprintSummary(TypedDict):
    cloud_providers: list[str]
    dns_provider: str | None
    cdn_waf: list[str]
    certificate_authorities: list[str]
    evidence: list[EvidenceReferenceSummary]


class ConsistencyObservationSummary(TypedDict):
    observation: str
    category: str
    evidence: list[EvidenceReferenceSummary]


class HardeningControlSummary(TypedDict):
    name: str
    present: bool
    detail: str
    evidence: list[EvidenceReferenceSummary]


class HardeningStatusSummary(TypedDict):
    controls: list[HardeningControlSummary]


class ExposureAssessmentResult(TypedDict):
    domain: str
    posture_score: int
    posture_score_label: str
    observability: ObservabilitySummary
    email_posture: EmailPostureSummary
    identity_posture: IdentityPostureSummary
    infrastructure_footprint: InfrastructureFootprintSummary
    consistency_observations: list[ConsistencyObservationSummary]
    hardening_status: HardeningStatusSummary
    disclaimer: str
    evidence: list[EvidenceReferenceSummary]


class HardeningGapSummary(TypedDict):
    category: str
    severity: str
    observation: str
    recommendation: str
    absence_confirmable: bool
    evidence: list[EvidenceReferenceSummary]


class GapReportResult(TypedDict):
    domain: str
    gaps: list[HardeningGapSummary]
    disclaimer: str
    unavailable_controls: list[str]
    degraded_sources: list[str]


class PostureMetricSummary(TypedDict):
    metric_name: str
    domain_a_value: str
    domain_b_value: str


class PostureDifferenceSummary(TypedDict):
    description: str
    domain_a_has: bool
    domain_b_has: bool


class RelativeAssessmentSummary(TypedDict):
    dimension: str
    summary: str


class PostureComparisonResult(TypedDict):
    domain_a: str
    domain_b: str
    metrics: list[PostureMetricSummary]
    differences: list[PostureDifferenceSummary]
    relative_assessment: list[RelativeAssessmentSummary]
    disclaimer: str


class PostureObservationSummary(TypedDict):
    category: str
    salience: str
    statement: str
    related_slugs: list[str]


class ExplanationSummary(TypedDict):
    item_name: str
    item_type: str
    matched_evidence: list[EvidenceReferenceSummary]
    fired_rules: list[str]
    confidence_derivation: str
    weakening_conditions: list[str]
    curated_explanation: str


class PostureAnalysisEnvelope(TypedDict):
    observations: list[PostureObservationSummary]


class ProfiledPostureAnalysisEnvelope(PostureAnalysisEnvelope):
    profile_note: str


class ExplainedPostureAnalysisEnvelope(PostureAnalysisEnvelope):
    explanations: list[ExplanationSummary]


class ProfiledExplainedPostureAnalysisEnvelope(ExplainedPostureAnalysisEnvelope):
    profile_note: str


AnalyzePostureOutput = (
    list[PostureObservationSummary]
    | PostureAnalysisEnvelope
    | ProfiledPostureAnalysisEnvelope
    | ExplainedPostureAnalysisEnvelope
    | ProfiledExplainedPostureAnalysisEnvelope
)


# Keyword groups for hypothesis matching — maps keywords to signal/slug categories
_HYPOTHESIS_KEYWORDS: dict[str, list[str]] = {
    "migration": ["migration", "migrate", "transition", "moving", "switching"],
    "security": ["security", "secure", "protection", "defense", "defensive"],
    "email": ["email", "mail", "dmarc", "dkim", "spf", "mta-sts", "bimi"],
    "identity": ["identity", "sso", "federated", "okta", "entra", "auth", "authentication"],
    "cloud": ["cloud", "aws", "azure", "gcp", "saas"],
    "ai": ["ai", "artificial intelligence", "llm", "openai", "generative", "machine learning"],
    "compliance": ["compliance", "governance", "audit", "regulation"],
    "collaboration": ["collaboration", "teams", "slack", "zoom", "communication"],
    "monitoring": ["monitoring", "observability", "logging", "telemetry"],
    "cdn": ["cdn", "edge", "waf", "firewall", "cloudflare", "akamai"],
}

_HYPOTHESIS_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "be",
        "doing",
        "does",
        "for",
        "has",
        "have",
        "in",
        "indicator",
        "indicators",
        "is",
        "it",
        "not",
        "observed",
        "of",
        "organization",
        "platform",
        "public",
        "service",
        "services",
        "that",
        "the",
        "their",
        "they",
        "this",
        "to",
        "tool",
        "tools",
        "use",
        "uses",
        "using",
        "vendor",
        "vendors",
        "we",
        "with",
    }
)


def _hypothesis_terms(text: str) -> frozenset[str]:
    """Return bounded semantic terms without substring or stopword matches."""
    return frozenset(term for term in re.findall(r"[a-z0-9]+", text.casefold()) if term not in _HYPOTHESIS_STOPWORDS)


def _keyword_group_matches(terms: frozenset[str], keywords: list[str]) -> bool:
    """Whether all meaningful terms from one configured keyword are present."""
    return any((keyword_terms := _hypothesis_terms(keyword)) and keyword_terms <= terms for keyword in keywords)


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def analyze_posture(
    domain: str,
    explain: bool = False,
    profile: str | None = None,
) -> AnalyzePostureOutput:
    """Analyze a domain's configuration posture and return neutral observations.

    Returns factual observations about the domain's email security, identity,
    infrastructure, SaaS footprint, certificate activity, and configuration
    consistency. Observations are neutral — they describe what is, not what
    should be.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")
        explain: When true, include explanation data for each posture observation.
        profile: Optional profile name (e.g. "fintech", "healthcare",
            "saas-b2b", "high-value-target", "public-sector"). Reweights
            and filters observations to the profile's lens without
            adding new intelligence.

    Returns:
        JSON array of observations, each with category, salience, statement,
        and related_slugs. When explain is true, includes explanation data.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.collection_view import collection_claim_info
    from recon_tool.formatter import format_posture_observations
    from recon_tool.posture import analyze_posture as _analyze_posture
    from recon_tool.profiles import apply_profile, list_profiles, load_profile

    info = collection_claim_info(info)
    observations = _analyze_posture(info)

    # Apply profile lens if requested. ``profile`` is typed
    # ``str | None``, but MCP arguments arrive unenforced at runtime (the same
    # caveat the detection-list guard below notes), so a truthy non-string would
    # raise ``TypeError`` on the ``profile[:100]`` slice. Guard the type and
    # treat a non-string as no lens, matching the ``None`` case.
    profile_note: str | None = None
    if isinstance(profile, str) and profile:  # pyright: ignore[reportUnnecessaryIsInstance]
        profile = profile[:100]
        prof = load_profile(profile)
        if prof is None:
            available = ", ".join(p.name for p in list_profiles()) or "(none)"
            raise ToolError(f"Unknown profile {profile!r}. Available profiles: {available}")
        observations = apply_profile(tuple(observations), prof)
        profile_note = prof.prepend_note or prof.description

    elapsed = time.monotonic() - start_time
    log_structured(
        logging.INFO,
        "posture_analyzed",
        request_id=request_id,
        domain=domain,
        observations=len(observations),
        elapsed_s=round(elapsed, 2),
    )

    result_list = cast(list[PostureObservationSummary], format_posture_observations(observations))

    if explain:
        from recon_tool.explanation import explain_observations, serialize_explanation
        from recon_tool.posture import load_posture_rules

        posture_rules = load_posture_rules()
        explanation_records = explain_observations(observations, posture_rules, info.evidence, info.detection_scores)
        explanations = cast(list[ExplanationSummary], [serialize_explanation(rec) for rec in explanation_records])
        if profile_note:
            return {"observations": result_list, "explanations": explanations, "profile_note": profile_note}
        return {"observations": result_list, "explanations": explanations}

    if profile_note:
        return {"observations": result_list, "profile_note": profile_note}
    return result_list


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def assess_exposure(domain: str) -> ExposureAssessmentResult:
    """Summarize a domain's public configuration evidence for defensive review.

    This is a model-bound public-evidence assessment, not an overall security
    score or certification.

    Returns a structured JSON object containing public email, identity,
    infrastructure, configuration-consistency, and hardening observations. The
    compatibility field ``posture_score`` is a 0-100 index based only on
    publicly observable controls.

    The score counts only observed-present controls, so it is a lower bound: the
    ``observability`` block carries ``score_is_lower_bound``,
    ``unconfirmable_absent_points`` (points from controls whose absence the
    passive channel cannot confirm), and ``score_ceiling``. Report the score as
    a floor with its ceiling; a low score can mean "quiet", not "weak".

    Args:
        domain: A domain name to assess (e.g., "northwindtraders.com")

    Returns:
        JSON object with the full exposure assessment, or an error message.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.exposure import assess_exposure_from_info
    from recon_tool.formatter import format_exposure_dict

    assessment = assess_exposure_from_info(info)

    log_structured(
        logging.INFO,
        "exposure_assessed",
        request_id=request_id,
        domain=domain,
        posture_score=assessment.posture_score,
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return cast(ExposureAssessmentResult, format_exposure_dict(assessment))


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def find_hardening_gaps(domain: str) -> GapReportResult:
    """Identify hardening opportunities in a domain's public configuration.

    This is a defensive review of public observations, not an overall security
    assessment or certification.

    Returns a JSON array of hardening gaps, each with category, severity,
    observation, suggested action, supporting evidence references, and an
    ``absence_confirmable`` flag: true when the gap is a confirmed public-records
    fact (a declarative record is absent or observed-weak), false when it rests
    on not observing a hideable control and so may be a false positive. Report a
    false-flagged gap as "not observed", not as a confirmed gap.

    Args:
        domain: A domain name to analyze (e.g., "northwindtraders.com")

    Returns:
        JSON object with the gap report, or an error message.
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info = await server_app.resolve_single_for_tool(domain, request_id)

    from recon_tool.exposure import find_gaps_from_info
    from recon_tool.formatter import format_gaps_dict

    report = find_gaps_from_info(info)

    log_structured(
        logging.INFO,
        "gaps_analyzed",
        request_id=request_id,
        domain=domain,
        gaps=len(report.gaps),
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return cast(GapReportResult, format_gaps_dict(report))


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def compare_postures(domain_a: str, domain_b: str) -> PostureComparisonResult:
    """Compare the public configuration evidence of two domains side by side.

    This is a model-bound comparison of public observations, not an overall
    security comparison or certification.

    Returns a structured comparison with side-by-side metrics,
    control differences, and relative posture assessment.

    Args:
        domain_a: First domain to compare (e.g., "northwindtraders.com")
        domain_b: Second domain to compare (e.g., "contoso.com")

    Returns:
        A structured posture comparison. Raises ToolError (isError) when either
        domain is invalid or cannot be resolved (both must resolve to compare).
    """
    request_id = uuid.uuid4().hex[:12]
    start_time = time.monotonic()

    info_a, info_b = await server_app.resolve_domains_for_tool((domain_a, domain_b), request_id)

    from recon_tool.exposure import compare_postures_from_infos
    from recon_tool.formatter import format_comparison_dict

    comparison = compare_postures_from_infos(info_a, info_b)

    log_structured(
        logging.INFO,
        "postures_compared",
        request_id=request_id,
        domain_a=domain_a,
        domain_b=domain_b,
        elapsed_s=round(time.monotonic() - start_time, 2),
    )

    return cast(PostureComparisonResult, format_comparison_dict(comparison))


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def test_hypothesis(domain: str, hypothesis: str) -> HypothesisAssessmentResult:
    """Test a theory about a domain against signals and evidence.

    Proposes a theory and receives related public observations plus explicit
    unresolved status. Passive catalog matches cannot validate active use,
    organizational intent, topology, or causal explanations.

    Operates purely on cached pipeline data — zero additional network calls
    beyond the initial domain resolution.

    Args:
        domain: A domain name to test against (e.g., "northwindtraders.com").
        hypothesis: A theory whose related public indicators should be listed.

    Returns:
        JSON object with unresolved likelihood, related and contradicting
        observations, missing evidence, and collection confidence.
    """
    # Bound the free-text hypothesis so a multi-megabyte argument cannot
    # multiply the per-signal substring scan cost.
    hypothesis = hypothesis[:4000]
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)

    info, _results = resolved

    from recon_tool.email_security import signal_context_from_tenant_info
    from recon_tool.signals import evaluate_signals, load_signals, signal_observation_label

    context = signal_context_from_tenant_info(info)
    signal_matches = evaluate_signals(context)
    public_signals = tuple(
        (signal, label) for signal in load_signals() if (label := signal_observation_label(signal.name)) is not None
    )
    fired_names = {m.name for m in signal_matches}

    # Map hypothesis to relevant categories via keyword matching
    hypothesis_terms = _hypothesis_terms(hypothesis)
    relevant_categories: set[str] = set()
    for cat, keywords in _HYPOTHESIS_KEYWORDS.items():
        if _keyword_group_matches(hypothesis_terms, keywords):
            relevant_categories.add(cat)

    # Find supporting and contradicting signals
    supporting: list[str] = []
    contradicting: list[str] = []
    missing: list[str] = []

    for sig, public_label in public_signals:
        # Check if signal is relevant to hypothesis via keyword matching
        sig_terms = _hypothesis_terms(f"{public_label} {sig.description} {sig.category} {sig.explain}")
        is_relevant = bool(hypothesis_terms & sig_terms) or any(
            _keyword_group_matches(sig_terms, keywords)
            for cat, keywords in _HYPOTHESIS_KEYWORDS.items()
            if cat in relevant_categories
        )
        if not is_relevant:
            continue

        if sig.name in fired_names:
            supporting.append(public_label)
        else:
            # Check if it contradicts or is just missing
            has_contradiction_slugs = sig.contradicts and any(
                slug in context.detected_slugs for slug in sig.contradicts
            )
            if has_contradiction_slugs:
                contradicting.append(public_label)
            else:
                missing.append(
                    f"Observation '{public_label}' did not fire; "
                    f"detecting additional slugs ({', '.join(sig.candidates[:3])}) "
                    f"could strengthen or weaken this hypothesis"
                    if sig.candidates
                    else f"Observation '{public_label}' did not fire; metadata conditions not met"
                )

    # Passive indicator co-observation cannot identify the truth of an
    # arbitrary semantic hypothesis. Counts of loosely related catalog rules
    # must never be converted into strong, moderate, or unsupported verdicts.
    likelihood: HypothesisLikelihood = "unresolved"

    # Determine confidence based on data completeness
    if info.degraded_sources:
        confidence: HypothesisConfidence = "low"
    elif len(info.sources) >= 3:
        confidence = "high"
    else:
        confidence = "medium"

    result: HypothesisAssessmentResult = {
        "domain": domain,
        "hypothesis": hypothesis,
        "likelihood": likelihood,
        "supporting_signals": supporting,
        "contradicting_signals": contradicting,
        "missing_evidence": missing,
        "confidence": confidence,
        "disclaimer": (
            "Likelihood is unresolved. Related entries are public indicators and "
            "observations; they do not confirm active use, organizational "
            "intent, topology, causation, or internal decisions."
        ),
    }
    return result


@dataclass
class _SimState:
    """Mutable simulation state for ``simulate_hardening`` fix application."""

    services: set[str]
    slugs: set[str]
    dmarc: str | None
    dmarc_pct: int | None
    dmarc_testing: bool
    mta_sts: str | None
    evidence: list[EvidenceRecord]


def _record_hypothetical_control(
    state: _SimState,
    *,
    source_type: str,
    rule_name: str,
    slug: str,
) -> None:
    """Add typed simulation evidence without representing a live observation."""
    marker = EvidenceRecord(
        source_type=source_type,
        raw_value="hypothetical simulation only",
        rule_name=rule_name,
        slug=slug,
    )
    if marker not in state.evidence:
        state.evidence.append(marker)


def _apply_dmarc_fix(fix: str, state: _SimState) -> str | None:
    """Apply a DMARC fix; return the applied message, or None when it is a no-op."""
    if "reject" in fix:
        state.dmarc = "reject"
        state.dmarc_pct = None
        state.dmarc_testing = False
        return "DMARC policy set to reject"
    if "quarantine" in fix:
        if state.dmarc != "reject":
            state.dmarc = "quarantine"
            state.dmarc_pct = None
            state.dmarc_testing = False
            return "DMARC policy set to quarantine"
        return None
    if state.dmarc is None or state.dmarc == "none":
        state.dmarc = "reject"
        state.dmarc_pct = None
        state.dmarc_testing = False
        return "DMARC policy set to reject"
    return None


def _apply_mta_sts_fix(fix: str, state: _SimState) -> str | None:
    """Apply an MTA-STS fix; return the applied message, or None when already set.

    Mirrors the original: an explicit "enforce" always applies, while a bare
    "mta-sts" applies only when no mode is currently set.
    """
    if "enforce" in fix or state.mta_sts is None:
        state.mta_sts = "enforce"
        state.services.add("MTA-STS")
        state.slugs.add("mta-sts-enforce")
        _record_hypothetical_control(
            state,
            source_type="MTA_STS_POLICY",
            rule_name="MTA-STS",
            slug="mta-sts-enforce",
        )
        return "MTA-STS set to enforce"
    return None


def _apply_one_fix(fix: str, state: _SimState) -> str | None:
    """Apply a single lowercased fix to the simulation state.

    Returns the applied message, or None when the fix is a recognised no-op.
    Keyword precedence mirrors the original elif chain: the first match wins.
    """
    if "dmarc" in fix:
        return _apply_dmarc_fix(fix, state)
    if "dkim" in fix:
        state.services.add("DKIM")
        state.slugs.add("dkim")
        _record_hypothetical_control(state, source_type="DKIM", rule_name="DKIM", slug="dkim")
        return "DKIM configured"
    if "mta-sts" in fix:
        return _apply_mta_sts_fix(fix, state)
    if "bimi" in fix:
        state.services.add("BIMI")
        state.slugs.add("bimi")
        _record_hypothetical_control(state, source_type="BIMI", rule_name="BIMI", slug="bimi")
        return "BIMI configured"
    if "spf" in fix and ("strict" in fix or "hardfail" in fix or "-all" in fix):
        state.services.add("SPF: strict (-all)")
        _record_hypothetical_control(
            state,
            source_type="SPF",
            rule_name="SPF: strict (-all)",
            slug="spf-strict",
        )
        return "SPF set to strict (-all)"
    if "tls-rpt" in fix or "tlsrpt" in fix:
        state.slugs.add("tls-rpt")
        return "TLS-RPT configured"
    if "caa" in fix:
        state.slugs.add("letsencrypt")
        _record_hypothetical_control(
            state,
            source_type="CAA",
            rule_name="CAA: Let's Encrypt",
            slug="letsencrypt",
        )
        return "CAA records configured"
    # Note the unrecognized fix, but sanitize and bound the caller-supplied
    # string so it cannot inject control sequences into the response.
    return f"Unrecognized fix: {strip_control_chars(fix)[:80]}"


def _simulate_fixes(fixes_lower: list[str], info: TenantInfo) -> tuple[list[str], _SimState]:
    """Apply each fix to a fresh simulation state seeded from ``info``."""
    state = _SimState(
        services=set(info.services),
        slugs=set(info.slugs),
        dmarc=info.dmarc_policy,
        dmarc_pct=info.dmarc_pct,
        dmarc_testing=info.dmarc_testing,
        mta_sts=info.mta_sts_mode,
        evidence=list(info.evidence),
    )
    applied: list[str] = []
    for fix in fixes_lower:
        message = _apply_one_fix(fix, state)
        if message is not None:
            applied.append(message)
    return applied, state


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def simulate_hardening(domain: str, fixes: list[str]) -> HardeningSimulationResult:
    """Re-compute the public-evidence index with hypothetical fixes.

    Accepts a list of fix descriptions (e.g., "DMARC reject", "MTA-STS enforce")
    and simulates how the model-bound compatibility index would change if those
    fixes were applied. This is not a prediction of overall security change.

    Operates purely on cached pipeline data — zero additional network calls
    beyond the initial domain resolution.

    Args:
        domain: A domain name to simulate against (e.g., "northwindtraders.com").
        fixes: Array of fix descriptions or gap slugs to hypothetically apply.

    Returns:
        JSON object with current_score, simulated_score, score_delta,
        applied_fixes, and remaining_gaps.
    """
    # Bound the fix list so a multi-million-element argument cannot drive
    # O(n) work and a proportionally huge response.
    fixes = fixes[:100]
    resolved = await server_app.resolve_or_cache(domain)
    if isinstance(resolved, str):
        raise ToolError(resolved)

    info, _results = resolved

    from recon_tool.exposure import assess_exposure_from_info, find_gaps_from_info

    current_assessment = assess_exposure_from_info(info)
    current_score = current_assessment.posture_score

    # Parse fixes and simulate by mutating a copy of TenantInfo fields
    applied, state = _simulate_fixes([f.lower() for f in fixes], info)

    # Build simulated TenantInfo
    sim_info = TenantInfo(
        tenant_id=info.tenant_id,
        display_name=info.display_name,
        default_domain=info.default_domain,
        queried_domain=info.queried_domain,
        confidence=info.confidence,
        region=info.region,
        sources=info.sources,
        services=tuple(sorted(state.services)),
        slugs=tuple(sorted(state.slugs)),
        auth_type=info.auth_type,
        dmarc_policy=state.dmarc,
        dmarc_pct=state.dmarc_pct,
        dmarc_testing=state.dmarc_testing,
        spf_include_count=info.spf_include_count,
        domain_count=info.domain_count,
        tenant_domains=info.tenant_domains,
        related_domains=info.related_domains,
        insights=info.insights,
        degraded_sources=info.degraded_sources,
        cert_summary=info.cert_summary,
        evidence=tuple(state.evidence),
        evidence_confidence=info.evidence_confidence,
        inference_confidence=info.inference_confidence,
        detection_scores=info.detection_scores,
        bimi_identity=info.bimi_identity,
        site_verification_tokens=info.site_verification_tokens,
        mta_sts_mode=state.mta_sts,
        google_auth_type=info.google_auth_type,
        google_idp_name=info.google_idp_name,
        merge_conflicts=info.merge_conflicts,
    )

    sim_assessment = assess_exposure_from_info(sim_info)
    simulated_score = sim_assessment.posture_score

    # Compute remaining gaps on simulated info
    sim_gap_report = find_gaps_from_info(sim_info)
    remaining_gaps: list[SimulatedGapSummary] = [
        {
            "category": gap.category,
            "severity": gap.severity,
            "observation": gap.observation,
            "recommendation": gap.recommendation,
        }
        for gap in sim_gap_report.gaps
    ]

    result: HardeningSimulationResult = {
        "domain": domain,
        "current_score": current_score,
        "simulated_score": simulated_score,
        "score_delta": simulated_score - current_score,
        "applied_fixes": applied,
        "remaining_gaps": remaining_gaps,
        "disclaimer": (
            "This simulation is based on publicly observable configuration data. "
            "Consider these results as directional guidance for prioritizing "
            "hardening actions, not as a prediction or guarantee of overall "
            "security improvement."
        ),
    }
    return result
