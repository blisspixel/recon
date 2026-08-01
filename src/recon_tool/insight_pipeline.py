"""Shared generated-insight and declarative-signal assembly pipeline."""

from __future__ import annotations

from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
from recon_tool.constants import effective_dmarc_policy
from recon_tool.insight_scopes import observation_scopes_available
from recon_tool.insights import InsightContext, generate_insight_claims
from recon_tool.merger_tables import SLUG_ACRONYMS, SLUG_HUMAN_NAMES, VARIANT_SLUG_PARENTS
from recon_tool.models import EvidenceRecord, InsightClaim, SignalContext
from recon_tool.signals import SignalMatch, evaluate_signals, load_signals, signal_observation_label

__all__ = ["build_insights_with_signals"]


def _humanize_slug(slug: str) -> str:
    """Map a raw slug to a user-friendly display name."""
    if slug in SLUG_HUMAN_NAMES:
        return SLUG_HUMAN_NAMES[slug]
    parts = slug.replace("_", "-").split("-")
    return " ".join(part.upper() if part.lower() in SLUG_ACRONYMS else part.capitalize() for part in parts)


def _dedup_variant_slugs(slugs: tuple[str, ...]) -> tuple[str, ...]:
    """Drop a variant when its parent is present while preserving order."""
    slug_set = set(slugs)
    deduped: list[str] = []
    seen: set[str] = set()
    for slug in slugs:
        parent = VARIANT_SLUG_PARENTS.get(slug)
        if (parent and parent in slug_set) or slug in seen:
            continue
        deduped.append(slug)
        seen.add(slug)
    return tuple(deduped)


def _render_signal_observation(signal: SignalMatch) -> str | None:
    """Render one signal without upgrading catalog matches into active use."""
    label = signal_observation_label(signal.name)
    if label is None:
        return None
    if not signal.matched:
        return label
    matched_names = ", ".join(_humanize_slug(slug) for slug in _dedup_variant_slugs(signal.matched))
    return f"{label}: {matched_names}"


def build_insights_with_signals(
    services: set[str],
    slugs: set[str],
    auth_type: str | None,
    dmarc_policy: str | None,
    domain_count: int,
    email_security_score: int | None = None,
    spf_include_count: int | None = None,
    issuance_velocity: int | None = None,
    google_auth_type: str | None = None,
    google_idp_name: str | None = None,
    dmarc_pct: int | None = None,
    primary_email_provider: str | None = None,
    likely_primary_email_provider: str | None = None,
    email_gateway: str | None = None,
    cloud_instance: str | None = None,
    tenant_region_sub_scope: str | None = None,
    msgraph_host: str | None = None,
    has_mx_records: bool = False,
    dmarc_effective_policy: str | None = None,
    evidence: tuple[EvidenceRecord, ...] = (),
    degraded_sources: tuple[str, ...] = (),
    insight_claims_out: list[InsightClaim] | None = None,
) -> list[str]:
    """Generate base insights, retain their lineage, and append signals.

    The optional sink is internal pipeline plumbing. Existing callers retain
    the list return contract, while merge and enrichment paths can persist the
    exact claims created during the same evaluation.
    """
    resolved_policy = dmarc_effective_policy or effective_dmarc_policy(dmarc_policy, dmarc_pct)
    insight_context = InsightContext.from_sets(
        services,
        slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        dmarc_effective_policy=resolved_policy,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        has_mx_records=has_mx_records,
        evidence=evidence,
        evidence_bound=True,
    )
    generated_claims = [
        claim
        for claim in generate_insight_claims(insight_context)
        if observation_scopes_available(claim.observation_scope, degraded_sources)
    ]
    if insight_claims_out is not None:
        insight_claims_out.extend(generated_claims)
    insights = [claim.text for claim in generated_claims]

    signal_context = SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        dmarc_effective_policy=resolved_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        dmarc_pct=dmarc_pct,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
    )
    active_signals = evaluate_signals(signal_context)
    for signal in active_signals:
        observation = _render_signal_observation(signal)
        if observation is not None and observation not in insights:
            insights.append(observation)

    signal_definitions = load_signals()
    absence_signals = evaluate_absence_signals(active_signals, signal_definitions, signal_context.detected_slugs)
    for signal in absence_signals:
        observation = _render_signal_observation(signal)
        if observation is not None and observation not in insights:
            insights.append(observation)

    positive_observations = evaluate_positive_absence(
        active_signals,
        signal_definitions,
        signal_context.detected_slugs,
    )
    insights.extend(f"{signal.name}: {signal.description}" for signal in positive_observations)
    return insights
