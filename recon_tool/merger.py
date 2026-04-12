"""Result merger, confidence scoring, and insight generation."""

from __future__ import annotations

import contextlib

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
)
from recon_tool.insights import generate_insights
from recon_tool.models import (
    BIMIIdentity,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    ReconLookupError,
    SignalContext,
    SourceResult,
    TenantInfo,
)
from recon_tool.signals import evaluate_signals

__all__ = [
    "build_insights_with_signals",
    "compute_confidence",
    "compute_detection_scores",
    "compute_evidence_confidence",
    "compute_inference_confidence",
    "merge_results",
]


def _min_confidence(a: ConfidenceLevel, b: ConfidenceLevel) -> ConfidenceLevel:
    """Return the lower of two confidence levels (HIGH > MEDIUM > LOW)."""
    order = {ConfidenceLevel.HIGH: 2, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.LOW: 0}
    return a if order[a] <= order[b] else b


def compute_evidence_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Compute evidence confidence from the number of successful sources.

    3+ successful sources → HIGH, 2 → MEDIUM, 1 or fewer → LOW.
    """
    successful = sum(1 for r in results if r.is_success)
    if successful >= 3:
        return ConfidenceLevel.HIGH
    if successful >= 2:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def compute_inference_confidence(results: list[SourceResult]) -> ConfidenceLevel:
    """Compute inference confidence from the strength of the logical chain.

    HIGH when tenant_id from OIDC + corroborating source, or 3+ independent
    record types confirm the same provider.
    LOW when single record type with no corroboration.
    MEDIUM otherwise.
    """
    has_tenant_id = any(r.tenant_id is not None for r in results)
    has_corroboration = any(
        r.is_success and r.source_name != "oidc_discovery" and (r.m365_detected or r.display_name or r.auth_type)
        for r in results
    )

    if has_tenant_id and has_corroboration:
        return ConfidenceLevel.HIGH

    # Check for multiple independent record types confirming same provider
    all_evidence: list[EvidenceRecord] = []
    for r in results:
        all_evidence.extend(r.evidence)

    if all_evidence:
        source_types = {e.source_type for e in all_evidence}
        if len(source_types) >= 3:
            return ConfidenceLevel.HIGH

    successful = sum(1 for r in results if r.is_success)
    if successful >= 2:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


def compute_detection_scores(
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[tuple[str, str], ...]:
    """Compute per-slug detection confidence from evidence diversity.

    Groups evidence by slug, counts distinct source_types per slug.
    3+ types → "high", 2 → "medium", 1 → "low".

    Returns tuple of (slug, score) pairs sorted by slug.
    """
    slug_types: dict[str, set[str]] = {}
    for ev in evidence:
        slug_types.setdefault(ev.slug, set()).add(ev.source_type)

    scores: list[tuple[str, str]] = []
    for slug in sorted(slug_types):
        count = len(slug_types[slug])
        if count >= 3:
            scores.append((slug, "high"))
        elif count >= 2:
            scores.append((slug, "medium"))
        else:
            scores.append((slug, "low"))
    return tuple(scores)


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
) -> list[str]:
    """Generate insights and append signal intelligence.

    Shared by merge_results (initial merge) and _enrich_from_related
    (related domain enrichment) to avoid duplicating the insight+signal
    formatting pipeline.
    """
    insights = generate_insights(
        services,
        slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
    )
    context = SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
    )
    active_signals = evaluate_signals(context)
    for sig in active_signals:
        matched_names = ", ".join(sig.matched)
        insights.append(f"{sig.name}: {matched_names}")
    return insights


def compute_confidence(results: list[SourceResult]) -> tuple[ConfidenceLevel, bool]:
    """Compute confidence based on cross-validation of results.

    For M365 domains: confidence is based on tenant_id presence plus
    corroboration from other sources (UserRealm display name, auth type,
    tenant domains). A single tenant_id with corroborating M365 evidence
    from another source is HIGH — the sources are independent and agree.

    For non-M365 domains: confidence is based on the richness of DNS data.
    DNS records are authoritative (you either have the record or you don't),
    so rich DNS data warrants high confidence in the overall picture.

    Returns:
        Tuple of (confidence_level, has_conflicting_tenant_ids).
    """
    tenant_ids = [r.tenant_id for r in results if r.tenant_id is not None]

    if tenant_ids:
        unique_ids = set(tenant_ids)
        if len(unique_ids) > 1:
            return ConfidenceLevel.LOW, True

        # We have at least one tenant_id. Check for corroboration from
        # other sources — UserRealm returning m365_detected + real data
        # (display_name, auth_type, or tenant_domains) counts as independent
        # confirmation that this is a real M365 tenant.
        tenant_id_sources = {r.source_name for r in results if r.tenant_id is not None}
        corroborating = [
            r
            for r in results
            if r.source_name not in tenant_id_sources
            and r.is_success
            and (r.m365_detected or r.display_name or r.auth_type or len(r.tenant_domains) > 0)
        ]
        if corroborating:
            return ConfidenceLevel.HIGH, False
        if len(tenant_ids) >= 2:
            return ConfidenceLevel.HIGH, False
        return ConfidenceLevel.MEDIUM, False

    # No tenant_id — check DNS service richness.
    # DNS records are authoritative, so even a single source with services
    # is meaningful. More services = higher confidence in the overall picture.
    total_services = sum(len(r.detected_services) for r in results)
    successful_sources = sum(1 for r in results if r.is_success)

    if total_services >= 8 and successful_sources >= 2:
        return ConfidenceLevel.HIGH, False
    if total_services >= 3 or successful_sources >= 2:
        return ConfidenceLevel.MEDIUM, False
    if total_services > 0:
        return ConfidenceLevel.LOW, False
    return ConfidenceLevel.LOW, False


def merge_results(
    results: list[SourceResult],
    queried_domain: str,
) -> TenantInfo:
    """Merge multiple SourceResults into a single TenantInfo with insights."""
    tenant_id: str | None = None
    display_name: str | None = None
    default_domain: str | None = None
    region: str | None = None
    auth_type: str | None = None
    dmarc_policy: str | None = None
    all_domains: set[str] = set()
    google_auth_type: str | None = None
    google_idp_name: str | None = None
    bimi_identity: BIMIIdentity | None = None
    mta_sts_mode: str | None = None
    all_site_verification_tokens: set[str] = set()

    # First-wins merge: for each field, the first source (in priority order)
    # that provides a non-None value wins. This is intentional — sources are
    # ordered by reliability (OIDC > UserRealm > DNS), so the first non-None
    # value is the most trustworthy. A "most-complete-wins" strategy would
    # require scoring each result, adding complexity for little benefit.
    for result in results:
        if tenant_id is None and result.tenant_id is not None:
            tenant_id = result.tenant_id
        if display_name is None and result.display_name is not None:
            display_name = result.display_name
        if default_domain is None and result.default_domain is not None:
            default_domain = result.default_domain
        if region is None and result.region is not None:
            region = result.region
        if auth_type is None and result.auth_type is not None:
            auth_type = result.auth_type
        if dmarc_policy is None and result.dmarc_policy is not None:
            dmarc_policy = result.dmarc_policy
        if google_auth_type is None and result.google_auth_type is not None:
            google_auth_type = result.google_auth_type
        if google_idp_name is None and result.google_idp_name is not None:
            google_idp_name = result.google_idp_name
        if bimi_identity is None and result.bimi_identity is not None:
            bimi_identity = result.bimi_identity
        if mta_sts_mode is None and result.mta_sts_mode is not None:
            mta_sts_mode = result.mta_sts_mode
        all_domains.update(result.tenant_domains)
        all_site_verification_tokens.update(result.site_verification_tokens)

    # If no tenant_id found, check if we at least have DNS services.
    # tenant_id stays None when no M365 tenant exists.
    if tenant_id is None:
        all_services_check: set[str] = set()
        for result in results:
            all_services_check.update(result.detected_services)
        if not all_services_check:
            raise ReconLookupError(
                domain=queried_domain,
                message=(f"No information could be resolved for {queried_domain} from any source"),
                error_type="all_sources_failed",
            )

    if display_name is None:
        # BIMI VMC organization name as fallback
        if bimi_identity is not None:
            display_name = bimi_identity.organization
        else:
            display_name = tenant_id if tenant_id else queried_domain
    if default_domain is None:
        default_domain = queried_domain

    confidence, has_id_conflict = compute_confidence(results)
    sources = tuple(r.source_name for r in results if r.is_success)

    all_services: set[str] = set()
    all_slugs: set[str] = set()
    all_related: set[str] = set()
    for result in results:
        all_services.update(result.detected_services)
        all_slugs.update(result.detected_slugs)
        all_related.update(result.related_domains)

    # Remove domains we already know about from related_domains
    all_related -= all_domains
    all_related.discard(queried_domain.lower())

    domain_count = len(all_domains)
    tenant_domains = tuple(sorted(all_domains))

    # Compute email_security_score: count presence of DMARC, any DKIM, SPF strict, MTA-STS, BIMI (0-5)
    _score_services = {SVC_DMARC, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
    email_security_score = min(sum(1 for svc in all_services if svc in _score_services), 5)

    # Extract spf_include_count from services like "SPF complexity: N includes"
    spf_include_count: int | None = None

    for svc in all_services:
        if svc.startswith("SPF complexity:"):
            with contextlib.suppress(ValueError, IndexError):
                spf_include_count = int(svc.split(":")[1].strip().split()[0])
            break

    # Extract issuance_velocity from cert_summary if available
    issuance_velocity: int | None = None

    # Propagate first non-None cert_summary from any source
    cert_summary: CertSummary | None = None
    for result in results:
        if result.cert_summary is not None:
            cert_summary = result.cert_summary
            break

    if cert_summary is not None:
        issuance_velocity = cert_summary.issuance_velocity

    # Build insights list, then append signal intelligence.
    insights = build_insights_with_signals(
        all_services,
        all_slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
    )

    # Surface conflicting tenant IDs — this is high-value intel that explains
    # why confidence is LOW and may indicate a misconfigured or transitioning tenant.
    if has_id_conflict:
        conflicting = sorted({r.tenant_id for r in results if r.tenant_id is not None})
        insights.insert(0, f"Conflicting tenant IDs detected: {', '.join(conflicting)}")

    # Collect degraded_sources from all results, deduplicate
    all_degraded: set[str] = set()
    for result in results:
        all_degraded.update(result.degraded_sources)

    # Propagate evidence from all sources
    all_evidence: list[EvidenceRecord] = []
    for result in results:
        all_evidence.extend(result.evidence)
    evidence_tuple = tuple(all_evidence)

    # Compute dual confidence
    evidence_confidence = compute_evidence_confidence(results)
    inference_confidence = compute_inference_confidence(results)
    # Backward-compatible confidence: min of the two dimensions
    confidence = _min_confidence(confidence, _min_confidence(evidence_confidence, inference_confidence))

    # Compute per-detection corroboration scores
    detection_scores = compute_detection_scores(evidence_tuple)

    return TenantInfo(
        tenant_id=tenant_id,
        display_name=display_name,
        default_domain=default_domain,
        queried_domain=queried_domain,
        confidence=confidence,
        region=region,
        sources=sources,
        services=tuple(sorted(all_services)),
        slugs=tuple(sorted(all_slugs)),
        auth_type=auth_type,
        dmarc_policy=dmarc_policy,
        domain_count=domain_count,
        tenant_domains=tenant_domains,
        related_domains=tuple(sorted(all_related)),
        insights=tuple(insights),
        degraded_sources=tuple(sorted(all_degraded)),
        cert_summary=cert_summary,
        evidence=evidence_tuple,
        evidence_confidence=evidence_confidence,
        inference_confidence=inference_confidence,
        detection_scores=detection_scores,
        bimi_identity=bimi_identity,
        site_verification_tokens=tuple(sorted(all_site_verification_tokens)),
        mta_sts_mode=mta_sts_mode,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
    )
