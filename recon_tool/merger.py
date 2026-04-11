"""Result merger, confidence scoring, and insight generation."""

from __future__ import annotations

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
    CertSummary,
    ConfidenceLevel,
    ReconLookupError,
    SignalContext,
    SourceResult,
    TenantInfo,
)
from recon_tool.signals import evaluate_signals

__all__ = [
    "build_insights_with_signals",
    "compute_confidence",
    "merge_results",
]


def build_insights_with_signals(
    services: set[str],
    slugs: set[str],
    auth_type: str | None,
    dmarc_policy: str | None,
    domain_count: int,
    email_security_score: int | None = None,
    spf_include_count: int | None = None,
    issuance_velocity: int | None = None,
) -> list[str]:
    """Generate insights and append signal intelligence.

    Shared by merge_results (initial merge) and _enrich_from_related
    (related domain enrichment) to avoid duplicating the insight+signal
    formatting pipeline.
    """
    insights = generate_insights(services, slugs, auth_type, dmarc_policy, domain_count)
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
            r for r in results
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
        all_domains.update(result.tenant_domains)

    # If no tenant_id found, check if we at least have DNS services.
    # tenant_id stays None when no M365 tenant exists.
    if tenant_id is None:
        all_services_check: set[str] = set()
        for result in results:
            all_services_check.update(result.detected_services)
        if not all_services_check:
            raise ReconLookupError(
                domain=queried_domain,
                message=(
                    f"No information could be resolved "
                    f"for {queried_domain} from any source"
                ),
                error_type="all_sources_failed",
            )

    if display_name is None:
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
    import contextlib
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
        all_services, all_slugs, auth_type, dmarc_policy, domain_count,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
    )

    # Surface conflicting tenant IDs — this is high-value intel that explains
    # why confidence is LOW and may indicate a misconfigured or transitioning tenant.
    if has_id_conflict:
        conflicting = sorted({r.tenant_id for r in results if r.tenant_id is not None})
        insights.insert(0, f"Conflicting tenant IDs detected: {', '.join(conflicting)}")

    # Check if crt.sh was degraded in any DNS result
    crtsh_degraded = any(r.crtsh_degraded for r in results)

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
        crtsh_degraded=crtsh_degraded,
        cert_summary=cert_summary,
    )
