"""Result merger, confidence scoring, and insight generation."""

from __future__ import annotations

from typing import Any, NamedTuple

from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
from recon_tool.confidence import (
    compute_confidence,
    compute_evidence_confidence,
    compute_inference_confidence,
    confidence_source_names,
)
from recon_tool.confidence import (
    minimum_confidence as _min_confidence,
)
from recon_tool.constants import (
    effective_dmarc_policy as _effective_dmarc_policy,
)
from recon_tool.constants import (
    email_security_score as _email_security_score,
)
from recon_tool.email_security import claim_safe_email_services, observed_email_control_services
from recon_tool.insights import generate_insights
from recon_tool.lexical import lexical_observations
from recon_tool.merger_catalog import (
    dedupe_motifs,
    dedupe_surface,
    dedupe_unclassified,
    merge_dns_catalog_diagnostics,
)
from recon_tool.models import (
    BIMIIdentity,
    CandidateValue,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    InfrastructureClusterReport,
    MergeConflicts,
    ReconLookupError,
    SignalContext,
    SourceResult,
    TenantInfo,
)
from recon_tool.signals import SignalMatch, evaluate_signals, load_signals, signal_observation_label
from recon_tool.validator import strip_control_chars

__all__ = [
    "build_insights_with_signals",
    "compute_confidence",
    "compute_detection_scores",
    "compute_email_topology",
    "compute_evidence_confidence",
    "compute_inference_confidence",
    "merge_results",
]

from recon_tool.merger_tables import (
    EMAIL_PROVIDER_SLUG_NAMES,
    GATEWAY_SLUG_NAMES,
    GATEWAY_SLUGS,
    LIKELY_PROVIDER_SLUG_NAMES,
    PROVIDER_INFERENCE_SOURCES,
    SLUG_ACRONYMS,
    SLUG_HUMAN_NAMES,
    VARIANT_SLUG_PARENTS,
)

_GATEWAY_SLUGS = GATEWAY_SLUGS
_EMAIL_PROVIDER_SLUG_NAMES = EMAIL_PROVIDER_SLUG_NAMES
_GATEWAY_SLUG_NAMES = GATEWAY_SLUG_NAMES
_PROVIDER_INFERENCE_SOURCES = PROVIDER_INFERENCE_SOURCES
_LIKELY_PROVIDER_SLUG_NAMES = LIKELY_PROVIDER_SLUG_NAMES
_SLUG_HUMAN_NAMES = SLUG_HUMAN_NAMES
_SLUG_ACRONYMS = SLUG_ACRONYMS
_VARIANT_SLUG_PARENTS = VARIANT_SLUG_PARENTS


def _humanize_slug(slug: str) -> str:
    """Map a raw slug to a user-friendly display name."""
    if slug in _SLUG_HUMAN_NAMES:
        return _SLUG_HUMAN_NAMES[slug]
    parts = slug.replace("_", "-").split("-")
    out: list[str] = []
    for part in parts:
        if part.lower() in _SLUG_ACRONYMS:
            out.append(part.upper())
        else:
            out.append(part.capitalize())
    return " ".join(out)


def _dedup_variant_slugs(slugs: tuple[str, ...]) -> tuple[str, ...]:
    """Drop variant slugs from ``slugs`` when their parent is also
    present. Preserves input order."""
    slug_set = set(slugs)
    out: list[str] = []
    seen: set[str] = set()
    for slug in slugs:
        parent = _VARIANT_SLUG_PARENTS.get(slug)
        if parent and parent in slug_set:
            continue
        if slug in seen:
            continue
        out.append(slug)
        seen.add(slug)
    return tuple(out)


def _render_signal_observation(signal: SignalMatch) -> str | None:
    """Render one signal without upgrading catalog matches into active use."""
    label = signal_observation_label(signal.name)
    if label is None:
        return None
    if not signal.matched:
        return label
    deduped = _dedup_variant_slugs(signal.matched)
    matched_names = ", ".join(_humanize_slug(slug) for slug in deduped)
    return f"{label}: {matched_names}"


def compute_email_topology(
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[str | None, str | None, str | None]:
    """Compute email topology from evidence records.

    Returns a triple of ``(primary_email_provider, email_gateway,
    likely_primary_email_provider)``:

    - ``primary_email_provider`` — stated when MX directly names a provider
      (e.g. ``aspmx.l.google.com`` → Google Workspace). Strict: only set from
      MX evidence. Never set when MX only contains an enterprise gateway.

    - ``email_gateway`` — stated when MX names an enterprise email security
      gateway (Proofpoint, Mimecast, Symantec, Barracuda, Trellix, Trend
      Micro, Cisco IronPort / Secure Email).

    - ``likely_primary_email_provider`` — inferred when a gateway is in MX
      but no direct provider appears there, AND non-MX evidence (DKIM
      selectors, identity-endpoint responses, TXT verification tokens)
      points to a specific downstream. Hedged: the word "likely" in the
      field name is load-bearing — this is inference, not a direct record.
      Only set when ``primary_email_provider`` is ``None``, so the two
      fields never contradict each other.
    """
    mx_evidence = [e for e in evidence if e.source_type == "MX"]
    mx_slugs = {e.slug for e in mx_evidence}

    # Identify gateways
    gateway_slugs = mx_slugs & _GATEWAY_SLUGS
    gateway_names = sorted(_GATEWAY_SLUG_NAMES[s] for s in gateway_slugs if s in _GATEWAY_SLUG_NAMES)
    email_gateway = " + ".join(gateway_names) if gateway_names else None

    # Identify primary providers (MX slugs that are NOT gateways)
    provider_slugs = mx_slugs - _GATEWAY_SLUGS
    provider_names = sorted(_EMAIL_PROVIDER_SLUG_NAMES[s] for s in provider_slugs if s in _EMAIL_PROVIDER_SLUG_NAMES)
    primary_email_provider = " + ".join(provider_names) if provider_names else None

    # When a gateway is present but no MX-based primary, non-MX provider
    # evidence can identify a plausible downstream only. DKIM establishes a
    # signing role, not the primary inbound mailbox system, so every such result
    # remains in the explicitly hedged likely-primary field.
    likely_primary_email_provider: str | None = None
    if email_gateway and primary_email_provider is None:
        non_mx_provider_slugs = {
            e.slug
            for e in evidence
            if e.source_type in _PROVIDER_INFERENCE_SOURCES and e.slug in _LIKELY_PROVIDER_SLUG_NAMES
        }
        if non_mx_provider_slugs:
            likely_names = sorted(_LIKELY_PROVIDER_SLUG_NAMES[s] for s in non_mx_provider_slugs)
            likely_primary_email_provider = " + ".join(likely_names)

    return primary_email_provider, email_gateway, likely_primary_email_provider


# Compatibility alias for existing internal tests and integrations.
_compute_email_topology = compute_email_topology


def _downgrade_confidence(level: ConfidenceLevel) -> ConfidenceLevel:
    """Step a confidence level down by one rung (HIGH → MEDIUM → LOW → LOW)."""
    if level == ConfidenceLevel.HIGH:
        return ConfidenceLevel.MEDIUM
    if level == ConfidenceLevel.MEDIUM:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def _build_detection_weight_map() -> dict[tuple[str, str], float]:
    """Build a (slug, source_type) → max weight mapping from loaded fingerprints.

    For each fingerprint, for each detection rule, maps (fp.slug, det.type)
    to the maximum weight seen across all fingerprints sharing that slug+type.
    """
    from recon_tool.fingerprints import load_fingerprints

    weight_map: dict[tuple[str, str], float] = {}
    for fp in load_fingerprints():
        for det in fp.detections:
            key = (fp.slug, det.type.upper())
            existing = weight_map.get(key)
            if existing is None or det.weight > existing:
                weight_map[key] = det.weight
    return weight_map


def compute_detection_scores(
    evidence: tuple[EvidenceRecord, ...],
    weights: dict[tuple[str, str], float] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Compute per-slug detection confidence from weighted evidence.

    Groups evidence by slug, computes a weighted sum of distinct source_types
    per slug using detection weights. Each (slug, source_type) pair contributes
    its weight once (max weight if duplicated).

    Thresholds: weighted_sum >= 2.5 → "high", >= 1.5 → "medium", else "low".

    When all weights are 1.0 (default), the weighted sum equals the count of
    distinct source types, preserving existing behavior:
    3+ types (sum >= 3.0 >= 2.5) → "high", 2 types (sum 2.0 >= 1.5) → "medium",
    1 type (sum 1.0 < 1.5) → "low".

    Args:
        evidence: Tuple of EvidenceRecord instances.
        weights: Optional mapping of (slug, source_type) → weight.
            If None, weights are loaded automatically from fingerprints.
            Pass an explicit dict to override (useful for testing).

    Returns tuple of (slug, score) pairs sorted by slug.
    """
    if not evidence:
        return ()

    if weights is None:
        weights = _build_detection_weight_map()

    # For each slug, track the max weight per distinct source_type
    slug_source_weights: dict[str, dict[str, float]] = {}
    for ev in evidence:
        per_source = slug_source_weights.setdefault(ev.slug, {})
        w = weights.get((ev.slug, ev.source_type), 1.0)
        # Keep max weight if multiple evidence records share (slug, source_type)
        if ev.source_type not in per_source or w > per_source[ev.source_type]:
            per_source[ev.source_type] = w

    scores: list[tuple[str, str]] = []
    for slug in sorted(slug_source_weights):
        weighted_sum = sum(slug_source_weights[slug].values())
        if weighted_sum >= 2.5:
            scores.append((slug, "high"))
        elif weighted_sum >= 1.5:
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
) -> list[str]:
    """Generate insights and append signal intelligence.

    Shared by merge_results (initial merge) and _enrich_from_related
    (related domain enrichment) to avoid duplicating the insight+signal
    formatting pipeline.
    """
    dmarc_effective_policy = dmarc_effective_policy or _effective_dmarc_policy(dmarc_policy, dmarc_pct)
    insights = generate_insights(
        services,
        slugs,
        auth_type,
        dmarc_policy,
        domain_count,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        has_mx_records=has_mx_records,
        dmarc_effective_policy=dmarc_effective_policy,
        evidence=evidence,
    )
    context = SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        dmarc_effective_policy=dmarc_effective_policy,
        auth_type=auth_type,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        dmarc_pct=dmarc_pct,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
    )
    active_signals = evaluate_signals(context)
    for sig in active_signals:
        observation = _render_signal_observation(sig)
        if observation is not None and observation not in insights:
            insights.append(observation)

    # Third pass: absence evaluation (missing counterparts)
    all_signal_defs = load_signals()
    absence_signals = evaluate_absence_signals(active_signals, all_signal_defs, context.detected_slugs)
    for sig in absence_signals:
        observation = _render_signal_observation(sig)
        if observation is not None and observation not in insights:
            insights.append(observation)

    # Positive-when-absent pass for hedged hardening observations.
    # Runs on the *base* fired set (not including absence signals) so a
    # hardening observation only fires from a genuine positive signal
    # match, never from an absence signal firing.
    positive_observations = evaluate_positive_absence(active_signals, all_signal_defs, context.detected_slugs)
    for sig in positive_observations:
        insights.append(f"{sig.name}: {sig.description}")

    return insights


# Placeholder tenant display names that are meaningless to a user.
# "Default Directory" is what Microsoft shows when a tenant owner never set a
# custom name — it's a placeholder, not the organization's name. The merge
# falls through to better signals (BIMI, domain) when it sees one. Exposed at
# module level so tests can exclude these from generated display-name inputs.
_PLACEHOLDER_DISPLAY_NAMES: frozenset[str] = frozenset(
    {
        "default directory",
        "directory",
    }
)


class _ScalarFields(NamedTuple):
    """First-wins scalar identity fields plus the accumulated domain/token sets."""

    tenant_id: str | None
    display_name: str | None
    default_domain: str | None
    region: str | None
    auth_type: str | None
    dmarc_policy: str | None
    dmarc_pct: int | None
    dmarc_testing: bool
    google_auth_type: str | None
    google_idp_name: str | None
    bimi_identity: BIMIIdentity | None
    mta_sts_mode: str | None
    all_domains: set[str]
    site_verification_tokens: set[str]


def _is_placeholder_name(name: str | None) -> bool:
    """True for an empty name or a generic placeholder ("directory")."""
    if not name:
        return True
    return name.strip().lower() in _PLACEHOLDER_DISPLAY_NAMES


def _first_non_none(results: list[SourceResult], attr: str) -> Any:
    """Return the first non-None ``result.<attr>`` across sources, else None."""
    for result in results:
        value = getattr(result, attr, None)
        if value is not None:
            return value
    return None


def _merge_scalar_fields(results: list[SourceResult]) -> _ScalarFields:
    """First-wins merge of the scalar identity fields.

    Sources are ordered by reliability (OIDC > UserRealm > DNS), so the first
    non-None value for each field is the most trustworthy; a most-complete-wins
    strategy would need per-result scoring for little benefit. ``display_name``
    additionally skips placeholder values.
    """
    tenant_id = display_name = default_domain = region = auth_type = dmarc_policy = None
    dmarc_pct: int | None = None
    dmarc_testing = False
    google_auth_type = google_idp_name = mta_sts_mode = None
    bimi_identity: BIMIIdentity | None = None
    all_domains: set[str] = set()
    tokens: set[str] = set()
    for result in results:
        if tenant_id is None and result.tenant_id is not None:
            tenant_id = result.tenant_id
        if _is_placeholder_name(display_name) and not _is_placeholder_name(result.display_name):
            display_name = result.display_name
        if default_domain is None and result.default_domain is not None:
            default_domain = result.default_domain
        if region is None and result.region is not None:
            region = result.region
        if auth_type is None and result.auth_type is not None:
            auth_type = result.auth_type
        if dmarc_policy is None and result.dmarc_policy is not None:
            dmarc_policy = result.dmarc_policy
            dmarc_pct = result.dmarc_pct
            dmarc_testing = result.dmarc_testing
        if google_auth_type is None and result.google_auth_type is not None:
            google_auth_type = result.google_auth_type
        if google_idp_name is None and result.google_idp_name is not None:
            google_idp_name = result.google_idp_name
        if bimi_identity is None and result.bimi_identity is not None:
            bimi_identity = result.bimi_identity
        if mta_sts_mode is None and result.mta_sts_mode is not None:
            mta_sts_mode = result.mta_sts_mode
        all_domains.update(result.tenant_domains)
        tokens.update(result.site_verification_tokens)
    return _ScalarFields(
        tenant_id=tenant_id,
        display_name=display_name,
        default_domain=default_domain,
        region=region,
        auth_type=auth_type,
        dmarc_policy=dmarc_policy,
        dmarc_pct=dmarc_pct,
        dmarc_testing=dmarc_testing,
        google_auth_type=google_auth_type,
        google_idp_name=google_idp_name,
        bimi_identity=bimi_identity,
        mta_sts_mode=mta_sts_mode,
        all_domains=all_domains,
        site_verification_tokens=tokens,
    )


def _compute_merge_conflicts(results: list[SourceResult]) -> MergeConflicts | None:
    """Collect per-field candidate values; surface only fields where 2+ sources disagree."""
    tracked: dict[str, list[CandidateValue]] = {
        "display_name": [],
        "auth_type": [],
        "region": [],
        "tenant_id": [],
        "dmarc_policy": [],
        "google_auth_type": [],
    }
    for result in results:
        confidence = "high" if result.is_complete else ("medium" if result.is_success else "low")
        for field_name in tracked:
            value = getattr(result, field_name)
            if value is not None:
                tracked[field_name].append(
                    CandidateValue(value=value, source=result.source_name, confidence=confidence)
                )
    conflict_fields: dict[str, tuple[CandidateValue, ...]] = {}
    for field_name, candidates in tracked.items():
        if len(candidates) >= 2 and len({c.value for c in candidates}) >= 2:
            conflict_fields[field_name] = tuple(candidates)
    return MergeConflicts(**conflict_fields) if conflict_fields else None


def _raise_if_all_sources_failed(results: list[SourceResult], queried_domain: str, tenant_id: str | None) -> None:
    """Raise ``all_sources_failed`` only when EVERY source returned an error.

    If any source produced a clean result (even with empty services/slugs), the
    successful lookup is honored downstream as a sparse TenantInfo: "we looked
    and found nothing" is a valid, hedged answer, not an error.
    """
    if tenant_id is not None or not all(r.error is not None for r in results):
        return
    source_errors: tuple[tuple[str, str], ...] = tuple((r.source_name, r.error) for r in results if r.error is not None)
    reasons = "; ".join(f"{n}: {e}" for n, e in source_errors)
    raise ReconLookupError(
        domain=queried_domain,
        message=(f"No information could be resolved for {queried_domain}. All sources returned errors: {reasons}"),
        error_type="all_sources_failed",
        source_errors=source_errors,
    )


def _resolve_display_name(display_name: str | None, queried_domain: str) -> str:
    """Use an observed identity brand when available, otherwise the domain."""
    if display_name is not None and not _is_placeholder_name(display_name):
        return display_name
    return queried_domain


def _scrub_optional(value: str | None) -> str | None:
    """Strip control chars from an optional source-derived string; None passes through."""
    return strip_control_chars(value) if value else value


def _scrub_free_text(
    display_name: str, auth_type: str | None, region: str | None
) -> tuple[str, str | None, str | None]:
    """Strip control chars from source-influenced free text before it reaches output.

    display_name (GetUserRealm FederationBrandName), auth_type (NameSpaceType),
    and region are influenced by the looked-up domain's federation config; rich's
    Text.append does not strip ESC, so an unscrubbed value is an ANSI-injection
    vector on a normal lookup. display_name is always a non-empty string from
    ``_resolve_display_name``, so it is scrubbed unconditionally.
    """
    display_name = strip_control_chars(display_name)
    if auth_type:
        auth_type = strip_control_chars(auth_type)
    if region:
        region = strip_control_chars(region)
    return display_name, auth_type, region


def _aggregate_detections(results: list[SourceResult]) -> tuple[set[str], set[str], set[str]]:
    """Union of detected services, slugs, and related domains across sources."""
    services: set[str] = set()
    slugs: set[str] = set()
    related: set[str] = set()
    for result in results:
        services.update(result.detected_services)
        slugs.update(result.detected_slugs)
        related.update(result.related_domains)
    return services, slugs, related


def extract_spf_include_count(results: list[SourceResult]) -> int | None:
    """Return the maximum typed apex-SPF include count across source results."""
    counts = [result.spf_include_count for result in results if result.spf_include_count > 0]
    return max(counts, default=None)


def _merge_ct_metadata(results: list[SourceResult]) -> tuple[str | None, int, int | None, str | None]:
    """Propagate CT provider attribution (first wins) and the first CT attempt outcome.

    ``ct_attempt_outcome`` can be set without a provider (e.g.
    "live_rate_limited"), so it is taken independently of ``ct_provider_used``.
    """
    ct_provider_used: str | None = None
    ct_subdomain_count = 0
    ct_cache_age_days: int | None = None
    ct_attempt_outcome: str | None = None
    for result in results:
        if result.ct_provider_used:
            ct_provider_used = result.ct_provider_used
            ct_subdomain_count = result.ct_subdomain_count
            ct_cache_age_days = result.ct_cache_age_days
            break
    for result in results:
        if getattr(result, "ct_attempt_outcome", None):
            ct_attempt_outcome = result.ct_attempt_outcome
            break
    return ct_provider_used, ct_subdomain_count, ct_cache_age_days, ct_attempt_outcome


def _merge_oidc_metadata(results: list[SourceResult]) -> tuple[str | None, str | None, str | None]:
    """First-wins propagation of OIDC tenant metadata (only OIDCSource sets these)."""
    cloud_instance: str | None = None
    tenant_region_sub_scope: str | None = None
    msgraph_host: str | None = None
    for result in results:
        if cloud_instance is None and result.cloud_instance is not None:
            cloud_instance = result.cloud_instance
        if tenant_region_sub_scope is None and result.tenant_region_sub_scope is not None:
            tenant_region_sub_scope = result.tenant_region_sub_scope
        if msgraph_host is None and result.msgraph_host is not None:
            msgraph_host = result.msgraph_host
        if cloud_instance and tenant_region_sub_scope and msgraph_host:
            break
    return cloud_instance, tenant_region_sub_scope, msgraph_host


def _collect_evidence(results: list[SourceResult]) -> tuple[EvidenceRecord, ...]:
    """Flatten evidence records from every source."""
    all_evidence: list[EvidenceRecord] = []
    for result in results:
        all_evidence.extend(result.evidence)
    return tuple(all_evidence)


def _collect_degraded(results: list[SourceResult]) -> set[str]:
    """Deduplicate granular markers and preserve whole DNS failure status."""
    degraded = {source for result in results for source in result.degraded_sources}
    degraded.update(f"source:{result.source_name}" for result in results if result.source_unavailable)
    if any(result.source_name == "dns_records" and result.error is not None for result in results):
        degraded.add("dns_records")
    return degraded


def _finalize_confidence(
    base_confidence: ConfidenceLevel,
    results: list[SourceResult],
    all_degraded: set[str],
    ct_provider_used: str | None,
) -> tuple[ConfidenceLevel, ConfidenceLevel, ConfidenceLevel]:
    """Combine the base, evidence, and inference confidences and apply the degraded downgrade.

    Skip the downgrade when the only degraded sources are CT providers
    and a CT fallback recovered the data (``ct_provider_used`` is set); penalising
    a successful recovery would undersell the result.
    """
    evidence_confidence = compute_evidence_confidence(results)
    inference_confidence = compute_inference_confidence(results)
    confidence = _min_confidence(base_confidence, _min_confidence(evidence_confidence, inference_confidence))

    ct_only_degradation = bool(all_degraded) and all(s in ("crt.sh", "certspotter") for s in all_degraded)
    ct_fallback_recovered = ct_only_degradation and ct_provider_used is not None
    if all_degraded and not ct_fallback_recovered:
        confidence = _downgrade_confidence(confidence)
        evidence_confidence = _downgrade_confidence(evidence_confidence)
    return confidence, evidence_confidence, inference_confidence


def _append_lexical_observations(insights: list[str], related: set[str], queried_domain: str) -> tuple[str, ...]:
    """Append lexical-taxonomy observations to insights and return their statements.

    Pure re-projection of related_domains through a rule-based parser; no
    new network calls, no generated candidates.
    """
    lex_obs = lexical_observations([d for d in related if "*" not in d], base_domain=queried_domain)
    for obs in lex_obs:
        insights.append(f"{obs.category}: {obs.statement}")
    return tuple(o.statement for o in lex_obs)


def merge_results(
    results: list[SourceResult],
    queried_domain: str,
) -> TenantInfo:
    """Merge multiple SourceResults into a single TenantInfo with insights."""
    usable_results = [result for result in results if result.error is None]
    from recon_tool.collection_view import collection_observable_results

    observable_results = collection_observable_results(usable_results)
    scalars = _merge_scalar_fields(usable_results)
    observable_scalars = _merge_scalar_fields(observable_results)
    tenant_id = scalars.tenant_id
    all_domains = scalars.all_domains
    merge_conflicts = _compute_merge_conflicts(usable_results)

    _raise_if_all_sources_failed(results, queried_domain, tenant_id)

    display_name = _resolve_display_name(scalars.display_name, queried_domain)
    default_domain = scalars.default_domain if scalars.default_domain is not None else queried_domain
    display_name, auth_type, region = _scrub_free_text(display_name, scalars.auth_type, scalars.region)
    # Round 6 (Track D): dmarc_policy is source-derived free text (the DMARC
    # ``p=`` value) that reaches the terminal panel via rich Text.append, which
    # does not strip ESC, so scrub it alongside the other free-text fields.
    # google_idp_name is folded in as defense in depth.
    dmarc_policy = _scrub_optional(scalars.dmarc_policy)
    google_idp_name = _scrub_optional(scalars.google_idp_name)

    base_confidence, has_id_conflict = compute_confidence(observable_results)
    sources = confidence_source_names(usable_results)

    all_services, all_slugs, all_related = _aggregate_detections(usable_results)
    observable_services, observable_slugs, _ = _aggregate_detections(observable_results)
    # Round 6 (Track D): a service string can carry attacker-controlled bytes
    # (e.g. a Google CSE discovery_uri host parsed in sources/google.py), so
    # strip control characters before the set reaches the email-security score,
    # the insight logic, and the terminal panel.
    all_services = {strip_control_chars(s) for s in all_services}
    observable_services = {strip_control_chars(s) for s in observable_services}
    # Remove domains we already know about from related_domains
    all_related -= all_domains
    all_related.discard(queried_domain.lower())

    domain_count = len(all_domains)
    tenant_domains = tuple(sorted(all_domains))

    evidence_tuple = _collect_evidence(usable_results)
    observable_evidence = _collect_evidence(observable_results)

    dmarc_pct = scalars.dmarc_pct
    observable_dmarc_policy = _scrub_optional(observable_scalars.dmarc_policy)
    observable_dmarc_pct = observable_scalars.dmarc_pct
    dmarc_effective_policy = _effective_dmarc_policy(
        observable_dmarc_policy,
        observable_dmarc_pct,
        observable_scalars.dmarc_testing,
    )
    email_security_score = _email_security_score(
        observed_email_control_services(observable_evidence),
        observable_dmarc_policy,
        observable_dmarc_pct,
        observable_scalars.dmarc_testing,
    )
    spf_include_count = extract_spf_include_count(observable_results)

    cert_summary: CertSummary | None = _first_non_none(usable_results, "cert_summary")
    issuance_velocity = cert_summary.issuance_velocity if cert_summary is not None else None

    ct_provider_used, ct_subdomain_count, ct_cache_age_days, ct_attempt_outcome = _merge_ct_metadata(usable_results)
    cloud_instance, tenant_region_sub_scope, msgraph_host = _merge_oidc_metadata(usable_results)

    primary_email_provider, email_gateway, likely_primary_email_provider = compute_email_topology(observable_evidence)
    # True if ANY MX evidence exists, regardless of slug match — lets
    # downstream insights distinguish "no email" from "custom / self-hosted".
    has_mx_records = any(e.source_type == "MX" for e in observable_evidence)

    # Build insights list, then append signal intelligence.
    insights = build_insights_with_signals(
        claim_safe_email_services(observable_services, observable_evidence),
        observable_slugs,
        auth_type,
        observable_dmarc_policy,
        domain_count,
        email_security_score=email_security_score,
        spf_include_count=spf_include_count,
        issuance_velocity=issuance_velocity,
        google_auth_type=observable_scalars.google_auth_type,
        google_idp_name=_scrub_optional(observable_scalars.google_idp_name),
        dmarc_pct=observable_dmarc_pct,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        email_gateway=email_gateway,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        has_mx_records=has_mx_records,
        dmarc_effective_policy=dmarc_effective_policy,
        evidence=observable_evidence,
    )

    # Surface conflicting tenant IDs — high-value intel that explains why
    # confidence is LOW and may indicate a misconfigured or transitioning tenant.
    if has_id_conflict:
        conflicting = sorted({strip_control_chars(r.tenant_id) for r in usable_results if r.tenant_id is not None})
        insights.insert(0, f"Conflicting tenant IDs detected: {', '.join(conflicting)}")

    all_degraded = _collect_degraded(results)
    confidence, evidence_confidence, inference_confidence = _finalize_confidence(
        base_confidence, observable_results, all_degraded, ct_provider_used
    )

    detection_scores = compute_detection_scores(evidence_tuple)
    lexical_observation_statements = _append_lexical_observations(insights, all_related, queried_domain)

    surface_tuple = dedupe_surface(usable_results)
    unclassified_tuple = dedupe_unclassified(usable_results)
    dns_catalog_summaries, unclassified_dns_observations = merge_dns_catalog_diagnostics(usable_results)
    chain_motifs_tuple = dedupe_motifs(usable_results)
    infrastructure_clusters: InfrastructureClusterReport | None = _first_non_none(
        usable_results, "infrastructure_clusters"
    )

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
        bimi_identity=None,
        site_verification_tokens=tuple(sorted(scalars.site_verification_tokens)),
        mta_sts_mode=scalars.mta_sts_mode,
        google_auth_type=scalars.google_auth_type,
        google_idp_name=google_idp_name,
        merge_conflicts=merge_conflicts,
        primary_email_provider=primary_email_provider,
        email_gateway=email_gateway,
        dmarc_pct=dmarc_pct,
        dmarc_testing=scalars.dmarc_testing,
        spf_include_count=spf_include_count or 0,
        likely_primary_email_provider=likely_primary_email_provider,
        ct_provider_used=ct_provider_used,
        ct_subdomain_count=ct_subdomain_count,
        ct_cache_age_days=ct_cache_age_days,
        ct_attempt_outcome=ct_attempt_outcome,
        cloud_instance=cloud_instance,
        tenant_region_sub_scope=tenant_region_sub_scope,
        msgraph_host=msgraph_host,
        lexical_observations=lexical_observation_statements,
        surface_attributions=surface_tuple,
        unclassified_cname_chains=unclassified_tuple,
        dns_catalog_summaries=dns_catalog_summaries,
        unclassified_dns_observations=unclassified_dns_observations,
        chain_motifs=chain_motifs_tuple,
        infrastructure_clusters=infrastructure_clusters,
    )
