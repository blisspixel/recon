"""Collection-aware reporting view for partially resolved tenant data.

``TenantInfo`` retains raw partial detector output for provenance and debugging.
User-facing surfaces must not present a value from an unavailable channel as a
complete observation. This module masks only channel-owned derived fields while
leaving raw evidence and ``degraded_sources`` intact for inspection.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from functools import lru_cache
from typing import TYPE_CHECKING

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.insight_scopes import observation_scopes_available
from recon_tool.models import EvidenceRecord, InsightClaim, SourceResult, TenantInfo
from recon_tool.source_status import ObservationChannel, SourceStatus

if TYPE_CHECKING:
    from recon_tool.fingerprints import Detection

_CHANNEL_SERVICES: dict[str, frozenset[str]] = {
    "dmarc": frozenset({SVC_DMARC}),
    "dkim": frozenset({SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE}),
    "apex_txt": frozenset({SVC_SPF_STRICT, SVC_SPF_SOFTFAIL}),
    "mta_sts": frozenset({SVC_MTA_STS}),
    "bimi": frozenset({SVC_BIMI}),
    "tls_rpt": frozenset({"TLS-RPT"}),
    "cname": frozenset({"Domain Connect (Azure)", "Domain Connect (GoDaddy)"}),
    "srv": frozenset({"XMPP (Jabber)", "CalDAV", "CardDAV"}),
}

_CHANNEL_SLUGS: dict[str, frozenset[str]] = {
    "dmarc": frozenset({"dmarc"}),
    "dkim": frozenset({"dkim", "dkim-exchange"}),
    "apex_txt": frozenset({"spf-strict", "spf-softfail"}),
    "mta_sts": frozenset({"mta-sts", "mta-sts-enforce"}),
    "bimi": frozenset({"bimi", "bimi-vmc"}),
    "tls_rpt": frozenset({"tls-rpt"}),
}

_EVIDENCE_SOURCE_CHANNELS: dict[str, ObservationChannel] = {
    "MX": "mx",
    "CAA": "caa",
    "DKIM": "dkim",
    "SPF": "apex_txt",
    "DMARC": "dmarc",
    "BIMI": "bimi",
    "MTA_STS": "mta_sts",
    "MTA_STS_POLICY": "mta_sts",
    "NS": "ns",
    "CNAME": "cname",
    "A": "a",
    "PTR": "a",
    "SUBDOMAIN_TXT": "subdomain_txt",
    "DMARC_RUA": "dmarc",
    "SRV": "srv",
}

_DNS_EVIDENCE_SOURCE_TYPES = frozenset(
    {
        "TXT",
        "MX",
        "CAA",
        "DKIM",
        "SPF",
        "DMARC",
        "DMARC_RUA",
        "BIMI",
        "MTA_STS",
        "MTA_STS_POLICY",
        "NS",
        "CNAME",
        "A",
        "PTR",
        "SRV",
        "SUBDOMAIN_TXT",
    }
)

_EVIDENCE_SLUG_CHANNELS: dict[str, ObservationChannel] = {
    "dmarc": "dmarc",
    "mta-sts": "mta_sts",
    "mta-sts-enforce": "mta_sts",
    "bimi": "bimi",
    "bimi-vmc": "bimi",
    "tls-rpt": "tls_rpt",
}

_INSIGHT_TERMS: dict[str, tuple[str, ...]] = {
    "dmarc": ("dmarc",),
    "dkim": ("dkim",),
    "apex_txt": ("spf",),
    "mta_sts": ("mta-sts",),
    "bimi": ("bimi",),
    "tls_rpt": ("tls-rpt",),
    "mx": ("email gateway", "mail gateway"),
    "caa": ("caa", "certificate authorit"),
}

# Bounded generator-owned prefixes complement the fallback terms above. These
# identify conclusions whose truth depends on a specific collection channel,
# including negative conclusions where the channel name may not appear in the
# rendered text. A failed channel must remove both positive and absence claims.
_CHANNEL_INSIGHT_PREFIXES: dict[ObservationChannel, tuple[str, ...]] = {
    "dmarc": (
        "dmarc:",
        "no dmarc record at apex",
        "no valid dmarc policy record observed at apex",
        "no observable email infrastructure",
        "email security:",
    ),
    "dkim": ("no dkim at common selectors", "no observable email infrastructure", "email security:"),
    "apex_txt": (
        "large org signal: spf complexity:",
        "no observable email infrastructure",
        "email security:",
    ),
    "mta_sts": ("email security:",),
    "bimi": ("email security:",),
    "tls_rpt": ("email security:",),
    "mx": (
        "email gateway:",
        "mx gateway observed:",
        "email delivery path:",
        "no observable email infrastructure",
        "sparse public signal: custom or unclassified mx",
        "sparse public signal: minimal public dns footprint",
        "sparse public signal: few observable records beyond mx and identity",
        # Retain old cached copy only so a degraded MX channel cannot leak a
        # superseded self-hosting claim into a current view.
        "sparse public signal \N{EM DASH} custom or self-hosted mail infrastructure",
        "sparse public signal \N{EM DASH} minimal public dns footprint",
        "sparse public signal \N{EM DASH} few observable records beyond mx and identity",
    ),
    "caa": ("pki:",),
}

_REMOVED_LEGACY_INSIGHT_PREFIXES = (
    "large org signal:",
    "m365 e3/e5 indicators",
    "m365 e3+ indicators",
    "m365 apps for enterprise indicators",
    "office proplus indicators",
    "dual mdm:",
    "mac management",
    "dual provider:",
    "sase/ztna:",
    "security stack:",
    "email gateway:",
    "email delivery path:",
    "federated identity indicators (likely",
    "federated identity indicators observed (likely",
    "google workspace modules:",
)

_USER_REALM_MARKERS = frozenset({"identity:user_realm", "source:user_realm", "user_realm"})
_AUTODISCOVER_MARKERS = frozenset({"identity:autodiscover", "source:user_realm", "user_realm"})
_OIDC_MARKERS = frozenset({"source:oidc_discovery", "oidc_discovery"})
_GOOGLE_IDENTITY_MARKERS = frozenset({"source:google_identity", "google_identity"})
_GOOGLE_WORKSPACE_MARKERS = frozenset({"source:google_workspace", "google_workspace"})
_IDENTITY_SOURCE_MARKERS = (
    _USER_REALM_MARKERS | _AUTODISCOVER_MARKERS | _OIDC_MARKERS | _GOOGLE_IDENTITY_MARKERS | _GOOGLE_WORKSPACE_MARKERS
)
_IDENTITY_EVIDENCE_RULES = (
    (_USER_REALM_MARKERS, frozenset({"GetUserRealm"})),
    (_AUTODISCOVER_MARKERS, frozenset({"Autodiscover"})),
    (_OIDC_MARKERS, frozenset({"OIDC Discovery", "OIDC Discovery metadata"})),
    (_GOOGLE_IDENTITY_MARKERS, frozenset({"Google Identity Routing"})),
    (_GOOGLE_WORKSPACE_MARKERS, frozenset({"Google Workspace CSE"})),
)


def auth_type_channel_unavailable(degraded_sources: Iterable[str]) -> bool:
    """True when the channel that determines ``auth_type`` was unavailable.

    ``collection_claim_info`` masks ``auth_type`` to ``None`` for exactly these
    markers. A consumer that scores a federated namespace needs the same
    decision to tell a namespace that is not federated from one whose identity
    channel could not be read.
    """
    return not frozenset(degraded_sources).isdisjoint(_USER_REALM_MARKERS)


def _is_retired_numeric_domain_insight(normalized: str) -> bool:
    """Match only the three numeric domain-count formats emitted historically."""
    count, separator, claim = normalized.partition(" ")
    if not separator or not count.isdecimal():
        return False
    return claim == "domains in tenant" or (
        claim.startswith("domains ") and claim.endswith(("large enterprise", "mid-size organization"))
    )


def _is_removed_legacy_insight(insight: str) -> bool:
    """Whether an immutable cached insight violates the current claim contract."""
    normalized = insight.casefold()
    if normalized.startswith(_REMOVED_LEGACY_INSIGHT_PREFIXES):
        return True
    if _is_retired_numeric_domain_insight(normalized):
        return True
    if "dkim (inferred via" in normalized:
        return True
    return normalized.startswith("sparse public signal") and any(
        marker in normalized
        for marker in ("small organization", "small web-only property", "holding / portfolio company")
    )


def claim_contract_insights(insights: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Return insights permitted by the current public claim contract."""
    from recon_tool.signals import canonicalize_signal_observation

    visible: list[str] = []
    for insight in insights:
        if _is_removed_legacy_insight(insight):
            continue
        candidate = (
            f"CAA issuer authorization observed:{insight.partition(':')[2]}"
            if insight.casefold().startswith("pki:")
            else insight
        )
        canonical = canonicalize_signal_observation(candidate)
        if canonical is not None:
            visible.append(canonical)
    return tuple(visible)


def _mask_evidence_owned_detections(
    info: TenantInfo | SourceResult,
    services: set[str],
    slugs: set[str],
    *,
    source_types: frozenset[str],
) -> None:
    """Remove detections supported only by unavailable source types."""
    unavailable = [evidence for evidence in info.evidence if evidence.source_type.upper() in source_types]
    other = [evidence for evidence in info.evidence if evidence.source_type.upper() not in source_types]
    other_slugs = {evidence.slug for evidence in other}
    other_services = {evidence.rule_name for evidence in other}
    slugs.difference_update(evidence.slug for evidence in unavailable if evidence.slug not in other_slugs)
    services.difference_update(
        evidence.rule_name for evidence in unavailable if evidence.rule_name not in other_services
    )


def _mask_unavailable_catalog_detections(
    info: TenantInfo | SourceResult,
    services: set[str],
    slugs: set[str],
    *,
    rules: tuple[Detection, ...],
    source_types: frozenset[str],
) -> None:
    """Remove catalog detections unless an available source corroborates them."""
    available_evidence = tuple(
        evidence for evidence in info.evidence if evidence.source_type.upper() not in source_types
    )
    corroborated_slugs: set[str] = set()
    corroborated_services: set[str] = set()
    for evidence in available_evidence:
        corroborated_slugs.add(evidence.slug)
        corroborated_services.add(evidence.rule_name)

    candidate_slugs = {rule.slug for rule in rules}
    slugs.difference_update(candidate_slugs - corroborated_slugs)
    uncorroborated_names: set[str] = set()
    for rule in rules:
        if rule.slug in corroborated_slugs:
            continue
        for name in (rule.name, rule.name.removeprefix("CAA: ")):
            if name not in corroborated_services:
                uncorroborated_names.add(name)
    services.difference_update(uncorroborated_names)
    services.difference_update(
        evidence.rule_name
        for evidence in info.evidence
        if evidence.source_type.upper() in source_types
        and evidence.slug in candidate_slugs
        and evidence.slug not in corroborated_slugs
    )


def _mask_unavailable_role_catalogs(
    info: TenantInfo | SourceResult,
    services: set[str],
    slugs: set[str],
    status: SourceStatus,
    unavailable_evidence_types: frozenset[str],
) -> None:
    """Mask role catalogs whose collector failed, including legacy no-evidence caches."""
    from recon_tool.fingerprints import get_caa_patterns, get_mx_patterns

    role_catalogs: tuple[tuple[ObservationChannel, tuple[Detection, ...]], ...] = (
        ("mx", get_mx_patterns()),
        ("caa", get_caa_patterns()),
    )
    for channel, rules in role_catalogs:
        if status.channel_unavailable(channel):
            _mask_unavailable_catalog_detections(
                info,
                services,
                slugs,
                rules=rules,
                source_types=unavailable_evidence_types,
            )
            if channel == "caa":
                corroborated = {
                    evidence.rule_name for evidence in _observable_evidence(info.evidence, info.degraded_sources)
                }
                services.difference_update(
                    rule.name.removeprefix("CAA: ") for rule in rules if rule.name not in corroborated
                )

    if not status.channel_unavailable("dkim"):
        return
    from recon_tool.sources.dns_tables import ESP_DKIM_SELECTORS

    provider_pairs = {
        ("microsoft365", SVC_DKIM_EXCHANGE),
        ("google-workspace", SVC_DKIM_GOOGLE),
        *((slug, service) for _, _, service, slug in ESP_DKIM_SELECTORS),
    }
    observable_slugs = {evidence.slug for evidence in _observable_evidence(info.evidence, info.degraded_sources)}
    for slug, service in provider_pairs:
        if slug not in observable_slugs:
            slugs.discard(slug)
            services.discard(service)


def _insight_owned_by_unavailable_channel(insight: str, status: SourceStatus) -> bool:
    """Whether a bounded generator-owned insight lacks observation opportunity."""
    normalized = insight.casefold()
    return any(
        status.channel_unavailable(channel) and any(normalized.startswith(prefix) for prefix in prefixes)
        for channel, prefixes in _CHANNEL_INSIGHT_PREFIXES.items()
    )


def _observable_evidence(
    evidence_records: tuple[EvidenceRecord, ...],
    degraded_sources: tuple[str, ...],
) -> tuple[EvidenceRecord, ...]:
    """Filter evidence occurrences against their collection opportunities."""
    status = SourceStatus.from_degraded_sources(degraded_sources)
    degraded = status.degraded_sources
    apex_txt_slugs: set[str] = set()
    if status.channel_unavailable("apex_txt"):
        from recon_tool.fingerprints import get_spf_patterns, get_txt_patterns

        apex_txt_slugs = {rule.slug for rule in (*get_txt_patterns(), *get_spf_patterns())}

    def observable(evidence: EvidenceRecord) -> bool:
        if any(
            not degraded.isdisjoint(markers) and evidence.rule_name in rule_names
            for markers, rule_names in _IDENTITY_EVIDENCE_RULES
        ):
            return False
        if status.whole_dns_unavailable and evidence.source_type.upper() in _DNS_EVIDENCE_SOURCE_TYPES:
            return False
        channel = _EVIDENCE_SOURCE_CHANNELS.get(evidence.source_type.upper())
        if channel is None:
            channel = _EVIDENCE_SLUG_CHANNELS.get(evidence.slug)
        if channel is None and evidence.source_type.upper() == "TXT" and evidence.slug in apex_txt_slugs:
            channel = "apex_txt"
        return channel is None or status.channel_available(channel)

    return tuple(evidence for evidence in evidence_records if observable(evidence))


def _mask_unavailable_identity_evidence(
    info: TenantInfo | SourceResult,
    services: set[str],
    slugs: set[str],
    degraded_sources: tuple[str, ...],
) -> None:
    """Remove detections supported only by an unavailable identity source."""
    degraded = frozenset(degraded_sources)
    if degraded.isdisjoint(_IDENTITY_SOURCE_MARKERS):
        return
    observable = _observable_evidence(info.evidence, degraded_sources)
    observable_slugs = {evidence.slug for evidence in observable}
    observable_services = {evidence.rule_name for evidence in observable}
    unavailable = tuple(evidence for evidence in info.evidence if evidence not in observable)
    slugs.difference_update(evidence.slug for evidence in unavailable if evidence.slug not in observable_slugs)
    services.difference_update(
        evidence.rule_name for evidence in unavailable if evidence.rule_name not in observable_services
    )


def collection_observable_evidence(info: TenantInfo) -> tuple[EvidenceRecord, ...]:
    """Return evidence usable for derived claims under collection degradation.

    ``TenantInfo.evidence`` remains the immutable raw provenance sequence. This
    filtered view prevents unavailable subchannels from corroborating provider,
    control, or explanation summaries. TXT evidence is classified by its rule
    slug because apex TXT, DMARC, BIMI, and TLS-RPT share a record type but have
    independent collection opportunities.
    """
    return _observable_evidence(info.evidence, info.degraded_sources)


def collection_observable_result(result: SourceResult) -> SourceResult:
    """Return a source result whose derived fields exclude unavailable channels."""
    status = SourceStatus.from_degraded_sources(result.degraded_sources)
    if not status.degraded_sources:
        return result

    services = set(result.detected_services)
    slugs = set(result.detected_slugs)
    if status.whole_dns_unavailable:
        retained = tuple(
            evidence for evidence in result.evidence if evidence.source_type.upper() not in _DNS_EVIDENCE_SOURCE_TYPES
        )
        retained_slugs = {evidence.slug for evidence in retained}
        retained_services = {evidence.rule_name for evidence in retained}
        slugs.intersection_update(retained_slugs)
        services.intersection_update(retained_services)
    for channel in status.unavailable_channels:
        services.difference_update(_CHANNEL_SERVICES.get(channel, ()))
        slugs.difference_update(_CHANNEL_SLUGS.get(channel, ()))

    unavailable_evidence_types = frozenset(
        source_type for source_type, channel in _EVIDENCE_SOURCE_CHANNELS.items() if status.channel_unavailable(channel)
    )
    if unavailable_evidence_types:
        _mask_evidence_owned_detections(
            result,
            services,
            slugs,
            source_types=unavailable_evidence_types,
        )
    _mask_unavailable_role_catalogs(
        result,
        services,
        slugs,
        status,
        unavailable_evidence_types,
    )
    _mask_unavailable_identity_evidence(
        result,
        services,
        slugs,
        result.degraded_sources,
    )

    if status.channel_unavailable("apex_txt"):
        from recon_tool.fingerprints import get_spf_patterns, get_txt_patterns

        apex_rules = tuple(
            rule for rule in (*get_txt_patterns(), *get_spf_patterns()) if rule.slug not in _EVIDENCE_SLUG_CHANNELS
        )
        _mask_unavailable_catalog_detections(
            result,
            services,
            slugs,
            rules=apex_rules,
            source_types=unavailable_evidence_types | {"TXT"},
        )

    evidence = _observable_evidence(result.evidence, result.degraded_sources)
    return replace(
        result,
        detected_services=tuple(sorted(services)),
        detected_slugs=tuple(sorted(slugs)),
        m365_detected=result.m365_detected and "microsoft365" in slugs,
        evidence=evidence,
        dmarc_policy=result.dmarc_policy if status.channel_available("dmarc") else None,
        dmarc_pct=result.dmarc_pct if status.channel_available("dmarc") else None,
        dmarc_testing=result.dmarc_testing if status.channel_available("dmarc") else False,
        spf_include_count=result.spf_include_count if status.channel_available("apex_txt") else 0,
        mta_sts_mode=result.mta_sts_mode if status.channel_available("mta_sts") else None,
        site_verification_tokens=(result.site_verification_tokens if status.channel_available("apex_txt") else ()),
        bimi_identity=None,
        related_domains=(() if status.channel_unavailable("cname") else result.related_domains),
        cert_summary=(None if status.whole_dns_unavailable else result.cert_summary),
        raw_dns_records=(() if status.whole_dns_unavailable else result.raw_dns_records),
        ct_provider_used=(None if status.whole_dns_unavailable else result.ct_provider_used),
        ct_subdomain_count=(0 if status.whole_dns_unavailable else result.ct_subdomain_count),
        ct_cache_age_days=(None if status.whole_dns_unavailable else result.ct_cache_age_days),
        ct_attempt_outcome=(None if status.whole_dns_unavailable else result.ct_attempt_outcome),
        surface_attributions=(() if status.channel_unavailable("cname") else result.surface_attributions),
        unclassified_cname_chains=(() if status.channel_unavailable("cname") else result.unclassified_cname_chains),
        chain_motifs=(() if status.channel_unavailable("cname") else result.chain_motifs),
        infrastructure_clusters=(None if status.whole_dns_unavailable else result.infrastructure_clusters),
        tenant_id=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else result.tenant_id),
        region=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else result.region),
        cloud_instance=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else result.cloud_instance),
        tenant_region_sub_scope=(
            None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else result.tenant_region_sub_scope
        ),
        msgraph_host=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else result.msgraph_host),
        display_name=(None if not status.degraded_sources.isdisjoint(_USER_REALM_MARKERS) else result.display_name),
        auth_type=(None if not status.degraded_sources.isdisjoint(_USER_REALM_MARKERS) else result.auth_type),
        default_domain=(
            None if not status.degraded_sources.isdisjoint(_AUTODISCOVER_MARKERS) else result.default_domain
        ),
        tenant_domains=(() if not status.degraded_sources.isdisjoint(_AUTODISCOVER_MARKERS) else result.tenant_domains),
        google_auth_type=(
            None if not status.degraded_sources.isdisjoint(_GOOGLE_IDENTITY_MARKERS) else result.google_auth_type
        ),
        google_idp_name=(
            None if not status.degraded_sources.isdisjoint(_GOOGLE_IDENTITY_MARKERS) else result.google_idp_name
        ),
    )


def collection_observable_results(results: list[SourceResult]) -> list[SourceResult]:
    """Project a source-result sequence through channel availability."""
    return [collection_observable_result(result) for result in results]


def _active_signal_rule_names(info: TenantInfo) -> set[str]:
    """Evaluate reportable, absence, and positive rules on projected state."""
    from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
    from recon_tool.email_security import signal_context_from_observable_info
    from recon_tool.signals import evaluate_signals, load_signals

    context = signal_context_from_observable_info(info)
    definitions = load_signals()
    positive = evaluate_signals(context)
    absence = evaluate_absence_signals(positive, definitions, context.detected_slugs)
    positive_absence = evaluate_positive_absence(positive, definitions, context.detected_slugs)
    return {match.name for match in (*positive, *absence, *positive_absence)}


def _filter_signal_insights(
    insights: tuple[str, ...],
    info: TenantInfo,
    active_rule_names: set[str],
) -> tuple[str, ...]:
    """Drop stored declarative conclusions that do not fire on projected state."""
    from recon_tool.signals import load_signals, signal_observation_label, signal_rule_names_from_observation

    known_rule_names = {rule.name for rule in load_signals()}
    visible: list[str] = []
    for insight in insights:
        prefix = insight.partition(": ")[0]
        if prefix in known_rule_names and signal_observation_label(prefix) is None:
            continue
        rule_names = signal_rule_names_from_observation(insight)
        if rule_names and active_rule_names.isdisjoint(rule_names):
            continue
        visible.append(insight)
    return tuple(visible)


def _generated_insight_claims(
    info: TenantInfo,
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[InsightClaim, ...]:
    """Regenerate exact bounded insight claims for one projected state."""
    from recon_tool.constants import effective_dmarc_policy
    from recon_tool.email_security import claim_safe_email_services
    from recon_tool.insights import InsightContext, generate_insight_claims

    context = InsightContext.from_sets(
        claim_safe_email_services(info.services, evidence),
        set(info.slugs),
        info.auth_type,
        info.dmarc_policy,
        info.domain_count,
        google_auth_type=info.google_auth_type,
        google_idp_name=info.google_idp_name,
        cloud_instance=info.cloud_instance,
        tenant_region_sub_scope=info.tenant_region_sub_scope,
        msgraph_host=info.msgraph_host,
        primary_email_provider=info.primary_email_provider,
        likely_primary_email_provider=info.likely_primary_email_provider,
        email_gateway=info.email_gateway,
        has_mx_records=any(item.source_type.upper() == "MX" for item in evidence),
        dmarc_effective_policy=effective_dmarc_policy(
            info.dmarc_policy,
            info.dmarc_pct,
            info.dmarc_testing,
        ),
        evidence=evidence,
        evidence_bound=True,
    )
    return tuple(generate_insight_claims(context))


@lru_cache(maxsize=1)
def _canonical_scope_only_sparse_claims() -> tuple[InsightClaim, ...]:
    """Return the exact sparse pair generated for an evidence-bound empty apex."""
    from recon_tool.insights import InsightContext, generate_insight_claims

    context = InsightContext.from_sets(set(), set(), None, None, 0, evidence=(), evidence_bound=True)
    return tuple(
        claim for claim in generate_insight_claims(context) if claim.generator_rule_id == "_sparse_signal_insights"
    )


def _preserve_pre_enrichment_sparse_claims(
    info: TenantInfo,
    generated_claims: tuple[InsightClaim, ...],
    visible_insights: tuple[str, ...],
) -> tuple[InsightClaim, ...]:
    """Preserve one exact scope-only sparse pair across related inventory enrichment."""
    if not info.related_domains or any(claim.text not in visible_insights for claim in info.insight_claims):
        return generated_claims
    sparse_rule = "_sparse_signal_insights"
    actual_sparse = tuple(claim for claim in info.insight_claims if claim.generator_rule_id == sparse_rule)
    actual_other = tuple(claim for claim in info.insight_claims if claim.generator_rule_id != sparse_rule)
    generated_other = tuple(claim for claim in generated_claims if claim.generator_rule_id != sparse_rule)
    if actual_sparse != _canonical_scope_only_sparse_claims() or actual_other != generated_other:
        return generated_claims
    return info.insight_claims


def _posterior_units_are_current(
    info: TenantInfo,
    visible_slugs: set[str],
    active_rule_names: set[str],
) -> bool:
    """Whether cached posterior diagnostics cite only retained evidence units."""
    from recon_tool.bayesian import signals_from_tenant_info

    claim_info = replace(
        info,
        evidence=_observable_evidence(info.evidence, info.degraded_sources),
    )
    visible_signals = active_rule_names | signals_from_tenant_info(claim_info)
    for posterior in info.posterior_observations:
        units: list[tuple[str, str]] = []
        for unit in posterior.evidence_used:
            kind, separator, name = unit.partition(":")
            if separator:
                units.append((kind, name))
        units.extend((item.kind, item.name) for item in posterior.evidence_ranked)
        units.extend(
            (item.kind, item.unit.removeprefix(f"{item.kind}:"))
            for item in posterior.unit_counterfactuals
            if item.observed == "fired"
        )
        for kind, name in units:
            if kind == "slug" and name not in visible_slugs:
                return False
            if kind == "signal" and name not in visible_signals:
                return False
    return True


def _posterior_contract_is_current(info: TenantInfo) -> bool:
    """Whether cached posterior rows match the currently shipped model."""
    if not info.posterior_observations:
        return True
    from recon_tool.bayesian import load_network

    nodes = {node.name: node for node in load_network().nodes}
    for posterior in info.posterior_observations:
        node = nodes.get(posterior.name)
        if node is None or posterior.description != node.description:
            return False
        bindings = {(binding.kind, binding.name) for binding in node.evidence}
        groups = {binding.group for binding in node.evidence if binding.group is not None}
        for encoded in posterior.evidence_used:
            kind, separator, name = encoded.partition(":")
            if not separator or (kind, name) not in bindings:
                return False
        if any((item.kind, item.name) not in bindings for item in posterior.evidence_ranked):
            return False
        for item in posterior.unit_counterfactuals:
            if item.kind == "group":
                if item.unit not in groups:
                    return False
            elif (item.kind, item.unit.removeprefix(f"{item.kind}:")) not in bindings:
                return False
    return True


def collection_observable_info(info: TenantInfo) -> TenantInfo:
    """Return a reporting copy with unavailable channel values masked.

    The original object and its raw evidence remain unchanged. The returned
    view keeps ``degraded_sources`` so consumers can explain every masked value.
    """
    visible_insights = claim_contract_insights(info.insights)
    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    if not status.degraded_sources:
        generated_claims = tuple(
            claim for claim in _generated_insight_claims(info, info.evidence) if claim.text in visible_insights
        )
        generated_claims = _preserve_pre_enrichment_sparse_claims(info, generated_claims, visible_insights)
        posterior_contract_current = _posterior_contract_is_current(info)
        if (
            visible_insights == info.insights
            and info.insight_claims == generated_claims
            and info.bimi_identity is None
            and posterior_contract_current
        ):
            return info
        return replace(
            info,
            insights=visible_insights,
            insight_claims=generated_claims,
            bimi_identity=None,
            posterior_observations=(info.posterior_observations if posterior_contract_current else ()),
            slug_confidences=(info.slug_confidences if posterior_contract_current else ()),
        )

    services = set(info.services)
    slugs = set(info.slugs)
    if status.whole_dns_unavailable:
        retained = tuple(
            evidence for evidence in info.evidence if evidence.source_type.upper() not in _DNS_EVIDENCE_SOURCE_TYPES
        )
        retained_slugs = {evidence.slug for evidence in retained}
        retained_services = {evidence.rule_name for evidence in retained}
        slugs.intersection_update(retained_slugs)
        services.intersection_update(retained_services)
    for channel in status.unavailable_channels:
        services.difference_update(_CHANNEL_SERVICES.get(channel, ()))
        slugs.difference_update(_CHANNEL_SLUGS.get(channel, ()))

    unavailable_evidence_types = frozenset(
        source_type for source_type, channel in _EVIDENCE_SOURCE_CHANNELS.items() if status.channel_unavailable(channel)
    )
    if unavailable_evidence_types:
        _mask_evidence_owned_detections(
            info,
            services,
            slugs,
            source_types=unavailable_evidence_types,
        )
    _mask_unavailable_role_catalogs(
        info,
        services,
        slugs,
        status,
        unavailable_evidence_types,
    )
    _mask_unavailable_identity_evidence(
        info,
        services,
        slugs,
        info.degraded_sources,
    )

    if status.channel_unavailable("apex_txt"):
        from recon_tool.fingerprints import get_spf_patterns, get_txt_patterns

        apex_rules = tuple(
            rule for rule in (*get_txt_patterns(), *get_spf_patterns()) if rule.slug not in _EVIDENCE_SLUG_CHANNELS
        )
        _mask_unavailable_catalog_detections(
            info,
            services,
            slugs,
            rules=apex_rules,
            source_types=unavailable_evidence_types | {"TXT"},
        )

    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.merger import compute_detection_scores, compute_email_topology

    observable_evidence = collection_observable_evidence(info)
    primary_email_provider, email_gateway, likely_primary_email_provider = compute_email_topology(observable_evidence)
    provisional = replace(
        info,
        services=tuple(sorted(services)),
        slugs=tuple(sorted(slugs)),
        insights=(),
        insight_claims=(),
        dmarc_policy=info.dmarc_policy if status.channel_available("dmarc") else None,
        dmarc_pct=info.dmarc_pct if status.channel_available("dmarc") else None,
        dmarc_testing=info.dmarc_testing if status.channel_available("dmarc") else False,
        spf_include_count=info.spf_include_count if status.channel_available("apex_txt") else 0,
        mta_sts_mode=info.mta_sts_mode if status.channel_available("mta_sts") else None,
        email_gateway=email_gateway,
        primary_email_provider=primary_email_provider,
        likely_primary_email_provider=likely_primary_email_provider,
        site_verification_tokens=info.site_verification_tokens if status.channel_available("apex_txt") else (),
        bimi_identity=None,
        related_domains=(() if status.channel_unavailable("cname") else info.related_domains),
        cert_summary=(None if status.whole_dns_unavailable else info.cert_summary),
        ct_provider_used=(None if status.whole_dns_unavailable else info.ct_provider_used),
        ct_subdomain_count=(0 if status.whole_dns_unavailable else info.ct_subdomain_count),
        ct_cache_age_days=(None if status.whole_dns_unavailable else info.ct_cache_age_days),
        ct_attempt_outcome=(None if status.whole_dns_unavailable else info.ct_attempt_outcome),
        lexical_observations=(() if status.channel_unavailable("cname") else info.lexical_observations),
        surface_attributions=(() if status.channel_unavailable("cname") else info.surface_attributions),
        unclassified_cname_chains=(() if status.channel_unavailable("cname") else info.unclassified_cname_chains),
        chain_motifs=(() if status.channel_unavailable("cname") else info.chain_motifs),
        infrastructure_clusters=(None if status.whole_dns_unavailable else info.infrastructure_clusters),
        tenant_id=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else info.tenant_id),
        display_name=(
            info.queried_domain if not status.degraded_sources.isdisjoint(_USER_REALM_MARKERS) else info.display_name
        ),
        auth_type=(None if not status.degraded_sources.isdisjoint(_USER_REALM_MARKERS) else info.auth_type),
        default_domain=(
            info.queried_domain
            if not status.degraded_sources.isdisjoint(_AUTODISCOVER_MARKERS)
            else info.default_domain
        ),
        domain_count=(0 if not status.degraded_sources.isdisjoint(_AUTODISCOVER_MARKERS) else info.domain_count),
        tenant_domains=(() if not status.degraded_sources.isdisjoint(_AUTODISCOVER_MARKERS) else info.tenant_domains),
        google_auth_type=(
            None if not status.degraded_sources.isdisjoint(_GOOGLE_IDENTITY_MARKERS) else info.google_auth_type
        ),
        google_idp_name=(
            None if not status.degraded_sources.isdisjoint(_GOOGLE_IDENTITY_MARKERS) else info.google_idp_name
        ),
        region=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else info.region),
        cloud_instance=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else info.cloud_instance),
        tenant_region_sub_scope=(
            None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else info.tenant_region_sub_scope
        ),
        msgraph_host=(None if not status.degraded_sources.isdisjoint(_OIDC_MARKERS) else info.msgraph_host),
        slug_confidences=(compute_slug_posteriors(observable_evidence) if info.slug_confidences else ()),
        detection_scores=compute_detection_scores(observable_evidence),
    )
    unavailable_terms = tuple(
        term for channel in status.unavailable_channels for term in _INSIGHT_TERMS.get(channel, ())
    )
    channel_visible_insights = tuple(
        insight
        for insight in visible_insights
        if not _insight_owned_by_unavailable_channel(insight, status)
        and not any(term in insight.lower() for term in unavailable_terms)
    )
    raw_generated_claims = _generated_insight_claims(info, info.evidence)
    observable_generated_claims = tuple(
        claim
        for claim in _generated_insight_claims(provisional, observable_evidence)
        if observation_scopes_available(claim.observation_scope, status.degraded_sources)
    )
    raw_generated_insights = {claim.text for claim in raw_generated_claims}
    observable_generated_insights = {claim.text for claim in observable_generated_claims}
    channel_visible_insights = tuple(
        insight
        for insight in channel_visible_insights
        if insight not in raw_generated_insights or insight in observable_generated_insights
    )
    active_rule_names = _active_signal_rule_names(provisional)
    insights = _filter_signal_insights(channel_visible_insights, provisional, active_rule_names)
    posterior_units_current = _posterior_contract_is_current(info) and _posterior_units_are_current(
        provisional,
        slugs,
        active_rule_names,
    )
    return replace(
        provisional,
        insights=insights,
        insight_claims=tuple(claim for claim in observable_generated_claims if claim.text in insights),
        posterior_observations=info.posterior_observations if posterior_units_current else (),
        slug_confidences=provisional.slug_confidences if posterior_units_current else (),
    )


def collection_claim_info(info: TenantInfo) -> TenantInfo:
    """Return a derived-claim view with only observable supporting evidence.

    Serializers intentionally keep raw provenance on ``collection_observable_info``.
    Claim engines use this stricter copy so an unavailable record cannot support
    an exposure, explanation, or score while the original ``TenantInfo`` remains
    available for diagnostics.
    """
    observable = collection_observable_info(info)
    return replace(observable, evidence=collection_observable_evidence(info))
