"""Data models for domain intelligence lookup."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from typing import Any

__all__ = [
    "BIMIIdentity",
    "CandidateValue",
    "CertSummary",
    "ChainReport",
    "ChainResult",
    "ConfidenceLevel",
    "DeltaReport",
    "EvidenceRecord",
    "ExplanationRecord",
    "MergeConflicts",
    "MetadataCondition",
    "Observation",
    "ReconLookupError",
    "SignalContext",
    "SourceResult",
    "SurfaceAttribution",
    "TenantInfo",
    "UnclassifiedCnameChain",
    "serialize_conflicts",
]


class ConfidenceLevel(str, Enum):
    """How reliable the resolved TenantInfo is based on source agreement."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class EvidenceRecord:
    """A single piece of evidence linking a detection to its source record.

    Created at detection time and propagated through the merge pipeline
    from SourceResult to TenantInfo without loss.
    """

    source_type: str  # "TXT", "MX", "CNAME", "HTTP", "SPF", "NS", "CAA", "SRV"
    raw_value: str  # The actual record value or HTTP response excerpt
    rule_name: str  # Fingerprint/detection rule name that matched
    slug: str  # The fingerprint slug that was detected


@dataclass(frozen=True)
class BIMIIdentity:
    """Corporate identity extracted from a BIMI VMC certificate.

    VMC certificates require strict legal verification, so the extracted
    organization name is a high-confidence corporate identity signal.
    """

    organization: str
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    trademark: str | None = None


@dataclass(frozen=True)
class CertSummary:
    """Certificate transparency summary from crt.sh metadata."""

    cert_count: int
    issuer_diversity: int
    issuance_velocity: int  # certs issued in last 90 days
    newest_cert_age_days: int
    oldest_cert_age_days: int
    top_issuers: tuple[str, ...]  # up to 3 most frequent issuer_name values


@dataclass(frozen=True)
class MetadataCondition:
    """A single metadata condition for signal evaluation."""

    field: str  # dmarc_policy, auth_type, email_security_score, spf_include_count, issuance_velocity
    operator: str  # eq, neq, gte, lte
    value: str | int


@dataclass(frozen=True)
class SignalContext:
    """All metadata available for signal evaluation."""

    detected_slugs: frozenset[str]
    dmarc_policy: str | None = None
    auth_type: str | None = None
    email_security_score: int | None = None
    spf_include_count: int | None = None
    issuance_velocity: int | None = None
    dmarc_pct: int | None = None
    primary_email_provider: str | None = None
    likely_primary_email_provider: str | None = None


@dataclass(frozen=True)
class Observation:
    """A neutral factual observation about a domain's configuration."""

    category: str  # identity, email, infrastructure, saas_footprint, certificate, consistency
    salience: str  # high, medium, low
    statement: str
    related_slugs: tuple[str, ...]


@dataclass(frozen=True)
class CandidateValue:
    """A per-source value for a merged field."""

    value: str
    source: str
    confidence: str  # "high" | "medium" | "low"


@dataclass(frozen=True)
class MergeConflicts:
    """Tracks disagreements between sources for merged fields.

    Each field is a tuple of CandidateValue. Empty tuple means no conflict.
    Only populated when 2+ sources provide different non-None values.
    """

    display_name: tuple[CandidateValue, ...] = ()
    auth_type: tuple[CandidateValue, ...] = ()
    region: tuple[CandidateValue, ...] = ()
    tenant_id: tuple[CandidateValue, ...] = ()
    dmarc_policy: tuple[CandidateValue, ...] = ()
    google_auth_type: tuple[CandidateValue, ...] = ()

    @property
    def has_conflicts(self) -> bool:
        """True if any tracked field has 2+ disagreeing candidates."""
        return any(
            [
                self.display_name,
                self.auth_type,
                self.region,
                self.tenant_id,
                self.dmarc_policy,
                self.google_auth_type,
            ]
        )


def serialize_conflicts(conflicts: MergeConflicts) -> dict[str, Any]:
    """Serialize MergeConflicts to a JSON-safe dict. Omits fields with no conflicts."""
    result: dict[str, Any] = {}
    for f in fields(conflicts):
        candidates: tuple[CandidateValue, ...] = getattr(conflicts, f.name)
        if candidates:
            result[f.name] = [{"value": c.value, "source": c.source, "confidence": c.confidence} for c in candidates]
    return result


@dataclass(frozen=True)
class UnclassifiedCnameChain:
    """A CNAME chain from a related subdomain that did NOT match any
    cname_target fingerprint.

    Surfaced only in JSON output when ``--include-unclassified`` is passed.
    Feeds the fingerprint-discovery loop: gap analysis and the
    ``/recon-fingerprint-triage`` skill use these to suggest new fingerprint
    candidates. Wildcard-DNS echoes are filtered before this list is
    populated, so every entry is a genuinely-distinct chain.
    """

    subdomain: str
    chain: tuple[str, ...]  # ordered hops, terminal last


@dataclass(frozen=True)
class SurfaceAttribution:
    """A subdomain's attribution to a SaaS or infrastructure provider via CNAME chain.

    Each instance maps one related subdomain to its primary service. ``primary_*``
    fields hold the application-tier match (Auth0, Shopify, Zendesk, ...) when one
    exists in the chain; otherwise they hold the most-specific infrastructure-tier
    match (Fastly, CloudFront, Akamai, ...). ``infra_slug`` and ``infra_name`` are
    populated only when both an application and an infrastructure tier matched —
    they record which CDN or load balancer fronts the application service.

    The full CNAME chain (every hop) is preserved on the corresponding
    EvidenceRecord, so --explain output can show the resolution path while the
    default panel and --full surface section show only the primary attribution.
    """

    subdomain: str
    primary_slug: str
    primary_name: str
    primary_tier: str  # "application" | "infrastructure"
    infra_slug: str | None = None
    infra_name: str | None = None


@dataclass(frozen=True)
class ExplanationRecord:
    """Structured explanation for a single insight, signal, or observation.

    Captures the full reasoning chain: what matched, which rules fired,
    how confidence was derived, and what would weaken the conclusion.
    """

    item_name: str
    item_type: str  # "insight" | "signal" | "observation" | "confidence"
    matched_evidence: tuple[EvidenceRecord, ...]
    fired_rules: tuple[str, ...]
    confidence_derivation: str
    weakening_conditions: tuple[str, ...]
    curated_explanation: str = ""


@dataclass(frozen=True)
class SourceResult:
    """Structured output from a single LookupSource."""

    source_name: str
    tenant_id: str | None = None
    display_name: str | None = None
    default_domain: str | None = None
    region: str | None = None
    m365_detected: bool = False
    error: str | None = None
    detected_services: tuple[str, ...] = ()
    # Extended intel fields
    auth_type: str | None = None  # "Federated" or "Managed"
    dmarc_policy: str | None = None  # "reject", "quarantine", "none"
    tenant_domains: tuple[str, ...] = ()  # All domains in the tenant
    detected_slugs: tuple[str, ...] = ()  # Fingerprint slugs that matched
    # Domains discovered from CNAME targets (autodiscover redirects, DKIM
    # delegation) that likely belong to the same organization but weren't
    # in the Autodiscover tenant domain list.
    related_domains: tuple[str, ...] = ()

    # Names of data sources that were unavailable during lookup
    degraded_sources: tuple[str, ...] = ()

    cert_summary: CertSummary | None = None

    # --- Google Workspace & evidence fields (v0.3.0) ---
    evidence: tuple[EvidenceRecord, ...] = ()
    bimi_identity: BIMIIdentity | None = None
    site_verification_tokens: tuple[str, ...] = ()
    mta_sts_mode: str | None = None  # "enforce", "testing", "none"
    google_auth_type: str | None = None  # "Federated", "Managed"
    google_idp_name: str | None = None  # "Okta", "Ping Identity", etc.

    # --- v0.9.0: Intelligence Amplification ---
    dmarc_pct: int | None = None  # DMARC pct= value (0-100)
    raw_dns_records: tuple[tuple[str, str], ...] = ()  # (record_type, value) pairs for reevaluation cache

    # --- v0.9.2: CT provider attribution ---
    # Name of the CT provider ("crt.sh" or "certspotter") that actually
    # returned results for this lookup, and how many subdomains came back
    # after filtering. None when no CT provider was queried or all failed.
    ct_provider_used: str | None = None
    ct_subdomain_count: int = 0

    # --- v0.10: CT cache fallback ---
    # When all live CT providers fail, the per-domain CT cache serves as
    # a fallback. ct_cache_age_days is set to the cache age when cached
    # data was used; None when data came from a live provider.
    ct_cache_age_days: int | None = None

    # --- v0.9.3: OIDC tenant metadata enrichment ---
    # Extracted from the Microsoft OIDC discovery document when present.
    # Distinguish commercial M365, Government Community Cloud / GCC High,
    # Azure China 21Vianet, Azure B2C, and Azure External ID tenancies.
    # All three are None for non-Microsoft sources.
    cloud_instance: str | None = None  # e.g. "microsoftonline.com", "microsoftonline.us"
    tenant_region_sub_scope: str | None = None  # e.g. "GCC", "DOD", "USGov"
    msgraph_host: str | None = None  # e.g. "graph.microsoft.com", "graph.microsoft.us"

    # --- v1.5: External surface attribution ---
    # Per-subdomain attribution from CNAME-chain classification of related
    # domains. Populated by the DNS source after CT and common-subdomain
    # discovery. Drives both the default-panel slug union and the --full
    # External surface section.
    surface_attributions: tuple[SurfaceAttribution, ...] = ()
    # CNAME chains resolved during surface classification that did not match
    # any cname_target rule. Always populated; surfaced in JSON only when
    # ``--include-unclassified`` is passed. Feeds the fingerprint-discovery
    # loop (validation/find_gaps.py and the triage skill).
    unclassified_cname_chains: tuple[UnclassifiedCnameChain, ...] = ()

    @property
    def crtsh_degraded(self) -> bool:
        """Backward-compatible: True when crt.sh was unreachable."""
        return "crt.sh" in self.degraded_sources

    @property
    def is_success(self) -> bool:
        """True if this result contains any useful data (identity or services)."""
        return self.tenant_id is not None or self.m365_detected or len(self.detected_services) > 0

    @property
    def is_complete(self) -> bool:
        """True if this result has all core fields."""
        return all([self.tenant_id, self.display_name, self.default_domain])


@dataclass(frozen=True)
class TenantInfo:
    """Structured tenant information merged from one or more sources.

    tenant_id is None when no M365 tenant was found but DNS services were
    detected. Downstream code should check `if info.tenant_id` or `is not None`.
    """

    # NOTE: tenant_id is Optional — None means "no M365 tenant found, but
    # we still have DNS-based service data worth showing."
    tenant_id: str | None
    display_name: str
    default_domain: str
    queried_domain: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    region: str | None = None
    sources: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    slugs: tuple[str, ...] = ()  # Stable fingerprint identifiers
    # Extended intel
    auth_type: str | None = None  # "Federated" or "Managed"
    dmarc_policy: str | None = None  # "reject", "quarantine", "none"
    domain_count: int = 0  # Number of domains in tenant
    tenant_domains: tuple[str, ...] = ()  # All domains found
    related_domains: tuple[str, ...] = ()  # Domains inferred from CNAME targets
    insights: tuple[str, ...] = ()  # Derived intelligence signals
    degraded_sources: tuple[str, ...] = ()  # Names of unavailable data sources
    cert_summary: CertSummary | None = None

    # --- Google Workspace, evidence & confidence fields (v0.3.0) ---
    evidence: tuple[EvidenceRecord, ...] = ()
    evidence_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    inference_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    detection_scores: tuple[tuple[str, str], ...] = ()  # (slug, score) pairs
    bimi_identity: BIMIIdentity | None = None
    site_verification_tokens: tuple[str, ...] = ()
    mta_sts_mode: str | None = None  # "enforce", "testing", "none"
    google_auth_type: str | None = None  # "Federated", "Managed"
    google_idp_name: str | None = None  # "Okta", "Ping Identity", etc.

    # --- v0.9.0: Intelligence Amplification ---
    primary_email_provider: str | None = None  # MX-detected provider name(s)
    email_gateway: str | None = None  # MX-detected gateway name
    dmarc_pct: int | None = None  # DMARC pct= value (0-100)
    # Downstream provider inferred from non-MX evidence (DKIM, identity
    # endpoints, TXT tokens) when a gateway is present in MX but no
    # direct provider appears there. Hedged: "likely" in the name is
    # load-bearing. Never set when primary_email_provider is also set.
    likely_primary_email_provider: str | None = None

    # --- v0.9.2: CT provider attribution ---
    # Which CT provider actually contributed subdomain data for this
    # lookup ("crt.sh" or "certspotter") and how many came back. Surfaced
    # in the panel bottom Note so enrichment asymmetry between runs is
    # visible. None when no CT provider succeeded.
    ct_provider_used: str | None = None
    ct_subdomain_count: int = 0

    # --- v0.10: CT cache fallback ---
    # Age of the CT cache entry in days when cached data was used as a
    # fallback. None when data came from a live provider. Surfaced in the
    # panel as "from local cache, N days old".
    ct_cache_age_days: int | None = None

    # --- v1.4: staleness timestamps (ISO-8601 UTC) ---
    # resolved_at is when the live resolution produced this TenantInfo.
    # cached_at is when the on-disk cache entry was written; it is None
    # on a fresh resolve and set only when the result was served from
    # ``~/.recon/cache/``. Agents reading --json can compare the two to
    # decide whether to re-resolve.
    resolved_at: str | None = None
    cached_at: str | None = None

    # --- v0.11: Bayesian fusion (experimental) ---
    # Per-slug posterior mean in [0, 1] from the Bayesian fusion layer.
    # Populated only when `--fusion` is passed. Empty otherwise.
    # Tagged EXPERIMENTAL — field shape may evolve in minor releases.
    slug_confidences: tuple[tuple[str, float], ...] = ()

    # --- v0.9.3: OIDC tenant metadata enrichment ---
    # Sovereignty / cloud instance information extracted from the
    # Microsoft OIDC discovery document. None for non-Microsoft tenants.
    # cloud_instance distinguishes commercial (microsoftonline.com) from
    # gov cloud (microsoftonline.us) and China 21Vianet
    # (partner.microsoftonline.cn). tenant_region_sub_scope is a
    # Microsoft extension that further disambiguates gov deployments
    # (e.g. "GCC", "DOD", "USGov"). msgraph_host surfaces the
    # authoritative Graph host for the tenant.
    cloud_instance: str | None = None
    tenant_region_sub_scope: str | None = None
    msgraph_host: str | None = None

    # --- v0.9.3: Shared verification token clustering (batch scope) ---
    # Populated only when a batch run observes the same site-verification
    # token on multiple domains. Each entry is a (token, peer_domain)
    # pair — one entry per peer that shares this token. Empty on single
    # lookups. Never persisted to disk cache (batch scope only).
    shared_verification_tokens: tuple[tuple[str, str], ...] = ()

    # --- v0.9.3: CT lexical taxonomy (pure rule-based) ---
    # Hedged observations derived from recognised environment / region /
    # tenancy-shard prefixes on CT-discovered subdomains. Empty when
    # fewer than the minimum number of matching subdomains are observed.
    lexical_observations: tuple[str, ...] = ()

    # --- Conflict-aware merge (v0.7.0) ---
    merge_conflicts: MergeConflicts | None = None

    # --- v1.5: External surface attribution ---
    # Per-subdomain attribution to SaaS or infrastructure providers, derived
    # from CNAME chains of related_domains. Populated alongside related_domains
    # but addresses a different question: not "what subdomains exist?" but
    # "what is each subdomain hosting?". Each entry is a SurfaceAttribution
    # with the subdomain and its primary service (application tier preferred
    # over infrastructure tier when a chain matches both).
    surface_attributions: tuple[SurfaceAttribution, ...] = ()
    # CNAME chains resolved during surface classification that did not match
    # any cname_target rule. Always populated; surfaced in JSON only when
    # ``--include-unclassified`` is passed. Feeds the fingerprint-discovery
    # loop (validation/find_gaps.py and the triage skill).
    unclassified_cname_chains: tuple[UnclassifiedCnameChain, ...] = ()

    @property
    def crtsh_degraded(self) -> bool:
        """Backward-compatible: True when crt.sh was unreachable."""
        return "crt.sh" in self.degraded_sources


@dataclass(frozen=True)
class DeltaReport:
    """Structured diff between two domain intelligence snapshots."""

    domain: str
    added_services: tuple[str, ...]
    removed_services: tuple[str, ...]
    added_slugs: tuple[str, ...]
    removed_slugs: tuple[str, ...]
    added_signals: tuple[str, ...]
    removed_signals: tuple[str, ...]
    changed_auth_type: tuple[str | None, str | None] | None = None
    changed_dmarc_policy: tuple[str | None, str | None] | None = None
    changed_email_security_score: tuple[int | None, int | None] | None = None
    changed_confidence: tuple[str, str] | None = None
    changed_domain_count: tuple[int, int] | None = None

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_services
            or self.removed_services
            or self.added_slugs
            or self.removed_slugs
            or self.added_signals
            or self.removed_signals
            or self.changed_auth_type is not None
            or self.changed_dmarc_policy is not None
            or self.changed_email_security_score is not None
            or self.changed_confidence is not None
            or self.changed_domain_count is not None
        )


@dataclass(frozen=True)
class ChainResult:
    """A single domain's intelligence within a chain resolution."""

    domain: str
    info: TenantInfo
    chain_depth: int


@dataclass(frozen=True)
class ChainReport:
    """Result of recursive domain chain resolution."""

    results: tuple[ChainResult, ...]
    max_depth_reached: int
    truncated: bool


@dataclass
class ReconLookupError(Exception):
    """Structured error from the resolver.

    Extends Exception via dataclass. Note: dataclass doesn't set Exception.args,
    so str() returns self.message (via __str__) while repr() shows all fields.
    This is intentional — str() is user-facing, repr() is for debugging.

    ``source_errors`` carries per-source failure reasons as a tuple of
    ``(source_name, error_message)`` pairs so CLI output can surface
    concrete causes ("oidc_discovery: HTTP 429; dns_records: no records
    found") instead of a single generic "no information found" message.
    Empty when the error isn't source-specific (e.g. timeout).
    """

    domain: str
    message: str
    error_type: str
    source_errors: tuple[tuple[str, str], ...] = ()

    def __str__(self) -> str:
        return self.message
