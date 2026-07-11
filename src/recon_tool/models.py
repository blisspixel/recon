"""Data models for domain intelligence lookup."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any

__all__ = [
    "BIMIIdentity",
    "CandidateValue",
    "CertBurst",
    "CertSummary",
    "ChainMotifObservation",
    "ChainReport",
    "ChainResult",
    "ConfidenceLevel",
    "DeltaComparisonIncomplete",
    "DeltaReport",
    "EvidenceRecord",
    "ExplanationRecord",
    "InfrastructureCluster",
    "InfrastructureClusterReport",
    "InfrastructureEdge",
    "MergeConflicts",
    "MetadataCondition",
    "NodeUnitCounterfactual",
    "Observation",
    "ReconLookupError",
    "SignalContext",
    "SourceResult",
    "SurfaceAttribution",
    "TenantInfo",
    "UnclassifiedCnameChain",
    "serialize_conflicts",
    "serialize_conflicts_array",
]


class ConfidenceLevel(StrEnum):
    """How reliable the resolved TenantInfo is based on source agreement.

    A ``StrEnum`` (Python 3.11+): members are strings equal to their value,
    so JSON, dict-key lookups, and comparisons behave as before, and
    ``str()`` / f-strings render the value (``"high"``) rather than the
    qualified name. Audited before the v1.9.34 conversion: every render
    site already used ``.value``, so this changes no user-facing output;
    the full suite covers the panel, markdown, and JSON renderers.
    """

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
    """Identity supplied by a trust-validated BIMI VMC source.

    The direct BIMI document probe does not populate this model because parsing
    a certificate subject without chain and VMC-profile validation is not enough
    to establish identity. The stable nullable model remains available for a
    future source that performs that validation.
    """

    organization: str
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    trademark: str | None = None


@dataclass(frozen=True)
class CertBurst:
    """A cluster of certificates issued within a short window.

    The same `not_before` window across multiple certs / SANs is a
    deployment-burst signal. Output is intentionally relative (window
    span in seconds, count of names, name list) rather than absolute
    timestamps — recon does not claim "same owner", only "co-issued".

    Surfaced under ``cert_summary.deployment_bursts`` in --json.
    """

    window_start: str  # ISO-8601 UTC of earliest not_before in this burst
    window_end: str  # ISO-8601 UTC of latest not_before in this burst
    span_seconds: int  # window_end - window_start, in seconds
    names: tuple[str, ...]  # distinct non-wildcard SANs in this burst, sorted


@dataclass(frozen=True)
class CertSummary:
    """Certificate transparency summary from crt.sh metadata."""

    cert_count: int
    issuer_diversity: int
    issuance_velocity: int  # certs issued in last 90 days
    newest_cert_age_days: int
    oldest_cert_age_days: int
    top_issuers: tuple[str, ...]  # up to 3 most frequent issuer_name values
    # Wildcard SAN sibling clusters. Each inner tuple is the sorted
    # set of non-wildcard SANs from a single cert that also covered a
    # wildcard. Empty when no wildcard cert produced siblings, or when
    # CT data was unavailable. Bounded.
    wildcard_sibling_clusters: tuple[tuple[str, ...], ...] = ()
    # Deployment bursts — cohorts of cert issuances clustered by
    # not_before within a short window. Empty when no burst meets the
    # minimum cohort size.
    deployment_bursts: tuple[CertBurst, ...] = ()


@dataclass(frozen=True)
class MetadataCondition:
    """A single metadata condition for signal evaluation."""

    field: str  # dmarc_policy, dmarc_effective_policy, auth_type, email_security_score, spf_include_count
    operator: str  # eq, neq, gte, lte
    value: str | int


@dataclass(frozen=True)
class SignalContext:
    """All metadata available for signal evaluation."""

    detected_slugs: frozenset[str]
    dmarc_policy: str | None = None
    dmarc_effective_policy: str | None = None
    auth_type: str | None = None
    email_security_score: int | None = None
    spf_include_count: int | None = None
    issuance_velocity: int | None = None
    dmarc_pct: int | None = None
    primary_email_provider: str | None = None
    likely_primary_email_provider: str | None = None
    # Metadata fields whose collection channel was unavailable. Conditions on
    # these fields remain unresolved instead of treating None as not equal.
    unavailable_metadata_fields: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Observation:
    """A neutral factual observation about a domain's configuration."""

    category: str  # identity, email, infrastructure, saas_footprint, certificate, consistency
    salience: str  # high, medium, low
    statement: str
    related_slugs: tuple[str, ...]
    source_name: str = ""  # originating posture rule name (data/posture.yaml); "" when not rule-derived


@dataclass(frozen=True)
class NodeConflict:
    """One cross-source disagreement carried through to a NodePosterior.

    Mirrors ``recon_tool.bayesian.ConflictProvenance`` for serialization
    and cache round-trips. ``field`` is the merged ``TenantInfo`` field
    whose sources disagreed; ``sources`` lists the distinct sources that
    contributed candidate values; ``magnitude`` is the n_eff penalty
    this conflict applied (uniform for now, exposed as a number so
    future per-node relevance weighting is schema-additive).
    """

    field: str
    sources: tuple[str, ...]
    magnitude: float


@dataclass(frozen=True)
class NodeEvidence:
    """One bound observation's quantified influence on a node's posterior.

    Public-facing counterpart to ``recon_tool.bayesian.EvidenceContribution``.
    Surfaced through ``PosteriorObservation.evidence_ranked`` so JSON
    consumers, the cache, and the ``--explain-dag`` renderer all read
    from a stable shape.

    ``llr`` is the natural-log likelihood ratio for the binding that
    fired — positive when the observation favours ``present``, negative
    when it favours ``absent``. ``influence_pct`` normalizes ``|llr|``
    to a percentage across all fired bindings for the same node.

    Supports top-3 influential-edge rendering. Schema-additive:
    the default empty tuple on ``PosteriorObservation.evidence_ranked``
    preserves the v1.9.0 JSON shape for consumers that don't read this
    field.
    """

    kind: str  # "slug" or "signal"
    name: str
    llr: float
    influence_pct: float


@dataclass(frozen=True)
class NodeUnitCounterfactual:
    """One evidence unit's exact leave-one-out influence on a node's posterior.

    Public-facing counterpart to ``recon_tool.bayesian.UnitCounterfactual``,
    surfaced through ``PosteriorObservation.unit_counterfactuals`` (added
    2.2.0; schema-additive). ``posterior_without`` is the node's posterior
    with this evidence unit masked as structurally unobserved (the exact
    leave-one-unit-out re-inference, global across the DAG); ``delta`` is
    ``posterior - posterior_without``. ``observed`` is ``"fired"`` for a
    fired unit or ``"absent"`` for an informative absence on a declarative
    node. Deltas are individually exact but not additive — units interact
    through the DAG.
    """

    unit: str  # group name, or the ungrouped binding's slug/signal name
    kind: str  # "group", "slug", or "signal"
    observed: str  # "fired" or "absent"
    posterior_without: float
    delta: float


@dataclass(frozen=True)
class PosteriorObservation:
    """Per-node posterior from the v1.9 Bayesian network (stable v2.0+).

    Each entry corresponds to a node in
    ``recon_tool/data/bayesian_network.yaml``. ``posterior`` is
    ``P(node=present | E)`` where ``E`` is the observed-evidence set
    for the queried domain (slugs and signals), under the committed model.
    ``interval_low`` and ``interval_high`` form an 80% evidence-responsive
    uncertainty band from ``Beta(p * n_eff, (1 - p) * n_eff)``, where ``p`` is
    the posterior. When both parameters are at least one, central quantiles are
    used if they contain ``p``; otherwise a clamped mean-centered normal
    fallback is used. It is not a credible or confidence interval.

    The band is a post-inference display heuristic, not a different inference
    method. The network math is exact for its model; the band does not quantify
    model validity. See
    ``docs/correlation.md`` section 4 for the exact semantics.

    ``conflict_provenance`` lists the cross-source
    disagreements that contributed to this node's n_eff penalty,
    alongside the existing top-level ``evidence_conflicts`` array.
    Empty tuple when no conflicts lowered the band's display mass.
    """

    name: str
    description: str
    posterior: float
    interval_low: float
    interval_high: float
    evidence_used: tuple[str, ...]
    n_eff: float
    sparse: bool
    conflict_provenance: tuple[NodeConflict, ...] = ()
    evidence_ranked: tuple[NodeEvidence, ...] = ()
    """Fired bindings ranked by absolute LLR contribution (descending).

    Same shape/order as the engine's
    ``EvidenceContribution`` tuple; default empty tuple preserves
    backward-compatibility with v1.9.0 / v1.9.3 JSON consumers."""

    entropy_reduction_nats: float = 0.0
    """Signed marginal entropy change H(prior marginal) - H(posterior).

    This is not pointwise information gain and can double count dependence when
    summed. Added 2.2.0; schema-additive (default 0.0 preserves prior shapes).
    """

    unit_counterfactuals: tuple[NodeUnitCounterfactual, ...] = ()
    """Exact leave-one-unit-out counterfactuals for the evidence units
    informative for this node, sorted by absolute delta descending. Added
    2.2.0; schema-additive (default empty tuple preserves prior shapes)."""


@dataclass(frozen=True)
class CandidateValue:
    """A per-source value for a merged field.

    ``confidence`` is the contributing source result's overall completeness
    tier. It is not field-specific reliability or calibrated truth confidence.
    """

    value: str
    source: str
    confidence: str  # source-result completeness: "high" | "medium" | "low"


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


def serialize_conflicts_array(conflicts: MergeConflicts | None) -> list[dict[str, Any]]:
    """Serialize MergeConflicts to a flat array of {field, candidates} records.

    Always returns a list. Empty list when ``conflicts`` is None or no
    field has 2+ disagreeing candidates. Used by the top-level
    ``evidence_conflicts`` array in --json output.
    """
    if conflicts is None:
        return []
    out: list[dict[str, Any]] = []
    for f in fields(conflicts):
        candidates: tuple[CandidateValue, ...] = getattr(conflicts, f.name)
        if not candidates:
            continue
        out.append(
            {
                "field": f.name,
                "candidates": [{"value": c.value, "source": c.source, "confidence": c.confidence} for c in candidates],
            }
        )
    return out


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
class ChainMotifObservation:
    """One CNAME chain motif observed against a related subdomain.

    A motif names an ordered proxy / CDN / origin shape (e.g.
    "Cloudflare → AWS origin"). The observation records which subdomain
    triggered the motif and the matched hop subsequence — never an
    ownership claim. See ``recon_tool/motifs.py`` for the matcher and
    ``recon_tool/data/motifs.yaml`` for the catalog.

    Surfaced under top-level ``chain_motifs`` in --json.
    """

    motif_name: str
    display_name: str
    confidence: str  # "high" | "medium" | "low"
    subdomain: str
    chain: tuple[str, ...]


@dataclass(frozen=True)
class InfrastructureCluster:
    """A community detected in the per-domain CT co-occurrence graph.

    Members are SAN names that co-occur across the same certificates,
    grouped by community detection (Louvain) over an in-memory graph
    whose edges weight shared-cert co-occurrence and same-issuer
    proximity. The cluster is observable structure — it does not assert
    ownership.

    Surfaced under top-level ``infrastructure_clusters.clusters`` in
    --json.
    """

    cluster_id: int
    members: tuple[str, ...]  # sorted SAN names
    size: int  # len(members)
    shared_cert_count: int  # certs that contributed at least one edge inside this cluster
    dominant_issuer: str | None = None  # most common issuer across contributing certs


@dataclass(frozen=True)
class InfrastructureEdge:
    """One edge in the per-domain CT co-occurrence graph.

    ``source`` and ``target`` are SAN hostnames (sorted alphabetically
    so the edge is canonical). ``shared_cert_count`` is the number of
    cert entries that placed both names in the same SAN list.

    Surfaced via the MCP ``export_graph`` tool. Not part of the v1.0
    JSON envelope: the cluster report ships in ``--json`` while raw
    edges stay behind the explicit MCP surface to keep the JSON
    contract narrow.
    """

    source: str
    target: str
    shared_cert_count: int


@dataclass(frozen=True)
class InfrastructureClusterReport:
    """Result of running community detection on the CT co-occurrence graph.

    ``algorithm`` records which path produced ``clusters`` — Louvain on
    small graphs, connected-components fallback when the graph exceeds
    ``MAX_GRAPH_NODES``, or "skipped" when the graph was empty / trivial.
    ``modularity`` is 0.0 in the fallback / skipped paths since modularity
    only applies to a Louvain partition.

    Surfaced under top-level ``infrastructure_clusters`` in --json.
    Always present in the JSON envelope (with empty
    ``clusters`` when nothing fired) so the field is part of the stable
    contract.
    """

    clusters: tuple[InfrastructureCluster, ...]
    modularity: float
    algorithm: str  # "louvain" | "connected_components" | "skipped"
    node_count: int
    edge_count: int
    # Edges in the underlying co-occurrence graph, sorted by weight
    # descending then alphabetically. Capped — see
    # ``recon_tool/infra_graph.MAX_EDGES_RETAINED``. Surfaced via the
    # MCP ``export_graph`` tool, not the default --json envelope.
    edges: tuple[InfrastructureEdge, ...] = ()
    # Partition stability across a Louvain seed sweep (CAL11): the mean
    # pairwise adjusted Rand index between the partitions produced by
    # ``stability_runs`` different seeds. 1.0 means every seed produced
    # the identical partition; lower values show optimizer seed sensitivity on
    # that fixed graph. They do not establish data or model stability.
    # None when the Louvain path did not run (skipped / fallback), where
    # the partition is deterministic and the measure is not applicable.
    # Added 2.2.0; schema-additive.
    partition_stability: float | None = None
    stability_runs: int = 0


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
    # A source-level failure. The merger ignores all other payload fields when set.
    error: str | None = None
    detected_services: tuple[str, ...] = ()
    # Extended intel fields
    auth_type: str | None = None  # "Federated" or "Managed"
    dmarc_policy: str | None = None  # "reject", "quarantine", "none"
    tenant_domains: tuple[str, ...] = ()  # All domains in the tenant
    detected_slugs: tuple[str, ...] = ()  # Fingerprint slugs that matched
    # Domains linked by bounded public CNAME, autodiscover, or DKIM breadcrumbs
    # and absent from the Autodiscover tenant-domain list. This does not
    # establish common ownership.
    related_domains: tuple[str, ...] = ()

    # Stable source, collector-channel, or detector identifiers unavailable
    # during lookup.
    degraded_sources: tuple[str, ...] = ()

    cert_summary: CertSummary | None = None

    # --- Google Workspace & evidence fields ---
    evidence: tuple[EvidenceRecord, ...] = ()
    bimi_identity: BIMIIdentity | None = None
    site_verification_tokens: tuple[str, ...] = ()
    mta_sts_mode: str | None = None  # "enforce", "testing", "none"
    google_auth_type: str | None = None  # "Federated", "Managed"
    google_idp_name: str | None = None  # "Okta", "Ping Identity", etc.

    # --- Intelligence Amplification ---
    dmarc_pct: int | None = None  # DMARC pct= value (0-100)
    dmarc_testing: bool = False  # Internal RFC 9989 t=y signal; not stable JSON output.
    dmarc_np: str | None = None  # Internal RFC 9989 np= policy; not stable JSON output.
    raw_dns_records: tuple[tuple[str, str], ...] = ()  # (record_type, value) pairs for reevaluation cache
    # Maximum include: mechanism count observed across apex SPF records.
    # Stored as a typed collector scalar so extensible service names cannot
    # fabricate the signal by resembling the display label.
    spf_include_count: int = 0

    # --- CT provider attribution ---
    # Name of the CT provider ("crt.sh" or "certspotter") that actually
    # returned results for this lookup, and how many subdomains came back
    # after filtering. None when no CT provider was queried or all failed.
    ct_provider_used: str | None = None
    ct_subdomain_count: int = 0

    # --- CT cache fallback ---
    # When all live CT providers fail, the per-domain CT cache serves as
    # a fallback. ct_cache_age_days is set to the cache age when cached
    # data was used; None when data came from a live provider.
    ct_cache_age_days: int | None = None

    # --- CT attempt outcome ---
    # See ``TenantInfo.ct_attempt_outcome`` for the enum semantics. Set
    # by ``DNSSource`` when CT enumeration is attempted; None on sources
    # that do not touch CT.
    ct_attempt_outcome: str | None = None

    # --- OIDC tenant metadata enrichment ---
    # Extracted from the Microsoft OIDC discovery document when present.
    # Distinguish commercial M365, Government Community Cloud / GCC High,
    # Azure China 21Vianet, Azure B2C, and Azure External ID tenancies.
    # All three are None for non-Microsoft sources.
    cloud_instance: str | None = None  # e.g. "microsoftonline.com", "microsoftonline.us"
    tenant_region_sub_scope: str | None = None  # e.g. "GCC", "DOD", "USGov"
    msgraph_host: str | None = None  # e.g. "graph.microsoft.com", "graph.microsoft.us"

    # --- External surface attribution ---
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

    # --- CNAME chain motif observations ---
    # Each entry records a motif from data/motifs.yaml that fired on the
    # CNAME chain of a related subdomain — e.g. Cloudflare → AWS origin,
    # Akamai → Azure origin. Always populated; never claims ownership.
    chain_motifs: tuple[ChainMotifObservation, ...] = ()

    # --- CT co-occurrence clusters ---
    # Communities detected in the per-domain SAN co-occurrence graph.
    # Always populated when CT entries were available (may have an
    # empty ``clusters`` tuple when the graph was too small or trivial).
    # See ``recon_tool/infra_graph.py`` for the builder.
    infrastructure_clusters: InfrastructureClusterReport | None = None
    # True only when the source had no observation opportunity because of a
    # transport, protocol, or internal failure. A stable negative response uses
    # ``error`` with this flag false. The distinction prevents failed sources
    # from being interpreted as observed absence during merge and delta.
    source_unavailable: bool = False

    @property
    def crtsh_degraded(self) -> bool:
        """Backward-compatible: True when crt.sh was unreachable."""
        return "crt.sh" in self.degraded_sources

    @property
    def is_success(self) -> bool:
        """Whether the payload has useful data, independent of source-level error state."""
        return self.tenant_id is not None or self.m365_detected or len(self.detected_services) > 0

    @property
    def is_complete(self) -> bool:
        """True if this result has all core fields."""
        return all([self.tenant_id, self.display_name, self.default_domain])


@dataclass(frozen=True)
class TenantInfo:
    """Structured tenant information merged from one or more sources.

    ``tenant_id is None`` means no tenant identifier was observed. It is not a
    proof that no Microsoft tenant exists; collection status determines whether
    the field was observable.
    """

    # Optional because the identifier may be absent, unavailable, or outside
    # the bounded discovery response even when other public signals exist.
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
    related_domains: tuple[str, ...] = ()  # Domain names linked by bounded public breadcrumbs
    insights: tuple[str, ...] = ()  # Derived intelligence signals
    # Stable source, collector-channel, or detector identifiers unavailable
    # during lookup.
    degraded_sources: tuple[str, ...] = ()
    cert_summary: CertSummary | None = None

    # --- Google Workspace, evidence & confidence fields ---
    evidence: tuple[EvidenceRecord, ...] = ()
    evidence_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    inference_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    detection_scores: tuple[tuple[str, str], ...] = ()  # (slug, score) pairs
    bimi_identity: BIMIIdentity | None = None
    site_verification_tokens: tuple[str, ...] = ()
    mta_sts_mode: str | None = None  # "enforce", "testing", "none"
    google_auth_type: str | None = None  # "Federated", "Managed"
    google_idp_name: str | None = None  # "Okta", "Ping Identity", etc.

    # --- Intelligence Amplification ---
    primary_email_provider: str | None = None  # MX-detected provider name(s)
    email_gateway: str | None = None  # MX-detected gateway name
    dmarc_pct: int | None = None  # DMARC pct= value (0-100)
    dmarc_testing: bool = False  # Internal RFC 9989 t=y signal; not stable JSON output.
    # Typed apex-SPF collector scalar used by declarative signal evaluation.
    # It is internal reporting state, not a claim about SPF lookup expansion.
    spf_include_count: int = 0
    # Downstream provider inferred from non-MX evidence (DKIM, identity
    # endpoints, TXT tokens) when a gateway is present in MX but no
    # direct provider appears there. Hedged: "likely" in the name is
    # load-bearing. Never set when primary_email_provider is also set.
    likely_primary_email_provider: str | None = None

    # --- CT provider attribution ---
    # Which CT provider actually contributed subdomain data for this
    # lookup ("crt.sh" or "certspotter") and how many came back. Surfaced
    # in the panel bottom Note so enrichment asymmetry between runs is
    # visible. None when no CT provider succeeded.
    ct_provider_used: str | None = None
    ct_subdomain_count: int = 0

    # --- CT cache fallback ---
    # Age of the CT cache entry in days when cached data was used as a
    # fallback. None when data came from a live provider. Surfaced in the
    # panel as "from local cache, N days old".
    ct_cache_age_days: int | None = None

    # --- CT attempt outcome ---
    # Records WHY this lookup did or did not get CT data, independent of
    # whether cert_summary is populated. Without this field, a record with
    # cert_summary=None could mean "no certs in CT", "rate-limited", "open
    # breaker", "cache miss after live failure" -- all indistinguishable
    # in the JSON. Values:
    #   cache_hit          -- the cache-first short-circuit served the
    #                         result, no live provider was called.
    #   live_success       -- a live provider returned data, which was
    #                         used and also written to the cache.
    #   live_rate_limited  -- at least one provider hit HTTP 429 or local
    #                         pacing / max-wait limits, no live provider or
    #                         cache fallback returned data.
    #   breaker_open       -- every failed provider was stopped by an open
    #                         local breaker before a useful live attempt.
    #   live_other_failure -- at least one provider raised a non-429 error
    #                         (timeout, 5xx, JSON parse failure), no live
    #                         provider or cache fallback returned data.
    #   cache_miss         -- providers returned empty-but-not-error
    #                         (soft failure) and no cache entry existed.
    #   skipped            -- the caller explicitly set ``--no-ct`` so no
    #                         CT enumeration was attempted.
    ct_attempt_outcome: str | None = None

    # --- Staleness timestamps (ISO-8601 UTC) ---
    # resolved_at is when the live resolution produced this TenantInfo.
    # cached_at is when the on-disk cache entry was written; it is None
    # on a fresh resolve and set only when the result was served from
    # ``~/.recon/cache/``. Agents reading --json can compare the two to
    # decide whether to re-resolve.
    resolved_at: str | None = None
    cached_at: str | None = None

    # --- Bayesian fusion (stable v2.0+) ---
    # Per-slug evidence-strength score in [0, 1] from the additive Beta-shaped
    # heuristic. Not an externally calibrated probability.
    # Populated only when `--fusion` is passed. Empty otherwise.
    # Shape: ``[(slug, score), ...]``. Stable v2.0.
    slug_confidences: tuple[tuple[str, float], ...] = ()

    # --- Bayesian-network posteriors (stable v2.0+) ---
    # Model-relative posterior P(node=present | E) and 80% evidence-responsive
    # uncertainty band for each
    # node in the v1.9 Bayesian network. Populated only when
    # ``--fusion`` is passed. Empty otherwise. The Beta layer
    # (``slug_confidences``) and the network layer
    # (``posterior_observations``) coexist: Beta operates on raw
    # evidence weights, the network propagates through chained claims.
    # Stable v2.0; shape pinned by ``PosteriorObservation``.
    posterior_observations: tuple[PosteriorObservation, ...] = ()

    # --- OIDC tenant metadata enrichment ---
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

    # --- Shared verification token clustering (batch scope) ---
    # Populated only when a batch run observes the same site-verification
    # token on multiple domains. Each entry is a (token, peer_domain)
    # pair — one entry per peer that shares this token. Empty on single
    # lookups. Never persisted to disk cache (batch scope only).
    shared_verification_tokens: tuple[tuple[str, str], ...] = ()

    # --- CT lexical taxonomy (pure rule-based) ---
    # Hedged observations derived from recognised environment / region /
    # tenancy-shard prefixes on CT-discovered subdomains. Empty when
    # fewer than the minimum number of matching subdomains are observed.
    lexical_observations: tuple[str, ...] = ()

    # --- Conflict-aware merge ---
    merge_conflicts: MergeConflicts | None = None

    # --- External surface attribution ---
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

    # --- CNAME chain motif observations ---
    # Each entry records a motif from data/motifs.yaml that fired on the
    # CNAME chain of a related subdomain — e.g. Cloudflare → AWS origin,
    # Akamai → Azure origin. Always populated; never claims ownership.
    chain_motifs: tuple[ChainMotifObservation, ...] = ()

    # --- CT co-occurrence clusters ---
    # Communities detected over the per-domain certificate SAN co-occurrence
    # graph. The report carries the cluster list, the modularity score, and
    # the algorithm path that produced it ("louvain" | "connected_components"
    # | "skipped"). None when CT data was unavailable.
    infrastructure_clusters: InfrastructureClusterReport | None = None

    @property
    def crtsh_degraded(self) -> bool:
        """Backward-compatible: True when crt.sh was unreachable."""
        return "crt.sh" in self.degraded_sources


@dataclass(frozen=True)
class DeltaComparisonIncomplete:
    """Why a delta could not safely compare every field."""

    # Union retained for compatibility with the first additive diagnostic.
    degraded_sources: tuple[str, ...]
    suppressed_fields: tuple[str, ...]
    previous_degraded_sources: tuple[str, ...] = ()
    current_degraded_sources: tuple[str, ...] = ()


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
    incomplete_comparison: DeltaComparisonIncomplete | None = None

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
