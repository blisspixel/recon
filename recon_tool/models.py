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
    "TenantInfo",
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

    # --- Conflict-aware merge (v0.7.0) ---
    merge_conflicts: MergeConflicts | None = None

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
    """

    domain: str
    message: str
    error_type: str

    def __str__(self) -> str:
        return self.message
