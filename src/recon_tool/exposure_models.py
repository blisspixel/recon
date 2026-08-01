"""Result models and narrow lineage validation for exposure assessment.

The frozen EmailPosture, IdentityPosture, ExposureAssessment, GapReport, and
PostureComparison families live here to keep exposure.py below its file-size
cap. Hardening models also validate their transient proof state at construction.
Established result names remain re-exported from ``recon_tool.exposure``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeAlias

HardeningObservationState: TypeAlias = Literal[
    "observed_weak_configuration",
    "bounded_non_observation",
    "unresolved_hideable_state",
    "observed_configuration_inconsistency",
]
HardeningMetadataValue: TypeAlias = str | int | bool | None
HardeningMetadataOperator: TypeAlias = Literal["eq", "neq", "is_none"]

_HARDENING_OBSERVATION_STATES = frozenset(
    {
        "observed_weak_configuration",
        "bounded_non_observation",
        "unresolved_hideable_state",
        "observed_configuration_inconsistency",
    }
)
_HARDENING_METADATA_FIELDS = frozenset(
    {
        "dmarc_policy",
        "effective_dmarc_policy",
        "dmarc_construction_state",
        "dkim_observed_at_common_selectors",
        "mta_sts_mode",
        "mta_sts_txt_observed",
        "tls_rpt_record_observed",
        "caa_record_observed",
        "spf_softfail_observed",
        "spf_strict_observed",
        "gateway_mx_observed",
        "email_gateway",
    }
)

# ── Data models (all frozen) ───────────────────────────────────────────


@dataclass(frozen=True)
class EvidenceReference:
    """Links an observation to the specific evidence that supports it."""

    source_type: str  # "TXT", "MX", "CNAME", etc.
    raw_value: str  # The actual record value
    rule_name: str  # Detection rule that matched
    slug: str  # Fingerprint slug


@dataclass(frozen=True)
class EmailPosture:
    """Email security configuration posture."""

    dmarc_policy: str | None
    dkim_configured: bool
    spf_strict: bool
    mta_sts_mode: str | None
    email_gateway: str | None
    bimi_configured: bool
    email_security_score: int  # 0–5
    evidence: tuple[EvidenceReference, ...]


@dataclass(frozen=True)
class IdentityPosture:
    """Identity and authentication posture."""

    auth_type: str | None
    # Named only when an explicit federation response identifies the provider;
    # generic DNS verification fingerprints do not populate this field.
    identity_provider: str | None
    google_auth_type: str | None
    google_idp_name: str | None
    evidence: tuple[EvidenceReference, ...]


@dataclass(frozen=True)
class InfrastructureFootprint:
    """Infrastructure and hosting footprint."""

    cloud_providers: tuple[str, ...]
    dns_provider: str | None
    cdn_waf: tuple[str, ...]
    certificate_authorities: tuple[str, ...]  # Issuers authorized by observed CAA records.
    evidence: tuple[EvidenceReference, ...]


@dataclass(frozen=True)
class ConsistencyObservation:
    """A neutral factual observation about configuration consistency."""

    observation: str
    category: str  # "dual_provider", "file_sharing", "consumer_saas"
    evidence: tuple[EvidenceReference, ...]


@dataclass(frozen=True)
class HardeningControl:
    """A single hardening control and its status."""

    name: str
    present: bool
    detail: str
    evidence: tuple[EvidenceReference, ...]


@dataclass(frozen=True)
class HardeningStatus:
    """Collection of hardening controls."""

    controls: tuple[HardeningControl, ...]


@dataclass(frozen=True)
class HardeningMetadataDependency:
    """One typed scalar predicate captured when a hardening rule fires."""

    field: str
    operator: HardeningMetadataOperator
    expected_value: HardeningMetadataValue
    observed_value: HardeningMetadataValue

    def __post_init__(self) -> None:
        if self.field not in _HARDENING_METADATA_FIELDS:
            raise ValueError(f"unsupported hardening metadata dependency field: {self.field}")
        if self.operator not in {"eq", "neq", "is_none"}:
            raise ValueError(f"unsupported hardening metadata operator: {self.operator}")
        if self.operator == "is_none" and self.expected_value is not None:
            raise ValueError("is_none hardening dependencies must expect null")


def hardening_metadata_predicate_satisfied(dependency: HardeningMetadataDependency) -> bool:
    """Evaluate a captured hardening predicate without consulting live state."""
    if dependency.operator == "is_none":
        return dependency.observed_value is None
    equal = type(dependency.expected_value) is type(dependency.observed_value) and (
        dependency.expected_value == dependency.observed_value
    )
    return equal if dependency.operator == "eq" else not equal


@dataclass(frozen=True)
class ExposureAssessment:
    """Complete exposure assessment for a domain."""

    domain: str
    email_posture: EmailPosture
    identity_posture: IdentityPosture
    infrastructure_footprint: InfrastructureFootprint
    consistency_observations: tuple[ConsistencyObservation, ...]
    hardening_status: HardeningStatus
    posture_score: int  # 0–100
    posture_score_label: str
    disclaimer: str
    evidence: tuple[EvidenceReference, ...]
    # The score counts only observed-present controls, so it is a *lower bound*:
    # this is how many points come from controls whose absence the passive
    # channel cannot confirm (DKIM at non-standard selectors or an email gateway
    # hidden behind non-MX routing). Generic vendor indicators receive no control
    # credit. The true posture may be this much
    # higher. Declarative-record absence is genuine when collection succeeded;
    # an unavailable DMARC or MTA-STS channel contributes its full weight to
    # this ceiling instead. See the "Reading the exposure score" MCP note and
    # docs/correlation.md.
    unconfirmable_absent_points: int = 0
    # Names of controls whose collection channel failed. This distinguishes an
    # unobserved value from an observed negative in structured output.
    unavailable_controls: tuple[str, ...] = ()


@dataclass(frozen=True)
class HardeningGap:
    """A review prompt with its exact transient generation-time basis.

    The original display fields and ``absence_confirmable`` remain compatible.
    The additive lineage fields distinguish direct weak observations, bounded
    non-observations, hideable states, and compound inconsistencies. Formatters
    expose them so an MCP consumer does not have to infer provenance from prose.
    """

    category: str  # "email", "identity", "infrastructure", "consistency"
    severity: str  # "high", "medium", "low"
    observation: str
    recommendation: str
    evidence: tuple[EvidenceReference, ...]
    # True when the gap is a confirmed public-records fact (a declarative record
    # is absent or observed-weak). False when the gap rests on *not observing* a
    # hideable control (DKIM at non-standard selectors, security tooling), so it
    # may be a false positive — the control could be present but unobservable
    # from the passive channel. Absence is not disproof (the MNAR rule).
    absence_confirmable: bool = True
    generator_rule_id: str = ""
    observation_state: HardeningObservationState | None = None
    metadata_dependencies: tuple[HardeningMetadataDependency, ...] = ()
    observation_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        lineage_present = bool(
            self.generator_rule_id or self.observation_state or self.metadata_dependencies or self.observation_scope
        )
        if not lineage_present:
            return
        if not self.generator_rule_id:
            raise ValueError("hardening lineage requires a generator rule ID")
        if self.observation_state is None:
            raise ValueError("hardening lineage requires an observation state")
        if self.observation_state not in _HARDENING_OBSERVATION_STATES:
            raise ValueError(f"unsupported hardening observation state: {self.observation_state}")
        if not self.metadata_dependencies:
            raise ValueError("hardening lineage requires at least one metadata dependency")
        if not self.observation_scope or any(not scope for scope in self.observation_scope):
            raise ValueError("hardening lineage requires non-empty observation scopes")
        if not all(hardening_metadata_predicate_satisfied(item) for item in self.metadata_dependencies):
            raise ValueError("hardening lineage contains an unsatisfied metadata dependency")
        if self.observation_state == "unresolved_hideable_state" and self.absence_confirmable:
            raise ValueError("a hideable hardening state cannot confirm absence")
        if self.observation_state == "bounded_non_observation" and not self.absence_confirmable:
            raise ValueError("a bounded non-observation must retain its compatibility confirmation flag")


@dataclass(frozen=True)
class GapReport:
    """Complete gap analysis report for a domain."""

    domain: str
    gaps: tuple[HardeningGap, ...]
    disclaimer: str
    unavailable_controls: tuple[str, ...] = ()
    degraded_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class PostureMetric:
    """A single side-by-side metric for posture comparison."""

    metric_name: str
    domain_a_value: str
    domain_b_value: str


@dataclass(frozen=True)
class PostureDifference:
    """A control or service present in one domain but not the other."""

    description: str
    domain_a_has: bool
    domain_b_has: bool


@dataclass(frozen=True)
class RelativeAssessment:
    """Relative posture assessment along a single dimension."""

    dimension: str
    summary: str


@dataclass(frozen=True)
class PostureComparison:
    """Side-by-side posture comparison of two domains."""

    domain_a: str
    domain_b: str
    metrics: tuple[PostureMetric, ...]
    differences: tuple[PostureDifference, ...]
    relative_assessment: tuple[RelativeAssessment, ...]
    disclaimer: str
