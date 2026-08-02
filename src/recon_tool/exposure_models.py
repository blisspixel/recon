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
ExposureIndexState: TypeAlias = Literal[
    "observed_value",
    "observed_empty",
    "unresolved",
    "unavailable",
    "hypothetical_value",
]
ExposureMetadataValue: TypeAlias = str | int | bool | None
ExposureMetadataOperator: TypeAlias = Literal["eq", "neq", "is_none"]

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
_EXPOSURE_INDEX_STATES = frozenset(
    {
        "observed_value",
        "observed_empty",
        "unresolved",
        "unavailable",
        "hypothetical_value",
    }
)
_EXPOSURE_METADATA_FIELDS = frozenset(
    {
        "auth_type",
        "bimi_record_observed",
        "caa_record_observed",
        "dkim_observed_at_common_selectors",
        "dmarc_construction_state",
        "dmarc_policy",
        "effective_dmarc_policy",
        "email_gateway",
        "gateway_mx_observed",
        "mta_sts_mode",
        "spf_strict_observed",
        "tls_rpt_record_observed",
    }
)
DMARC_COMPONENT_ID = "index.email.dmarc.v1"
DKIM_COMPONENT_ID = "index.email.dkim.v1"
SPF_COMPONENT_ID = "index.email.spf-strict.v1"
MTA_STS_COMPONENT_ID = "index.email.mta-sts.v1"
BIMI_COMPONENT_ID = "index.email.bimi.v1"
TLS_RPT_COMPONENT_ID = "index.email.tls-rpt.v1"
CAA_COMPONENT_ID = "index.infrastructure.caa.v1"
FEDERATED_IDENTITY_COMPONENT_ID = "index.identity.federation.v1"
EMAIL_GATEWAY_COMPONENT_ID = "index.email.gateway.v1"
DMARC_QUARANTINE_POINTS = 12
MTA_STS_TESTING_POINTS = 8
EXPOSURE_COMPONENT_SPECS: tuple[tuple[str, str, int], ...] = (
    (DMARC_COMPONENT_ID, "DMARC", 20),
    (DKIM_COMPONENT_ID, "DKIM", 15),
    (SPF_COMPONENT_ID, "SPF strict policy", 10),
    (MTA_STS_COMPONENT_ID, "MTA-STS", 15),
    (BIMI_COMPONENT_ID, "BIMI", 5),
    (TLS_RPT_COMPONENT_ID, "TLS-RPT", 5),
    (CAA_COMPONENT_ID, "CAA", 5),
    (FEDERATED_IDENTITY_COMPONENT_ID, "Federated identity", 10),
    (EMAIL_GATEWAY_COMPONENT_ID, "Email gateway", 5),
)
EXPOSURE_COMPONENT_IDS = frozenset(component_id for component_id, _, _ in EXPOSURE_COMPONENT_SPECS)
_EXPOSURE_COMPONENT_SPEC_BY_ID = {
    component_id: (control, maximum_points) for component_id, control, maximum_points in EXPOSURE_COMPONENT_SPECS
}
_EXPOSURE_UNAVAILABLE_LABELS = {SPF_COMPONENT_ID: "SPF"}


def exposure_component_spec(component_id: str) -> tuple[str, int]:
    """Return the canonical display name and weight for one index component."""
    try:
        return _EXPOSURE_COMPONENT_SPEC_BY_ID[component_id]
    except KeyError as exc:
        raise ValueError(f"unsupported exposure-index component ID: {component_id}") from exc


# ── Data models (all frozen) ───────────────────────────────────────────


@dataclass(frozen=True)
class EvidenceReference:
    """Links an observation to the specific evidence that supports it."""

    source_type: str  # "TXT", "MX", "CNAME", etc.
    raw_value: str  # The actual record value
    rule_name: str  # Detection rule that matched
    slug: str  # Fingerprint slug


@dataclass(frozen=True)
class ExposureMetadataDependency:
    """One typed scalar predicate captured when an index rule is evaluated."""

    field: str
    operator: ExposureMetadataOperator
    expected_value: ExposureMetadataValue
    observed_value: ExposureMetadataValue

    def __post_init__(self) -> None:
        if self.field not in _EXPOSURE_METADATA_FIELDS:
            raise ValueError(f"unsupported exposure metadata dependency field: {self.field}")
        if self.operator not in {"eq", "neq", "is_none"}:
            raise ValueError(f"unsupported exposure metadata operator: {self.operator}")
        if self.operator == "is_none" and self.expected_value is not None:
            raise ValueError("is_none exposure dependencies must expect null")


def exposure_metadata_predicate_satisfied(dependency: ExposureMetadataDependency) -> bool:
    """Evaluate a captured exposure predicate without consulting live state."""
    if dependency.operator == "is_none":
        return dependency.observed_value is None
    equal = type(dependency.expected_value) is type(dependency.observed_value) and (
        dependency.expected_value == dependency.observed_value
    )
    return equal if dependency.operator == "eq" else not equal


@dataclass(frozen=True)
class ExposureIndexComponent:
    """One weighted index rule with its exact generation-time proof state."""

    component_id: str
    control: str
    state: ExposureIndexState
    awarded_points: int
    maximum_points: int
    generator_rule_id: str
    metadata_dependencies: tuple[ExposureMetadataDependency, ...]
    observation_scope: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        if not self.component_id or self.generator_rule_id != self.component_id:
            raise ValueError("exposure-index component and generator IDs must be the same non-empty value")
        if self.state not in _EXPOSURE_INDEX_STATES:
            raise ValueError(f"unsupported exposure-index state: {self.state}")
        if self.maximum_points <= 0 or not 0 <= self.awarded_points <= self.maximum_points:
            raise ValueError("exposure-index points must satisfy 0 <= awarded <= positive maximum")
        if not self.metadata_dependencies:
            raise ValueError("exposure-index component requires at least one metadata dependency")
        if not all(exposure_metadata_predicate_satisfied(item) for item in self.metadata_dependencies):
            raise ValueError("exposure-index component contains an unsatisfied metadata dependency")
        if not self.observation_scope or any(not scope for scope in self.observation_scope):
            raise ValueError("exposure-index component requires non-empty observation scopes")
        if self.awarded_points > 0 and not self.evidence:
            raise ValueError("positive exposure-index credit requires retained evidence")
        if self.state in {"observed_value", "hypothetical_value"} and not self.evidence:
            raise ValueError(f"{self.state} exposure-index component requires retained evidence")
        if self.state == "unavailable" and self.awarded_points:
            raise ValueError("unavailable exposure-index component cannot award points")
        if self.state == "unavailable" and self.evidence:
            raise ValueError("unavailable exposure-index component cannot retain evidence")
        if self.state in {"observed_empty", "unresolved"} and self.awarded_points:
            raise ValueError(f"{self.state} exposure-index component cannot award points")
        if self.state == "observed_empty" and self.evidence:
            raise ValueError("observed-empty exposure-index component cannot retain positive evidence")

    @property
    def unconfirmable_points(self) -> int:
        """Return capacity not fixed by an exact current component value."""
        if self.state in {"unavailable", "unresolved"}:
            return self.maximum_points - self.awarded_points
        return 0


@dataclass(frozen=True)
class ExposureIndex:
    """Validated component ledger for one model-bound public-evidence index."""

    components: tuple[ExposureIndexComponent, ...]

    def __post_init__(self) -> None:
        component_ids = tuple(component.component_id for component in self.components)
        if not component_ids or len(component_ids) != len(set(component_ids)):
            raise ValueError("exposure index requires distinct component IDs")
        if frozenset(component_ids) != EXPOSURE_COMPONENT_IDS:
            raise ValueError("exposure index requires the complete weighted component set")
        expected_order = tuple(component_id for component_id, _, _ in EXPOSURE_COMPONENT_SPECS)
        if component_ids != expected_order:
            raise ValueError("exposure index requires canonical component order")
        for component in self.components:
            expected_control, expected_maximum = exposure_component_spec(component.component_id)
            if (component.control, component.maximum_points) != (expected_control, expected_maximum):
                raise ValueError(f"exposure-index component specification differs from {component.component_id}")
        if self.model_maximum_points > 100:
            raise ValueError("exposure-index component maxima cannot exceed 100 points")

    @property
    def score_floor(self) -> int:
        """Return the points supported by exact observed or hypothetical evidence."""
        return sum(component.awarded_points for component in self.components)

    @property
    def unconfirmable_absent_points(self) -> int:
        """Return compatibility capacity from unresolved or unavailable states."""
        return sum(component.unconfirmable_points for component in self.components)

    @property
    def score_ceiling(self) -> int:
        """Return the bounded model ceiling for this observation state."""
        return min(100, self.score_floor + self.unconfirmable_absent_points)

    @property
    def model_maximum_points(self) -> int:
        """Return the maximum points assigned by the current component model."""
        return sum(component.maximum_points for component in self.components)

    @property
    def unavailable_controls(self) -> tuple[str, ...]:
        """Return every component whose observation channel was unavailable."""
        return tuple(
            _EXPOSURE_UNAVAILABLE_LABELS.get(component.component_id, component.control)
            for component in self.components
            if component.state == "unavailable"
        )


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
    # Compatibility name retained from the original lower-bound envelope. The
    # value now includes every component whose current value remains unresolved
    # or unavailable, including narrow public scopes, collection failures, and
    # inconsistent retained evidence.
    unconfirmable_absent_points: int = 0
    # Names of controls whose collection channel failed. This distinguishes an
    # unobserved value from an observed negative in structured output.
    unavailable_controls: tuple[str, ...] = ()
    # Appended after the original defaulted fields so positional construction
    # from earlier 2.x releases keeps its meaning.
    index_components: tuple[ExposureIndexComponent, ...] = ()

    def __post_init__(self) -> None:
        if not self.index_components:
            return
        index = ExposureIndex(self.index_components)
        if self.posture_score != index.score_floor:
            raise ValueError("posture score differs from its exposure-index component ledger")
        if self.unconfirmable_absent_points != index.unconfirmable_absent_points:
            raise ValueError("exposure observability total differs from its component ledger")
        if self.unavailable_controls != index.unavailable_controls:
            raise ValueError("exposure unavailable controls differ from the component ledger")


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
    domain_a_index_components: tuple[ExposureIndexComponent, ...] = ()
    domain_b_index_components: tuple[ExposureIndexComponent, ...] = ()
    domain_a_unavailable_controls: tuple[str, ...] = ()
    domain_b_unavailable_controls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not any(
            (
                self.domain_a_index_components,
                self.domain_b_index_components,
                self.domain_a_unavailable_controls,
                self.domain_b_unavailable_controls,
            )
        ):
            return
        if not self.domain_a_index_components or not self.domain_b_index_components:
            raise ValueError("posture comparison requires both component ledgers")
        index_a = ExposureIndex(self.domain_a_index_components)
        index_b = ExposureIndex(self.domain_b_index_components)
        if self.domain_a_unavailable_controls != index_a.unavailable_controls:
            raise ValueError("domain A unavailable controls differ from its component ledger")
        if self.domain_b_unavailable_controls != index_b.unavailable_controls:
            raise ValueError("domain B unavailable controls differ from its component ledger")
