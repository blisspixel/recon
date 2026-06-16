"""Result dataclasses for the exposure assessment.

Pure frozen dataclasses (the EmailPosture / IdentityPosture / ExposureAssessment /
GapReport / PostureComparison family), split out of exposure.py so the analysis
logic stays under the file-size cap. No logic, no imports beyond the dataclass
decorator. `recon_tool.exposure` re-exports every name so existing imports are
unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    certificate_authorities: tuple[str, ...]
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
    # channel cannot confirm (DKIM at non-standard selectors, security tooling,
    # an email gateway behind non-MX routing). The true posture may be this much
    # higher. Declarative-record absence (DMARC/MTA-STS/TLS-RPT/CAA) is genuine
    # and is not counted here. See the "Reading the exposure score" MCP note and
    # docs/correlation.md on the hideability spectrum.
    unconfirmable_absent_points: int = 0


@dataclass(frozen=True)
class HardeningGap:
    """A single hardening gap with category, severity, and guidance."""

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


@dataclass(frozen=True)
class GapReport:
    """Complete gap analysis report for a domain."""

    domain: str
    gaps: tuple[HardeningGap, ...]
    disclaimer: str


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

