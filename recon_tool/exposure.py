"""Defensive security exposure assessment — pure analysis of resolved domain data.

This module synthesizes existing TenantInfo data into structured security
posture views for defensive review, vendor due diligence, and security
architecture planning. All functions are pure (no I/O, no network calls)
and operate exclusively on frozen dataclasses from the existing pipeline.

All output uses neutral, defensive language. The extended BANNED_TERMS set
is enforced at construction time to prevent offensive or prescriptive
language from appearing in any output field. Observations describe what
IS configured, not what SHOULD be configured. Gaps use "Consider ..."
language rather than imperative directives.

This module imports only from recon_tool.models and recon_tool.constants —
never from httpx, dns.resolver, or any LookupSource.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.models import TenantInfo
from recon_tool.posture import BANNED_TERMS

logger = logging.getLogger(__name__)

# ── Banned terms ────────────────────────────────────────────────────────

EXPOSURE_BANNED_TERMS: frozenset[str] = BANNED_TERMS | frozenset(
    {
        "target",
        "attack surface",
        "vulnerabilities to exploit",
        "finding",
        "remediation",
    }
)

# Module-level strict mode flag — True by default (raises ValueError).
# Production code can set this to False for graceful degradation.
_STRICT_MODE: bool = True


# ── Slug classification maps ───────────────────────────────────────────

_CLOUD_PROVIDER_SLUGS: dict[str, str] = {
    "aws-route53": "AWS",
    "aws-cloudfront": "AWS",
    "aws-elb": "AWS",
    "aws-s3": "AWS",
    "azure-dns": "Azure",
    "azure-cdn": "Azure",
    "azure-appservice": "Azure",
    "azure-fd": "Azure",
    "gcp-dns": "GCP",
    "gcp-app": "GCP",
}

_CDN_WAF_SLUGS: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "imperva": "Imperva",
}

_DNS_PROVIDER_SLUGS: dict[str, str] = {
    "aws-route53": "AWS Route 53",
    "azure-dns": "Azure DNS",
    "gcp-dns": "Google Cloud DNS",
    "cloudflare": "Cloudflare",
}

_CA_SLUGS: dict[str, str] = {
    "letsencrypt": "Let's Encrypt",
    "digicert": "DigiCert",
    "sectigo": "Sectigo",
    "aws-acm": "AWS ACM",
    "google-trust": "Google Trust",
    "globalsign": "GlobalSign",
}

_SECURITY_TOOL_SLUGS: frozenset[str] = frozenset(
    {
        "crowdstrike",
        "knowbe4",
        "proofpoint",
        "mimecast",
        "zscaler",
        "paloalto",
        "wiz",
        "sophos",
        "sentinelone",
        "netskope",
        "okta",
        "auth0",
        "duo",
        "1password",
        "cyberark",
        "cato",
        "onelogin",
        "imperva",
    }
)

_EMAIL_GATEWAY_SLUGS: dict[str, str] = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "trendmicro": "Trend Micro",
    "symantec": "Symantec/Broadcom",
    "trellix": "Trellix (FireEye)",
}

_CONSUMER_SAAS_SLUGS: frozenset[str] = frozenset(
    {
        "canva",
        "dropbox",
        "mailchimp",
        "zoom",
        "airtable",
        "notion",
        "monday",
        "clickup",
        "loom",
    }
)

_IDP_SLUGS: dict[str, str] = {
    "okta": "Okta",
    "auth0": "Auth0",
    "duo": "Duo",
    "1password": "1Password",
    "cyberark": "CyberArk",
    "onelogin": "OneLogin",
}


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


@dataclass(frozen=True)
class HardeningGap:
    """A single hardening gap with category, severity, and guidance."""

    category: str  # "email", "identity", "infrastructure", "consistency"
    severity: str  # "high", "medium", "low"
    observation: str
    recommendation: str
    evidence: tuple[EvidenceReference, ...]


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


# ── Helper functions ───────────────────────────────────────────────────


def _enforce_banned_terms(text: str) -> str:
    """Validate that text contains no banned terms.

    In strict mode (tests), raises ValueError on violation.
    In production mode, logs a warning and returns the text unchanged.
    """
    lower = text.lower()
    for term in EXPOSURE_BANNED_TERMS:
        if term in lower:
            if _STRICT_MODE:
                msg = f"Banned term '{term}' found in output: {text!r}"
                raise ValueError(msg)
            logger.warning("Banned term '%s' found in output: %s", term, text)
    return text


def _build_evidence_refs(info: TenantInfo, slugs: frozenset[str] | set[str]) -> tuple[EvidenceReference, ...]:
    """Build EvidenceReference entries from TenantInfo.evidence matching given slugs."""
    refs: list[EvidenceReference] = []
    for ev in info.evidence:
        if ev.slug in slugs:
            refs.append(
                EvidenceReference(
                    source_type=ev.source_type,
                    raw_value=ev.raw_value,
                    rule_name=ev.rule_name,
                    slug=ev.slug,
                )
            )
    return tuple(refs)


def _compute_email_security_score(info: TenantInfo) -> int:
    """Compute email security score (0–5) matching existing insights.py logic."""
    score_services = {SVC_DMARC, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
    return min(sum(1 for svc in info.services if svc in score_services), 5)


# ── Internal posture computation ───────────────────────────────────────


def _compute_email_posture(info: TenantInfo) -> EmailPosture:
    """Derive email security posture from TenantInfo."""
    services_set = set(info.services)
    slugs_set = set(info.slugs)

    dkim_configured = SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set
    spf_strict = SVC_SPF_STRICT in services_set
    bimi_configured = SVC_BIMI in services_set

    # Detect email gateway
    gateway: str | None = None
    for slug, name in _EMAIL_GATEWAY_SLUGS.items():
        if slug in slugs_set:
            gateway = name
            break

    # Collect relevant slugs for evidence
    relevant_slugs: set[str] = set()
    if info.dmarc_policy is not None:
        relevant_slugs.add("dmarc")
    if dkim_configured:
        relevant_slugs.update(slugs_set & {"dkim", "dkim-exchange"})
    if spf_strict:
        relevant_slugs.add("spf-strict")
    if bimi_configured:
        relevant_slugs.add("bimi")
    if info.mta_sts_mode is not None:
        relevant_slugs.add("mta-sts")
        if info.mta_sts_mode == "enforce":
            relevant_slugs.add("mta-sts-enforce")
    if gateway:
        relevant_slugs.update(slugs_set & set(_EMAIL_GATEWAY_SLUGS.keys()))
    # Also include any TLS-RPT evidence
    if "tls-rpt" in slugs_set:
        relevant_slugs.add("tls-rpt")

    evidence = _build_evidence_refs(info, relevant_slugs)

    return EmailPosture(
        dmarc_policy=info.dmarc_policy,
        dkim_configured=dkim_configured,
        spf_strict=spf_strict,
        mta_sts_mode=info.mta_sts_mode,
        email_gateway=gateway,
        bimi_configured=bimi_configured,
        email_security_score=_compute_email_security_score(info),
        evidence=evidence,
    )


def _compute_identity_posture(info: TenantInfo) -> IdentityPosture:
    """Derive identity posture from TenantInfo."""
    slugs_set = set(info.slugs)

    # Detect identity provider from slugs
    idp: str | None = None
    for slug, name in _IDP_SLUGS.items():
        if slug in slugs_set:
            idp = name
            break

    relevant_slugs: set[str] = set()
    if idp:
        relevant_slugs.update(slugs_set & set(_IDP_SLUGS.keys()))
    if info.auth_type == "Federated":
        relevant_slugs.add("microsoft365")
    if info.google_auth_type is not None:
        relevant_slugs.add("google-workspace")

    evidence = _build_evidence_refs(info, relevant_slugs)

    return IdentityPosture(
        auth_type=info.auth_type,
        identity_provider=idp,
        google_auth_type=info.google_auth_type,
        google_idp_name=info.google_idp_name,
        evidence=evidence,
    )


def _compute_infrastructure_footprint(info: TenantInfo) -> InfrastructureFootprint:
    """Derive infrastructure footprint from TenantInfo."""
    slugs_set = set(info.slugs)

    # Cloud providers (deduplicated by provider name)
    cloud_names: set[str] = set()
    for slug, name in _CLOUD_PROVIDER_SLUGS.items():
        if slug in slugs_set:
            cloud_names.add(name)
    cloud_providers = tuple(sorted(cloud_names))

    # DNS provider
    dns_provider: str | None = None
    for slug, name in _DNS_PROVIDER_SLUGS.items():
        if slug in slugs_set:
            dns_provider = name
            break

    # CDN/WAF
    cdn_names: list[str] = []
    for slug, name in _CDN_WAF_SLUGS.items():
        if slug in slugs_set:
            cdn_names.append(name)
    cdn_waf = tuple(sorted(cdn_names))

    # Certificate authorities
    ca_names: list[str] = []
    for slug, name in _CA_SLUGS.items():
        if slug in slugs_set:
            ca_names.append(name)
    certificate_authorities = tuple(sorted(ca_names))

    # Evidence from all infrastructure slugs
    relevant_slugs = slugs_set & (
        set(_CLOUD_PROVIDER_SLUGS.keys())
        | set(_DNS_PROVIDER_SLUGS.keys())
        | set(_CDN_WAF_SLUGS.keys())
        | set(_CA_SLUGS.keys())
    )
    evidence = _build_evidence_refs(info, relevant_slugs)

    return InfrastructureFootprint(
        cloud_providers=cloud_providers,
        dns_provider=dns_provider,
        cdn_waf=cdn_waf,
        certificate_authorities=certificate_authorities,
        evidence=evidence,
    )


def _compute_consistency_observations(info: TenantInfo) -> tuple[ConsistencyObservation, ...]:
    """Derive configuration consistency observations from TenantInfo."""
    slugs_set = set(info.slugs)
    observations: list[ConsistencyObservation] = []

    # Dual email provider detection
    has_exchange = "microsoft365" in slugs_set
    has_google = "google-workspace" in slugs_set
    if has_exchange and has_google:
        obs = _enforce_banned_terms("Both Microsoft 365 and Google Workspace email services detected")
        evidence = _build_evidence_refs(info, {"microsoft365", "google-workspace"})
        observations.append(ConsistencyObservation(observation=obs, category="dual_provider", evidence=evidence))

    # Consumer SaaS alongside enterprise security
    consumer_present = slugs_set & _CONSUMER_SAAS_SLUGS
    security_present = slugs_set & _SECURITY_TOOL_SLUGS
    if consumer_present and not security_present:
        consumer_names = sorted(consumer_present)
        obs = _enforce_banned_terms(
            f"Consumer-grade SaaS detected ({', '.join(consumer_names)}) without enterprise security controls"
        )
        evidence = _build_evidence_refs(info, consumer_present)
        observations.append(ConsistencyObservation(observation=obs, category="consumer_saas", evidence=evidence))

    return tuple(observations)


def _compute_hardening_status(info: TenantInfo) -> HardeningStatus:
    """Derive hardening control status from TenantInfo."""
    services_set = set(info.services)
    slugs_set = set(info.slugs)
    controls: list[HardeningControl] = []

    # DMARC enforcement
    if info.dmarc_policy == "reject":
        detail = "reject"
    elif info.dmarc_policy == "quarantine":
        detail = "quarantine"
    elif info.dmarc_policy == "none":
        detail = "policy set to none"
    else:
        detail = "not configured"
    dmarc_present = info.dmarc_policy is not None
    controls.append(
        HardeningControl(
            name="DMARC",
            present=dmarc_present,
            detail=detail,
            evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set) if dmarc_present else (),
        )
    )

    # DKIM
    dkim_present = SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set
    controls.append(
        HardeningControl(
            name="DKIM",
            present=dkim_present,
            detail="configured" if dkim_present else "not configured",
            evidence=_build_evidence_refs(info, slugs_set & {"dkim", "dkim-exchange"}) if dkim_present else (),
        )
    )

    # MTA-STS
    mta_present = info.mta_sts_mode is not None
    mta_detail = info.mta_sts_mode if mta_present else "not configured"
    controls.append(
        HardeningControl(
            name="MTA-STS",
            present=mta_present,
            detail=mta_detail or "not configured",
            evidence=_build_evidence_refs(info, {"mta-sts", "mta-sts-enforce"} & slugs_set) if mta_present else (),
        )
    )

    # BIMI
    bimi_present = SVC_BIMI in services_set
    controls.append(
        HardeningControl(
            name="BIMI",
            present=bimi_present,
            detail="configured" if bimi_present else "not configured",
            evidence=_build_evidence_refs(info, {"bimi"} & slugs_set) if bimi_present else (),
        )
    )

    # TLS-RPT
    tls_rpt_present = "tls-rpt" in slugs_set
    controls.append(
        HardeningControl(
            name="TLS-RPT",
            present=tls_rpt_present,
            detail="configured" if tls_rpt_present else "not configured",
            evidence=_build_evidence_refs(info, {"tls-rpt"}) if tls_rpt_present else (),
        )
    )

    # CAA records
    caa_present = bool(slugs_set & set(_CA_SLUGS.keys()))
    controls.append(
        HardeningControl(
            name="CAA",
            present=caa_present,
            detail="configured" if caa_present else "not configured",
            evidence=_build_evidence_refs(info, slugs_set & set(_CA_SLUGS.keys())) if caa_present else (),
        )
    )

    return HardeningStatus(controls=tuple(controls))


def _compute_posture_score(
    email: EmailPosture,
    identity: IdentityPosture,
    infra: InfrastructureFootprint,
    hardening: HardeningStatus,
    info: TenantInfo,
) -> int:
    """Compute weighted posture score (0–100) from observable controls."""
    slugs_set = set(info.slugs)
    score = 0

    # DMARC: reject=20, quarantine=12 (mutually exclusive)
    if email.dmarc_policy == "reject":
        score += 20
    elif email.dmarc_policy == "quarantine":
        score += 12

    # DKIM: 15
    if email.dkim_configured:
        score += 15

    # SPF strict: 10
    if email.spf_strict:
        score += 10

    # MTA-STS: enforce=15, testing=8 (mutually exclusive)
    if email.mta_sts_mode == "enforce":
        score += 15
    elif email.mta_sts_mode == "testing":
        score += 8

    # BIMI: 5
    if email.bimi_configured:
        score += 5

    # TLS-RPT: 5
    tls_rpt_control = next((c for c in hardening.controls if c.name == "TLS-RPT"), None)
    if tls_rpt_control and tls_rpt_control.present:
        score += 5

    # CAA: 5
    caa_control = next((c for c in hardening.controls if c.name == "CAA"), None)
    if caa_control and caa_control.present:
        score += 5

    # Federated identity: 10
    if identity.auth_type == "Federated":
        score += 10

    # Security tooling (2+ tools): 10
    security_count = len(slugs_set & _SECURITY_TOOL_SLUGS)
    if security_count >= 2:
        score += 10

    # Enterprise email gateway: 5
    if email.email_gateway is not None:
        score += 5

    return min(score, 100)


# ── Public API: assess_exposure_from_info ──────────────────────────────

_ASSESSMENT_DISCLAIMER = (
    "This assessment identifies the publicly observable security configuration "
    "of the domain. It is intended for defensive review, vendor due diligence, "
    "and security architecture planning."
)


def assess_exposure_from_info(info: TenantInfo) -> ExposureAssessment:
    """Assess a domain's publicly observable security posture.

    Pure function: TenantInfo in, ExposureAssessment out. No I/O.
    """
    email = _compute_email_posture(info)
    identity = _compute_identity_posture(info)
    infra = _compute_infrastructure_footprint(info)
    consistency = _compute_consistency_observations(info)
    hardening = _compute_hardening_status(info)
    score = _compute_posture_score(email, identity, infra, hardening, info)

    # Collect all evidence from subsections
    all_evidence: list[EvidenceReference] = []
    all_evidence.extend(email.evidence)
    all_evidence.extend(identity.evidence)
    all_evidence.extend(infra.evidence)
    for obs in consistency:
        all_evidence.extend(obs.evidence)
    for ctrl in hardening.controls:
        all_evidence.extend(ctrl.evidence)

    return ExposureAssessment(
        domain=info.queried_domain,
        email_posture=email,
        identity_posture=identity,
        infrastructure_footprint=infra,
        consistency_observations=consistency,
        hardening_status=hardening,
        posture_score=score,
        posture_score_label=_enforce_banned_terms("based on publicly observable controls"),
        disclaimer=_enforce_banned_terms(_ASSESSMENT_DISCLAIMER),
        evidence=tuple(all_evidence),
    )


# ── Gap detection helpers ──────────────────────────────────────────────


def _detect_missing_controls(info: TenantInfo) -> list[HardeningGap]:
    """Detect absent security controls."""
    services_set = set(info.services)
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []

    # Missing DMARC
    if info.dmarc_policy is None:
        gaps.append(
            HardeningGap(
                category="email",
                severity="high",
                observation=_enforce_banned_terms("No DMARC record detected for this domain"),
                recommendation=_enforce_banned_terms(
                    "Consider configuring a DMARC record to protect against email spoofing"
                ),
                evidence=(),
            )
        )

    # DMARC not enforcing (policy == "none")
    if info.dmarc_policy == "none":
        gaps.append(
            HardeningGap(
                category="email",
                severity="high",
                observation=_enforce_banned_terms("DMARC policy is set to 'none' (monitoring only)"),
                recommendation=_enforce_banned_terms("Consider setting DMARC policy to quarantine or reject"),
                evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set),
            )
        )

    # DMARC quarantine (not reject)
    if info.dmarc_policy == "quarantine":
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_enforce_banned_terms("DMARC policy is set to quarantine, not reject"),
                recommendation=_enforce_banned_terms(
                    "Consider upgrading DMARC policy from quarantine to reject for stronger enforcement"
                ),
                evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set),
            )
        )

    # Missing DKIM
    dkim_present = SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set
    if not dkim_present:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_enforce_banned_terms("No DKIM selectors detected for this domain"),
                recommendation=_enforce_banned_terms("Consider configuring DKIM to enable email signing"),
                evidence=(),
            )
        )

    # Missing MTA-STS
    if info.mta_sts_mode is None:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_enforce_banned_terms("No MTA-STS policy detected for this domain"),
                recommendation=_enforce_banned_terms("Consider deploying MTA-STS to enforce encrypted email transport"),
                evidence=(),
            )
        )

    # Missing TLS-RPT
    if "tls-rpt" not in slugs_set:
        gaps.append(
            HardeningGap(
                category="email",
                severity="low",
                observation=_enforce_banned_terms("No TLS-RPT record detected for this domain"),
                recommendation=_enforce_banned_terms(
                    "Consider configuring TLS-RPT to receive email transport failure reports"
                ),
                evidence=(),
            )
        )

    # Missing CAA
    if not (slugs_set & set(_CA_SLUGS.keys())):
        gaps.append(
            HardeningGap(
                category="infrastructure",
                severity="low",
                observation=_enforce_banned_terms("No CAA records detected for this domain"),
                recommendation=_enforce_banned_terms(
                    "Consider adding CAA records to restrict which certificate authorities can issue certificates"
                ),
                evidence=(),
            )
        )

    return gaps


def _detect_weak_configs(info: TenantInfo) -> list[HardeningGap]:
    """Detect weak but present configurations."""
    services_set = set(info.services)
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []

    # SPF softfail (without strict)
    has_softfail = SVC_SPF_SOFTFAIL in services_set
    has_strict = SVC_SPF_STRICT in services_set
    if has_softfail and not has_strict:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_enforce_banned_terms("SPF policy uses softfail (~all) instead of hardfail (-all)"),
                recommendation=_enforce_banned_terms(
                    "Consider changing SPF policy from ~all (softfail) to -all (hardfail)"
                ),
                evidence=_build_evidence_refs(info, {"spf-softfail"} & slugs_set),
            )
        )

    # MTA-STS testing (not enforce)
    if info.mta_sts_mode == "testing":
        gaps.append(
            HardeningGap(
                category="email",
                severity="low",
                observation=_enforce_banned_terms("MTA-STS policy is in testing mode, not enforce"),
                recommendation=_enforce_banned_terms("Consider upgrading MTA-STS policy from testing to enforce"),
                evidence=_build_evidence_refs(info, {"mta-sts", "mta-sts-enforce"} & slugs_set),
            )
        )

    return gaps


def _detect_inconsistencies(info: TenantInfo) -> list[HardeningGap]:
    """Detect configuration inconsistencies."""
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []

    # Gateway without DMARC enforcement
    gateway_slugs = slugs_set & set(_EMAIL_GATEWAY_SLUGS.keys())
    if gateway_slugs and info.dmarc_policy != "reject":
        gateway_names = [_EMAIL_GATEWAY_SLUGS[s] for s in sorted(gateway_slugs)]
        gaps.append(
            HardeningGap(
                category="consistency",
                severity="high",
                observation=_enforce_banned_terms(
                    f"Email gateway ({', '.join(gateway_names)}) detected without DMARC reject enforcement"
                ),
                recommendation=_enforce_banned_terms(
                    "Consider enforcing DMARC alongside the email gateway for comprehensive email protection"
                ),
                evidence=_build_evidence_refs(info, gateway_slugs),
            )
        )

    # Consumer SaaS without enterprise security
    consumer_present = slugs_set & _CONSUMER_SAAS_SLUGS
    security_present = slugs_set & _SECURITY_TOOL_SLUGS
    if consumer_present and not security_present:
        consumer_names = sorted(consumer_present)
        gaps.append(
            HardeningGap(
                category="consistency",
                severity="medium",
                observation=_enforce_banned_terms(
                    f"Consumer-grade SaaS detected ({', '.join(consumer_names)}) without enterprise security controls"
                ),
                recommendation=_enforce_banned_terms(
                    "Consider reviewing consumer-grade SaaS usage alongside enterprise security controls"
                ),
                evidence=_build_evidence_refs(info, consumer_present),
            )
        )

    return gaps


def _detect_stale_indicators(info: TenantInfo) -> list[HardeningGap]:
    """Detect potentially stale or orphaned DNS configurations."""
    gaps: list[HardeningGap] = []

    # Look for slugs that have only a single evidence record with a single
    # source type — these may be orphaned DNS records
    slug_evidence: dict[str, set[str]] = {}
    for ev in info.evidence:
        slug_evidence.setdefault(ev.slug, set()).add(ev.source_type)

    for slug, source_types in slug_evidence.items():
        if (
            len(source_types) == 1
            and slug
            not in {
                # Exclude well-known single-record-type detections
                "dmarc",
                "bimi",
                "mta-sts",
                "mta-sts-enforce",
                "tls-rpt",
                "spf-strict",
                "spf-softfail",
            }
            and slug not in set(_CA_SLUGS.keys())
        ):
            # Only flag if this slug has exactly one evidence record total
            ev_count = sum(1 for ev in info.evidence if ev.slug == slug)
            if ev_count == 1:
                gaps.append(
                    HardeningGap(
                        category="infrastructure",
                        severity="low",
                        observation=_enforce_banned_terms(
                            f"Single-record detection for '{slug}' — may indicate an orphaned configuration"
                        ),
                        recommendation=_enforce_banned_terms(
                            "Consider reviewing DNS records for potentially orphaned service configurations"
                        ),
                        evidence=_build_evidence_refs(info, {slug}),
                    )
                )

    return gaps


# ── Public API: find_gaps_from_info ────────────────────────────────────

_GAPS_DISCLAIMER = (
    "These observations identify publicly visible configuration gaps that "
    "the domain owner may wish to review. They are based on industry best "
    "practices for email security, identity management, and DNS hygiene."
)


def find_gaps_from_info(info: TenantInfo) -> GapReport:
    """Identify hardening opportunities in a domain's public configuration.

    Pure function: TenantInfo in, GapReport out. No I/O.
    """
    gaps: list[HardeningGap] = []
    gaps.extend(_detect_missing_controls(info))
    gaps.extend(_detect_weak_configs(info))
    gaps.extend(_detect_inconsistencies(info))
    gaps.extend(_detect_stale_indicators(info))

    return GapReport(
        domain=info.queried_domain,
        gaps=tuple(gaps),
        disclaimer=_enforce_banned_terms(_GAPS_DISCLAIMER),
    )


# ── Public API: compare_postures_from_infos ────────────────────────────

_COMPARISON_DISCLAIMER = (
    "This comparison is based on publicly observable configuration data. "
    "Differences in posture may reflect different organizational priorities, "
    "not necessarily security deficiencies."
)


def _build_metrics(info_a: TenantInfo, info_b: TenantInfo) -> tuple[PostureMetric, ...]:
    """Build side-by-side metrics for two domains."""
    score_a = _compute_email_security_score(info_a)
    score_b = _compute_email_security_score(info_b)

    return (
        PostureMetric(
            metric_name="email_security_score",
            domain_a_value=str(score_a),
            domain_b_value=str(score_b),
        ),
        PostureMetric(
            metric_name="confidence",
            domain_a_value=info_a.confidence.value,
            domain_b_value=info_b.confidence.value,
        ),
        PostureMetric(
            metric_name="auth_type",
            domain_a_value=info_a.auth_type or "",
            domain_b_value=info_b.auth_type or "",
        ),
        PostureMetric(
            metric_name="service_count",
            domain_a_value=str(len(info_a.services)),
            domain_b_value=str(len(info_b.services)),
        ),
        PostureMetric(
            metric_name="dmarc_policy",
            domain_a_value=info_a.dmarc_policy or "",
            domain_b_value=info_b.dmarc_policy or "",
        ),
        PostureMetric(
            metric_name="mta_sts_mode",
            domain_a_value=info_a.mta_sts_mode or "",
            domain_b_value=info_b.mta_sts_mode or "",
        ),
    )


def _build_differences(info_a: TenantInfo, info_b: TenantInfo) -> tuple[PostureDifference, ...]:
    """Build control/service differences between two domains."""
    # Compare key security controls
    controls_a = _compute_hardening_status(info_a)
    controls_b = _compute_hardening_status(info_b)

    diffs: list[PostureDifference] = []

    for ctrl_a, ctrl_b in zip(controls_a.controls, controls_b.controls, strict=True):
        if ctrl_a.present != ctrl_b.present:
            if ctrl_a.present:
                desc = f"{ctrl_a.name} present in {info_a.queried_domain} but absent in {info_b.queried_domain}"
            else:
                desc = f"{ctrl_a.name} present in {info_b.queried_domain} but absent in {info_a.queried_domain}"
            diffs.append(
                PostureDifference(
                    description=_enforce_banned_terms(desc),
                    domain_a_has=ctrl_a.present,
                    domain_b_has=ctrl_b.present,
                )
            )

    return tuple(diffs)


def _build_relative_assessment(info_a: TenantInfo, info_b: TenantInfo) -> tuple[RelativeAssessment, ...]:
    """Build relative posture assessment across dimensions."""
    assessments: list[RelativeAssessment] = []

    # Email security
    score_a = _compute_email_security_score(info_a)
    score_b = _compute_email_security_score(info_b)
    if score_a > score_b:
        summary = f"{info_a.queried_domain} has stronger email security (score {score_a}/5 vs {score_b}/5)"
    elif score_b > score_a:
        summary = f"{info_b.queried_domain} has stronger email security (score {score_b}/5 vs {score_a}/5)"
    else:
        summary = f"Both domains have comparable email security (score {score_a}/5)"
    assessments.append(RelativeAssessment(dimension="email_security", summary=_enforce_banned_terms(summary)))

    # Identity maturity
    a_federated = info_a.auth_type == "Federated"
    b_federated = info_b.auth_type == "Federated"
    if a_federated and not b_federated:
        summary = f"{info_a.queried_domain} uses federated identity; {info_b.queried_domain} does not"
    elif b_federated and not a_federated:
        summary = f"{info_b.queried_domain} uses federated identity; {info_a.queried_domain} does not"
    elif a_federated and b_federated:
        summary = "Both domains use federated identity"
    else:
        summary = "Neither domain uses federated identity"
    assessments.append(RelativeAssessment(dimension="identity_maturity", summary=_enforce_banned_terms(summary)))

    # Security tooling
    slugs_a = set(info_a.slugs)
    slugs_b = set(info_b.slugs)
    tools_a = len(slugs_a & _SECURITY_TOOL_SLUGS)
    tools_b = len(slugs_b & _SECURITY_TOOL_SLUGS)
    if tools_a > tools_b:
        summary = f"{info_a.queried_domain} has broader security tooling ({tools_a} vs {tools_b} detected)"
    elif tools_b > tools_a:
        summary = f"{info_b.queried_domain} has broader security tooling ({tools_b} vs {tools_a} detected)"
    else:
        summary = f"Both domains have comparable security tooling ({tools_a} detected)"
    assessments.append(RelativeAssessment(dimension="security_tooling", summary=_enforce_banned_terms(summary)))

    return tuple(assessments)


def compare_postures_from_infos(info_a: TenantInfo, info_b: TenantInfo) -> PostureComparison:
    """Compare the security postures of two domains side by side.

    Pure function: two TenantInfo in, PostureComparison out. No I/O.
    """
    return PostureComparison(
        domain_a=info_a.queried_domain,
        domain_b=info_b.queried_domain,
        metrics=_build_metrics(info_a, info_b),
        differences=_build_differences(info_a, info_b),
        relative_assessment=_build_relative_assessment(info_a, info_b),
        disclaimer=_enforce_banned_terms(_COMPARISON_DISCLAIMER),
    )
