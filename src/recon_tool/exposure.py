"""Pure defensive exposure assessment over resolved TenantInfo data.

Generated prose must stay neutral and hedged. The terminology guard is a
copy-style lint for recon-authored text, not an input blocklist.
"""

from __future__ import annotations

import logging

from recon_tool import exposure_observability as observability
from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.email_security import observed_email_control_services
from recon_tool.exposure_comparison import build_metrics
from recon_tool.exposure_models import (
    ConsistencyObservation,
    EmailPosture,
    EvidenceReference,
    ExposureAssessment,
    GapReport,
    HardeningControl,
    HardeningGap,
    HardeningStatus,
    IdentityPosture,
    InfrastructureFootprint,
    PostureComparison,
    PostureDifference,
    RelativeAssessment,
)
from recon_tool.models import TenantInfo
from recon_tool.posture import DISCOURAGED_COPY_TERMS

logger = logging.getLogger(__name__)

# ── Neutral-language copy terms ─────────────────────────────────────────

EXPOSURE_DISCOURAGED_COPY_TERMS: frozenset[str] = DISCOURAGED_COPY_TERMS | frozenset(
    {
        "target",
        "attack surface",
        "vulnerabilities to exploit",
        "finding",
        "remediation",
    }
)

# Backward-compatible alias for older tests or callers that imported the old internal name.
EXPOSURE_BANNED_TERMS = EXPOSURE_DISCOURAGED_COPY_TERMS


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
    "aws-acm": "Amazon",
    "google-trust": "Google Trust",
    "globalsign": "GlobalSign",
}

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

# ── Helper functions ───────────────────────────────────────────────────


def _check_neutral_copy(text: str) -> str:
    """Log discouraged generated-copy terms without blocking the output."""
    lower = text.lower()
    for term in EXPOSURE_DISCOURAGED_COPY_TERMS:
        if term in lower:
            logger.warning("Discouraged copy term '%s' found in generated prose: %s", term, text)
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


def _evidence_slugs(info: TenantInfo, source_types: frozenset[str]) -> set[str]:
    """Return slugs backed by one of the role-bearing evidence types."""
    return {
        evidence.slug for evidence in info.evidence if evidence.slug and evidence.source_type.upper() in source_types
    }


def _compute_email_security_score(info: TenantInfo) -> int:
    """Email-security score (0-5); see ``constants.email_security_score`` for the definition."""
    return observability.ObservableEmailState.from_info(info).security_score


def _effective_email_dmarc_policy(info: TenantInfo) -> str | None:
    return observability.ObservableEmailState.from_info(info).effective_dmarc_policy


def _compute_email_posture(info: TenantInfo) -> EmailPosture:
    """Derive email security posture from TenantInfo."""
    observed = observability.ObservableEmailState.from_info(info)
    services_set = observed_email_control_services(info.evidence)
    slugs_set = set(info.slugs)
    dmarc_policy = observed.dmarc_policy
    mta_sts_mode = observed.mta_sts_mode

    dkim_configured = observed.dkim_available and (
        SVC_DKIM in services_set or SVC_DKIM_EXCHANGE in services_set or SVC_DKIM_GOOGLE in services_set
    )
    spf_strict = observed.spf_available and SVC_SPF_STRICT in services_set
    bimi_configured = observed.bimi_available and SVC_BIMI in services_set

    # ``email_gateway`` is set only from the MX topology path. A generic
    # vendor-verification slug is an indicator, not routing evidence.
    mx_gateway_slugs = _evidence_slugs(info, frozenset({"MX"})) & set(_EMAIL_GATEWAY_SLUGS)
    gateway = info.email_gateway if observed.gateway_available and mx_gateway_slugs else None

    # Collect relevant slugs for evidence
    relevant_slugs: set[str] = set()
    if dmarc_policy is not None:
        relevant_slugs.add("dmarc")
    if dkim_configured:
        relevant_slugs.update(_evidence_slugs(info, frozenset({"DKIM"})))
    if spf_strict:
        relevant_slugs.add("spf-strict")
    if bimi_configured:
        relevant_slugs.add("bimi")
    if mta_sts_mode is not None:
        relevant_slugs.add("mta-sts")
        if mta_sts_mode == "enforce":
            relevant_slugs.add("mta-sts-enforce")
    if gateway:
        relevant_slugs.update(mx_gateway_slugs)
    # Also include any TLS-RPT evidence
    if "tls-rpt" in slugs_set:
        relevant_slugs.add("tls-rpt")

    evidence = _build_evidence_refs(info, relevant_slugs)

    return EmailPosture(
        dmarc_policy=dmarc_policy,
        dkim_configured=dkim_configured,
        spf_strict=spf_strict,
        mta_sts_mode=mta_sts_mode,
        email_gateway=gateway,
        bimi_configured=bimi_configured,
        email_security_score=_compute_email_security_score(info),
        evidence=evidence,
    )


def _compute_identity_posture(info: TenantInfo) -> IdentityPosture:
    """Derive identity posture from TenantInfo."""
    # A vendor TXT token does not establish the operating IdP. The only
    # currently retained named route is Google's explicit federation response.
    idp = info.google_idp_name

    relevant_slugs: set[str] = set()
    if idp:
        relevant_slugs.add("google-workspace")
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
    cname_slugs = _evidence_slugs(info, frozenset({"CNAME"}))
    ns_slugs = _evidence_slugs(info, frozenset({"NS"}))
    caa_slugs = _evidence_slugs(info, frozenset({"CAA"}))

    # Cloud providers (deduplicated by provider name)
    cloud_names: set[str] = set()
    for slug, name in _CLOUD_PROVIDER_SLUGS.items():
        if slug in cname_slugs:
            cloud_names.add(name)
    cloud_providers = tuple(sorted(cloud_names))

    # DNS provider
    dns_provider: str | None = None
    for slug, name in _DNS_PROVIDER_SLUGS.items():
        if slug in ns_slugs:
            dns_provider = name
            break

    # CDN/WAF
    cdn_names: list[str] = []
    for slug, name in _CDN_WAF_SLUGS.items():
        if slug in cname_slugs:
            cdn_names.append(name)
    cdn_waf = tuple(sorted(cdn_names))

    # Certificate authorities
    ca_names: list[str] = []
    for slug, name in _CA_SLUGS.items():
        if slug in caa_slugs:
            ca_names.append(name)
    certificate_authorities = tuple(sorted(ca_names))

    # Evidence from all infrastructure slugs
    relevant_slugs = (
        (cname_slugs & (set(_CLOUD_PROVIDER_SLUGS) | set(_CDN_WAF_SLUGS)))
        | (ns_slugs & set(_DNS_PROVIDER_SLUGS))
        | (caa_slugs & set(_CA_SLUGS))
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
    observations: list[ConsistencyObservation] = []

    # Only MX records establish simultaneous delivery paths. Account or
    # verification indicators alone do not establish active mail service.
    mx_slugs = _evidence_slugs(info, frozenset({"MX"}))
    has_exchange = "microsoft365" in mx_slugs
    has_google = "google-workspace" in mx_slugs
    if has_exchange and has_google:
        obs = _check_neutral_copy("MX records reference both Microsoft 365 and Google Workspace delivery paths")
        evidence = _build_evidence_refs(info, {"microsoft365", "google-workspace"} & mx_slugs)
        observations.append(ConsistencyObservation(observation=obs, category="dual_provider", evidence=evidence))

    return tuple(observations)


def _compute_hardening_status(info: TenantInfo) -> HardeningStatus:
    """Derive hardening control status from TenantInfo."""
    observed = observability.ObservableEmailState.from_info(info)
    services_set = observed_email_control_services(info.evidence)
    slugs_set = set(info.slugs)
    controls: list[HardeningControl] = []

    # DMARC enforcement
    dmarc_effective_policy = _effective_email_dmarc_policy(info)
    dmarc_available = observed.dmarc_available
    if not dmarc_available:
        detail = "source unavailable"
    elif info.dmarc_policy is None:
        detail = "not configured"
    elif info.dmarc_policy == "none":
        detail = "policy set to none"
    elif dmarc_effective_policy is not None and dmarc_effective_policy != info.dmarc_policy:
        detail = f"{info.dmarc_policy} (effective {dmarc_effective_policy})"
    else:
        detail = info.dmarc_policy
    dmarc_present = dmarc_available and info.dmarc_policy is not None
    controls.append(
        HardeningControl(
            name="DMARC",
            present=dmarc_present,
            detail=detail,
            evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set) if dmarc_present else (),
        )
    )

    # DKIM
    dkim_available = observed.dkim_available
    dkim_present = dkim_available and bool(services_set & {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE})
    controls.append(
        HardeningControl(
            name="DKIM",
            present=dkim_present,
            detail=("configured" if dkim_present else "not observed at recon's bounded common-selector set")
            if dkim_available
            else "source unavailable",
            evidence=(_build_evidence_refs(info, _evidence_slugs(info, frozenset({"DKIM"}))) if dkim_present else ()),
        )
    )

    # MTA-STS
    mta_available = observed.mta_sts_available
    mta_present = mta_available and info.mta_sts_mode is not None
    mta_detail = (info.mta_sts_mode or "not configured") if mta_available else "source unavailable"
    controls.append(
        HardeningControl(
            name="MTA-STS",
            present=mta_present,
            detail=mta_detail or "not configured",
            evidence=_build_evidence_refs(info, {"mta-sts", "mta-sts-enforce"} & slugs_set) if mta_present else (),
        )
    )

    # BIMI
    bimi_available = observed.bimi_available
    bimi_present = bimi_available and SVC_BIMI in services_set
    controls.append(
        HardeningControl(
            name="BIMI",
            present=bimi_present,
            detail=("configured" if bimi_present else "not configured") if bimi_available else "source unavailable",
            evidence=_build_evidence_refs(info, {"bimi"} & slugs_set) if bimi_present else (),
        )
    )

    # TLS-RPT
    tls_rpt_available = observed.tls_rpt_available
    tls_rpt_present = tls_rpt_available and "tls-rpt" in slugs_set
    controls.append(
        HardeningControl(
            name="TLS-RPT",
            present=tls_rpt_present,
            detail=("configured" if tls_rpt_present else "not configured")
            if tls_rpt_available
            else "source unavailable",
            evidence=_build_evidence_refs(info, {"tls-rpt"}) if tls_rpt_present else (),
        )
    )

    # CAA records
    caa_available = observed.caa_available
    caa_evidence_slugs = _evidence_slugs(info, frozenset({"CAA"}))
    caa_present = caa_available and bool(caa_evidence_slugs)
    controls.append(
        HardeningControl(
            name="CAA",
            present=caa_present,
            detail=("configured" if caa_present else "not configured") if caa_available else "source unavailable",
            evidence=_build_evidence_refs(info, caa_evidence_slugs) if caa_present else (),
        )
    )

    return HardeningStatus(controls=tuple(controls))


def _unconfirmable_absent_points(email: EmailPosture, info: TenantInfo) -> int:
    """Points from absent controls whose absence is not passively confirmable."""
    return observability.ObservableEmailState.from_info(info).unconfirmable_points(
        dkim_configured=email.dkim_configured,
        email_gateway=email.email_gateway,
    )


def _compute_posture_score(
    email: EmailPosture,
    identity: IdentityPosture,
    hardening: HardeningStatus,
    info: TenantInfo,
) -> int:
    """Compute weighted posture score (0–100) from observable controls."""
    score = 0

    # DMARC: reject=20, quarantine=12 (mutually exclusive)
    dmarc_effective_policy = _effective_email_dmarc_policy(info)
    if dmarc_effective_policy == "reject":
        score += observability.SCORE_DMARC
    elif dmarc_effective_policy == "quarantine":
        score += 12

    # DKIM: 15
    if email.dkim_configured:
        score += observability.SCORE_DKIM

    # SPF strict: 10
    if email.spf_strict:
        score += 10

    # MTA-STS: enforce=15, testing=8 (mutually exclusive)
    if email.mta_sts_mode == "enforce":
        score += observability.SCORE_MTA_STS
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

    # Enterprise email gateway: 5
    if email.email_gateway is not None:
        score += observability.SCORE_EMAIL_GATEWAY

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
    from recon_tool.collection_view import collection_claim_info

    info = collection_claim_info(info)
    email = _compute_email_posture(info)
    identity = _compute_identity_posture(info)
    infra = _compute_infrastructure_footprint(info)
    consistency = _compute_consistency_observations(info)
    hardening = _compute_hardening_status(info)
    score = _compute_posture_score(email, identity, hardening, info)

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
        posture_score_label=_check_neutral_copy("based on publicly observable controls"),
        disclaimer=_check_neutral_copy(_ASSESSMENT_DISCLAIMER),
        evidence=tuple(all_evidence),
        unconfirmable_absent_points=_unconfirmable_absent_points(email, info),
        unavailable_controls=observability.ObservableEmailState.from_info(info).unavailable_control_names(),
    )


# ── Gap detection helpers ──────────────────────────────────────────────


def _detect_missing_controls(info: TenantInfo) -> list[HardeningGap]:
    """Detect absent security controls."""
    observed = observability.ObservableEmailState.from_info(info)
    services_set = observed_email_control_services(info.evidence)
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []
    dmarc_effective_policy = _effective_email_dmarc_policy(info)

    # Missing DMARC
    if observed.dmarc_available and info.dmarc_policy is None:
        gaps.append(
            HardeningGap(
                category="email",
                severity="high",
                observation=_check_neutral_copy("No valid DMARC policy record observed for this domain"),
                recommendation=_check_neutral_copy(
                    "Consider configuring a DMARC record to protect against email spoofing"
                ),
                evidence=(),
            )
        )

    # DMARC not effectively enforcing.
    if observed.dmarc_available and info.dmarc_policy is not None and dmarc_effective_policy == "none":
        observation = (
            "DMARC policy is set to 'none' (monitoring only)"
            if info.dmarc_policy == "none"
            else "DMARC policy is not effectively enforcing after rollout or testing tags"
        )
        gaps.append(
            HardeningGap(
                category="email",
                severity="high",
                observation=_check_neutral_copy(observation),
                recommendation=_check_neutral_copy("Consider setting DMARC policy to quarantine or reject"),
                evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set),
            )
        )

    # DMARC quarantine-level enforcement (not reject-level enforcement).
    if dmarc_effective_policy == "quarantine":
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_check_neutral_copy("Effective DMARC policy is quarantine, not reject"),
                recommendation=_check_neutral_copy(
                    "Consider upgrading DMARC policy from quarantine to reject for stronger enforcement"
                ),
                evidence=_build_evidence_refs(info, {"dmarc"} & slugs_set),
            )
        )

    # Missing DKIM
    dkim_present = bool(services_set & {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE})
    if observed.dkim_available and not dkim_present:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_check_neutral_copy("No DKIM selectors observed at common names for this domain"),
                recommendation=_check_neutral_copy(
                    "Consider verifying DKIM configuration and, if missing, "
                    "deploying signing with a common selector name"
                ),
                evidence=(),
                # DKIM uses operator-chosen selectors; absence at the common
                # names recon probes does not establish absence of DKIM.
                absence_confirmable=False,
            )
        )

    # Missing MTA-STS
    if observed.mta_sts_available and info.mta_sts_mode is None:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_check_neutral_copy("No MTA-STS policy detected for this domain"),
                recommendation=_check_neutral_copy("Consider deploying MTA-STS to enforce encrypted email transport"),
                evidence=(),
            )
        )

    # Missing TLS-RPT
    if observed.tls_rpt_available and "tls-rpt" not in slugs_set:
        gaps.append(
            HardeningGap(
                category="email",
                severity="low",
                observation=_check_neutral_copy("No TLS-RPT record detected for this domain"),
                recommendation=_check_neutral_copy(
                    "Consider configuring TLS-RPT to receive email transport failure reports"
                ),
                evidence=(),
            )
        )

    # Missing CAA
    caa_evidence_slugs = _evidence_slugs(info, frozenset({"CAA"}))
    if observed.caa_available and not caa_evidence_slugs:
        gaps.append(
            HardeningGap(
                category="infrastructure",
                severity="low",
                observation=_check_neutral_copy("No CAA records detected for this domain"),
                recommendation=_check_neutral_copy(
                    "Consider adding CAA records to restrict which certificate authorities can issue certificates"
                ),
                evidence=(),
            )
        )

    return gaps


def _detect_weak_configs(info: TenantInfo) -> list[HardeningGap]:
    """Detect weak but present configurations."""
    services_set = observed_email_control_services(info.evidence)
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []

    observed = observability.ObservableEmailState.from_info(info)

    # SPF softfail (without strict)
    has_softfail = SVC_SPF_SOFTFAIL in services_set
    has_strict = SVC_SPF_STRICT in services_set
    if observed.spf_available and has_softfail and not has_strict:
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_check_neutral_copy("SPF policy uses softfail (~all) instead of hardfail (-all)"),
                recommendation=_check_neutral_copy(
                    "Consider changing SPF policy from ~all (softfail) to -all (hardfail)"
                ),
                evidence=_build_evidence_refs(info, {"spf-softfail"} & slugs_set),
            )
        )

    # MTA-STS testing (not enforce)
    if observed.mta_sts_available and info.mta_sts_mode == "testing":
        gaps.append(
            HardeningGap(
                category="email",
                severity="low",
                observation=_check_neutral_copy("MTA-STS policy is in testing mode, not enforce"),
                recommendation=_check_neutral_copy("Consider upgrading MTA-STS policy from testing to enforce"),
                evidence=_build_evidence_refs(info, {"mta-sts", "mta-sts-enforce"} & slugs_set),
            )
        )

    return gaps


def _detect_inconsistencies(info: TenantInfo) -> list[HardeningGap]:
    """Detect configuration inconsistencies."""
    observed = observability.ObservableEmailState.from_info(info)
    gaps: list[HardeningGap] = []

    # Gateway without DMARC enforcement
    gateway_slugs = _evidence_slugs(info, frozenset({"MX"})) & set(_EMAIL_GATEWAY_SLUGS)
    if (
        gateway_slugs
        and info.email_gateway is not None
        and observed.gateway_available
        and observed.dmarc_available
        and _effective_email_dmarc_policy(info) != "reject"
    ):
        gaps.append(
            HardeningGap(
                category="consistency",
                severity="high",
                observation=_check_neutral_copy(
                    f"MX gateway ({info.email_gateway}) observed without DMARC reject enforcement"
                ),
                recommendation=_check_neutral_copy(
                    "Consider enforcing DMARC alongside the email gateway for comprehensive email protection"
                ),
                evidence=_build_evidence_refs(info, gateway_slugs),
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
    from recon_tool.collection_view import collection_claim_info

    info = collection_claim_info(info)
    gaps: list[HardeningGap] = []
    gaps.extend(_detect_missing_controls(info))
    gaps.extend(_detect_weak_configs(info))
    gaps.extend(_detect_inconsistencies(info))

    observed = observability.ObservableEmailState.from_info(info)
    return GapReport(
        domain=info.queried_domain,
        gaps=tuple(gaps),
        disclaimer=_check_neutral_copy(_GAPS_DISCLAIMER),
        unavailable_controls=observed.unavailable_control_names(),
        degraded_sources=tuple(sorted(set(info.degraded_sources))),
    )


# ── Public API: compare_postures_from_infos ────────────────────────────

_COMPARISON_DISCLAIMER = (
    "This comparison is based on publicly observable configuration data. "
    "Differences in posture may reflect different organizational priorities, "
    "not necessarily security deficiencies."
)


def _build_differences(info_a: TenantInfo, info_b: TenantInfo) -> tuple[PostureDifference, ...]:
    """Build control/service differences between two domains."""
    # Compare key security controls
    controls_a = _compute_hardening_status(info_a)
    controls_b = _compute_hardening_status(info_b)

    diffs: list[PostureDifference] = []

    for ctrl_a, ctrl_b in zip(controls_a.controls, controls_b.controls, strict=True):
        if "source unavailable" in {ctrl_a.detail, ctrl_b.detail}:
            continue
        if ctrl_a.present != ctrl_b.present:
            if ctrl_a.name == "DKIM":
                observed_domain = info_a.queried_domain if ctrl_a.present else info_b.queried_domain
                unobserved_domain = info_b.queried_domain if ctrl_a.present else info_a.queried_domain
                desc = (
                    f"DKIM observed at a probed selector for {observed_domain}; no DKIM record was observed "
                    f"at recon's bounded common-selector set for {unobserved_domain}"
                )
            elif ctrl_a.present:
                desc = f"{ctrl_a.name} present in {info_a.queried_domain} but absent in {info_b.queried_domain}"
            else:
                desc = f"{ctrl_a.name} present in {info_b.queried_domain} but absent in {info_a.queried_domain}"
            diffs.append(
                PostureDifference(
                    description=desc,
                    domain_a_has=ctrl_a.present,
                    domain_b_has=ctrl_b.present,
                )
            )

    return tuple(diffs)


def _build_relative_assessment(info_a: TenantInfo, info_b: TenantInfo) -> tuple[RelativeAssessment, ...]:
    """Build relative posture assessment across dimensions."""
    assessments: list[RelativeAssessment] = []

    # Email security
    observed_a = observability.ObservableEmailState.from_info(info_a)
    observed_b = observability.ObservableEmailState.from_info(info_b)
    if not observed_a.score_collection_available or not observed_b.score_collection_available:
        unavailable_domains = ", ".join(
            info.queried_domain
            for info, observed in ((info_a, observed_a), (info_b, observed_b))
            if not observed.score_collection_available
        )
        summary = (
            "Email-security control observations are not comparable because collection was unavailable for "
            f"{unavailable_domains}"
        )
    else:
        score_a = observed_a.security_score
        score_b = observed_b.security_score
        if score_a > score_b:
            summary = f"{info_a.queried_domain} has more email-security controls observed than {info_b.queried_domain}"
        elif score_b > score_a:
            summary = f"{info_b.queried_domain} has more email-security controls observed than {info_a.queried_domain}"
        else:
            summary = (
                f"{info_a.queried_domain} and {info_b.queried_domain} have a comparable set of email-security controls"
            )
    assessments.append(RelativeAssessment(dimension="email_security", summary=summary))

    # Identity federation. ``None`` is unobserved, never a negative result.
    identity_states: dict[str | None, str] = {
        None: "the identity federation state is unknown",
        "Federated": "federated identity was observed",
        "Managed": "a managed identity response was observed",
    }
    state_a = identity_states.get(info_a.auth_type, "the identity federation state is unknown")
    state_b = identity_states.get(info_b.auth_type, "the identity federation state is unknown")
    if state_a == state_b:
        summary = f"For both domains, {state_a}"
    else:
        summary = f"For {info_a.queried_domain}, {state_a}; for {info_b.queried_domain}, {state_b}"
    assessments.append(RelativeAssessment(dimension="identity_federation", summary=summary))

    # Generic slugs are public fingerprint indicators, not proof of active use.
    indicators_a = len(info_a.slugs)
    indicators_b = len(info_b.slugs)
    if info_a.degraded_sources or info_b.degraded_sources:
        incomplete_domains = ", ".join(info.queried_domain for info in (info_a, info_b) if info.degraded_sources)
        summary = (
            "Public fingerprint counts are not compared because collection opportunity was incomplete for "
            f"{incomplete_domains}"
        )
    elif indicators_a > indicators_b:
        summary = (
            f"{info_a.queried_domain} has more public fingerprint indicators "
            f"({indicators_a} vs {indicators_b} observed)"
        )
    elif indicators_b > indicators_a:
        summary = (
            f"{info_b.queried_domain} has more public fingerprint indicators "
            f"({indicators_b} vs {indicators_a} observed)"
        )
    else:
        summary = f"Both domains have the same public fingerprint count ({indicators_a} observed)"
    assessments.append(RelativeAssessment(dimension="public_fingerprints", summary=summary))

    return tuple(assessments)


def compare_postures_from_infos(info_a: TenantInfo, info_b: TenantInfo) -> PostureComparison:
    """Compare the security postures of two domains side by side.

    Pure function: two TenantInfo in, PostureComparison out. No I/O.
    """
    from recon_tool.collection_view import collection_claim_info

    info_a = collection_claim_info(info_a)
    info_b = collection_claim_info(info_b)
    return PostureComparison(
        domain_a=info_a.queried_domain,
        domain_b=info_b.queried_domain,
        metrics=build_metrics(info_a, info_b),
        differences=_build_differences(info_a, info_b),
        relative_assessment=_build_relative_assessment(info_a, info_b),
        disclaimer=_check_neutral_copy(_COMPARISON_DISCLAIMER),
    )
