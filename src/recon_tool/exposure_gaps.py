"""Hardening-gap detection over resolved TenantInfo data.

Split out of ``exposure.py`` to keep that module under the size guard in
``docs/engineering-practices.md``. These three detectors are the only producers
of ``HardeningGap``; ``exposure.find_gaps_from_info`` composes them and owns the
collection-aware projection and disclaimer. Generated prose stays neutral and
hedged, so every observation and recommendation string routes through
``_check_neutral_copy``.
"""

from __future__ import annotations

from typing import NotRequired, TypedDict, Unpack

from recon_tool import exposure_observability as observability
from recon_tool.claim_contract import ConstructionState, dmarc_policy_projection
from recon_tool.constants import (
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.email_security import observed_email_control_services
from recon_tool.exposure_copy import build_evidence_refs as _build_evidence_refs
from recon_tool.exposure_copy import check_neutral_copy as _check_neutral_copy
from recon_tool.exposure_copy import evidence_slugs as _evidence_slugs
from recon_tool.exposure_models import (
    EvidenceReference,
    HardeningGap,
    HardeningMetadataDependency,
    HardeningMetadataOperator,
    HardeningMetadataValue,
    HardeningObservationState,
)
from recon_tool.models import TenantInfo
from recon_tool.source_status import ObservationChannel, SourceStatus
from recon_tool.sources.mta_sts import select_mta_sts_record

__all__ = [
    "EMAIL_GATEWAY_SLUGS",
    "GAPS_DISCLAIMER",
    "detect_inconsistencies",
    "detect_missing_controls",
    "detect_weak_configs",
    "effective_email_dmarc_policy",
    "hardening_scopes_available",
    "mta_sts_mode_evidence",
    "mta_sts_txt_evidence",
    "validate_gap_lineage",
]


# Gateway vendors whose MX presence can mask the downstream mailbox provider.
EMAIL_GATEWAY_SLUGS: dict[str, str] = {
    "proofpoint": "Proofpoint",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "cisco-ironport": "Cisco IronPort",
    "cisco-email": "Cisco Secure Email",
    "trendmicro": "Trend Micro",
    "symantec": "Symantec/Broadcom",
    "trellix": "Trellix (FireEye)",
}

_HARDENING_SCOPE_CHANNELS: dict[str, ObservationChannel] = {
    "dns:dmarc": "dmarc",
    "dns:dkim_common_selectors": "dkim",
    "dns:tls_rpt": "tls_rpt",
    "dns:caa": "caa",
    "dns:apex_txt": "apex_txt",
    "dns:mx": "mx",
}
_MTA_STS_SCOPE_DEGRADATION: dict[str, frozenset[str]] = {
    "dns:mta_sts": frozenset({"dns:mta_sts", "detector:email_security"}),
    "http:mta_sts_policy": frozenset({"http:mta_sts_policy", "detector:email_security"}),
}
_DMARC_EVIDENCE_TYPES = frozenset({"DMARC"})
_MTA_STS_EVIDENCE_TYPES = frozenset({"MTA_STS", "MTA_STS_POLICY"})
_SPF_EVIDENCE_TYPES = frozenset({"SPF"})
_MX_EVIDENCE_TYPES = frozenset({"MX"})
_TLS_RPT_RULE_NAME = "TLS-RPT"


def _dependency(
    field: str,
    operator: HardeningMetadataOperator,
    expected_value: HardeningMetadataValue,
    observed_value: HardeningMetadataValue,
) -> HardeningMetadataDependency:
    return HardeningMetadataDependency(field, operator, expected_value, observed_value)


def mta_sts_txt_evidence(info: TenantInfo) -> tuple[EvidenceReference, ...]:
    """Return one syntactically valid retained MTA-STS TXT declaration."""
    records = tuple(
        dict.fromkeys(
            record for record in info.evidence if record.source_type.upper() == "MTA_STS" and record.slug == "mta-sts"
        )
    )
    selected = select_mta_sts_record(record.raw_value for record in records)
    if selected is None:
        return ()
    return tuple(
        EvidenceReference(record.source_type, record.raw_value, record.rule_name, record.slug)
        for record in records
        if record.raw_value == selected
    )


def mta_sts_mode_evidence(info: TenantInfo, mode: str) -> tuple[EvidenceReference, ...]:
    """Return one valid TXT declaration and its matching fetched policy mode."""
    txt_refs = mta_sts_txt_evidence(info)
    policy_records = tuple(
        dict.fromkeys(record for record in info.evidence if record.source_type.upper() == "MTA_STS_POLICY")
    )
    expected_slug = "mta-sts-enforce" if mode == "enforce" else "mta-sts"
    expected_policy = f"mode: {mode}"
    if (
        not txt_refs
        or len(policy_records) != 1
        or policy_records[0].slug != expected_slug
        or policy_records[0].raw_value.strip().casefold() != expected_policy
    ):
        return ()
    policy_refs = _build_evidence_refs(
        info,
        {expected_slug},
        source_types=_MTA_STS_EVIDENCE_TYPES,
    )
    return tuple(dict.fromkeys((*txt_refs, *policy_refs)))


class _GapValues(TypedDict):
    rule_id: str
    state: HardeningObservationState
    scope: tuple[str, ...]
    dependencies: tuple[HardeningMetadataDependency, ...]
    category: str
    severity: str
    observation: str
    recommendation: str
    evidence: NotRequired[tuple[EvidenceReference, ...]]
    absence_confirmable: NotRequired[bool]


def _gap(**values: Unpack[_GapValues]) -> HardeningGap:
    """Build one neutral review prompt with complete generation-time proof."""
    return HardeningGap(
        category=values["category"],
        severity=values["severity"],
        observation=_check_neutral_copy(values["observation"]),
        recommendation=_check_neutral_copy(values["recommendation"]),
        evidence=values.get("evidence", ()),
        absence_confirmable=values.get("absence_confirmable", True),
        generator_rule_id=values["rule_id"],
        observation_state=values["state"],
        metadata_dependencies=values["dependencies"],
        observation_scope=values["scope"],
    )


def effective_email_dmarc_policy(info: TenantInfo) -> str | None:
    return observability.ObservableEmailState.from_info(info).effective_dmarc_policy


def hardening_scopes_available(scopes: tuple[str, ...], degraded_sources: tuple[str, ...]) -> bool:
    """Return whether every declared hardening observation scope succeeded."""
    status = SourceStatus.from_degraded_sources(degraded_sources)
    if not scopes:
        return False
    for scope in scopes:
        if markers := _MTA_STS_SCOPE_DEGRADATION.get(scope):
            if (scope.startswith("dns:") and status.whole_dns_unavailable) or not status.degraded_sources.isdisjoint(
                markers
            ):
                return False
            continue
        channel = _HARDENING_SCOPE_CHANNELS.get(scope)
        if channel is None or not status.channel_available(channel):
            return False
    return True


def validate_gap_lineage(gaps: list[HardeningGap], degraded_sources: tuple[str, ...]) -> None:
    """Fail closed when an internal hardening producer loses its proof state."""
    seen_rule_ids: set[str] = set()
    for gap in gaps:
        if not gap.generator_rule_id or gap.generator_rule_id in seen_rule_ids:
            raise ValueError("hardening gaps require distinct non-empty generator rule IDs")
        seen_rule_ids.add(gap.generator_rule_id)
        if not gap.observation_state or not gap.metadata_dependencies or not gap.observation_scope:
            raise ValueError(f"hardening gap {gap.generator_rule_id!r} has incomplete lineage")
        if not hardening_scopes_available(gap.observation_scope, degraded_sources):
            raise ValueError(f"hardening gap {gap.generator_rule_id!r} uses an unavailable observation scope")
        if (
            gap.observation_state
            in {
                "observed_weak_configuration",
                "observed_configuration_inconsistency",
            }
            and not gap.evidence
        ):
            raise ValueError(f"hardening gap {gap.generator_rule_id!r} has no retained supporting evidence")


def detect_missing_controls(info: TenantInfo) -> list[HardeningGap]:
    """Detect absent security controls."""
    observed = observability.ObservableEmailState.from_info(info)
    services_set = observed_email_control_services(info.evidence)
    gaps: list[HardeningGap] = []
    dmarc_projection = dmarc_policy_projection(info)
    dmarc_effective_policy = dmarc_projection.effective_policy
    dmarc_evidence = _build_evidence_refs(
        info,
        {"dmarc"},
        source_types=_DMARC_EVIDENCE_TYPES,
    )
    dmarc_observation_evidence = _build_evidence_refs(
        info,
        {record.slug for record in dmarc_projection.evidence},
        source_types=_DMARC_EVIDENCE_TYPES,
    )

    # Missing DMARC
    if observed.dmarc_available and dmarc_projection.exact_empty:
        gaps.append(
            _gap(
                rule_id="guidance.email.dmarc.missing.v1",
                state="bounded_non_observation",
                scope=("dns:dmarc",),
                dependencies=(_dependency("dmarc_policy", "is_none", None, dmarc_projection.policy),),
                category="email",
                severity="high",
                observation="No valid DMARC policy record observed for this domain",
                recommendation="Consider configuring a DMARC record to protect against email spoofing",
            )
        )

    # Invalid, conflicting, or otherwise unbound DMARC material is an observed
    # unresolved state, not a bounded absence and not support for a specific
    # policy claim.
    if (
        observed.dmarc_available
        and dmarc_projection.construction_state in {ConstructionState.INCOMPLETE, ConstructionState.INVALID}
        and dmarc_observation_evidence
    ):
        invalid = dmarc_projection.construction_state is ConstructionState.INVALID
        gaps.append(
            _gap(
                rule_id=(
                    "guidance.email.dmarc.invalid-observation.v1"
                    if invalid
                    else "guidance.email.dmarc.ambiguous-observation.v1"
                ),
                state=("observed_weak_configuration" if invalid else "observed_configuration_inconsistency"),
                scope=("dns:dmarc",),
                dependencies=(
                    _dependency(
                        "dmarc_construction_state",
                        "eq",
                        dmarc_projection.construction_state.value,
                        dmarc_projection.construction_state.value,
                    ),
                ),
                category="email",
                severity="high",
                observation=(
                    "Retained DMARC record evidence did not form one valid policy observation"
                    if invalid
                    else "Retained DMARC evidence and derived policy state did not form one unambiguous observation"
                ),
                recommendation="Consider reviewing the published DMARC record set and policy tags",
                evidence=dmarc_observation_evidence,
            )
        )

    # DMARC not effectively enforcing.
    if (
        observed.dmarc_available
        and dmarc_projection.exact_value
        and dmarc_effective_policy == "none"
        and dmarc_evidence
    ):
        observation = (
            "DMARC policy is set to 'none' (monitoring only)"
            if dmarc_projection.policy == "none"
            else "DMARC policy is not effectively enforcing after rollout or testing tags"
        )
        if dmarc_projection.policy == "none":
            rule_id = "guidance.email.dmarc.monitoring.v1"
            dependencies = (_dependency("dmarc_policy", "eq", "none", dmarc_projection.policy),)
        else:
            rule_id = "guidance.email.dmarc.not-effectively-enforcing.v1"
            dependencies = (
                _dependency("dmarc_policy", "neq", "none", dmarc_projection.policy),
                _dependency("effective_dmarc_policy", "eq", "none", dmarc_effective_policy),
            )
        gaps.append(
            _gap(
                rule_id=rule_id,
                state="observed_weak_configuration",
                scope=("dns:dmarc",),
                dependencies=dependencies,
                category="email",
                severity="high",
                observation=observation,
                recommendation="Consider setting DMARC policy to quarantine or reject",
                evidence=dmarc_evidence,
            )
        )

    # DMARC quarantine-level enforcement (not reject-level enforcement).
    if dmarc_projection.exact_value and dmarc_effective_policy == "quarantine" and dmarc_evidence:
        gaps.append(
            _gap(
                rule_id="guidance.email.dmarc.quarantine.v1",
                state="observed_weak_configuration",
                scope=("dns:dmarc",),
                dependencies=(_dependency("effective_dmarc_policy", "eq", "quarantine", dmarc_effective_policy),),
                category="email",
                severity="medium",
                observation="Effective DMARC policy is quarantine, not reject",
                recommendation="Consider upgrading DMARC policy from quarantine to reject for stronger enforcement",
                evidence=dmarc_evidence,
            )
        )

    # Missing DKIM
    dkim_present = bool(services_set & {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE})
    if observed.dkim_available and not dkim_present:
        gaps.append(
            _gap(
                rule_id="guidance.email.dkim.common-selectors-not-observed.v1",
                state="unresolved_hideable_state",
                scope=("dns:dkim_common_selectors",),
                dependencies=(_dependency("dkim_observed_at_common_selectors", "eq", False, dkim_present),),
                category="email",
                severity="medium",
                observation="No DKIM selectors observed at common names for this domain",
                recommendation=(
                    "Consider verifying DKIM signing through an authoritative configuration source; "
                    "selector names are operator chosen"
                ),
                # DKIM uses operator-chosen selectors; absence at the common
                # names recon probes does not establish absence of DKIM.
                absence_confirmable=False,
            )
        )

    # No MTA-STS activation record. Without a valid TXT declaration, the HTTP
    # policy request is intentionally not attempted and is not part of scope.
    mta_sts_txt_refs = mta_sts_txt_evidence(info)
    mta_sts_policy_evidence = tuple(
        record for record in info.evidence if record.source_type.upper() == "MTA_STS_POLICY"
    )
    dns_mta_sts_available = hardening_scopes_available(("dns:mta_sts",), info.degraded_sources)
    mta_sts_policy_scopes_available = hardening_scopes_available(
        ("dns:mta_sts", "http:mta_sts_policy"), info.degraded_sources
    )
    if dns_mta_sts_available and info.mta_sts_mode is None and not mta_sts_txt_refs:
        gaps.append(
            _gap(
                rule_id="guidance.email.mta-sts.missing.v1",
                state="bounded_non_observation",
                scope=("dns:mta_sts",),
                dependencies=(_dependency("mta_sts_txt_observed", "eq", False, bool(mta_sts_txt_refs)),),
                category="email",
                severity="medium",
                observation="No valid MTA-STS TXT declaration observed for this domain",
                recommendation="Consider reviewing whether to publish an MTA-STS policy declaration",
            )
        )

    # A valid TXT declaration activates the HTTP observation. A stable HTTP
    # response without one valid mode is distinct from the DNS-only absence.
    if (
        mta_sts_policy_scopes_available
        and info.mta_sts_mode is None
        and mta_sts_txt_refs
        and not mta_sts_policy_evidence
    ):
        gaps.append(
            _gap(
                rule_id="guidance.email.mta-sts.policy-not-observed.v1",
                state="bounded_non_observation",
                scope=("dns:mta_sts", "http:mta_sts_policy"),
                dependencies=(
                    _dependency("mta_sts_txt_observed", "eq", True, bool(mta_sts_txt_refs)),
                    _dependency("mta_sts_mode", "is_none", None, info.mta_sts_mode),
                ),
                category="email",
                severity="medium",
                observation="MTA-STS TXT declaration observed without a valid policy mode",
                recommendation="Consider reviewing the published MTA-STS policy document",
                evidence=mta_sts_txt_refs,
            )
        )

    # MTA-STS declared but not in effect. RFC 8461 mode "none" states the
    # policy is not in effect, so the control is off even though a record and
    # policy file are published; without this gap a declared-off policy
    # looked better than never deploying MTA-STS at all.
    mta_sts_evidence = mta_sts_mode_evidence(info, "none")
    has_none_policy_evidence = any(ref.source_type.upper() == "MTA_STS_POLICY" for ref in mta_sts_evidence)
    if mta_sts_policy_scopes_available and info.mta_sts_mode == "none" and has_none_policy_evidence:
        gaps.append(
            _gap(
                rule_id="guidance.email.mta-sts.mode-none.v1",
                state="observed_weak_configuration",
                scope=("dns:mta_sts", "http:mta_sts_policy"),
                dependencies=(_dependency("mta_sts_mode", "eq", "none", info.mta_sts_mode),),
                category="email",
                severity="medium",
                observation="MTA-STS policy is published with mode none, so it is not in effect",
                recommendation="Consider upgrading MTA-STS policy from none to testing or enforce",
                evidence=mta_sts_evidence,
            )
        )

    # Missing TLS-RPT
    tls_rpt_present = any(
        record.source_type.upper() == "TXT" and record.rule_name == _TLS_RPT_RULE_NAME and record.slug == "tls-rpt"
        for record in info.evidence
    )
    if observed.tls_rpt_available and not tls_rpt_present:
        gaps.append(
            _gap(
                rule_id="guidance.email.tls-rpt.missing.v1",
                state="bounded_non_observation",
                scope=("dns:tls_rpt",),
                dependencies=(_dependency("tls_rpt_record_observed", "eq", False, tls_rpt_present),),
                category="email",
                severity="low",
                observation="No TLS-RPT record detected for this domain",
                recommendation="Consider configuring TLS-RPT to receive email transport failure reports",
            )
        )

    # Missing CAA
    caa_evidence_slugs = _evidence_slugs(info, frozenset({"CAA"}))
    if observed.caa_available and not caa_evidence_slugs:
        gaps.append(
            _gap(
                rule_id="guidance.infrastructure.caa.missing.v1",
                state="bounded_non_observation",
                scope=("dns:caa",),
                dependencies=(_dependency("caa_record_observed", "eq", False, bool(caa_evidence_slugs)),),
                category="infrastructure",
                severity="low",
                observation="No CAA records detected for this domain",
                recommendation=(
                    "Consider adding CAA records to restrict which certificate authorities can issue certificates"
                ),
            )
        )

    return gaps


def detect_weak_configs(info: TenantInfo) -> list[HardeningGap]:
    """Detect weak but present configurations."""
    services_set = observed_email_control_services(info.evidence)
    gaps: list[HardeningGap] = []

    observed = observability.ObservableEmailState.from_info(info)

    # SPF softfail (without strict)
    has_softfail = SVC_SPF_SOFTFAIL in services_set
    has_strict = SVC_SPF_STRICT in services_set
    spf_evidence = _build_evidence_refs(
        info,
        {"spf-softfail"},
        source_types=_SPF_EVIDENCE_TYPES,
    )
    if observed.spf_available and has_softfail and not has_strict and spf_evidence:
        gaps.append(
            _gap(
                rule_id="guidance.email.spf.softfail.v1",
                state="observed_weak_configuration",
                scope=("dns:apex_txt",),
                dependencies=(
                    _dependency("spf_softfail_observed", "eq", True, has_softfail),
                    _dependency("spf_strict_observed", "eq", False, has_strict),
                ),
                category="email",
                severity="medium",
                observation="SPF policy uses softfail (~all) instead of hardfail (-all)",
                recommendation="Consider changing SPF policy from ~all (softfail) to -all (hardfail)",
                evidence=spf_evidence,
            )
        )

    # MTA-STS testing (not enforce)
    mta_sts_evidence = mta_sts_mode_evidence(info, "testing")
    has_testing_policy_evidence = any(ref.source_type.upper() == "MTA_STS_POLICY" for ref in mta_sts_evidence)
    if (
        hardening_scopes_available(("dns:mta_sts", "http:mta_sts_policy"), info.degraded_sources)
        and info.mta_sts_mode == "testing"
        and has_testing_policy_evidence
    ):
        gaps.append(
            _gap(
                rule_id="guidance.email.mta-sts.testing.v1",
                state="observed_weak_configuration",
                scope=("dns:mta_sts", "http:mta_sts_policy"),
                dependencies=(_dependency("mta_sts_mode", "eq", "testing", info.mta_sts_mode),),
                category="email",
                severity="low",
                observation="MTA-STS policy is in testing mode, not enforce",
                recommendation="Consider upgrading MTA-STS policy from testing to enforce",
                evidence=mta_sts_evidence,
            )
        )

    return gaps


def detect_inconsistencies(info: TenantInfo) -> list[HardeningGap]:
    """Detect configuration inconsistencies."""
    observed = observability.ObservableEmailState.from_info(info)
    gaps: list[HardeningGap] = []

    # Gateway without DMARC enforcement
    gateway_slugs = _evidence_slugs(info, frozenset({"MX"})) & set(EMAIL_GATEWAY_SLUGS)
    evidence_gateway_name = (
        " + ".join(sorted({EMAIL_GATEWAY_SLUGS[slug] for slug in gateway_slugs})) if gateway_slugs else None
    )
    matching_gateway_slugs = gateway_slugs if evidence_gateway_name == info.email_gateway else set()
    gateway_evidence = _build_evidence_refs(
        info,
        matching_gateway_slugs,
        source_types=_MX_EVIDENCE_TYPES,
    )
    dmarc_evidence = _build_evidence_refs(
        info,
        {"dmarc"},
        source_types=_DMARC_EVIDENCE_TYPES,
    )
    dmarc_projection = dmarc_policy_projection(info)
    effective_policy = dmarc_projection.effective_policy
    dmarc_basis_available = dmarc_projection.exact_empty or dmarc_projection.exact_value
    if (
        evidence_gateway_name is not None
        and gateway_evidence
        and info.email_gateway is not None
        and observed.gateway_available
        and observed.dmarc_available
        and effective_policy != "reject"
        and dmarc_basis_available
    ):
        gaps.append(
            _gap(
                rule_id="guidance.consistency.gateway-without-dmarc-reject.v1",
                state="observed_configuration_inconsistency",
                scope=("dns:mx", "dns:dmarc"),
                dependencies=(
                    _dependency("gateway_mx_observed", "eq", True, bool(gateway_evidence)),
                    _dependency(
                        "email_gateway",
                        "eq",
                        evidence_gateway_name,
                        info.email_gateway,
                    ),
                    _dependency("effective_dmarc_policy", "neq", "reject", effective_policy),
                ),
                category="consistency",
                severity="high",
                observation=f"MX gateway ({info.email_gateway}) observed without DMARC reject enforcement",
                recommendation="Consider reviewing DMARC enforcement alongside the observed email gateway",
                evidence=tuple(dict.fromkeys((*gateway_evidence, *dmarc_evidence))),
            )
        )

    return gaps


# ── Public API: find_gaps_from_info ────────────────────────────────────

GAPS_DISCLAIMER = (
    "These configuration gaps are neutral review prompts derived from recon's bounded public observations. "
    "They are not an overall security assessment. Unobserved controls may exist "
    "outside the documented scope, and unavailable collection channels produce no absence conclusion."
)
