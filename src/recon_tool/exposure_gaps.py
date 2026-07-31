"""Hardening-gap detection over resolved TenantInfo data.

Split out of ``exposure.py`` to keep that module under the size guard in
``docs/engineering-practices.md``. These three detectors are the only producers
of ``HardeningGap``; ``exposure.find_gaps_from_info`` composes them and owns the
collection-aware projection and disclaimer. Generated prose stays neutral and
hedged, so every observation and recommendation string routes through
``_check_neutral_copy``.
"""

from __future__ import annotations

from recon_tool import exposure_observability as observability
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
from recon_tool.exposure_models import HardeningGap
from recon_tool.models import TenantInfo

__all__ = [
    "EMAIL_GATEWAY_SLUGS",
    "GAPS_DISCLAIMER",
    "detect_inconsistencies",
    "detect_missing_controls",
    "detect_weak_configs",
    "effective_email_dmarc_policy",
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

def effective_email_dmarc_policy(info: TenantInfo) -> str | None:
    return observability.ObservableEmailState.from_info(info).effective_dmarc_policy


def detect_missing_controls(info: TenantInfo) -> list[HardeningGap]:
    """Detect absent security controls."""
    observed = observability.ObservableEmailState.from_info(info)
    services_set = observed_email_control_services(info.evidence)
    slugs_set = set(info.slugs)
    gaps: list[HardeningGap] = []
    dmarc_effective_policy = effective_email_dmarc_policy(info)

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

    # MTA-STS declared but not in effect. RFC 8461 mode "none" states the
    # policy is not in effect, so the control is off even though a record and
    # policy file are published; without this gap a declared-off policy
    # looked better than never deploying MTA-STS at all.
    if observed.mta_sts_available and info.mta_sts_mode == "none":
        gaps.append(
            HardeningGap(
                category="email",
                severity="medium",
                observation=_check_neutral_copy("MTA-STS policy is published with mode none, so it is not in effect"),
                recommendation=_check_neutral_copy("Consider upgrading MTA-STS policy from none to testing or enforce"),
                evidence=_build_evidence_refs(info, {"mta-sts"} & slugs_set),
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


def detect_weak_configs(info: TenantInfo) -> list[HardeningGap]:
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


def detect_inconsistencies(info: TenantInfo) -> list[HardeningGap]:
    """Detect configuration inconsistencies."""
    observed = observability.ObservableEmailState.from_info(info)
    gaps: list[HardeningGap] = []

    # Gateway without DMARC enforcement
    gateway_slugs = _evidence_slugs(info, frozenset({"MX"})) & set(EMAIL_GATEWAY_SLUGS)
    if (
        gateway_slugs
        and info.email_gateway is not None
        and observed.gateway_available
        and observed.dmarc_available
        and effective_email_dmarc_policy(info) != "reject"
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

GAPS_DISCLAIMER = (
    "These observations identify publicly visible configuration gaps that "
    "the domain owner may wish to review. They are based on industry best "
    "practices for email security, identity management, and DNS hygiene."
)
