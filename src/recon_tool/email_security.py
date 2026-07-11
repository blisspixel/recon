"""Email-security and signal-context helpers shared across output surfaces."""

from __future__ import annotations

from collections.abc import Iterable

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
)
from recon_tool.models import EvidenceRecord, SignalContext, TenantInfo

_EMAIL_CONTROL_SERVICES = frozenset(
    {
        SVC_DMARC,
        SVC_DKIM,
        SVC_DKIM_EXCHANGE,
        SVC_DKIM_GOOGLE,
        SVC_SPF_STRICT,
        SVC_SPF_SOFTFAIL,
        SVC_MTA_STS,
        SVC_BIMI,
    }
)


def observed_email_control_services(evidence: Iterable[EvidenceRecord]) -> set[str]:
    """Project evidence into only the email controls its record type proves."""
    controls: set[str] = set()
    for record in evidence:
        source_type = record.source_type.upper()
        if source_type == "DMARC" and record.slug == "dmarc":
            controls.add(SVC_DMARC)
        elif source_type == "DKIM":
            controls.add(record.rule_name if record.rule_name in _EMAIL_CONTROL_SERVICES else SVC_DKIM)
        elif source_type == "SPF" and record.slug == "spf-strict":
            controls.add(SVC_SPF_STRICT)
        elif source_type == "SPF" and record.slug == "spf-softfail":
            controls.add(SVC_SPF_SOFTFAIL)
        elif source_type in {"MTA_STS", "MTA_STS_POLICY"}:
            controls.add(SVC_MTA_STS)
        elif source_type == "BIMI":
            controls.add(SVC_BIMI)
    return controls


def claim_safe_email_services(
    services: Iterable[str],
    evidence: Iterable[EvidenceRecord],
) -> set[str]:
    """Replace name-based email-control claims with record-role evidence.

    Catalog and ephemeral fingerprint names are user-extensible. They may be
    useful inventory labels, but a matching label cannot stand in for a DMARC,
    DKIM, SPF, MTA-STS, or BIMI record. This projection preserves every
    non-control service and reconstructs the control subset from typed evidence.
    """
    projected = set(services)
    projected.difference_update(_EMAIL_CONTROL_SERVICES)
    projected.update(observed_email_control_services(evidence))
    return projected


def compute_email_security_score(info: TenantInfo) -> int:
    """Compute the email security score surfaced in JSON and CSV output.

    DMARC is credited only when the effective policy is enforcing
    (``reject`` or ``quarantine`` after ``pct=`` and ``t=`` downgrades). A
    monitoring-only ``p=none`` record does not count. Delta mode reuses this
    helper so it compares like with like against a prior export.
    """
    from recon_tool.exposure_observability import ObservableEmailState

    return ObservableEmailState.from_info(info).security_score


def signal_context_from_tenant_info(info: TenantInfo) -> SignalContext:
    """Build the canonical signal metadata context for a resolved tenant.

    CLI explanation and MCP tools evaluate signals outside the merge pipeline.
    Keeping this helper beside the canonical email-security score prevents those
    surfaces from drifting when signal metadata gains new derived fields.
    """
    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)
    return signal_context_from_observable_info(info)


def signal_context_from_observable_info(info: TenantInfo) -> SignalContext:
    """Build signal context from an already collection-projected TenantInfo."""
    from recon_tool.exposure_observability import ObservableEmailState
    from recon_tool.source_status import SourceStatus

    observed = ObservableEmailState.from_info(info)
    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    unavailable_fields: set[str] = set()
    if status.channel_unavailable("dmarc"):
        unavailable_fields.update({"dmarc_policy", "dmarc_effective_policy", "dmarc_pct"})
    if status.channel_unavailable("apex_txt"):
        unavailable_fields.add("spf_include_count")
    if status.channel_unavailable("mx"):
        unavailable_fields.update({"primary_email_provider", "likely_primary_email_provider"})
    if any(status.channel_unavailable(channel) for channel in ("dmarc", "dkim", "apex_txt", "mta_sts", "bimi")):
        unavailable_fields.add("email_security_score")
    return SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=observed.dmarc_policy,
        dmarc_effective_policy=observed.effective_dmarc_policy,
        auth_type=info.auth_type,
        email_security_score=compute_email_security_score(info),
        spf_include_count=info.spf_include_count if observed.spf_available else 0,
        issuance_velocity=info.cert_summary.issuance_velocity if info.cert_summary is not None else None,
        dmarc_pct=info.dmarc_pct if observed.dmarc_available else None,
        primary_email_provider=info.primary_email_provider,
        likely_primary_email_provider=info.likely_primary_email_provider,
        unavailable_metadata_fields=frozenset(unavailable_fields),
    )


def signal_context_metadata(context: SignalContext) -> dict[str, object]:
    """Return explanation metadata using the same fields signal evaluation sees."""
    return {
        "dmarc_policy": context.dmarc_policy,
        "dmarc_effective_policy": context.dmarc_effective_policy,
        "auth_type": context.auth_type,
        "email_security_score": context.email_security_score,
        "spf_include_count": context.spf_include_count,
        "issuance_velocity": context.issuance_velocity,
        "dmarc_pct": context.dmarc_pct,
        "primary_email_provider": context.primary_email_provider,
        "likely_primary_email_provider": context.likely_primary_email_provider,
    }
