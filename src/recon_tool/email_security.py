"""Email-security and signal-context helpers shared across output surfaces."""

from __future__ import annotations

from recon_tool.models import SignalContext, TenantInfo


def compute_email_security_score(info: TenantInfo) -> int:
    """Compute the email security score surfaced in JSON and CSV output.

    DMARC is credited only when the effective policy is enforcing
    (``reject`` or ``quarantine`` after ``pct=`` and ``t=`` downgrades). A
    monitoring-only ``p=none`` record does not count. Delta mode reuses this
    helper so it compares like with like against a prior export.
    """
    from recon_tool.constants import email_security_score

    return email_security_score(
        info.services,
        info.dmarc_policy,
        info.dmarc_pct,
        info.dmarc_testing,
    )


def signal_context_from_tenant_info(info: TenantInfo) -> SignalContext:
    """Build the canonical signal metadata context for a resolved tenant.

    CLI explanation and MCP tools evaluate signals outside the merge pipeline.
    Keeping this helper beside the canonical email-security score prevents those
    surfaces from drifting when signal metadata gains new derived fields.
    """
    from recon_tool.constants import effective_dmarc_policy
    from recon_tool.merger import extract_spf_include_count

    return SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=info.dmarc_policy,
        dmarc_effective_policy=effective_dmarc_policy(
            info.dmarc_policy,
            info.dmarc_pct,
            info.dmarc_testing,
        ),
        auth_type=info.auth_type,
        email_security_score=compute_email_security_score(info),
        spf_include_count=extract_spf_include_count(set(info.services)),
        issuance_velocity=info.cert_summary.issuance_velocity if info.cert_summary is not None else None,
        dmarc_pct=info.dmarc_pct,
        primary_email_provider=info.primary_email_provider,
        likely_primary_email_provider=info.likely_primary_email_provider,
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
