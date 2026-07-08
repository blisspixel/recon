"""Email-security scoring helpers shared by renderers and delta logic."""

from __future__ import annotations

from recon_tool.models import TenantInfo


def compute_email_security_score(info: TenantInfo) -> int:
    """Compute the email security score surfaced in JSON and CSV output.

    DMARC is credited only when the published policy is enforcing
    (``reject`` or ``quarantine``). A monitoring-only ``p=none`` record does not
    count. Delta mode reuses this helper so it compares like with like against a
    prior export.
    """
    from recon_tool.constants import email_security_score

    return email_security_score(info.services, info.dmarc_policy)

