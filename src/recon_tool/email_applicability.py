"""Retained declarations that bound mail-control applicability, without I/O."""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.claim_contract import dmarc_policy_projection
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.source_status import SourceStatus
from recon_tool.sources.dns_tables import is_null_mx_set, is_spf_record, select_spf_record


@dataclass(frozen=True)
class MailApplicability:
    """Exact available proof of declared no-inbound and no-mail policies.

    These are published declarations for the queried namespace. They do not
    establish delivery behavior, actual sending, or policy for other domains.
    """

    inbound_evidence: tuple[EvidenceRecord, ...] = ()
    outbound_evidence: tuple[EvidenceRecord, ...] = ()

    @property
    def inbound_not_applicable(self) -> bool:
        return bool(self.inbound_evidence)

    @property
    def outbound_not_applicable(self) -> bool:
        return bool(self.outbound_evidence)

    def evidence_for(self, control: str) -> tuple[EvidenceRecord, ...]:
        """Return the declaration proof that makes one mail control inapplicable."""
        if control in {"MTA-STS", "TLS-RPT", "Email gateway"}:
            return self.inbound_evidence
        if control in {"DKIM", "BIMI"}:
            return self.outbound_evidence
        return ()


def mail_applicability(info: TenantInfo) -> MailApplicability:
    """Bind applicability only to complete, available, role-bearing evidence."""
    status = SourceStatus.from_degraded_sources(info.degraded_sources)
    mx = tuple(record for record in info.evidence if record.source_type.upper() == "MX")
    if (
        not status.channel_available("mx")
        or not any(record.slug == "null-mx" for record in mx)
        or not is_null_mx_set(record.raw_value for record in mx)
    ):
        return MailApplicability()
    inbound = tuple(dict.fromkeys(mx))
    if not status.channel_available("apex_txt"):
        return MailApplicability(inbound)
    spf = tuple(
        record for record in info.evidence if record.source_type.upper() == "SPF" and is_spf_record(record.raw_value)
    )
    # One wire policy can carry multiple fingerprint rows. A live competing
    # SPF set is never admitted with the canonical spf-strict policy label.
    selected = select_spf_record(dict.fromkeys(record.raw_value for record in spf))
    if (
        selected is None
        or tuple(term for term in selected.lower().split(" ") if term) != ("v=spf1", "-all")
        or not any(record.slug == "spf-strict" and record.raw_value == selected for record in spf)
        or any(record.slug == "spf" for record in spf)
    ):
        return MailApplicability(inbound)
    dmarc = dmarc_policy_projection(info)
    if dmarc.effective_policy not in {"quarantine", "reject"}:
        return MailApplicability(inbound)
    return MailApplicability(inbound, tuple(dict.fromkeys((*inbound, *spf, *dmarc.evidence))))
