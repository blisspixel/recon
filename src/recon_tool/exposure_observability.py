"""Collection-aware email state for exposure reporting."""

from __future__ import annotations

from dataclasses import dataclass

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DKIM_GOOGLE,
    SVC_MTA_STS,
    SVC_SPF_SOFTFAIL,
    SVC_SPF_STRICT,
    effective_dmarc_policy,
    email_security_score,
)
from recon_tool.email_security import observed_email_control_services
from recon_tool.models import TenantInfo
from recon_tool.source_status import SourceStatus


@dataclass(frozen=True, slots=True)
class ObservableEmailState:
    """Email values after unavailable channels have been masked."""

    dmarc_available: bool
    dkim_available: bool
    spf_available: bool
    mta_sts_available: bool
    bimi_available: bool
    tls_rpt_available: bool
    caa_available: bool
    gateway_available: bool
    dmarc_policy: str | None
    effective_dmarc_policy: str | None
    mta_sts_mode: str | None
    security_score: int

    @classmethod
    def from_info(cls, info: TenantInfo) -> ObservableEmailState:
        status = SourceStatus.from_degraded_sources(info.degraded_sources)
        dmarc_available = status.channel_available("dmarc")
        dkim_available = status.channel_available("dkim")
        spf_available = status.channel_available("apex_txt")
        mta_sts_available = status.channel_available("mta_sts")
        bimi_available = status.channel_available("bimi")
        tls_rpt_available = status.channel_available("tls_rpt")
        caa_available = status.channel_available("caa")
        gateway_available = status.channel_available("mx")
        policy = info.dmarc_policy if dmarc_available else None
        services = observed_email_control_services(info.evidence)
        if not dkim_available:
            services.difference_update({SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE})
        if not spf_available:
            services.difference_update({SVC_SPF_STRICT, SVC_SPF_SOFTFAIL})
        if not mta_sts_available:
            services.discard(SVC_MTA_STS)
        # RFC 8461 mode "none" means the policy is not in effect, so the
        # fetched mode revokes the credit the TXT record earned. The evidence
        # projection already withholds it when the policy record is retained;
        # this guard keeps the scalar authoritative when they disagree.
        if mta_sts_available and info.mta_sts_mode == "none":
            services.discard(SVC_MTA_STS)
        if not bimi_available:
            services.discard(SVC_BIMI)
        effective_policy = effective_dmarc_policy(
            policy,
            info.dmarc_pct if dmarc_available else None,
            info.dmarc_testing if dmarc_available else False,
        )
        score = email_security_score(
            services,
            policy,
            info.dmarc_pct if dmarc_available else None,
            info.dmarc_testing if dmarc_available else False,
        )
        return cls(
            dmarc_available=dmarc_available,
            dkim_available=dkim_available,
            spf_available=spf_available,
            mta_sts_available=mta_sts_available,
            bimi_available=bimi_available,
            tls_rpt_available=tls_rpt_available,
            caa_available=caa_available,
            gateway_available=gateway_available,
            dmarc_policy=policy,
            effective_dmarc_policy=effective_policy,
            mta_sts_mode=info.mta_sts_mode if mta_sts_available else None,
            security_score=score,
        )

    def unavailable_control_names(self) -> tuple[str, ...]:
        """Return public controls whose collection channel was unavailable."""
        availability = (
            ("DMARC", self.dmarc_available),
            ("DKIM", self.dkim_available),
            ("SPF", self.spf_available),
            ("MTA-STS", self.mta_sts_available),
            ("BIMI", self.bimi_available),
            ("TLS-RPT", self.tls_rpt_available),
            ("CAA", self.caa_available),
            ("Email gateway", self.gateway_available),
        )
        return tuple(name for name, available in availability if not available)

    @property
    def score_collection_available(self) -> bool:
        """Whether every channel contributing to the 0-5 email count was observed."""
        return all(
            (
                self.dmarc_available,
                self.dkim_available,
                self.spf_available,
                self.mta_sts_available,
                self.bimi_available,
            )
        )
