"""Email-security score: one definition, shared by every surface.

Regression coverage for the score-divergence bug: DKIM was double-counted
(``SVC_DKIM`` and ``SVC_DKIM_EXCHANGE`` both scored) and raw ``SVC_DMARC``
presence was credited instead of an enforcing policy, in five places that
disagreed with the canonical ``email_security_score`` used for the JSON field.
"""

from __future__ import annotations

import pytest

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DKIM_EXCHANGE,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
    effective_dmarc_policy,
    email_security_score,
)
from recon_tool.email_security import signal_context_from_tenant_info, signal_context_metadata
from recon_tool.exposure import _compute_email_security_score
from recon_tool.formatter_serialize import compute_email_security_score
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo
from recon_tool.posture import _compute_metadata_value
from recon_tool.signals import evaluate_signals

GATEWAY_GAP_SIGNAL = "Security Gap \u2014 Gateway Without DMARC Enforcement"


def _info(
    services: set[str],
    dmarc_policy: str | None,
    *,
    dmarc_pct: int | None = None,
    dmarc_testing: bool = False,
    slugs: tuple[str, ...] = (),
    likely_primary_email_provider: str | None = None,
    spf_include_count: int = 0,
) -> TenantInfo:
    evidence: list[EvidenceRecord] = []
    for service in services:
        if service in {SVC_DKIM, SVC_DKIM_EXCHANGE}:
            slug = "microsoft365" if service == SVC_DKIM_EXCHANGE else "dkim"
            evidence.append(EvidenceRecord("DKIM", "selector response", service, slug))
        elif service == SVC_SPF_STRICT:
            evidence.append(EvidenceRecord("SPF", "v=spf1 -all", service, "spf-strict"))
        elif service == SVC_MTA_STS:
            evidence.append(EvidenceRecord("MTA_STS", "v=STSv1", service, "mta-sts"))
        elif service == SVC_BIMI:
            evidence.append(EvidenceRecord("BIMI", "v=BIMI1", service, "bimi"))
    return TenantInfo(
        tenant_id=None,
        display_name="Test Corp",
        default_domain="test.onmicrosoft.com",
        queried_domain="test.invalid",
        confidence=ConfidenceLevel.HIGH,
        sources=("test_source",),
        services=tuple(services),
        slugs=slugs,
        dmarc_policy=dmarc_policy,
        dmarc_pct=dmarc_pct,
        dmarc_testing=dmarc_testing,
        likely_primary_email_provider=likely_primary_email_provider,
        evidence=tuple(evidence),
        spf_include_count=spf_include_count,
    )


class TestCanonicalScore:
    def test_dkim_counted_once_when_both_variants_present(self) -> None:
        both = {SVC_DKIM, SVC_DKIM_EXCHANGE}
        assert email_security_score(both, None) == 1
        assert email_security_score({SVC_DKIM}, None) == 1
        assert email_security_score({SVC_DKIM_EXCHANGE}, None) == 1

    def test_dmarc_counts_only_when_enforcing(self) -> None:
        assert email_security_score({SVC_DMARC}, "reject") == 1
        assert email_security_score({SVC_DMARC}, "quarantine") == 1
        # Mere SVC_DMARC presence with a non-enforcing / absent policy scores 0.
        assert email_security_score({SVC_DMARC}, "none") == 0
        assert email_security_score({SVC_DMARC}, None) == 0

    def test_dmarc_testing_mode_steps_effective_policy_down(self) -> None:
        assert effective_dmarc_policy("reject", dmarc_testing=True) == "quarantine"
        assert effective_dmarc_policy("quarantine", dmarc_testing=True) == "none"
        assert effective_dmarc_policy("none", dmarc_testing=True) == "none"
        assert email_security_score({SVC_DMARC}, "reject", dmarc_testing=True) == 1
        assert email_security_score({SVC_DMARC}, "quarantine", dmarc_testing=True) == 0

    @pytest.mark.parametrize(
        ("policy", "pct", "testing", "effective", "score"),
        [
            ("reject", 50, True, "none", 0),
            ("reject", 100, True, "quarantine", 1),
            ("quarantine", 50, True, "none", 0),
        ],
    )
    def test_dmarc_pct_and_testing_compose(
        self,
        policy: str,
        pct: int,
        testing: bool,
        effective: str,
        score: int,
    ) -> None:
        assert effective_dmarc_policy(policy, pct, testing) == effective
        assert email_security_score({SVC_DMARC}, policy, pct, testing) == score

    def test_full_stack_maxes_at_five(self) -> None:
        services = {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI}
        assert email_security_score(services, "reject") == 5

    def test_empty_is_zero(self) -> None:
        assert email_security_score(set(), None) == 0


class TestAllSurfacesAgree:
    @pytest.mark.parametrize(
        ("services", "policy"),
        [
            ({SVC_DKIM, SVC_DKIM_EXCHANGE}, "reject"),
            ({SVC_DMARC, SVC_DKIM, SVC_SPF_STRICT}, "none"),
            ({SVC_DMARC, SVC_DKIM_EXCHANGE, SVC_MTA_STS, SVC_BIMI}, "quarantine"),
            (set(), None),
        ],
    )
    def test_serialize_exposure_posture_match(self, services: set[str], policy: str | None) -> None:
        info = _info(services, policy)
        expected = email_security_score(services, policy)
        assert compute_email_security_score(info) == expected
        assert _compute_email_security_score(info) == expected
        assert _compute_metadata_value("email_security_score", info) == expected

    def test_testing_mode_agrees_across_surfaces(self) -> None:
        info = _info({SVC_DMARC}, "quarantine", dmarc_testing=True)
        assert compute_email_security_score(info) == 0
        assert _compute_email_security_score(info) == 0
        assert _compute_metadata_value("email_security_score", info) == 0


class TestSignalContextFromTenantInfo:
    def test_enforcing_policy_reaches_gateway_gap_signal_context(self) -> None:
        info = _info(
            {SVC_DMARC, "SPF complexity: 5 includes"},
            "reject",
            slugs=("proofpoint",),
            likely_primary_email_provider="Microsoft 365",
            spf_include_count=5,
        )
        context = signal_context_from_tenant_info(info)
        metadata = signal_context_metadata(context)
        names = {match.name for match in evaluate_signals(context)}
        assert context.dmarc_effective_policy == "reject"
        assert metadata["dmarc_effective_policy"] == "reject"
        assert metadata["spf_include_count"] == 5
        assert metadata["likely_primary_email_provider"] == "Microsoft 365"
        assert GATEWAY_GAP_SIGNAL not in names

    def test_testing_mode_downgrade_reaches_gateway_gap_signal_context(self) -> None:
        info = _info({SVC_DMARC}, "quarantine", dmarc_testing=True, slugs=("proofpoint",))
        context = signal_context_from_tenant_info(info)
        names = {match.name for match in evaluate_signals(context)}
        assert context.dmarc_effective_policy == "none"
        assert GATEWAY_GAP_SIGNAL in names
