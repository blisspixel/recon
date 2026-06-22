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
    email_security_score,
)
from recon_tool.exposure import _compute_email_security_score
from recon_tool.formatter_serialize import compute_email_security_score
from recon_tool.models import ConfidenceLevel, TenantInfo
from recon_tool.posture import _compute_metadata_value


def _info(services: set[str], dmarc_policy: str | None) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Test Corp",
        default_domain="test.onmicrosoft.com",
        queried_domain="test.com",
        confidence=ConfidenceLevel.HIGH,
        sources=("test_source",),
        services=tuple(services),
        slugs=(),
        dmarc_policy=dmarc_policy,
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
