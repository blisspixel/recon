"""Shared test fixtures.

Auto-patches the cert intel HTTP calls in all non-integration tests to avoid
real network calls and timeouts per test. Also resets the global Rich Console
between tests so CliRunner-based tests get a fresh stdout binding rather than
inheriting a stale one from earlier tests that called set_console().
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from recon_tool.models import (
    BIMIIdentity,
    CandidateValue,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    TenantInfo,
)


@pytest.fixture
def fully_populated_tenant_info() -> TenantInfo:
    """A TenantInfo with every documented v1.0 stable field populated.

    Shared between the schema-contract tests and the schema-file drift tests.
    Keep in sync with ``docs/schema.md`` and ``docs/recon-schema.json``.
    """
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Contoso Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("oidc_discovery", "userrealm", "dns_records"),
        services=("Microsoft 365", "Slack"),
        slugs=("microsoft365", "slack"),
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=3,
        tenant_domains=("contoso.com", "contoso.onmicrosoft.com", "contoso.co.uk"),
        related_domains=("api.contoso.com", "login.contoso.com"),
        insights=("Email security 4/5 strong (DMARC reject, DKIM, SPF strict, MTA-STS)",),
        degraded_sources=(),
        cert_summary=CertSummary(
            cert_count=42,
            issuer_diversity=3,
            issuance_velocity=7,
            newest_cert_age_days=2,
            oldest_cert_age_days=365,
            top_issuers=("Let's Encrypt", "DigiCert", "Sectigo"),
        ),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="v=spf1 include:spf.protection.outlook.com ~all",
                rule_name="SPF M365",
                slug="microsoft365",
            ),
        ),
        evidence_confidence=ConfidenceLevel.HIGH,
        inference_confidence=ConfidenceLevel.HIGH,
        detection_scores=(("microsoft365", "high"), ("slack", "medium")),
        bimi_identity=BIMIIdentity(
            organization="Contoso Ltd",
            country="US",
            state="WA",
            locality="Redmond",
            trademark="CONTOSO",
        ),
        site_verification_tokens=("MS=ms12345", "google-site-verification=abc"),
        mta_sts_mode="enforce",
        google_auth_type=None,
        google_idp_name=None,
        primary_email_provider="Microsoft 365",
        email_gateway="Proofpoint",
        dmarc_pct=100,
        likely_primary_email_provider=None,
        ct_provider_used="crt.sh",
        ct_subdomain_count=87,
        ct_cache_age_days=None,
        slug_confidences=(("microsoft365", 0.9542), ("slack", 0.7123)),
        cloud_instance="microsoftonline.com",
        tenant_region_sub_scope=None,
        msgraph_host="graph.microsoft.com",
        lexical_observations=(),
        merge_conflicts=MergeConflicts(
            display_name=(
                CandidateValue(value="Contoso Ltd", source="oidc", confidence="high"),
                CandidateValue(value="Contoso Limited", source="userrealm", confidence="medium"),
            ),
        ),
    )


@pytest.fixture(autouse=True)
def _mock_crtsh():
    """Disable cert intel HTTP calls in all tests by default.

    Integration tests that need real cert intel can override this fixture.
    The cert intel detector is a bonus source — tests for DNS fingerprinting
    shouldn't depend on it or be slowed by its timeout.
    """

    async def _noop_cert_intel(ctx, domain):
        pass

    with patch("recon_tool.sources.dns._detect_cert_intel", _noop_cert_intel):
        yield


@pytest.fixture(autouse=True)
def _reset_global_console():
    """Reset the formatter's global Rich Console between tests.

    Several tests use ``set_console()`` to inject a StringIO-backed Console
    for output capture. If the previous test forgot to restore it, a later
    CliRunner-based test will write into the orphaned StringIO and see
    empty result.stdout. Setting _console = None forces ``get_console()``
    to construct a fresh Console bound to whatever sys.stdout the current
    test framework has captured.
    """
    import recon_tool.formatter as _formatter

    _formatter._console = None
    yield
    _formatter._console = None
