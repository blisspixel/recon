"""Tests for the posture analyzer."""

from recon_tool.models import CertSummary, ConfidenceLevel, TenantInfo
from recon_tool.posture import BANNED_TERMS, analyze_posture


def _make_info(**overrides) -> TenantInfo:
    defaults = dict(
        tenant_id=None,
        display_name="Test",
        default_domain="test.com",
        queried_domain="test.com",
        confidence=ConfidenceLevel.MEDIUM,
    )
    defaults.update(overrides)
    return TenantInfo(**defaults)


class TestAnalyzePosture:
    def test_empty_domain_returns_observations(self):
        info = _make_info()
        result = analyze_posture(info)
        assert isinstance(result, tuple)

    def test_gateway_without_dmarc(self):
        info = _make_info(
            slugs=("proofpoint",),
            services=("Proofpoint",),
            dmarc_policy="none",
        )
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("gateway" in s.lower() or "dmarc" in s.lower() for s in statements)

    def test_federated_identity_observation(self):
        info = _make_info(auth_type="Federated")
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("federated" in s.lower() for s in statements)

    def test_ai_tooling_observation(self):
        info = _make_info(slugs=("anthropic",), services=("Anthropic",))
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("ai" in s.lower() or "llm" in s.lower() for s in statements)

    def test_high_cert_issuance(self):
        cs = CertSummary(
            cert_count=50,
            issuer_diversity=3,
            issuance_velocity=25,
            newest_cert_age_days=1,
            oldest_cert_age_days=365,
            top_issuers=("Let's Encrypt",),
        )
        info = _make_info(cert_summary=cs)
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("certificate" in s.lower() or "25" in s for s in statements)

    def test_no_banned_terms_in_observations(self):
        """No observation should ever contain banned terms."""
        info = _make_info(
            slugs=("proofpoint", "okta", "crowdstrike", "slack", "anthropic"),
            services=("Proofpoint", "Okta", "CrowdStrike", "Slack", "Anthropic"),
            auth_type="Federated",
            dmarc_policy="none",
            cert_summary=CertSummary(
                cert_count=100,
                issuer_diversity=5,
                issuance_velocity=30,
                newest_cert_age_days=1,
                oldest_cert_age_days=1000,
                top_issuers=("LE", "DigiCert", "Sectigo"),
            ),
        )
        result = analyze_posture(info)
        for obs in result:
            lower = obs.statement.lower()
            for term in BANNED_TERMS:
                assert term not in lower, f"Banned term '{term}' found in: {obs.statement}"

    def test_valid_categories(self):
        info = _make_info(
            slugs=("proofpoint", "okta"),
            services=("Proofpoint", "Okta"),
            auth_type="Federated",
            dmarc_policy="reject",
        )
        result = analyze_posture(info)
        valid = {"identity", "email", "infrastructure", "saas_footprint", "certificate", "consistency"}
        for obs in result:
            assert obs.category in valid

    def test_valid_salience(self):
        info = _make_info(
            slugs=("proofpoint",),
            services=("Proofpoint",),
            dmarc_policy="none",
        )
        result = analyze_posture(info)
        for obs in result:
            assert obs.salience in {"high", "medium", "low"}

    def test_dual_email_provider(self):
        info = _make_info(slugs=("microsoft365", "google-workspace"))
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("microsoft" in s.lower() and "google" in s.lower() for s in statements)
