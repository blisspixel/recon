"""Tests for the posture analyzer."""

import pytest

from recon_tool.models import (
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    Observation,
    PostureMetadataDependency,
    TenantInfo,
)
from recon_tool.posture import DISCOURAGED_COPY_TERMS, analyze_posture
from recon_tool.posture_models import metadata_predicate_satisfied


def test_posture_lineage_models_reject_incomplete_identity_and_scope() -> None:
    with pytest.raises(ValueError, match="field must not be empty"):
        PostureMetadataDependency("", "eq", "expected", "observed")
    with pytest.raises(ValueError, match="operator must not be empty"):
        PostureMetadataDependency("auth_type", "", "expected", "observed")
    with pytest.raises(ValueError, match="non-empty source name"):
        Observation("identity", "low", "Synthetic", (), observation_scope=("profile:synthetic",))
    with pytest.raises(ValueError, match="scopes must not be empty"):
        Observation("identity", "low", "Synthetic", (), source_name="synthetic", observation_scope=("",))


def test_posture_metadata_predicate_handles_all_typed_operators_fail_closed() -> None:
    assert metadata_predicate_satisfied("gte", 2, "3")
    assert metadata_predicate_satisfied("lte", 3, 2)
    assert not metadata_predicate_satisfied("gte", 2, ("3",))
    assert not metadata_predicate_satisfied("lte", 2, "not-a-number")
    assert metadata_predicate_satisfied("eq", "Federated", "federated")
    assert metadata_predicate_satisfied("neq", "Managed", "Federated")
    assert metadata_predicate_satisfied("not_contains", "Security", ("Email", "Identity"))
    assert not metadata_predicate_satisfied("not_contains", "Security", "Email")
    assert not metadata_predicate_satisfied("unsupported", "expected", "observed")


def _make_info(**overrides) -> TenantInfo:
    defaults = {
        "tenant_id": None,
        "display_name": "Test",
        "default_domain": "test.invalid",
        "queried_domain": "test.invalid",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    defaults.update(overrides)
    if "slugs" in overrides and "evidence" not in overrides:
        defaults["evidence"] = tuple(
            EvidenceRecord("TXT", f"{slug}=synthetic", slug, slug) for slug in overrides["slugs"]
        )
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
        assert any("proofpoint" in s.lower() and "indicator" in s.lower() for s in statements)
        assert not any("gateway" in s.lower() or "active" in s.lower() for s in statements)

    def test_gateway_with_testing_mode_dmarc_uses_effective_policy(self):
        info = _make_info(
            slugs=("proofpoint",),
            services=("Proofpoint", "DMARC"),
            dmarc_policy="quarantine",
            dmarc_testing=True,
        )
        result = analyze_posture(info)
        statements = [o.statement for o in result]
        assert any("indicator" in s.lower() and "effective dmarc" in s.lower() for s in statements)
        assert not any("gateway" in s.lower() or "active" in s.lower() for s in statements)

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

    def test_no_discouraged_copy_terms_in_observations(self):
        """Built-in posture observations keep neutral generated copy."""
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
            for term in DISCOURAGED_COPY_TERMS:
                assert term not in lower, f"Discouraged copy term '{term}' found in: {obs.statement}"

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
        assert not any("migration" in s.lower() or "hybrid" in s.lower() for s in statements)

    def test_generic_vendor_slugs_remain_indicators(self):
        info = _make_info(slugs=("okta", "crowdstrike", "zscaler"))

        statements = [observation.statement for observation in analyze_posture(info)]

        assert any("identity-vendor indicator" in statement.lower() for statement in statements)
        assert any("security-vendor indicators" in statement.lower() for statement in statements)
        assert not any("identity provider detected" in statement.lower() for statement in statements)
        assert not any("security tools detected" in statement.lower() for statement in statements)

    def test_high_aggregate_email_score_does_not_invent_dkim(self):
        info = _make_info(
            services=("SPF: strict (-all)", "MTA-STS", "BIMI"),
            dmarc_policy="reject",
            evidence=(
                EvidenceRecord("SPF", "v=spf1 -all", "SPF: strict (-all)", "spf-strict"),
                EvidenceRecord("MTA_STS", "v=STSv1", "MTA-STS", "mta-sts"),
                EvidenceRecord("BIMI", "v=BIMI1", "BIMI", "bimi"),
            ),
        )

        strong = [
            observation for observation in analyze_posture(info) if observation.source_name == "strong_email_security"
        ]

        assert len(strong) == 1
        assert "DKIM" not in strong[0].statement

    def test_tls_rpt_record_establishes_email_posture_observation_opportunity(self):
        info = _make_info(
            services=("TLS-RPT",),
            slugs=("tls-rpt",),
            evidence=(
                EvidenceRecord(
                    "TXT",
                    "v=TLSRPTv1; rua=mailto:reports@example.net",
                    "TLS-RPT",
                    "tls-rpt",
                ),
            ),
        )

        names = {observation.source_name for observation in analyze_posture(info)}

        assert "weak_email_security" in names

    def test_slug_rule_requires_retained_matching_evidence(self) -> None:
        info = _make_info(
            services=("Anthropic",),
            slugs=("anthropic",),
            evidence=(),
        )

        names = {observation.source_name for observation in analyze_posture(info)}

        assert "ai_tooling_detected" not in names

    def test_hybrid_rule_carries_exact_generation_dependencies(self) -> None:
        proofpoint = EvidenceRecord(
            "MX",
            "10 mx.synthetic.invalid",
            "Proofpoint",
            "proofpoint",
        )
        info = _make_info(
            slugs=("proofpoint",),
            services=("Proofpoint",),
            dmarc_policy="none",
            evidence=(proofpoint,),
        )

        observation = next(
            item for item in analyze_posture(info) if item.source_name == "gateway_without_dmarc_enforcement"
        )

        assert observation.supporting_evidence == (proofpoint,)
        assert observation.metadata_dependencies == (
            PostureMetadataDependency("dmarc_effective_policy", "neq", "reject", "none"),
            PostureMetadataDependency("dmarc_effective_policy", "neq", "quarantine", "none"),
        )

    def test_metadata_only_rule_carries_typed_observed_value(self) -> None:
        observation = next(
            item
            for item in analyze_posture(_make_info(auth_type="Federated"))
            if item.source_name == "federated_identity"
        )

        assert observation.supporting_evidence == ()
        assert observation.metadata_dependencies == (
            PostureMetadataDependency("auth_type", "eq", "Federated", "Federated"),
        )
