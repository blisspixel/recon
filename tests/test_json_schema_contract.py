"""JSON schema conformance tests (v1.0).

Asserts that the JSON output shape matches docs/schema.md. Changes to the
set of top-level keys or their types must update docs/schema.md AND these
tests in the same PR. This is the 1.0 stability contract.
"""

from __future__ import annotations

import json

from recon_tool.formatter import format_tenant_json
from recon_tool.models import (
    BIMIIdentity,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    TenantInfo,
)


def _build_fixture() -> TenantInfo:
    """Build a TenantInfo with every documented field populated."""
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
    )


# Every field documented in docs/schema.md as stable. Keep in sync.
_STABLE_FIELDS: dict[str, type | tuple[type, ...]] = {
    # Core identity
    "tenant_id": (str, type(None)),
    "display_name": str,
    "default_domain": str,
    "queried_domain": str,
    # Provider & confidence
    "provider": str,
    "confidence": str,
    "evidence_confidence": str,
    "inference_confidence": str,
    "region": (str, type(None)),
    "auth_type": (str, type(None)),
    "google_auth_type": (str, type(None)),
    "google_idp_name": (str, type(None)),
    "primary_email_provider": (str, type(None)),
    "likely_primary_email_provider": (str, type(None)),
    "email_gateway": (str, type(None)),
    # Sources & degradation
    "sources": list,
    "partial": bool,
    "degraded_sources": list,
    # Services & detection
    "services": list,
    "slugs": list,
    "detection_scores": dict,
    "insights": list,
    # Domains
    "domain_count": int,
    "tenant_domains": list,
    "related_domains": list,
    # Email security
    "email_security_score": int,
    "dmarc_policy": (str, type(None)),
    "dmarc_pct": (int, type(None)),
    "mta_sts_mode": (str, type(None)),
    "site_verification_tokens": list,
    # CT
    "ct_provider_used": (str, type(None)),
    "ct_subdomain_count": int,
    "ct_cache_age_days": (int, type(None)),
    "cert_summary": (dict, type(None)),
    # Sovereignty
    "cloud_instance": (str, type(None)),
    "tenant_region_sub_scope": (str, type(None)),
    "msgraph_host": (str, type(None)),
    # Additional metadata
    "lexical_observations": list,
    "bimi_identity": (dict, type(None)),
}

# Experimental fields — documented but can evolve in minor releases.
_EXPERIMENTAL_FIELDS: dict[str, type] = {
    "slug_confidences": list,
}


class TestJSONSchemaContract:
    def test_every_stable_field_present(self) -> None:
        """docs/schema.md contract: all stable fields must appear in --json output."""
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        missing = [f for f in _STABLE_FIELDS if f not in payload]
        assert not missing, f"Stable fields missing from JSON output: {missing}"

    def test_every_stable_field_typed_correctly(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        mistyped: list[str] = []
        for field, expected in _STABLE_FIELDS.items():
            value = payload[field]
            if not isinstance(value, expected):
                mistyped.append(f"{field}: got {type(value).__name__}, want {expected}")
        assert not mistyped, f"Type mismatches: {mistyped}"

    def test_experimental_fields_present_and_documented(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        for field, expected in _EXPERIMENTAL_FIELDS.items():
            assert field in payload, f"Experimental field {field} missing"
            assert isinstance(payload[field], expected), f"{field} should be {expected.__name__}"

    def test_confidence_values_allowed(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        for field in ("confidence", "evidence_confidence", "inference_confidence"):
            assert payload[field] in {"high", "medium", "low"}, f"{field} outside allowed values"

    def test_email_security_score_range(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        assert 0 <= payload["email_security_score"] <= 5

    def test_dmarc_policy_allowed_values(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        if payload["dmarc_policy"] is not None:
            assert payload["dmarc_policy"] in {"reject", "quarantine", "none"}

    def test_cert_summary_nested_shape(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        cs = payload["cert_summary"]
        assert cs is not None
        for field in (
            "cert_count",
            "issuer_diversity",
            "issuance_velocity",
            "newest_cert_age_days",
            "oldest_cert_age_days",
        ):
            assert isinstance(cs[field], int)
        assert isinstance(cs["top_issuers"], list)

    def test_bimi_identity_nested_shape(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        bi = payload["bimi_identity"]
        assert bi is not None
        assert isinstance(bi["organization"], str)
        for field in ("country", "state", "locality", "trademark"):
            # nullable string fields
            assert bi[field] is None or isinstance(bi[field], str)

    def test_slug_confidences_pair_shape(self) -> None:
        info = _build_fixture()
        payload = json.loads(format_tenant_json(info))
        sc = payload["slug_confidences"]
        assert isinstance(sc, list)
        for entry in sc:
            assert isinstance(entry, list)
            assert len(entry) == 2
            assert isinstance(entry[0], str)
            assert isinstance(entry[1], (int, float))
            assert 0.0 <= entry[1] <= 1.0

    def test_sparse_tenant_still_conforms(self) -> None:
        """Sparse-data lookup (no tenant, minimal evidence) must still match the schema."""
        sparse = TenantInfo(
            tenant_id=None,
            display_name="sparse.example",
            default_domain="sparse.example",
            queried_domain="sparse.example",
            confidence=ConfidenceLevel.LOW,
        )
        payload = json.loads(format_tenant_json(sparse))
        for field in _STABLE_FIELDS:
            assert field in payload, f"Field {field} missing on sparse lookup"
