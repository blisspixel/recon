"""Tests for GWS-related features across multiple modules.

Covers:
- DNS: _detect_gws_cnames, site-verification token extraction, TLS-RPT,
  _parse_bimi_vmc, _fetch_mta_sts_policy
- Google source: parse_cse_config (KACLS, key_providers), GoogleSource.lookup
- Merger: compute_evidence_confidence, compute_inference_confidence,
  compute_detection_scores, _min_confidence
- Chain: _correlate_site_verification
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from recon_tool.chain import _correlate_site_verification
from recon_tool.merger import (
    _min_confidence,
    compute_detection_scores,
    compute_evidence_confidence,
    compute_inference_confidence,
)
from recon_tool.models import (
    ChainResult,
    ConfidenceLevel,
    EvidenceRecord,
    SourceResult,
    TenantInfo,
)
from recon_tool.sources.dns import DNSSource
from recon_tool.sources.google import GoogleSource, parse_cse_config

# ── Helpers ─────────────────────────────────────────────────────────────


def _mock_safe_resolve_factory(records_by_query: dict[str, list[str]]):
    async def mock_resolve(domain, rdtype, **kwargs):
        key = f"{domain}/{rdtype}"
        return records_by_query.get(key, [])
    return mock_resolve


def _make_info(
    domain: str,
    site_verification_tokens: tuple[str, ...] = (),
    insights: tuple[str, ...] = (),
) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        services=("svc",),
        site_verification_tokens=site_verification_tokens,
        insights=insights,
    )


# ═══════════════════════════════════════════════════════════════════════
# DNS sub-detector tests
# ═══════════════════════════════════════════════════════════════════════


class TestDetectGwsCnames:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_single_gws_module_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "mail.example.com/CNAME": ["ghs.googlehosted.com"],
        })
        result = await DNSSource().lookup("example.com")
        assert "Google Workspace: Mail" in result.detected_services
        assert "google-workspace" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_multiple_gws_modules_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "mail.example.com/CNAME": ["ghs.googlehosted.com"],
            "calendar.example.com/CNAME": ["ghs.googlehosted.com"],
            "drive.example.com/CNAME": ["ghs.googlehosted.com"],
        })
        result = await DNSSource().lookup("example.com")
        assert "Google Workspace: Mail" in result.detected_services
        assert "Google Workspace: Calendar" in result.detected_services
        assert "Google Workspace: Drive" in result.detected_services
        assert "google-workspace-modules" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_non_gws_cname_ignored(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "mail.example.com/CNAME": ["some.other.host.com"],
        })
        result = await DNSSource().lookup("example.com")
        gws_services = [s for s in (result.detected_services or ()) if "Google Workspace:" in s]
        assert len(gws_services) == 0


class TestSiteVerificationTokenExtraction:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_google_site_verification_extracted(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": ["google-site-verification=abc123xyz"],
            "example.com/MX": [],
        })
        result = await DNSSource().lookup("example.com")
        assert "abc123xyz" in result.site_verification_tokens

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_multiple_tokens_extracted(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [
                "google-site-verification=token1",
                "google-site-verification=token2",
            ],
            "example.com/MX": [],
        })
        result = await DNSSource().lookup("example.com")
        assert "token1" in result.site_verification_tokens
        assert "token2" in result.site_verification_tokens

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_no_verification_token(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": ["v=spf1 -all"],
            "example.com/MX": [],
        })
        result = await DNSSource().lookup("example.com")
        assert len(result.site_verification_tokens) == 0


class TestTlsRptDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_tls_rpt_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        })
        result = await DNSSource().lookup("example.com")
        assert "TLS-RPT" in result.detected_services
        assert "tls-rpt" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_tls_rpt_not_detected_without_record(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
        })
        result = await DNSSource().lookup("example.com")
        assert "TLS-RPT" not in (result.detected_services or ())


class TestParseBimiVmc:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_bimi_vmc_identity_extracted(self, mock_resolve):
        """BIMI with a= PEM URL should extract VMC corporate identity."""
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "default._bimi.example.com/TXT": [
                "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
            ],
        })

        # Mock the HTTP fetch for the PEM file — use regex fallback path
        pem_content = (
            "Subject: O=Northwind Traders, C=US\n"
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        )
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://example.com/vmc.pem"),
            content=pem_content.encode(),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns._http_client", return_value=mock_client):
            # Also need to make cryptography import fail to test regex fallback
            with patch.dict("sys.modules", {"cryptography": None, "cryptography.x509": None}):
                result = await DNSSource().lookup("example.com")

        assert result.bimi_identity is not None
        assert result.bimi_identity.organization == "Northwind Traders"
        assert result.bimi_identity.country == "US"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_bimi_no_a_tag_skips_vmc(self, mock_resolve):
        """BIMI without a= tag should not attempt VMC fetch."""
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "default._bimi.example.com/TXT": [
                "v=BIMI1; l=https://example.com/logo.svg"
            ],
        })
        result = await DNSSource().lookup("example.com")
        assert "BIMI" in result.detected_services
        assert result.bimi_identity is None

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_bimi_vmc_http_error(self, mock_resolve):
        """BIMI VMC fetch returning non-200 should not crash."""
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "default._bimi.example.com/TXT": [
                "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
            ],
        })
        mock_resp = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", "https://example.com/vmc.pem"),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert "BIMI" in result.detected_services
        assert result.bimi_identity is None


class TestFetchMtaStsPolicy:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_mta_sts_enforce_mode(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
        })
        policy_body = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: *.example.com\n"
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt"),
            content=policy_body.encode(),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert "MTA-STS" in result.detected_services
        assert result.mta_sts_mode == "enforce"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_mta_sts_testing_mode(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
        })
        policy_body = "version: STSv1\nmode: testing\nmax_age: 86400\n"
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt"),
            content=policy_body.encode(),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert result.mta_sts_mode == "testing"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_mta_sts_policy_fetch_failure(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory({
            "example.com/TXT": [],
            "example.com/MX": [],
            "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
        })
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert "MTA-STS" in result.detected_services
        assert result.mta_sts_mode is None


# ═══════════════════════════════════════════════════════════════════════
# Google source: parse_cse_config and GoogleSource.lookup
# ═══════════════════════════════════════════════════════════════════════


class TestParseCseConfig:
    def test_basic_cse_enabled(self):
        result = parse_cse_config({}, "example.com")
        assert result["cse_enabled"] is True

    def test_discovery_uri_snake_case(self):
        data = {"discovery_uri": "https://accounts.google.com/.well-known/openid-configuration"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_idp"] == "https://accounts.google.com/.well-known/openid-configuration"

    def test_discovery_uri_camel_case(self):
        data = {"discoveryUri": "https://login.okta.com/discovery"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_idp"] == "https://login.okta.com/discovery"

    def test_client_id_snake_case(self):
        data = {"client_id": "abc123.apps.googleusercontent.com"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_client_id"] == "abc123.apps.googleusercontent.com"

    def test_client_id_camel_case(self):
        data = {"clientId": "abc123"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_client_id"] == "abc123"

    def test_kacls_url_snake_case(self):
        data = {"kacls_url": "https://kms.example.com/kacls"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_kacls"] == "https://kms.example.com/kacls"

    def test_kacls_url_camel_case(self):
        data = {"kaclsUrl": "https://kms.example.com/kacls"}
        result = parse_cse_config(data, "example.com")
        assert result["cse_kacls"] == "https://kms.example.com/kacls"

    def test_key_providers_snake_case(self):
        data = {
            "key_services": [
                {"provider": "Thales"},
                {"provider": "Fortanix"},
            ]
        }
        result = parse_cse_config(data, "example.com")
        assert result["cse_key_providers"] == ["Fortanix", "Thales"]

    def test_key_providers_camel_case(self):
        data = {
            "keyServices": [
                {"name": "Virtru"},
            ]
        }
        result = parse_cse_config(data, "example.com")
        assert result["cse_key_providers"] == ["Virtru"]

    def test_key_providers_deduplication(self):
        data = {
            "key_services": [
                {"provider": "Thales"},
                {"provider": "Thales"},
                {"provider": "Fortanix"},
            ]
        }
        result = parse_cse_config(data, "example.com")
        assert result["cse_key_providers"] == ["Fortanix", "Thales"]

    def test_empty_key_services(self):
        data = {"key_services": []}
        result = parse_cse_config(data, "example.com")
        assert "cse_key_providers" not in result

    def test_non_string_values_ignored(self):
        data = {
            "discovery_uri": 123,
            "client_id": None,
            "kacls_url": True,
        }
        result = parse_cse_config(data, "example.com")
        assert "cse_idp" not in result
        assert "cse_client_id" not in result
        assert "cse_kacls" not in result

    def test_full_config(self):
        data = {
            "discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "abc.apps.googleusercontent.com",
            "kacls_url": "https://kms.example.com/kacls",
            "key_services": [{"provider": "Thales"}],
        }
        result = parse_cse_config(data, "example.com")
        assert result["cse_enabled"] is True
        assert result["cse_idp"] is not None
        assert result["cse_client_id"] is not None
        assert result["cse_kacls"] is not None
        assert result["cse_key_providers"] == ["Thales"]


class TestGoogleSourceLookup:
    @pytest.mark.asyncio
    async def test_invalid_domain(self):
        source = GoogleSource()
        result = await source.lookup("example.com/path")
        assert "Invalid domain" in result.error

    @pytest.mark.asyncio
    async def test_cse_found(self):
        cse_json = {
            "discovery_uri": "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "abc.apps.googleusercontent.com",
        }
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://cse.example.com/.well-known/cse-configuration"),
            json=cse_json,
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google.http_client", return_value=mock_client):
            source = GoogleSource()
            result = await source.lookup("example.com")

        assert "Google Workspace CSE" in result.detected_services
        assert "google-cse" in result.detected_slugs
        assert result.is_success

    @pytest.mark.asyncio
    async def test_cse_not_found(self):
        mock_resp = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", "https://cse.example.com/.well-known/cse-configuration"),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google.http_client", return_value=mock_client):
            source = GoogleSource()
            result = await source.lookup("example.com")

        assert result.error is not None
        assert not result.is_success

    @pytest.mark.asyncio
    async def test_cse_timeout(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.google.http_client", return_value=mock_client):
            source = GoogleSource()
            result = await source.lookup("example.com")

        assert result.error is not None

    def test_source_name(self):
        assert GoogleSource().name == "google_workspace"


# ═══════════════════════════════════════════════════════════════════════
# Merger: new confidence and scoring functions
# ═══════════════════════════════════════════════════════════════════════


class TestMinConfidence:
    def test_both_high(self):
        assert _min_confidence(ConfidenceLevel.HIGH, ConfidenceLevel.HIGH) == ConfidenceLevel.HIGH

    def test_high_and_low(self):
        assert _min_confidence(ConfidenceLevel.HIGH, ConfidenceLevel.LOW) == ConfidenceLevel.LOW

    def test_low_and_high(self):
        assert _min_confidence(ConfidenceLevel.LOW, ConfidenceLevel.HIGH) == ConfidenceLevel.LOW

    def test_medium_and_high(self):
        assert _min_confidence(ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH) == ConfidenceLevel.MEDIUM

    def test_medium_and_low(self):
        assert _min_confidence(ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW) == ConfidenceLevel.LOW

    def test_both_low(self):
        assert _min_confidence(ConfidenceLevel.LOW, ConfidenceLevel.LOW) == ConfidenceLevel.LOW

    def test_both_medium(self):
        assert _min_confidence(ConfidenceLevel.MEDIUM, ConfidenceLevel.MEDIUM) == ConfidenceLevel.MEDIUM


class TestComputeEvidenceConfidence:
    def test_zero_successful_sources(self):
        results = [SourceResult(source_name="a", error="fail")]
        assert compute_evidence_confidence(results) == ConfidenceLevel.LOW

    def test_one_successful_source(self):
        results = [SourceResult(source_name="a", tenant_id="tid")]
        assert compute_evidence_confidence(results) == ConfidenceLevel.LOW

    def test_two_successful_sources(self):
        results = [
            SourceResult(source_name="a", tenant_id="tid"),
            SourceResult(source_name="b", detected_services=("svc",)),
        ]
        assert compute_evidence_confidence(results) == ConfidenceLevel.MEDIUM

    def test_three_successful_sources(self):
        results = [
            SourceResult(source_name="a", tenant_id="tid"),
            SourceResult(source_name="b", detected_services=("svc",)),
            SourceResult(source_name="c", m365_detected=True),
        ]
        assert compute_evidence_confidence(results) == ConfidenceLevel.HIGH

    def test_four_successful_sources(self):
        results = [
            SourceResult(source_name="a", tenant_id="tid"),
            SourceResult(source_name="b", detected_services=("svc",)),
            SourceResult(source_name="c", m365_detected=True),
            SourceResult(source_name="d", detected_services=("svc2",)),
        ]
        assert compute_evidence_confidence(results) == ConfidenceLevel.HIGH

    def test_empty_list(self):
        assert compute_evidence_confidence([]) == ConfidenceLevel.LOW


class TestComputeInferenceConfidence:
    def test_tenant_id_with_corroboration(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(source_name="user_realm", m365_detected=True, display_name="Contoso"),
        ]
        assert compute_inference_confidence(results) == ConfidenceLevel.HIGH

    def test_tenant_id_without_corroboration(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(source_name="dns_records", error="no data"),
        ]
        # Single successful source → MEDIUM or LOW depending on evidence
        conf = compute_inference_confidence(results)
        assert conf in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)

    def test_three_independent_source_types(self):
        results = [
            SourceResult(
                source_name="a",
                evidence=(
                    EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),
                    EvidenceRecord(source_type="MX", raw_value="mx.outlook.com", rule_name="MX", slug="m365"),
                    EvidenceRecord(source_type="CNAME", raw_value="autodiscover", rule_name="CNAME", slug="m365"),
                ),
                detected_services=("svc",),
            ),
        ]
        assert compute_inference_confidence(results) == ConfidenceLevel.HIGH

    def test_single_source_no_tenant_id(self):
        results = [
            SourceResult(source_name="dns_records", detected_services=("svc",)),
        ]
        conf = compute_inference_confidence(results)
        assert conf in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)

    def test_empty_results(self):
        assert compute_inference_confidence([]) == ConfidenceLevel.LOW


class TestComputeDetectionScores:
    def test_single_source_type_low(self):
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),
        )
        scores = compute_detection_scores(evidence)
        assert scores == (("m365", "low"),)

    def test_two_source_types_medium(self):
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),
            EvidenceRecord(source_type="MX", raw_value="mx.outlook.com", rule_name="MX", slug="m365"),
        )
        scores = compute_detection_scores(evidence)
        assert scores == (("m365", "medium"),)

    def test_three_source_types_high(self):
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),
            EvidenceRecord(source_type="MX", raw_value="mx.outlook.com", rule_name="MX", slug="m365"),
            EvidenceRecord(source_type="CNAME", raw_value="autodiscover", rule_name="CNAME", slug="m365"),
        )
        scores = compute_detection_scores(evidence)
        assert scores == (("m365", "high"),)

    def test_multiple_slugs(self):
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),
            EvidenceRecord(source_type="MX", raw_value="mx.google.com", rule_name="MX", slug="google-workspace"),
        )
        scores = compute_detection_scores(evidence)
        assert len(scores) == 2
        slugs = {s[0] for s in scores}
        assert slugs == {"google-workspace", "m365"}

    def test_empty_evidence(self):
        assert compute_detection_scores(()) == ()

    def test_sorted_by_slug(self):
        evidence = (
            EvidenceRecord(source_type="TXT", raw_value="x", rule_name="r", slug="zzz"),
            EvidenceRecord(source_type="TXT", raw_value="x", rule_name="r", slug="aaa"),
        )
        scores = compute_detection_scores(evidence)
        assert scores[0][0] == "aaa"
        assert scores[1][0] == "zzz"


# ═══════════════════════════════════════════════════════════════════════
# Chain: _correlate_site_verification
# ═══════════════════════════════════════════════════════════════════════


class TestCorrelateSiteVerification:
    def test_shared_tokens_add_insights(self):
        results = [
            ChainResult(
                domain="a.com",
                info=_make_info("a.com", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.com",
                info=_make_info("b.com", site_verification_tokens=("token1",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        a_insights = updated[0].info.insights
        b_insights = updated[1].info.insights
        assert any("Shares google-site-verification" in i for i in a_insights)
        assert any("b.com" in i for i in a_insights)
        assert any("a.com" in i for i in b_insights)

    def test_no_shared_tokens_no_change(self):
        results = [
            ChainResult(
                domain="a.com",
                info=_make_info("a.com", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.com",
                info=_make_info("b.com", site_verification_tokens=("token2",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        # No correlation insights should be added
        for r in updated:
            assert not any("Shares google-site-verification" in i for i in r.info.insights)

    def test_empty_results(self):
        assert _correlate_site_verification([]) == []

    def test_single_domain_no_correlation(self):
        results = [
            ChainResult(
                domain="a.com",
                info=_make_info("a.com", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
        ]
        updated = _correlate_site_verification(results)
        assert len(updated) == 1
        assert not any("Shares" in i for i in updated[0].info.insights)

    def test_three_domains_shared_token(self):
        results = [
            ChainResult(
                domain="a.com",
                info=_make_info("a.com", site_verification_tokens=("shared",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.com",
                info=_make_info("b.com", site_verification_tokens=("shared",)),
                chain_depth=1,
            ),
            ChainResult(
                domain="c.com",
                info=_make_info("c.com", site_verification_tokens=("shared",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        # a.com should mention b.com and c.com
        a_insights = " ".join(updated[0].info.insights)
        assert "b.com" in a_insights
        assert "c.com" in a_insights

    def test_no_tokens_no_change(self):
        results = [
            ChainResult(
                domain="a.com",
                info=_make_info("a.com"),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.com",
                info=_make_info("b.com"),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        assert updated == results
