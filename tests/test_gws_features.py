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
    merge_results,
)
from recon_tool.models import (
    ChainResult,
    ConfidenceLevel,
    EvidenceRecord,
    SourceResult,
    TenantInfo,
)
from recon_tool.sources.dns import DNSSource
from recon_tool.sources.google import GoogleSource, _extract_idp_name, parse_cse_config

# ── Helpers ─────────────────────────────────────────────────────────────


class TestCseIdpNameMatching:
    """The CSE IdP-name helper matches by hostname suffix, not raw substring."""

    def test_known_idp_subdomain_matches(self):
        assert _extract_idp_name("https://login.okta.com/oauth2/discovery") == "Okta"

    def test_lookalike_host_does_not_match(self):
        assert _extract_idp_name("https://notokta.invalid/.well-known/openid") == "notokta.invalid"

    def test_pattern_only_in_path_does_not_match(self):
        assert _extract_idp_name("https://kacls.delta.invalid/discovery?ref=okta.com") == "kacls.delta.invalid"


def _mock_safe_resolve_factory(records_by_query: dict[str, list[str]]):
    async def mock_resolve(domain, rdtype, **kwargs):
        key = f"{domain}/{rdtype}"
        return records_by_query.get(key, [])

    return mock_resolve


def _make_info(
    domain: str,
    site_verification_tokens: tuple[str, ...] = (),
    insights: tuple[str, ...] = (),
    degraded_sources: tuple[str, ...] = (),
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
        degraded_sources=degraded_sources,
    )


# ═══════════════════════════════════════════════════════════════════════
# DNS sub-detector tests
# ═══════════════════════════════════════════════════════════════════════


class TestDetectGwsCnames:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_single_gws_module_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "mail.example.com/CNAME": ["ghs.googlehosted.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Google Workspace: Mail" in result.detected_services
        assert "google-workspace" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_multiple_gws_modules_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "mail.example.com/CNAME": ["ghs.googlehosted.com"],
                "calendar.example.com/CNAME": ["ghs.googlehosted.com"],
                "drive.example.com/CNAME": ["ghs.googlehosted.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Google Workspace: Mail" in result.detected_services
        assert "Google Workspace: Calendar" in result.detected_services
        assert "Google Workspace: Drive" in result.detected_services
        assert "google-workspace-modules" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_non_gws_cname_ignored(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "mail.example.com/CNAME": ["some.other.host.invalid"],
            }
        )
        result = await DNSSource().lookup("example.com")
        gws_services = [s for s in (result.detected_services or ()) if "Google Workspace:" in s]
        assert len(gws_services) == 0

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_gws_lookalike_cname_ignored(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "mail.example.com/CNAME": ["ghs.googlehosted.com.example.net"],
            }
        )
        result = await DNSSource().lookup("example.com")
        gws_services = [s for s in (result.detected_services or ()) if "Google Workspace:" in s]
        assert len(gws_services) == 0


class TestSiteVerificationTokenExtraction:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_google_site_verification_extracted(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["google-site-verification=abc123xyz"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "abc123xyz" in result.site_verification_tokens

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_multiple_tokens_extracted(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [
                    "google-site-verification=token1",
                    "google-site-verification=token2",
                ],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "token1" in result.site_verification_tokens
        assert "token2" in result.site_verification_tokens

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_no_verification_token(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 -all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert len(result.site_verification_tokens) == 0


class TestTlsRptDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_tls_rpt_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "TLS-RPT" in result.detected_services
        assert "tls-rpt" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_tls_rpt_not_detected_without_record(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "TLS-RPT" not in (result.detected_services or ())


class TestParseBimiVmc:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_bimi_vmc_unverified_subject_not_used(self, mock_resolve):
        """An unverified PEM subject must not become corporate identity."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "default._bimi.example.com/TXT": [
                    "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
                ],
            }
        )

        # A certificate-looking subject line does not make an invalid PEM trusted.
        pem_content = "Subject: O=Synthetic Gamma, C=US\n-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        mock_resp = httpx.Response(
            status_code=200,
            request=httpx.Request("GET", "https://example.com/vmc.pem"),
            content=pem_content.encode(),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns_email._http_client", return_value=mock_client):
            # VMC fetch is opt-in (--direct-probes); enable it for this test.
            result = await DNSSource().lookup("example.com", active_probes=True)

        assert "BIMI" in result.detected_services
        assert result.bimi_identity is None
        assert "bimi-vmc" not in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_bimi_no_a_tag_skips_vmc(self, mock_resolve):
        """BIMI without a= tag should not attempt VMC fetch."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "default._bimi.example.com/TXT": ["v=BIMI1; l=https://example.com/logo.svg"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "BIMI" in result.detected_services
        assert result.bimi_identity is None

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_bimi_vmc_http_error(self, mock_resolve):
        """BIMI VMC fetch returning non-200 should not crash."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "default._bimi.example.com/TXT": [
                    "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
                ],
            }
        )
        mock_resp = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", "https://example.com/vmc.pem"),
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns_email._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert "BIMI" in result.detected_services
        assert result.bimi_identity is None


class TestFetchMtaStsPolicy:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_no_policy_fetch_without_mta_sts_record(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_mta-sts.example.com/TXT": [],
            }
        )

        with patch("recon_tool.sources.dns_email._http_client") as mock_http_client:
            result = await DNSSource().lookup("example.com", skip_ct=True)

        mock_http_client.assert_not_called()
        assert "MTA-STS" not in result.detected_services
        assert result.mta_sts_mode is None

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_mta_sts_enforce_mode(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
            }
        )
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

        with patch("recon_tool.sources.dns_email._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert "MTA-STS" in result.detected_services
        assert result.mta_sts_mode == "enforce"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_mta_sts_testing_mode(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
            }
        )
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

        with patch("recon_tool.sources.dns_email._http_client", return_value=mock_client):
            result = await DNSSource().lookup("example.com")

        assert result.mta_sts_mode == "testing"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns_base.safe_resolve")
    async def test_mta_sts_policy_fetch_failure(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
            }
        )
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("recon_tool.sources.dns_email._http_client", return_value=mock_client):
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
            result = await source.lookup("example.com", active_probes=True)

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
            result = await source.lookup("example.com", active_probes=True)

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
            result = await source.lookup("example.com", active_probes=True)

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

    def test_errored_result_with_data_is_not_a_confidence_contributor(self):
        results = [
            SourceResult(
                source_name=source_name,
                detected_services=("Google Workspace",),
                error="source failed",
            )
            for source_name in ("dns_records", "google_identity", "google_workspace")
        ]

        assert compute_evidence_confidence(results) == ConfidenceLevel.LOW

    def test_duplicate_results_from_one_source_count_once(self):
        results = [
            SourceResult(source_name="dns_records", detected_services=(service,))
            for service in ("Service A", "Service B", "Service C")
        ]

        assert compute_evidence_confidence(results) == ConfidenceLevel.LOW


class TestComputeInferenceConfidence:
    def test_tenant_id_with_corroboration(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(source_name="user_realm", m365_detected=True, display_name="Synthetic Alpha"),
        ]
        assert compute_inference_confidence(results) == ConfidenceLevel.HIGH

    def test_tenant_id_without_corroboration(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(source_name="dns_records", error="no data"),
        ]
        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_failed_m365_claim_does_not_corroborate_oidc_tenant(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(
                source_name="user_realm",
                m365_detected=True,
                detected_services=("Microsoft 365",),
                detected_slugs=("microsoft365",),
                error="upstream response was invalid",
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

        merged = merge_results(results, queried_domain="alpha.example")
        assert "Microsoft 365" not in merged.services
        assert merged.sources == ("oidc_discovery",)

    def test_failed_three_type_evidence_does_not_raise_inference(self):
        result = SourceResult(
            source_name="dns_records",
            detected_services=("Google Workspace",),
            detected_slugs=("google-workspace",),
            evidence=tuple(
                EvidenceRecord(
                    source_type=source_type,
                    raw_value="value",
                    rule_name="Google Workspace",
                    slug="google-workspace",
                )
                for source_type in ("MX", "TXT", "CNAME")
            ),
            error="DNS collection failed",
        )

        assert compute_inference_confidence([result]) == ConfidenceLevel.LOW

    def test_failed_same_claim_sources_do_not_raise_inference(self):
        results = [
            SourceResult(
                source_name=source_name,
                detected_services=("Google Workspace",),
                detected_slugs=("google-workspace",),
                error="source failed",
            )
            for source_name in ("dns_records", "google_identity")
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_google_auth_does_not_corroborate_microsoft_tenant(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(
                source_name="google_identity",
                detected_services=("Google Workspace",),
                detected_slugs=("google-workspace",),
                google_auth_type="Federated",
                evidence=(
                    EvidenceRecord(
                        source_type="HTTP",
                        raw_value="federated Google tenant",
                        rule_name="Google Identity Routing",
                        slug="google-workspace",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

        merged = merge_results(results, queried_domain="alpha.example")
        assert merged.evidence_confidence == ConfidenceLevel.MEDIUM
        assert merged.inference_confidence == ConfidenceLevel.LOW
        assert merged.confidence == ConfidenceLevel.LOW

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

    def test_cross_slug_record_types_do_not_combine(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Microsoft 365", "Google Workspace", "Cloudflare"),
                evidence=(
                    EvidenceRecord(source_type="TXT", raw_value="ms=123", rule_name="M365", slug="microsoft365"),
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="CNAME",
                        raw_value="edge.cloudflare.net",
                        rule_name="Cloudflare",
                        slug="cloudflare",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_source_type_case_variants_are_one_record_type(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace",),
                evidence=tuple(
                    EvidenceRecord(
                        source_type=source_type,
                        raw_value=source_type,
                        rule_name="Google MX",
                        slug="google-workspace",
                    )
                    for source_type in ("MX", " mx ", "Mx", " ")
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_unscoped_evidence_does_not_form_a_claim(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Unscoped evidence",),
                evidence=tuple(
                    EvidenceRecord(source_type=source_type, raw_value="value", rule_name="rule", slug=" ")
                    for source_type in ("TXT", "MX", "CNAME")
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_two_record_types_for_same_slug_are_medium(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace",),
                evidence=(
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="DKIM",
                        raw_value="google._domainkey",
                        rule_name="Google DKIM",
                        slug="google-workspace",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.MEDIUM

    def test_google_site_verification_is_not_workspace_corroboration(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace", "Google (site verified)"),
                evidence=(
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="DKIM",
                        raw_value="google._domainkey",
                        rule_name="Google DKIM",
                        slug="google-workspace",
                    ),
                    EvidenceRecord(
                        source_type="TXT",
                        raw_value="google-site-verification=123",
                        rule_name="Google site verification",
                        slug="google-site",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.MEDIUM

    def test_google_cse_corroborates_google_workspace_claim(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace",),
                detected_slugs=("google-workspace",),
                evidence=(
                    EvidenceRecord(
                        source_type="MX",
                        raw_value="aspmx.l.google.com",
                        rule_name="Google MX",
                        slug="google-workspace",
                    ),
                ),
            ),
            SourceResult(
                source_name="google_workspace",
                detected_services=("Google Workspace CSE",),
                detected_slugs=("google-cse",),
                evidence=(
                    EvidenceRecord(
                        source_type="HTTP",
                        raw_value="CSE configuration found",
                        rule_name="Google Workspace CSE",
                        slug="google-cse",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.MEDIUM

    def test_unrelated_successful_sources_do_not_raise_inference(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Cloudflare",),
                evidence=(
                    EvidenceRecord(
                        source_type="CNAME",
                        raw_value="edge.cloudflare.net",
                        rule_name="Cloudflare",
                        slug="cloudflare",
                    ),
                ),
            ),
            SourceResult(
                source_name="other",
                detected_services=("Slack",),
                evidence=(
                    EvidenceRecord(
                        source_type="TXT",
                        raw_value="slack-verification=123",
                        rule_name="Slack",
                        slug="slack",
                    ),
                ),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_two_sources_supporting_same_slug_are_medium(self):
        results = [
            SourceResult(
                source_name="dns_records",
                detected_services=("Google Workspace",),
                detected_slugs=("google-workspace",),
            ),
            SourceResult(
                source_name="google_identity",
                detected_services=("Google Workspace",),
                detected_slugs=("google-workspace",),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.MEDIUM

    def test_same_tenant_id_from_two_sources_is_medium(self):
        results = [
            SourceResult(source_name="source_a", tenant_id="tid"),
            SourceResult(source_name="source_b", tenant_id="tid"),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.MEDIUM

    def test_government_m365_evidence_corroborates_oidc_tenant(self):
        results = [
            SourceResult(source_name="oidc_discovery", tenant_id="tid"),
            SourceResult(
                source_name="dns_records",
                detected_services=("Microsoft 365 (US Government cloud)",),
                detected_slugs=("microsoft365-gov",),
            ),
        ]

        assert compute_inference_confidence(results) == ConfidenceLevel.HIGH

    def test_single_source_no_tenant_id(self):
        results = [
            SourceResult(source_name="dns_records", detected_services=("svc",)),
        ]
        assert compute_inference_confidence(results) == ConfidenceLevel.LOW

    def test_empty_results(self):
        assert compute_inference_confidence([]) == ConfidenceLevel.LOW


class TestComputeDetectionScores:
    def test_single_source_type_low(self):
        evidence = (EvidenceRecord(source_type="TXT", raw_value="v=spf1", rule_name="SPF", slug="m365"),)
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
                domain="a.invalid",
                info=_make_info("a.invalid", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid", site_verification_tokens=("token1",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        a_insights = updated[0].info.insights
        b_insights = updated[1].info.insights
        assert any("Shares google-site-verification" in i for i in a_insights)
        assert any("b.invalid" in i for i in a_insights)
        assert any("a.invalid" in i for i in b_insights)

    def test_no_shared_tokens_no_change(self):
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid", site_verification_tokens=("token2",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        # No correlation insights should be added
        for r in updated:
            assert not any("Shares google-site-verification" in i for i in r.info.insights)

    def test_unavailable_apex_txt_cannot_create_a_correlation_insight(self) -> None:
        results = [
            ChainResult(
                domain=domain,
                info=_make_info(
                    domain,
                    site_verification_tokens=("shared",),
                    degraded_sources=("dns:apex_txt",),
                ),
                chain_depth=depth,
            )
            for domain, depth in (("a.invalid", 0), ("b.invalid", 1))
        ]

        updated = _correlate_site_verification(results)

        assert all(
            not any("Shares google-site-verification" in insight for insight in result.info.insights)
            for result in updated
        )

    def test_empty_results(self):
        assert _correlate_site_verification([]) == []

    def test_single_domain_no_correlation(self):
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid", site_verification_tokens=("token1",)),
                chain_depth=0,
            ),
        ]
        updated = _correlate_site_verification(results)
        assert len(updated) == 1
        assert not any("Shares" in i for i in updated[0].info.insights)

    def test_three_domains_shared_token(self):
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid", site_verification_tokens=("shared",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid", site_verification_tokens=("shared",)),
                chain_depth=1,
            ),
            ChainResult(
                domain="c.invalid",
                info=_make_info("c.invalid", site_verification_tokens=("shared",)),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        # a.invalid should mention b.invalid and c.invalid
        a_insights = " ".join(updated[0].info.insights)
        assert "b.invalid" in a_insights
        assert "c.invalid" in a_insights

    def test_no_tokens_no_change(self):
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid"),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid"),
                chain_depth=1,
            ),
        ]
        updated = _correlate_site_verification(results)
        assert updated == results
