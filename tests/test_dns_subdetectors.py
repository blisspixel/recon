"""Tests for DNS sub-detectors: BIMI, MTA-STS, NS, CNAME infra, Domain Connect,
subdomain TXT, CAA, and SRV records.

All tests mock _safe_resolve (the async DNS boundary function) rather than
the underlying dns.asyncresolver, keeping tests decoupled from the DNS library.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from recon_tool.sources.dns import DNSSource, _parse_rdata


def _mock_safe_resolve_factory(records_by_query: dict[str, list[str]]):
    """Create an async mock for _safe_resolve based on (name/rdtype) key.

    Returns parsed string values directly (as _safe_resolve does after
    processing rdata.to_text()).
    """

    async def mock_resolve(domain, rdtype, **kwargs):
        key = f"{domain}/{rdtype}"
        if key in records_by_query:
            return records_by_query[key]
        return []

    return mock_resolve


class TestBIMIDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_bimi_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "default._bimi.example.com/TXT": ["v=BIMI1; l=https://example.com/logo.svg"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "BIMI" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_bimi_not_detected_without_record(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "BIMI" not in (result.detected_services or ())


class TestMTASTSDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_mta_sts_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_mta-sts.example.com/TXT": ["v=STSv1; id=20240101"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "MTA-STS" in result.detected_services


class TestNSDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_cloudflare_ns_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Cloudflare" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_aws_route53_ns_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/NS": ["ns-123.awsdns-45.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "AWS Route 53" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_godaddy_ns_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/NS": ["ns01.domaincontrol.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "GoDaddy" in result.detected_services


class TestCNAMEInfraDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_cloudfront_cname_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "www.example.com/CNAME": ["d1234.cloudfront.net"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "AWS CloudFront" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_vercel_cname_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "www.example.com/CNAME": ["cname.vercel-dns.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Vercel" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_netlify_cname_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "www.example.com/CNAME": ["example.netlify.app"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Netlify" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_akamai_cname_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "www.example.com/CNAME": ["example.akamaiedge.net"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Akamai" in result.detected_services


class TestDomainConnectDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_azure_domain_connect(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_domainconnect.example.com/CNAME": ["_domainconnect.azurewebsites.net"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Domain Connect (Azure)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_godaddy_domain_connect(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_domainconnect.example.com/CNAME": ["_domainconnect.godaddy.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Domain Connect (GoDaddy)" in result.detected_services


class TestDMARCPolicyExtraction:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dmarc_reject_policy(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert result.dmarc_policy == "reject"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dmarc_none_policy(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_dmarc.example.com/TXT": ["v=DMARC1; p=none"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert result.dmarc_policy == "none"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_no_dmarc_returns_none(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert result.dmarc_policy is None


class TestSPFAnalysis:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_spf_strict_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 include:_spf.google.com -all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "SPF: strict (-all)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_spf_softfail_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 include:_spf.google.com ~all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "SPF: softfail (~all)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_spf_complexity_large(self, mock_resolve):
        includes = " ".join(f"include:svc{i}.example.com" for i in range(9))
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [f"v=spf1 {includes} ~all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        complexity_svcs = [s for s in result.detected_services if "SPF complexity" in s]
        assert len(complexity_svcs) == 1
        assert "large" in complexity_svcs[0]

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_spf_complexity_medium(self, mock_resolve):
        includes = " ".join(f"include:svc{i}.example.com" for i in range(5))
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [f"v=spf1 {includes} ~all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        complexity_svcs = [s for s in result.detected_services if "SPF complexity" in s]
        assert len(complexity_svcs) == 1
        assert "large" not in complexity_svcs[0]


class TestMsoidCNAME:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_msoid_cname_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "msoid.example.com/CNAME": ["clientconfig.microsoftonline.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Office ProPlus (msoid)" in result.detected_services
        assert result.m365_detected is True


class TestSRVDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_teams_via_srv_federation(self, mock_resolve):
        """SRV record for _sipfederationtls._tcp should detect Teams."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_sipfederationtls._tcp.example.com/SRV": ["100 1 5061 sipfed.online.lync.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Microsoft Teams" in result.detected_services
        assert result.m365_detected is True


class TestSubdomainTxtDetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_slack_enterprise_grid_via_subdomain(self, mock_resolve):
        """_slack-challenge subdomain TXT should detect Slack."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_slack-challenge.example.com/TXT": ["abc123-verification-token"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Slack" in result.detected_services
        assert "slack" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_gitlab_via_subdomain(self, mock_resolve):
        """_gitlab-pages-verification-code subdomain TXT should detect GitLab."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_gitlab-pages-verification-code.example.com/TXT": ["gitlab-pages-verification-code=abc123def"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "GitLab" in result.detected_services
        assert "gitlab" in result.detected_slugs

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_no_subdomain_txt_no_match(self, mock_resolve):
        """No subdomain TXT records should not produce false positives."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Slack" not in (result.detected_services or ())
        assert "GitLab" not in (result.detected_services or ())


class TestCAADetection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_letsencrypt_caa(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/CAA": ['0 issue "letsencrypt.org"'],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "CAA: Let's Encrypt" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_digicert_caa(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/CAA": ['0 issue "digicert.com"'],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "CAA: DigiCert" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_aws_acm_caa(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "example.com/CAA": ['0 issue "amazontrust.com"'],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "CAA: AWS Certificate Manager" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_no_caa_no_match(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        caa_services = [s for s in (result.detected_services or ()) if s.startswith("CAA:")]
        assert len(caa_services) == 0


class TestMultiPartTxtRecords:
    """Test that _parse_rdata correctly joins multi-part TXT records."""

    def test_multi_part_joined(self):
        raw = '"v=DMARC1;" "p=reject; rua=mailto:d@example.com"'
        assert _parse_rdata(raw) == "v=DMARC1;p=reject; rua=mailto:d@example.com"

    def test_single_part(self):
        raw = '"v=spf1 include:_spf.google.com -all"'
        assert _parse_rdata(raw) == "v=spf1 include:_spf.google.com -all"

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dmarc_split_across_chunks(self, mock_resolve):
        """DMARC record split across chunks should parse policy correctly."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_dmarc.example.com/TXT": ["v=DMARC1;p=reject; rua=mailto:d@example.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert result.dmarc_policy == "reject"
        assert "DMARC" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_spf_split_across_chunks(self, mock_resolve):
        """SPF record should still detect includes."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 include:spf.protection.outlook.com ~all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Microsoft 365" in result.detected_services
        assert "SPF: softfail (~all)" in result.detected_services


class TestExchangeOnpremAutodiscover:
    """Regression tests for autodiscover handling in _detect_exchange_onprem.

    Querying type A chases CNAMEs through dnspython, so a plain A query
    returns IPs even for M365 cloud endpoints. These tests pin the
    CNAME-first behavior that distinguishes M365 cloud autodiscover
    (suppressed) from self-operated autodiscover (fires on-prem).
    """

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_autodiscover_cname_to_m365_cloud_is_not_onprem(self, mock_resolve):
        # Classic M365 pattern: autodiscover CNAMEs to autodiscover.outlook.com.
        # Slug must NOT fire — this is Exchange Online, not on-prem.
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "autodiscover.example.com/CNAME": ["autodiscover.outlook.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Exchange Server (on-prem / hybrid)" not in (result.detected_services or ())

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_autodiscover_cname_to_org_infra_is_onprem(self, mock_resolve):
        # Genuine hybrid: autodiscover CNAMEs to an org-owned endpoint.
        # Slug must fire.
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "autodiscover.example.com/CNAME": ["mailpex.example.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Exchange Server (on-prem / hybrid)" in (result.detected_services or ())

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_autodiscover_direct_a_is_onprem(self, mock_resolve):
        # No CNAME, direct A — self-operated autodiscover responder.
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "autodiscover.example.com/A": ["10.0.0.1"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Exchange Server (on-prem / hybrid)" in (result.detected_services or ())

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_autodiscover_cname_to_mail_protection_is_not_onprem(self, mock_resolve):
        # Suffix match: anything under *.mail.protection.outlook.com is M365.
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "autodiscover.example.com/CNAME": [
                    "example-com.mail.protection.outlook.com"
                ],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Exchange Server (on-prem / hybrid)" not in (result.detected_services or ())

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_owa_direct_a_still_fires(self, mock_resolve):
        # Non-autodiscover prefix path: owa A-resolves → on-prem.
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "owa.example.com/A": ["10.0.0.1"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Exchange Server (on-prem / hybrid)" in (result.detected_services or ())
