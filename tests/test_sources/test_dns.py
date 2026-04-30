"""Unit tests for the DNS lookup source with tech stack fingerprinting."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from recon_tool.models import SourceResult
from recon_tool.sources.base import LookupSource
from recon_tool.sources.dns import DNSSource


def _mock_safe_resolve_factory(records_by_query: dict[str, list[str]]):
    """Create an async mock for _safe_resolve based on (name/rdtype) key."""

    async def mock_resolve(domain, rdtype, **kwargs):
        key = f"{domain}/{rdtype}"
        if key in records_by_query:
            return records_by_query[key]
        return []

    return mock_resolve


class TestDNSSourceBasics:
    def test_name_property(self):
        assert DNSSource().name == "dns_records"

    def test_implements_lookup_source_protocol(self):
        assert isinstance(DNSSource(), LookupSource)


class TestM365Detection:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_exchange_via_mx(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": [],
                "contoso.com/MX": ["10 contoso-com.mail.protection.outlook.com"],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.m365_detected is True
        assert "Microsoft 365" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_exchange_via_spf(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": ["v=spf1 include:spf.protection.outlook.com ~all"],
                "contoso.com/MX": [],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.m365_detected is True
        assert "Microsoft 365" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_domain_verification(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": ["MS=ms12345678"],
                "contoso.com/MX": [],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.m365_detected is True
        assert "Microsoft 365" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_teams_via_lyncdiscover(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": [],
                "contoso.com/MX": [],
                "lyncdiscover.contoso.com/CNAME": ["webdir.online.lync.com"],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert "Microsoft Teams" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_intune_via_enterpriseregistration(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": [],
                "contoso.com/MX": [],
                "enterpriseregistration.contoso.com/CNAME": ["enterpriseregistration.windows.net"],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert "Intune / MDM" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dkim_exchange(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": [],
                "contoso.com/MX": [],
                "selector1._domainkey.contoso.com/CNAME": ["sel1.protection.outlook.com"],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert "DKIM (Exchange Online)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dkim_exchange_onmicrosoft(self, mock_resolve):
        """DKIM CNAME pointing to *.onmicrosoft.com should also be detected."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "fabrikam.com/TXT": [],
                "fabrikam.com/MX": [],
                "selector1._domainkey.fabrikam.com/CNAME": [
                    "selector1-fabrikam-com._domainkey.fabrikam.onmicrosoft.com"
                ],
            }
        )
        result = await DNSSource().lookup("fabrikam.com")
        assert "DKIM (Exchange Online)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_autodiscover(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "contoso.com/TXT": [],
                "contoso.com/MX": [],
                "autodiscover.contoso.com/CNAME": ["autodiscover.outlook.com"],
            }
        )
        result = await DNSSource().lookup("contoso.com")
        assert "Exchange Autodiscover" in result.detected_services


class TestTechStackFingerprinting:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_google_site_verified_and_workspace_mx(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["google-site-verification=abc123"],
                "example.com/MX": ["10 aspmx.l.google.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Google (site verified)" in result.detected_services
        assert "Google Workspace" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_salesforce(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["salesforce-domain-verification=abc"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Salesforce" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_hubspot(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["hubspot-domain-verification=abc"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "HubSpot" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_proofpoint_mx_and_spf(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 include:spf.pphosted.com ~all"],
                "example.com/MX": ["10 mx1.pphosted.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Proofpoint" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_knowbe4(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["knowbe4-site-verification=abc123"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "KnowBe4" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_crowdstrike(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["crowdstrike-falcon-site-verification=abc"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "CrowdStrike Falcon" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_slack_and_atlassian(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [
                    "slack-domain-verification=abc",
                    "atlassian-domain-verification=xyz",
                ],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Slack" in result.detected_services
        assert "Atlassian (Jira/Confluence)" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_kartra_via_cname(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/CNAME": ["example.kartra.com"],
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Kartra" in result.detected_services
        assert "kartra" in result.detected_slugs
        assert any(e.source_type == "CNAME" and e.slug == "kartra" for e in result.evidence)

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_disciple_media_via_cname(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "www.example.com/CNAME": ["tenant.custom.disciplemedia.com"],
                "example.com/TXT": [],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Disciple Media" in result.detected_services
        assert "disciple-media" in result.detected_slugs
        assert any(e.source_type == "CNAME" and e.slug == "disciple-media" for e in result.evidence)

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_sendgrid_and_aws_ses(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["v=spf1 include:sendgrid.net include:amazonses.com ~all"],
                "example.com/MX": [],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "SendGrid" in result.detected_services
        assert "AWS SES" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_mimecast_mx(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": ["10 us-smtp-inbound-1.mimecast.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "Mimecast" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_dmarc_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": [],
                "example.com/MX": [],
                "_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert "DMARC" in result.detected_services

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_no_services_detected(self, mock_resolve):
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "example.com/TXT": ["some-random-record"],
                "example.com/MX": ["10 mx.randomhost.com"],
            }
        )
        result = await DNSSource().lookup("example.com")
        assert result.m365_detected is False
        # An unrecognized MX host now synthesizes a ``Self-hosted mail``
        # detection so the provider line has a concrete label instead of
        # falling through to weaker signals. No other services should fire.
        assert result.detected_services == ("Self-hosted mail",)

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_full_stack_detection(self, mock_resolve):
        """A domain with many services should detect them all."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "big.com/TXT": [
                    "MS=ms99999",
                    "google-site-verification=abc",
                    "atlassian-domain-verification=xyz",
                    "v=spf1 include:spf.protection.outlook.com include:sendgrid.net ~all",
                ],
                "big.com/MX": ["10 big-com.mail.protection.outlook.com"],
                "autodiscover.big.com/CNAME": ["autodiscover.outlook.com"],
                "lyncdiscover.big.com/CNAME": ["webdir.online.lync.com"],
                "enterpriseregistration.big.com/CNAME": ["enterpriseregistration.windows.net"],
                "_dmarc.big.com/TXT": ["v=DMARC1; p=quarantine"],
            }
        )
        result = await DNSSource().lookup("big.com")
        assert result.m365_detected is True
        assert len(result.detected_services) >= 7


class TestDNSSourceErrorHandling:
    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_all_queries_fail_returns_no_services(self, mock_resolve):
        async def always_empty(*args, **kwargs):
            return []

        mock_resolve.side_effect = always_empty
        result = await DNSSource().lookup("contoso.com")
        assert result.m365_detected is False
        assert isinstance(result, SourceResult)

    @pytest.mark.asyncio
    async def test_total_failure_returns_error(self):
        """If _detect_services raises, lookup returns an error SourceResult."""
        with patch.object(DNSSource, "_detect_services", side_effect=RuntimeError("boom")):
            result = await DNSSource().lookup("contoso.com")
            assert result.error is not None
            assert isinstance(result, SourceResult)
