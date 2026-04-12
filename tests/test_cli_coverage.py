"""Additional CLI tests to improve coverage on uncovered paths."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from recon_tool.cli import _debug_callback, app, version_callback
from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "dns_records"),
    services=("Exchange Online", "Microsoft 365", "Slack"),
    slugs=("microsoft365", "slack"),
    auth_type="Federated",
    insights=("Federated identity indicators observed (likely Okta)",),
    related_domains=("contoso-internal.com",),
    domain_count=3,
    tenant_domains=("contoso.com", "contoso.onmicrosoft.com", "contoso-internal.com"),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="dns_records", detected_services=("Slack",), detected_slugs=("slack",)),
]


class TestVersionAndDebug:
    def test_version_false_does_nothing(self):
        """version_callback(False) should not raise."""
        version_callback(False)

    def test_debug_false_does_nothing(self):
        """_debug_callback(False) should not raise."""
        _debug_callback(False)

    def test_debug_true_enables_logging(self):
        """_debug_callback(True) should set debug level."""
        import logging
        _debug_callback(True)
        logger = logging.getLogger("recon")
        assert logger.level == logging.DEBUG


class TestLookupFlags:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_services_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--services"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_domains_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--domains"])
        assert result.exit_code == 0

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_full_flag(self, mock_resolve):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--full"])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output


class TestDoctorFailures:
    @patch("dns.resolver.resolve")
    @patch("httpx.AsyncClient")
    def test_doctor_with_dns_failure(self, mock_http_cls, mock_dns):
        import dns.resolver
        mock_dns.side_effect = dns.resolver.NoNameservers("no nameservers")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_http_cls.return_value = mock_client

        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "FAIL" in result.output


class TestBatchEdgeCases:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_deduplicates(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\ncontoso.com\nCONTOSO.COM\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_unexpected_error(self, mock_resolve, tmp_path):
        mock_resolve.side_effect = RuntimeError("network exploded")
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_panel_error_display(self, mock_resolve, tmp_path):
        """Batch in default (panel) mode should show errors inline."""
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com", message="No data", error_type="all_sources_failed",
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("bad.com\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 0

    def test_batch_too_many_domains(self, tmp_path):
        domain_file = tmp_path / "big.txt"
        lines = "\n".join(f"domain{i}.com" for i in range(10001))
        domain_file.write_text(lines)

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 2
