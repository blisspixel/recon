"""Unit tests for CLI application."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import (
    ConfidenceLevel,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)

runner = CliRunner()

SAMPLE_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    region="NA",
    sources=("oidc_discovery", "azure_ad_metadata"),
    services=("Exchange Online", "Microsoft 365"),
    slugs=("microsoft365",),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="azure_ad_metadata", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", region="NA"),
    SourceResult(source_name="dns_records", error="no indicators"),
]

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"


class TestHelp:
    def test_help_shows_usage(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "recon" in result.output.lower()

    def test_lookup_help(self) -> None:
        result = runner.invoke(app, ["lookup", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--md" in result.output
        assert "--full" in result.output

    def test_version_flag(self) -> None:
        from recon_tool.cli import version_callback
        with pytest.raises(typer.Exit):
            version_callback(True)


class TestDirectDomainLookup:
    """recon pepsi.com works via sys.argv preprocessing (not testable via CliRunner).
    These test the lookup subcommand which is equivalent."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_default(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com"])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_json(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["display_name"] == "Contoso Ltd"

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_md(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--md"])
        assert result.exit_code == 0
        assert "# " in result.output


class TestLookupSubcommand:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_lookup_subcommand(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com"])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_verbose_flag(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--verbose"])
        assert result.exit_code == 0
        assert "oidc_discovery" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_sources_flag(self, mock_resolve) -> None:
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        result = runner.invoke(app, ["lookup", "contoso.com", "--sources"])
        assert result.exit_code == 0
        assert "Source Details" in result.output


class TestErrors:
    def test_invalid_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "not a domain"])
        assert result.exit_code == 2

    def test_empty_domain(self) -> None:
        result = runner.invoke(app, ["lookup", "   "])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_not_found(self, mock_resolve) -> None:
        mock_resolve.side_effect = ReconLookupError(
            domain="unknown.com", message="No tenant found", error_type="all_sources_failed",
        )
        result = runner.invoke(app, ["lookup", "unknown.com"])
        assert result.exit_code == 3
        assert "unknown.com" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_unexpected_error(self, mock_resolve) -> None:
        mock_resolve.side_effect = RuntimeError("connection failed")
        result = runner.invoke(app, ["lookup", "example.com"])
        assert result.exit_code == 4
        assert "connection failed" in result.output


class TestDoctor:
    @patch("dns.resolver.resolve")
    @patch("httpx.AsyncClient")
    def test_doctor_all_pass(self, mock_http_cls, mock_dns) -> None:
        mock_dns.return_value = [MagicMock()]
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
        assert "All checks passed" in result.output
