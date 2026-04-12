"""Tests for CLI batch mode."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.cli import app
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
    sources=("oidc_discovery",),
    services=("Microsoft 365",),
    slugs=("microsoft365",),
)

SAMPLE_RESULTS = [
    SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
]


class TestBatchCommand:
    """Tests for the batch subcommand."""

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nexample.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["display_name"] == "Contoso Ltd"

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_markdown_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--md"])
        assert result.exit_code == 0
        assert "# " in result.output
        assert "Contoso Ltd" in result.output

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_default_panel_output(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 0
        assert "Contoso Ltd" in result.output

    def test_batch_file_not_found(self):
        result = runner.invoke(app, ["batch", "nonexistent.txt"])
        assert result.exit_code == 2

    def test_batch_empty_file(self, tmp_path):
        domain_file = tmp_path / "empty.txt"
        domain_file.write_text("# just a comment\n\n")

        result = runner.invoke(app, ["batch", str(domain_file)])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_skips_comments_and_blanks(self, mock_resolve, tmp_path):
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("# header\ncontoso.com\n\n# another comment\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_handles_errors(self, mock_resolve, tmp_path):
        mock_resolve.side_effect = ReconLookupError(
            domain="bad.com",
            message="No data",
            error_type="all_sources_failed",
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("bad.com\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_json_handles_invalid_domain(self, mock_resolve, tmp_path):
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("not a domain\n")

        result = runner.invoke(app, ["batch", str(domain_file), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert "error" in data[0]

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_batch_concurrency_clamped(self, mock_resolve, tmp_path):
        """Concurrency is clamped to 1-20 range."""
        mock_resolve.return_value = (SAMPLE_INFO, SAMPLE_RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\n")

        # -c 0 should be clamped to 1, -c 100 to 20 — both should work
        result = runner.invoke(app, ["batch", str(domain_file), "--json", "-c", "0"])
        assert result.exit_code == 0
        result = runner.invoke(app, ["batch", str(domain_file), "--json", "-c", "100"])
        assert result.exit_code == 0
