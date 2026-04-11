"""Tests for CLI batch mode and _preprocess_args."""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

import recon_tool.cli
from recon_tool.cli import _preprocess_args, app
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


class TestPreprocessArgs:
    """Tests for the sys.argv preprocessing that enables `recon pepsi.com`."""

    def _reset(self):
        """Reset the idempotency guard so each test starts fresh."""
        recon_tool.cli._preprocessed = False

    def test_domain_inserts_lookup(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "pepsi.com"])
        _preprocess_args()
        assert sys.argv == ["recon", "lookup", "pepsi.com"]

    def test_subcommand_not_modified(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "doctor"])
        _preprocess_args()
        assert sys.argv == ["recon", "doctor"]

    def test_flag_not_modified(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "--version"])
        _preprocess_args()
        assert sys.argv == ["recon", "--version"]

    def test_no_args_not_modified(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon"])
        _preprocess_args()
        assert sys.argv == ["recon"]

    def test_domain_with_flags_inserts_lookup(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "pepsi.com", "--json"])
        _preprocess_args()
        assert sys.argv == ["recon", "lookup", "pepsi.com", "--json"]

    def test_batch_subcommand_not_modified(self, monkeypatch):
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "batch", "domains.txt"])
        _preprocess_args()
        assert sys.argv == ["recon", "batch", "domains.txt"]

    def test_idempotent_double_call(self, monkeypatch):
        """Calling _preprocess_args twice should not double-insert 'lookup'."""
        self._reset()
        monkeypatch.setattr(sys, "argv", ["recon", "pepsi.com"])
        _preprocess_args()
        _preprocess_args()  # second call should be a no-op
        assert sys.argv == ["recon", "lookup", "pepsi.com"]


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
            domain="bad.com", message="No data", error_type="all_sources_failed",
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
