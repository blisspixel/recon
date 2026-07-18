"""CLI-level contract tests for `recon discover`.

The command mines a single domain for fingerprint candidates. Its implementation
(``cli_batch.discover``) had no CLI-level coverage, so a regression in the
command wrapper (exit codes, output routing) would have gone unnoticed. These
pin the output shape (stdout vs file) and the exit-code contract.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import ConfidenceLevel, ReconLookupError, TenantInfo

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Synthetic Alpha Ltd",
    default_domain="alpha.onmicrosoft.com",
    queried_domain="alpha.invalid",
    confidence=ConfidenceLevel.HIGH,
)


class TestDiscoverCommand:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_emits_json_list_to_stdout(self, mock_resolve) -> None:
        """Default output is a JSON candidate list on stdout, exit 0."""
        mock_resolve.return_value = (_INFO, [])
        result = runner.invoke(app, ["discover", "alpha.invalid"])
        assert result.exit_code == 0
        assert isinstance(json.loads(result.output), list)

    def test_rejects_malformed_domain(self) -> None:
        """Validation fails before any network work: exit 2 = EXIT_VALIDATION."""
        result = runner.invoke(app, ["discover", "not a domain"])
        assert result.exit_code == 2

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_writes_output_file(self, mock_resolve, tmp_path) -> None:
        """--output routes the candidate JSON to a file instead of stdout."""
        mock_resolve.return_value = (_INFO, [])
        out = tmp_path / "candidates.json"
        result = runner.invoke(app, ["discover", "alpha.invalid", "--output", str(out)])
        assert result.exit_code == 0
        assert isinstance(json.loads(out.read_text(encoding="utf-8")), list)

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_no_data_exits_3(self, mock_resolve) -> None:
        """A clean 'resolved but nothing to show' maps to exit 3 = EXIT_NO_DATA."""
        mock_resolve.side_effect = ReconLookupError(
            domain="alpha.invalid", message="no indicators found", error_type="no_data"
        )
        result = runner.invoke(app, ["discover", "alpha.invalid"])
        assert result.exit_code == 3

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_unexpected_error_exits_4(self, mock_resolve) -> None:
        """An unclassified failure maps to exit 4 = EXIT_INTERNAL."""
        mock_resolve.side_effect = RuntimeError("boom")
        result = runner.invoke(app, ["discover", "alpha.invalid"])
        assert result.exit_code == 4
