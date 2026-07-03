"""Regression tests for CLI output and exit-code contracts.

These pin defects found in a maintenance review: a validation exit code that was
reclassified to an internal error, and machine-readable output streams (ndjson,
markdown) contaminated by a human notice or an internal error sentinel.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.models import ConfidenceLevel, ReconLookupError, SourceResult, TenantInfo

runner = CliRunner()

RESOLVE_PATH = "recon_tool.resolver.resolve_tenant"

_INFO = TenantInfo(
    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.HIGH,
    sources=("oidc_discovery",),
    services=("Microsoft 365",),
    slugs=("microsoft365",),
)
_RESULTS = [SourceResult(source_name="oidc_discovery", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]


class TestLookupExitContract:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_unknown_profile_exits_2_not_4(self, mock_resolve) -> None:
        """An unknown --profile is a validation error (exit 2), not an internal
        crash (exit 4), and must not print a bare 'Exit' line. The profile check
        raises typer.Exit(2) from inside the lookup try block, which was being
        caught by the generic handler and reclassified."""
        mock_resolve.return_value = (_INFO, _RESULTS)
        result = runner.invoke(app, ["contoso.com", "--profile", "totally-bogus-xyz"])
        assert result.exit_code == 2
        assert "Exit\n" not in result.output


class TestBatchMachineOutputClean:
    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_ndjson_stdout_is_all_json(self, mock_resolve, tmp_path) -> None:
        """A duplicate domain must not inject a human 'duplicate(s) removed'
        notice into the ndjson stream: every non-empty stdout line must parse as
        JSON."""
        mock_resolve.return_value = (_INFO, _RESULTS)
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("contoso.com\nCONTOSO.com\n", encoding="utf-8")

        result = runner.invoke(app, ["batch", str(domain_file), "--ndjson"])
        assert result.exit_code == 0
        for line in result.output.splitlines():
            if line.strip():
                json.loads(line)  # raises if any emitted line is not valid JSON

    @patch(RESOLVE_PATH, new_callable=AsyncMock)
    def test_markdown_error_does_not_leak_sentinel(self, mock_resolve, tmp_path) -> None:
        """A resolve failure in --md mode must not echo the internal NUL error
        sentinel into stdout."""
        mock_resolve.side_effect = ReconLookupError(
            domain="broken.example", message="no data", error_type="no_data"
        )
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("broken.example\n", encoding="utf-8")

        result = runner.invoke(app, ["batch", str(domain_file), "--md"])
        assert "\x00" not in result.output
        assert "ERR:" not in result.output
