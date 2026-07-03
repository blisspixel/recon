"""CLI contract test for `recon <domain> --compare <file>`.

The compare path loads a previous JSON export before any network work, so a
missing or unreadable export must be rejected with the validation exit code.
That branch had no CLI-level coverage.
"""

from __future__ import annotations

from typer.testing import CliRunner

from recon_tool.cli import app

runner = CliRunner()


def test_compare_with_missing_file_exits_2(tmp_path) -> None:
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["contoso.com", "--compare", str(missing)])
    # load_previous fails before any resolution: exit 2 = EXIT_VALIDATION.
    assert result.exit_code == 2
