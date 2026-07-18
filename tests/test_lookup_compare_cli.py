"""CLI contract test for `recon <domain> --compare <file>`.

The compare path loads a previous JSON export before any network work, so a
missing or unreadable export must be rejected with the validation exit code.
That branch had no CLI-level coverage.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from recon_tool.cli import app

runner = CliRunner()


def test_compare_with_missing_file_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["alpha.invalid", "--compare", str(missing)])
    # load_previous fails before any resolution: exit 2 = EXIT_VALIDATION.
    assert result.exit_code == 2


def test_compare_rejects_snapshot_for_another_domain_before_resolution(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps({"queried_domain": "beta.invalid"}), encoding="utf-8")
    resolver = AsyncMock()

    with patch("recon_tool.resolver.resolve_tenant", new=resolver):
        result = runner.invoke(app, ["alpha.invalid", "--compare", str(snapshot)])

    assert result.exit_code == 2
    assert "does not match current domain" in result.stderr
    resolver.assert_not_awaited()
