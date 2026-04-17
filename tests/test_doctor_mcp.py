"""Tests for `recon doctor --mcp` flag (v0.10.3)."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from typer.testing import CliRunner

from recon_tool.cli import app

runner = CliRunner()


class TestDoctorMcp:
    def test_doctor_mcp_succeeds(self) -> None:
        """With MCP installed, --mcp should run all checks and emit config snippet."""
        result = runner.invoke(app, ["doctor", "--mcp"])
        assert result.exit_code == 0
        out = result.output
        # Core checks
        assert "MCP package" in out
        assert "Server module" in out
        assert "Server Instructions" in out
        assert "Tools enumerated" in out
        # Copy-paste config block
        assert "mcpServers" in out
        assert "recon" in out
        assert "autoApprove" in out
        # Per-client comments
        assert "Claude Desktop" in out
        assert "Cursor" in out
        assert "Windsurf" in out

    def test_doctor_mcp_no_regular_checks(self) -> None:
        """--mcp should only run MCP checks, not the full connectivity suite."""
        result = runner.invoke(app, ["doctor", "--mcp"])
        assert result.exit_code == 0
        # These appear in regular --doctor but not in --mcp
        assert "OIDC discovery" not in result.output
        assert "crt.sh" not in result.output
