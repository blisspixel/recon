"""Tests for `recon doctor --mcp` flag (v0.10.3)."""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("mcp")

from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.mcp_client.install import build_recon_block

runner = CliRunner()


class TestDoctorMcp:
    def test_importing_server_does_not_install_a_shared_logger_handler(self) -> None:
        probe = (
            "import logging; "
            "logger = logging.getLogger('recon'); logger.handlers.clear(); "
            "import recon_tool.server; "
            "print(len(logger.handlers)); "
            "logging.getLogger().handlers.clear(); "
            "ctx = recon_tool.server._runtime_logging(); ctx.__enter__(); "
            "print(len(logger.handlers), logger.level); "
            "ctx.__exit__(None, None, None); "
            "print(len(logger.handlers), logger.level)"
        )
        result = subprocess.run(  # noqa: S603 - fixed interpreter and test-owned probe.
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == ["0", "1 20", "0 0"]

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
        # Parseable reference config block
        assert "mcpServers" in out
        assert "recon" in out
        assert '"autoApprove": []' in out
        assert "Security note" in out
        # Per-client comments
        assert "Claude Desktop" in out
        assert "Cursor" in out
        assert "Windsurf" in out
        collapsed = " ".join(out.split())
        assert "VS Code uses a different top-level `servers` key" in collapsed
        assert "recon mcp install --client=vscode" in collapsed
        assert "Prefer `recon mcp install --client=<name>`" in collapsed

        config_start = out.index("{")
        config, _ = json.JSONDecoder().raw_decode(out[config_start:])
        assert config == {"mcpServers": {"recon": build_recon_block()}}
        launcher = " ".join(config["mcpServers"]["recon"]["args"])
        assert "sys.path[:] = [" in launcher

    def test_doctor_mcp_no_regular_checks(self) -> None:
        """--mcp should only run MCP checks, not the full connectivity suite."""
        result = runner.invoke(app, ["doctor", "--mcp"])
        assert result.exit_code == 0
        # These appear in regular --doctor but not in --mcp
        assert "OIDC discovery" not in result.output
        assert "crt.sh" not in result.output

    def test_doctor_mcp_exits_one_when_mcp_missing(self) -> None:
        """A missing MCP package cannot produce a working setup, so --mcp exits 1
        instead of always reading success."""
        import importlib

        real_import = importlib.import_module

        def fake_import(name, *args, **kwargs):
            if name == "mcp" or name.startswith("mcp."):
                raise ImportError("No module named 'mcp'")
            return real_import(name, *args, **kwargs)

        with patch("importlib.import_module", side_effect=fake_import):
            result = runner.invoke(app, ["doctor", "--mcp"])

        assert result.exit_code == 1
        assert "MCP package" in result.output
        assert "not installed" in result.output

    def test_doctor_mcp_exits_one_when_no_tools_registered(self) -> None:
        """A server that loads but registers no tools is broken, so --mcp exits 1
        while still printing the checks."""
        from recon_tool.server import mcp as server_mcp

        with patch.object(server_mcp, "list_tools", new=AsyncMock(return_value=[])):
            result = runner.invoke(app, ["doctor", "--mcp"])

        assert result.exit_code == 1
        assert "no tools registered" in result.output
