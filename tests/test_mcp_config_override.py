"""Explicit client profiles and workspace installs are independent of HOME."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.mcp_client.client_doctor import check_client
from recon_tool.mcp_client.install import SUPPORTED_CLIENTS, default_scope, resolve_config_path

runner = CliRunner()


@pytest.fixture
def no_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def unavailable() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", staticmethod(unavailable))
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APPDATA", raising=False)


@pytest.mark.parametrize("client", SUPPORTED_CLIENTS)
def test_explicit_install_needs_no_home(client: str, no_home: None, tmp_path: Path) -> None:
    target = tmp_path / "profile with spaces" / "mcp.json"
    result = runner.invoke(app, ["mcp", "install", "--client", client, "--config-path", str(target)])

    assert result.exit_code == 0, result.output
    key = "servers" if client == "vscode" else "mcpServers"
    assert "recon" in json.loads(target.read_text(encoding="utf-8"))[key]
    assert json.loads(result.stdout)[key]["recon"]
    assert "--config-path" in result.stderr
    assert str(target) in result.stderr

    verified = runner.invoke(app, ["doctor", "--client", client, "--config-path", str(target)])
    assert verified.exit_code == 0, verified.output
    assert "explicit:" in verified.output
    assert "registered" in verified.output


@pytest.mark.parametrize("client", ["claude-code", "cursor", "vscode", "kiro"])
def test_workspace_install_needs_no_home(client: str, no_home: None, tmp_path: Path) -> None:
    result = runner.invoke(app, ["mcp", "install", "--client", client, "--scope", "workspace"])
    assert result.exit_code == 0, result.output
    path = resolve_config_path(client, "workspace")
    assert path.is_relative_to(tmp_path)
    assert path.exists()


def test_vscode_auto_scope_needs_no_home(no_home: None) -> None:
    assert default_scope("vscode") == "workspace"
    result = runner.invoke(app, ["mcp", "install", "--client", "vscode"])
    assert result.exit_code == 0, result.output
    assert runner.invoke(app, ["doctor", "--client", "vscode"]).exit_code == 0


def test_appdata_desktop_path_needs_no_home(no_home: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    assert resolve_config_path("claude-desktop", "user", platform_name="win32") == (
        tmp_path / "roaming" / "Claude" / "claude_desktop_config.json"
    )


def test_home_dependent_install_and_doctor_fail_actionably(no_home: None) -> None:
    for args in (["mcp", "install", "--client", "cursor"], ["doctor", "--client", "cursor"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 2
        assert "--config-path" in result.output
        assert "cannot resolve user home" in " ".join(result.output.split())


def test_missing_explicit_profile_does_not_fall_back_to_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / ".vscode" / "mcp.json"
    workspace.parent.mkdir()
    workspace.write_text('{"servers":{"recon":{"command":"recon","args":["mcp"]}}}', encoding="utf-8")
    selected = tmp_path / "absent-profile.json"

    report = check_client("vscode", config_path_override=selected)

    assert not report.ok
    files = [check for check in report.checks if check.name == "config file"]
    assert len(files) == 1
    assert str(selected) in files[0].detail
    assert str(workspace) not in " ".join(check.detail for check in report.checks)


@pytest.mark.parametrize("mode", [[], ["--mcp"], ["--fix"]])
def test_doctor_rejects_override_without_client_before_any_probe(
    mode: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("recon_tool.cli._doctor", lambda: pytest.fail("must not collect"))
    monkeypatch.setattr("recon_tool.cli._doctor_mcp", lambda: pytest.fail("must not inspect MCP"))
    monkeypatch.setattr("recon_tool.cli._doctor_fix", lambda: pytest.fail("must not write"))
    result = runner.invoke(app, ["doctor", *mode, "--config-path", "profile.json"])
    assert result.exit_code == 2
    assert "--config-path requires --client" in result.output


@pytest.mark.parametrize("command", [["mcp", "install"], ["doctor"]])
def test_path_expansion_failure_is_a_validation_error(command: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_path: Path) -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "expanduser", unavailable)
    result = runner.invoke(app, [*command, "--client", "vscode", "--config-path", "~/mcp.json"])
    assert result.exit_code == 2
    assert "explicit absolute config file path" in " ".join(result.output.split())


def test_verification_command_quotes_exact_path(tmp_path: Path) -> None:
    target = tmp_path / "O'Brien; $literal profile.json"
    result = runner.invoke(app, ["mcp", "install", "--client", "vscode", "--config-path", str(target)])
    quoted = "'" + str(target).replace("'", "''") + "'" if os.name == "nt" else shlex.quote(str(target))
    assert result.exit_code == 0, result.output
    assert f"recon doctor --client=vscode --config-path {quoted}" in result.stderr


def test_doctor_expands_same_environment_path_as_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECON_TEST_PROFILE", str(tmp_path))
    path = "${RECON_TEST_PROFILE}/profile.json"
    installed = runner.invoke(app, ["mcp", "install", "--client", "vscode", "--config-path", path])
    verified = runner.invoke(app, ["doctor", "--client", "vscode", "--config-path", path])
    assert installed.exit_code == 0, installed.output
    assert verified.exit_code == 0, verified.output
