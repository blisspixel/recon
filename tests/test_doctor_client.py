"""Tests for `recon doctor --client` — the client-side MCP config check.

Covers the pure-data layer in `recon_tool.client_doctor` (config read,
recon-stanza location across user / workspace / project-nested scopes,
command sanity) and the typer command surface in `recon_tool.cli`.
Filesystem effects are confined to ``tmp_path``; no network, no spawn.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool import client_doctor
from recon_tool.cli import EXIT_NO_DATA, EXIT_VALIDATION, app
from recon_tool.client_doctor import check_client

runner = CliRunner()


def _statuses(report: client_doctor.ClientDoctorReport) -> dict[str, str]:
    """Map each check name to its status for terse assertions.

    The last check wins when names repeat (e.g. multiple "config file"
    lines); tests that care about a specific line assert on the list.
    """
    return {c.name: c.status for c in report.checks}


def _write(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point ``Path.home`` and ``$APPDATA`` at an isolated tmp home."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    return tmp_path


@pytest.fixture
def recon_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend ``recon`` resolves on PATH so the bare-command check is ok."""

    def _which(_name: str) -> str | None:
        return "/usr/local/bin/recon"

    monkeypatch.setattr(client_doctor.shutil, "which", _which)


@pytest.fixture
def recon_off_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend ``recon`` is not on PATH so the bare-command check warns."""

    def _which(_name: str) -> str | None:
        return None

    monkeypatch.setattr(client_doctor.shutil, "which", _which)


class TestCheckClient:
    def test_claude_code_missing_file(self, home: Path) -> None:
        report = check_client("claude-code", platform_name="linux")
        assert not report.ok
        assert _statuses(report)["recon stanza"] == "fail"
        # The plugin-scope teaching note is always attached for claude-code.
        assert any("plugin" in n.lower() for n in report.notes)
        assert any("mcp__recon__" in n for n in report.notes)
        assert any("/mcp" in n for n in report.notes)

    def test_claude_code_top_level_stanza(self, home: Path, recon_on_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"], "autoApprove": []}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert report.ok
        stanza = next(c for c in report.checks if c.name == "recon stanza")
        assert stanza.status == "ok"
        assert "mcpServers.recon" in stanza.detail
        assert _statuses(report)["command"] == "ok"

    def test_claude_code_projects_nested(self, home: Path, recon_on_path: None, tmp_path: Path) -> None:
        project = tmp_path / "work"
        _write(
            home / ".claude.json",
            {"projects": {str(project): {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}}}},
        )
        report = check_client("claude-code", platform_name="linux", cwd=project)
        assert report.ok
        stanza = next(c for c in report.checks if c.name == "recon stanza")
        assert "projects[" in stanza.detail

    def test_mcpservers_without_recon_fails(self, home: Path) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"context7": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert not report.ok
        assert _statuses(report)["recon stanza"] == "fail"

    def test_malformed_json_is_reported(self, home: Path) -> None:
        (home / ".claude.json").write_text("{ not valid json", encoding="utf-8")
        report = check_client("claude-code", platform_name="linux")
        assert not report.ok
        config_checks = [c for c in report.checks if c.name == "config file"]
        assert any(c.status == "fail" and "JSON" in c.detail for c in config_checks)

    def test_bom_tolerant_read(self, home: Path, recon_on_path: None) -> None:
        # A UTF-8 BOM prepended by a Windows editor must not break parsing.
        raw = json.dumps({"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}})
        (home / ".claude.json").write_text("﻿" + raw, encoding="utf-8")
        report = check_client("claude-code", platform_name="linux")
        assert report.ok

    def test_bare_recon_not_on_path_warns_not_fails(self, home: Path, recon_off_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        # A PATH warning does not fail the report — the stanza may still
        # load in a client that resolves a different PATH.
        assert report.ok
        assert _statuses(report)["command"] == "warn"
        command = next(c for c in report.checks if c.name == "command")
        assert "sys.path-stripping Python fallback" in command.detail
        assert "python -m recon_tool.server form" not in command.detail

    def test_missing_command_fails(self, home: Path) -> None:
        _write(home / ".claude.json", {"mcpServers": {"recon": {"args": ["mcp"]}}})
        report = check_client("claude-code", platform_name="linux")
        assert not report.ok
        assert _statuses(report)["command"] == "fail"

    def test_python_module_command_warns_about_launcher_isolation(self, home: Path, recon_off_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "python", "args": ["-m", "recon_tool.server"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert _statuses(report)["command"] == "ok"
        isolation = next(c for c in report.checks if c.name == "launcher isolation")
        assert isolation.status == "warn"
        assert "sys.path" in isolation.detail
        assert "recon mcp install" in isolation.detail

    def test_installer_fallback_command_has_no_launcher_isolation_warning(
        self, home: Path, recon_off_path: None
    ) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "python", "args": ["-c", "import sys; print('safe')"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert _statuses(report)["command"] == "ok"
        assert "launcher isolation" not in _statuses(report)

    def test_autoapprove_populated_is_info(self, home: Path, recon_on_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"], "autoApprove": ["lookup_tenant"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        auto = next(c for c in report.checks if c.name == "autoApprove")
        assert auto.status == "info"
        assert "lookup_tenant" in auto.detail

    def test_cursor_workspace_stanza(
        self, home: Path, recon_on_path: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        workdir = tmp_path / "proj"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        _write(
            workdir / ".cursor" / "mcp.json",
            {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}},
        )
        report = check_client("cursor", platform_name="linux")
        assert report.ok
        # cursor is a non-claude-code client: generic notes, no plugin note.
        assert not any("plugin" in n.lower() for n in report.notes)

    def test_directory_instead_of_file(self, home: Path) -> None:
        # ~/.claude.json exists but is a directory — report, don't crash.
        (home / ".claude.json").mkdir()
        report = check_client("claude-code", platform_name="linux")
        assert not report.ok


class TestDoctorClientCLI:
    def test_unknown_client_exits_validation(self) -> None:
        result = runner.invoke(app, ["doctor", "--client", "bogus"])
        assert result.exit_code == EXIT_VALIDATION
        assert "Supported" in result.stdout

    def test_found_exits_zero(self, home: Path, recon_on_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"], "autoApprove": []}}},
        )
        result = runner.invoke(app, ["doctor", "--client", "claude-code"])
        assert result.exit_code == 0
        assert "registered" in result.stdout

    def test_not_found_exits_no_data(self, home: Path) -> None:
        result = runner.invoke(app, ["doctor", "--client", "claude-code"])
        assert result.exit_code == EXIT_NO_DATA
        assert "not found" in result.stdout


class TestVscodeServersKey:
    """VS Code uses a top-level `servers` key, not `mcpServers`."""

    def test_found_under_servers_key(
        self, recon_on_path: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _write(tmp_path / ".vscode" / "mcp.json", {"servers": {"recon": {"command": "recon", "args": ["mcp"]}}})
        report = check_client("vscode", platform_name="linux")
        assert report.ok
        stanza = next(c for c in report.checks if c.name == "recon stanza")
        assert "servers.recon" in stanza.detail
        assert any("VS Code reads MCP servers" in n for n in report.notes)

    def test_legacy_mcpservers_still_found_and_flagged(
        self, recon_on_path: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # An older recon installer left the stanza under mcpServers, which
        # VS Code does not read. The check should still locate it (so the
        # operator sees where it is) and the notes explain the move.
        monkeypatch.chdir(tmp_path)
        _write(tmp_path / ".vscode" / "mcp.json", {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}})
        report = check_client("vscode", platform_name="linux")
        stanza = next(c for c in report.checks if c.name == "recon stanza")
        assert "mcpServers.recon" in stanza.detail
        assert any("move it" in n for n in report.notes)


class TestRegressionFixes:
    """Round-2 bug-hunt regressions."""

    def test_absolute_recon_path_command_ok_not_warn(self, home: Path, recon_off_path: None) -> None:
        # The common installed form is an absolute path ending in recon.
        # It must read as ok even when the path does not resolve on this
        # machine (e.g. a config synced from elsewhere).
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "/usr/local/bin/recon", "args": ["mcp"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert _statuses(report)["command"] == "ok"

    def test_windows_recon_exe_command_ok(self, home: Path, recon_off_path: None) -> None:
        _write(
            home / ".claude.json",
            {"mcpServers": {"recon": {"command": "C:\\Tools\\Scripts\\recon.exe", "args": ["mcp"]}}},
        )
        report = check_client("claude-code", platform_name="linux")
        assert _statuses(report)["command"] == "ok"

    def test_duplicate_stanza_not_mislabelled(
        self, home: Path, recon_on_path: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # recon present in BOTH the user config and the workspace config.
        # The second file must not be reported as "no recon"; it should be
        # labelled as a duplicate that the first candidate already covers.
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        _write(tmp_path / ".claude.json", {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}})
        _write(tmp_path / ".mcp.json", {"mcpServers": {"recon": {"command": "recon", "args": ["mcp"]}}})
        report = check_client("claude-code", platform_name="linux")
        assert report.ok
        config_lines = [c for c in report.checks if c.name == "config file"]
        assert any("also has recon" in c.detail and "first wins" in c.detail for c in config_lines)


def test_command_check_strips_terminal_control_bytes() -> None:
    """A workspace config command with ANSI/OSC bytes is sanitized before display.

    rich.markup.escape does not remove terminal control bytes, so an untrusted
    workspace MCP config could otherwise inject ANSI / OSC sequences into the
    operator's terminal through `recon doctor --client=<name>`. The command value
    is stripped of control characters before it becomes a ClientCheck detail.
    """
    malicious = "\x1b[31mEVIL\x1b]52;c;cGF3bnVk\x07tail"
    checks = client_doctor._command_checks({"command": malicious})  # pyright: ignore[reportPrivateUsage]
    command_checks = [c for c in checks if c.name == "command"]
    assert command_checks, "expected a command check"
    for check in command_checks:
        assert "\x1b" not in check.detail
        assert "\x07" not in check.detail
        assert "EVIL" in check.detail  # printable content preserved
