"""Codex and Gemini install, doctor, and symlink behavior.

No client binary, model session, or network call.
"""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from recon_tool.cli import EXIT_NO_DATA, app
from recon_tool.mcp_client.install import InstallError, build_recon_block, install, plan_install

runner = CliRunner()


def _json_object(text: str) -> dict[str, object]:
    loaded: object = json.loads(text)
    if not isinstance(loaded, dict):
        raise AssertionError("JSON value is not an object")
    return cast(dict[str, object], loaded)


def _toml_object(text: str) -> dict[str, object]:
    return cast(dict[str, object], tomllib.loads(text))


def _recon_table(text: str) -> dict[str, object]:
    servers = _toml_object(text)["mcp_servers"]
    assert isinstance(servers, dict)
    recon = cast(dict[str, object], servers)["recon"]
    assert isinstance(recon, dict)
    return cast(dict[str, object], recon)


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def _isolate_home(monkeypatch: pytest.MonkeyPatch, home: Path, work: Path) -> None:
    home.mkdir()
    work.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(work)


class TestCodexInstall:
    def test_create_writes_a_toml_table(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        result = install("codex", "user", config_path_override=target)

        assert result.action == "create"
        text = target.read_text(encoding="utf-8")
        recon = _recon_table(text)
        assert recon["command"] == build_recon_block("codex")["command"]
        assert recon["args"] == build_recon_block("codex")["args"]
        assert "tool_timeout_sec" not in text
        assert "default_tools_approval_mode" not in text
        assert "autoApprove" not in text

    def test_dry_run_stdout_is_toml_only(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        result = runner.invoke(
            app,
            ["mcp", "install", "--client", "codex", "--config-path", str(target), "--dry-run"],
        )

        assert result.exit_code == 0, result.output
        assert not target.exists()
        assert _recon_table(result.stdout)["command"] == build_recon_block("codex")["command"]
        assert "tool_timeout_sec" not in result.stdout
        assert "default_tools_approval_mode" not in result.stdout
        assert "scope" not in result.stdout
        assert "dry-run" in result.stderr.lower()
        assert "tool_timeout_sec" in result.stderr

    def test_append_preserves_a_sibling_table(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        original = '# café\nmodel = "keep"\n\n[mcp_servers.other]\ncommand = "sibling"\n'
        target.write_text(original, encoding="utf-8")

        result = install("codex", "user", config_path_override=target)

        assert result.action == "merge"
        text = target.read_text(encoding="utf-8")
        assert text.startswith(original + "\n")
        assert _recon_table(text)["args"] == build_recon_block("codex")["args"]

    def test_matching_command_and_args_do_not_touch_mtime(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        install("codex", "user", config_path_override=target)
        written = target.read_bytes()
        stale = target.stat().st_mtime_ns - 5_000_000_000
        os.utime(target, ns=(stale, stale))

        result = install("codex", "user", config_path_override=target, force=True)

        assert result.action == "merge"
        assert target.read_bytes() == written
        assert target.stat().st_mtime_ns == stale

    def test_refuse_a_different_command_without_force(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        target.write_text('[mcp_servers.recon]\ncommand = "old"\nargs = ["mcp"]\n', encoding="utf-8")

        with pytest.raises(InstallError, match=r"would change"):
            plan_install("codex", "user", config_path_override=target)

    def test_force_replaces_the_span_and_keeps_siblings(self, tmp_path: Path) -> None:
        target = tmp_path / "config.toml"
        target.write_text(
            (
                "[mcp_servers.other]\n"
                'command = "sibling"\n'
                "\n"
                "[mcp_servers.recon]\n"
                'command = "old"\n'
                'args = ["mcp"]\n'
                'custom = "drop"\n'
                "\n"
                "# belongs to next\n"
                "[keep]\n"
                'value = "1"\n'
            ),
            encoding="utf-8",
        )

        result = install("codex", "user", config_path_override=target, force=True)

        assert result.action == "replace"
        text = target.read_text(encoding="utf-8")
        assert 'command = "sibling"' in text
        assert "# belongs to next" in text
        assert 'custom = "drop"' not in text
        assert 'command = "old"' not in text
        assert _recon_table(text)["command"] == build_recon_block("codex")["command"]

    def test_workspace_scope_writes_under_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = install("codex", "workspace")

        target = tmp_path / ".codex" / "config.toml"
        assert result.path == target
        assert target.is_file()
        assert _recon_table(target.read_text(encoding="utf-8"))["command"]

    def test_implicit_workspace_symlink_file_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        real = outside / "config.toml"
        real.write_text('model = "keep"\n', encoding="utf-8")
        codex_dir = workspace / ".codex"
        codex_dir.mkdir()
        _symlink(codex_dir / "config.toml", real)
        monkeypatch.chdir(workspace)

        with pytest.raises(InstallError, match=r"outside current directory"):
            install("codex", "workspace")

    def test_implicit_workspace_symlink_directory_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        _symlink(workspace / ".codex", outside)
        monkeypatch.chdir(workspace)

        with pytest.raises(InstallError, match=r"outside current directory"):
            install("codex", "workspace")

    def test_implicit_workspace_symlink_inside_cwd_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        real = workspace / "real.toml"
        real.write_text('model = "keep"\n', encoding="utf-8")
        codex_dir = workspace / ".codex"
        codex_dir.mkdir()
        _symlink(codex_dir / "config.toml", real)
        monkeypatch.chdir(workspace)

        with pytest.raises(InstallError, match=r"workspace symlink"):
            install("codex", "workspace")

    def test_explicit_symlink_updates_the_target(self, tmp_path: Path) -> None:
        real = tmp_path / "real" / "config.toml"
        real.parent.mkdir()
        real.write_text('model = "keep"\n', encoding="utf-8")
        link = tmp_path / "config.toml"
        _symlink(link, real)

        result = install("codex", "user", config_path_override=link)

        assert link.is_symlink()
        assert result.target_path == real.resolve()
        assert 'model = "keep"' in real.read_text(encoding="utf-8")
        assert "[mcp_servers.recon]" in real.read_text(encoding="utf-8")


class TestGeminiInstall:
    def test_create_omits_autoapprove_and_timeout(self, tmp_path: Path) -> None:
        target = tmp_path / "settings.json"
        result = install("gemini", "user", config_path_override=target)

        assert result.action == "create"
        written = _json_object(target.read_text(encoding="utf-8"))
        servers = written["mcpServers"]
        assert isinstance(servers, dict)
        recon = cast(dict[str, object], servers)["recon"]
        assert isinstance(recon, dict)
        block = cast(dict[str, object], recon)
        assert "autoApprove" not in block
        assert "timeout" not in block
        assert "type" not in block
        assert block["env"] == {"PYTHONSAFEPATH": "1"}

    def test_dry_run_stdout_is_json_only(self, tmp_path: Path) -> None:
        target = tmp_path / "settings.json"
        result = runner.invoke(
            app,
            ["mcp", "install", "--client", "gemini", "--config-path", str(target), "--dry-run"],
        )

        assert result.exit_code == 0, result.output
        assert not target.exists()
        echoed = _json_object(result.stdout)
        servers = echoed["mcpServers"]
        assert isinstance(servers, dict)
        recon = cast(dict[str, object], servers)["recon"]
        assert isinstance(recon, dict)
        assert "autoApprove" not in recon
        assert "scope" not in result.stdout

    def test_force_preserves_siblings_and_custom_env(self, tmp_path: Path) -> None:
        target = tmp_path / "settings.json"
        target.write_text(
            json.dumps(
                {
                    "theme": "dark",
                    "mcpServers": {
                        "other": {"command": "keep", "args": ["serve"]},
                        "recon": {
                            "command": "old",
                            "args": ["mcp"],
                            "env": {"DEBUG": "1"},
                            "autoApprove": ["lookup_tenant"],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        result = install("gemini", "user", config_path_override=target, force=True)

        assert result.action == "replace"
        written = _json_object(target.read_text(encoding="utf-8"))
        assert written["theme"] == "dark"
        servers = written["mcpServers"]
        assert isinstance(servers, dict)
        server_map = cast(dict[str, object], servers)
        other = server_map["other"]
        assert isinstance(other, dict)
        assert cast(dict[str, object], other)["command"] == "keep"
        recon = server_map["recon"]
        assert isinstance(recon, dict)
        block = cast(dict[str, object], recon)
        assert block["command"] != "old"
        assert block["env"] == {"DEBUG": "1"}
        assert "autoApprove" not in block
        assert "timeout" not in block

    def test_workspace_scope_writes_project_settings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        install("gemini", "workspace")
        target = tmp_path / ".gemini" / "settings.json"
        assert target.is_file()
        written = _json_object(target.read_text(encoding="utf-8"))
        assert "mcpServers" in written

    def test_implicit_workspace_symlink_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        real = outside / "settings.json"
        real.write_text("{}", encoding="utf-8")
        gemini_dir = workspace / ".gemini"
        gemini_dir.mkdir()
        _symlink(gemini_dir / "settings.json", real)
        monkeypatch.chdir(workspace)

        with pytest.raises(InstallError, match=r"outside current directory"):
            install("gemini", "workspace")

    def test_explicit_symlink_updates_the_target(self, tmp_path: Path) -> None:
        real = tmp_path / "real" / "settings.json"
        real.parent.mkdir()
        real.write_text(json.dumps({"mcpServers": {"other": {"command": "keep"}}}), encoding="utf-8")
        link = tmp_path / "settings.json"
        _symlink(link, real)

        install("gemini", "user", config_path_override=link)

        assert link.is_symlink()
        written = _json_object(real.read_text(encoding="utf-8"))
        servers = written["mcpServers"]
        assert isinstance(servers, dict)
        assert "other" in servers
        assert "recon" in servers


class TestClientDoctor:
    def test_codex_missing_stanza_exits_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _isolate_home(monkeypatch, tmp_path / "home", tmp_path / "work")
        result = runner.invoke(app, ["doctor", "--client", "codex"])

        assert result.exit_code == EXIT_NO_DATA
        assert "not found" in result.stdout or "no mcp_servers.recon" in result.stdout

    def test_codex_valid_stanza_exits_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        _isolate_home(monkeypatch, home, tmp_path / "work")
        install("codex", "user", config_path_override=home / ".codex" / "config.toml")

        result = runner.invoke(app, ["doctor", "--client", "codex"])

        assert result.exit_code == 0, result.output
        assert "registered" in result.stdout
        assert "tool_timeout_sec" in result.stdout

    def test_codex_invalid_toml_exits_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        _isolate_home(monkeypatch, home, tmp_path / "work")
        target = home / ".codex" / "config.toml"
        target.parent.mkdir()
        target.write_text("[[mcp_servers.recon]]\n", encoding="utf-8")

        result = runner.invoke(app, ["doctor", "--client", "codex"])

        assert result.exit_code == EXIT_NO_DATA
        assert "array of tables" in result.stdout

    def test_gemini_missing_stanza_exits_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _isolate_home(monkeypatch, tmp_path / "home", tmp_path / "work")
        result = runner.invoke(app, ["doctor", "--client", "gemini"])

        assert result.exit_code == EXIT_NO_DATA

    def test_gemini_valid_stanza_exits_zero_without_a_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        _isolate_home(monkeypatch, home, tmp_path / "work")
        install("gemini", "user", config_path_override=home / ".gemini" / "settings.json")

        result = runner.invoke(app, ["doctor", "--client", "gemini"])

        assert result.exit_code == 0, result.output
        assert "registered" in result.stdout
        assert "600000" in result.stdout
