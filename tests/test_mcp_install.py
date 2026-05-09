"""Tests for `recon mcp install` — the MCP-config installer.

Covers the pure-data layer in `recon_tool.mcp_install` (path resolution,
JSON merge, refusal cases) and the typer command surface in
`recon_tool.cli`. Filesystem effects are confined to ``tmp_path``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.mcp_install import (
    SUPPORTED_CLIENTS,
    InstallError,
    _os_family,
    build_recon_block,
    default_scope,
    install,
    plan_install,
    resolve_config_path,
)

runner = CliRunner()


class TestOSFamily:
    @pytest.mark.parametrize(
        ("platform_name", "expected"),
        [
            ("win32", "windows"),
            ("Win64", "windows"),
            ("darwin", "darwin"),
            ("linux", "linux"),
            ("linux2", "linux"),
            ("freebsd13", "linux"),
        ],
    )
    def test_buckets(self, platform_name: str, expected: str) -> None:
        assert _os_family(platform_name) == expected


class TestResolveConfigPath:
    def test_claude_desktop_windows_user(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))

        path = resolve_config_path("claude-desktop", "user", platform_name="win32")
        assert path == tmp_path / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"

    def test_claude_desktop_macos_user(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        path = resolve_config_path("claude-desktop", "user", platform_name="darwin")
        assert path == tmp_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"

    def test_claude_desktop_linux_user(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        path = resolve_config_path("claude-desktop", "user", platform_name="linux")
        assert path == tmp_path / ".config" / "Claude" / "claude_desktop_config.json"

    def test_claude_desktop_has_no_workspace_scope(self) -> None:
        with pytest.raises(ValueError, match="workspace-scoped"):
            resolve_config_path("claude-desktop", "workspace")

    def test_vscode_has_no_user_scope(self) -> None:
        with pytest.raises(ValueError, match="user-scoped"):
            resolve_config_path("vscode", "user")

    def test_vscode_workspace(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)

        path = resolve_config_path("vscode", "workspace")
        assert path == tmp_path / ".vscode" / "mcp.json"

    def test_cursor_workspace(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)

        path = resolve_config_path("cursor", "workspace")
        assert path == tmp_path / ".cursor" / "mcp.json"

    def test_cursor_user_all_oses(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        for os_name in ("win32", "darwin", "linux"):
            assert resolve_config_path("cursor", "user", platform_name=os_name) == tmp_path / ".cursor" / "mcp.json"

    def test_windsurf_user_paths(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        for os_name in ("win32", "darwin", "linux"):
            assert (
                resolve_config_path("windsurf", "user", platform_name=os_name)
                == tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
            )

    def test_kiro_workspace(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)
        assert resolve_config_path("kiro", "workspace") == tmp_path / ".kiro" / "settings" / "mcp.json"

    def test_claude_code_workspace(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)
        assert resolve_config_path("claude-code", "workspace") == tmp_path / ".mcp.json"


class TestDefaultScope:
    def test_clients_with_user_default_to_user(self) -> None:
        for client in ("claude-desktop", "cursor", "windsurf", "kiro", "claude-code"):
            assert default_scope(client) == "user"  # pyright: ignore[reportArgumentType]

    def test_workspace_only_clients_default_to_workspace(self) -> None:
        assert default_scope("vscode") == "workspace"


class TestBuildReconBlock:
    def test_uses_recon_when_on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _which(_cmd: str) -> str:
            return "/usr/local/bin/recon"

        monkeypatch.setattr("recon_tool.mcp_install.shutil.which", _which)
        block = build_recon_block()
        assert block["command"] == "/usr/local/bin/recon"
        assert block["args"] == ["mcp"]
        assert block["autoApprove"] == []

    def test_falls_back_to_python_module_form(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _which(_cmd: str) -> str | None:
            return None

        monkeypatch.setattr("recon_tool.mcp_install.shutil.which", _which)
        monkeypatch.setattr("recon_tool.mcp_install.sys.executable", "/opt/python/bin/python3")
        block = build_recon_block()
        assert block["command"] == "/opt/python/bin/python3"
        assert block["args"] == ["-m", "recon_tool.server"]


class TestPlanAndInstallCreate:
    """Fresh-config path: file doesn't exist yet."""

    def test_plan_create_when_file_absent(self, tmp_path: Path) -> None:
        target = tmp_path / "newdir" / "mcp.json"
        plan = plan_install("cursor", "user", config_path_override=target)
        assert plan.action == "create"
        assert plan.existing_block is None
        assert tmp_path / "newdir" in plan.parent_dirs_to_create

    def test_install_creates_file_and_writes_block(self, tmp_path: Path) -> None:
        target = tmp_path / "subdir" / "mcp.json"
        result = install("cursor", "user", config_path_override=target)

        assert result.path == target
        assert result.action == "create"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["mcpServers"]["recon"]["args"] == ["mcp"]
        assert data["mcpServers"]["recon"]["autoApprove"] == []

    def test_install_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        result = install("cursor", "user", config_path_override=target, dry_run=True)
        assert result.action == "noop-dry-run"
        assert not target.exists()


class TestPlanAndInstallMerge:
    """Existing file path: must merge into mcpServers without clobbering siblings."""

    def test_merge_preserves_other_servers(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "other-tool": {"command": "other", "args": ["serve"]},
                    },
                    "unrelatedTopLevel": {"keep": True},
                }
            ),
            encoding="utf-8",
        )

        result = install("cursor", "user", config_path_override=target)
        assert result.action == "merge"

        data = json.loads(target.read_text(encoding="utf-8"))
        assert "other-tool" in data["mcpServers"]
        assert data["mcpServers"]["other-tool"]["command"] == "other"
        assert "recon" in data["mcpServers"]
        assert data["unrelatedTopLevel"]["keep"] is True

    def test_merge_when_recon_already_matches_is_noop(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        block = build_recon_block()
        target.write_text(json.dumps({"mcpServers": {"recon": block}}), encoding="utf-8")

        plan = plan_install("cursor", "user", config_path_override=target)
        assert plan.action == "merge"
        assert plan.existing_block == block

    def test_merge_when_no_mcpservers_key_yet(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")

        result = install("cursor", "user", config_path_override=target)
        assert result.action == "merge"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["theme"] == "dark"
        assert "recon" in data["mcpServers"]


class TestInstallRefusals:
    def test_refuse_overwrite_differing_recon_block_without_force(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "recon": {"command": "uvx", "args": ["--from", "recon-tool", "recon", "mcp"]},
                    }
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(InstallError, match="already has"):
            plan_install("cursor", "user", config_path_override=target)

    def test_force_overwrites_existing_recon_block(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {"mcpServers": {"recon": {"command": "old-binary", "args": ["mcp"]}}}
            ),
            encoding="utf-8",
        )

        result = install("cursor", "user", config_path_override=target, force=True)
        assert result.action == "replace"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["mcpServers"]["recon"]["command"] != "old-binary"

    def test_refuse_unparseable_json(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text("{not: valid json", encoding="utf-8")

        with pytest.raises(InstallError, match="not valid JSON"):
            plan_install("cursor", "user", config_path_override=target)

    def test_refuse_when_top_level_is_not_object(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

        with pytest.raises(InstallError, match="not an object"):
            plan_install("cursor", "user", config_path_override=target)

    def test_refuse_when_mcpservers_is_not_object(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(json.dumps({"mcpServers": "wrong"}), encoding="utf-8")

        with pytest.raises(InstallError, match="not an object"):
            plan_install("cursor", "user", config_path_override=target)

    def test_refuse_when_config_path_is_a_directory(self, tmp_path: Path) -> None:
        # Common reflex error: trailing slash, or pointing at a parent.
        with pytest.raises(InstallError, match="directory, not a config file"):
            plan_install("cursor", "user", config_path_override=tmp_path)


class TestUserFieldPreservation:
    """The fork audit found that --force used to clobber `env`,
    `disabled`, and a non-empty `autoApprove`. These tests pin the
    fixed behavior: only `command` and `args` are authoritative on
    the install side; everything else the user added stays."""

    def test_force_preserves_custom_env_dict(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "recon": {
                            "command": "old-recon",
                            "args": ["mcp"],
                            "env": {"DEBUG": "1", "RECON_HOME": "/srv/recon"},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        install("cursor", "user", config_path_override=target, force=True)
        data = json.loads(target.read_text(encoding="utf-8"))
        recon = data["mcpServers"]["recon"]
        assert recon["env"] == {"DEBUG": "1", "RECON_HOME": "/srv/recon"}
        assert recon["command"] != "old-recon"  # canonical refresh still happened

    def test_force_preserves_existing_autoapprove_entries(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "recon": {
                            "command": "old-recon",
                            "args": ["mcp"],
                            "autoApprove": ["lookup_tenant", "analyze_posture"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        install("cursor", "user", config_path_override=target, force=True)
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["mcpServers"]["recon"]["autoApprove"] == ["lookup_tenant", "analyze_posture"]

    def test_force_preserves_disabled_and_unknown_keys(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "recon": {
                            "command": "old-recon",
                            "args": ["mcp"],
                            "disabled": False,
                            "_note": "kept by ops on 2026-04-01",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        install("cursor", "user", config_path_override=target, force=True)
        data = json.loads(target.read_text(encoding="utf-8"))
        recon = data["mcpServers"]["recon"]
        assert recon["disabled"] is False
        assert recon["_note"] == "kept by ops on 2026-04-01"

    def test_install_seeds_empty_autoapprove_only_when_absent(self, tmp_path: Path) -> None:
        """A fresh install should surface the canonical `autoApprove: []`
        so users see the field exists; reruns must not reset it."""
        target = tmp_path / "mcp.json"

        install("cursor", "user", config_path_override=target)
        data1 = json.loads(target.read_text(encoding="utf-8"))
        assert data1["mcpServers"]["recon"]["autoApprove"] == []

        # Operator hand-edits to allow some tools.
        data1["mcpServers"]["recon"]["autoApprove"] = ["lookup_tenant"]
        target.write_text(json.dumps(data1), encoding="utf-8")

        # Rerun must not reset their hand-curated list.
        install("cursor", "user", config_path_override=target)
        data2 = json.loads(target.read_text(encoding="utf-8"))
        assert data2["mcpServers"]["recon"]["autoApprove"] == ["lookup_tenant"]


class TestIdempotency:
    """Reruns on an unchanged config must short-circuit — no rewrite,
    no mtime change, no Cursor/VS Code file-watcher reload loop."""

    def test_rerun_with_only_canonical_keys_is_noop(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        install("cursor", "user", config_path_override=target)
        first_mtime = target.stat().st_mtime_ns

        # Sleep is unnecessary — if we write at all, mtime changes;
        # if we don't, mtime is identical regardless of clock resolution.
        install("cursor", "user", config_path_override=target)

        assert target.stat().st_mtime_ns == first_mtime

    def test_rerun_after_user_added_extra_field_still_idempotent(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        install("cursor", "user", config_path_override=target)

        # Operator adds a field the canonical block doesn't know about.
        data = json.loads(target.read_text(encoding="utf-8"))
        data["mcpServers"]["recon"]["disabled"] = False
        target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        first_mtime = target.stat().st_mtime_ns

        # Without --force, rerun must succeed (the canonical fields are
        # unchanged) AND must not rewrite the file (idempotency holds
        # over the operator's extra fields).
        result = install("cursor", "user", config_path_override=target)
        assert result.action == "merge"
        assert target.stat().st_mtime_ns == first_mtime

        data2 = json.loads(target.read_text(encoding="utf-8"))
        assert data2["mcpServers"]["recon"]["disabled"] is False


class TestEncodingAndLineEndings:
    """The fork audit flagged BOM, ensure_ascii, and CRLF risk on
    Windows. Pin the fixed behavior."""

    def test_utf8_bom_is_consumed_on_read(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        # Some Windows tools (Notepad with old encoding setting,
        # PowerShell `>` redirect on certain versions) prepend a BOM.
        body = json.dumps({"mcpServers": {"other-tool": {"command": "x"}}})
        target.write_bytes("﻿".encode() + body.encode("utf-8"))

        # Must not raise InstallError("not valid JSON").
        result = install("cursor", "user", config_path_override=target)
        assert result.action == "merge"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert "other-tool" in data["mcpServers"]
        assert "recon" in data["mcpServers"]

    def test_unicode_in_unrelated_fields_round_trips(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {"sibling": {"description": "café — résumé"}},
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        install("cursor", "user", config_path_override=target)

        # Read as raw bytes so we can assert no \uXXXX escape sequences leaked in.
        raw = target.read_bytes().decode("utf-8")
        assert "café" in raw
        assert "résumé" in raw
        assert "\\u00e9" not in raw

    def test_writes_lf_line_endings_even_on_windows(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        install("cursor", "user", config_path_override=target)

        raw_bytes = target.read_bytes()
        # No CR bytes anywhere — pure LF.
        assert b"\r\n" not in raw_bytes
        assert b"\r" not in raw_bytes


class TestCLI:
    def test_install_help(self) -> None:
        result = runner.invoke(app, ["mcp", "install", "--help"])
        assert result.exit_code == 0
        assert "client" in result.output.lower()

    def test_install_dry_run_emits_plan_without_writing(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                str(target),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "client" in result.output
        assert "cursor" in result.output
        assert "dry-run" in result.output.lower()
        assert not target.exists()

    def test_install_writes_file(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                str(target),
            ],
        )
        assert result.exit_code == 0
        assert target.exists()
        data = json.loads(target.read_text(encoding="utf-8"))
        assert "recon" in data["mcpServers"]

    def test_install_unknown_client_validation_error(self) -> None:
        result = runner.invoke(app, ["mcp", "install", "--client", "atom"])
        assert result.exit_code != 0
        assert "Unknown client" in result.output or "atom" in result.output

    def test_install_bad_scope_validation_error(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--scope",
                "global",
                "--config-path",
                str(tmp_path / "x.json"),
            ],
        )
        assert result.exit_code != 0
        assert "scope" in result.output.lower()

    def test_install_refuses_existing_recon_without_force(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "recon": {"command": "old", "args": ["mcp"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                str(target),
            ],
        )
        assert result.exit_code != 0
        assert "refused" in result.output.lower() or "already" in result.output.lower()

    def test_install_with_force_replaces(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        target.write_text(
            json.dumps(
                {"mcpServers": {"recon": {"command": "old", "args": ["mcp"]}}}
            ),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                str(target),
                "--force",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["mcpServers"]["recon"]["command"] != "old"


class TestAtomicWrite:
    """A failed write must never leave the user with a truncated config.

    The fix uses a sibling tempfile + os.replace, so the rename is the
    only file-content-changing op the operator's filesystem ever sees.
    """

    def test_no_tmpfile_debris_after_successful_install(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"

        install("cursor", "user", config_path_override=target)

        # Only the real config should be present — no `*.tmp` siblings.
        siblings = sorted(p.name for p in tmp_path.iterdir())
        assert siblings == ["mcp.json"], f"unexpected debris: {siblings}"

    def test_partial_write_failure_preserves_original_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "mcp.json"
        original = json.dumps(
            {"mcpServers": {"sibling": {"command": "untouched", "args": ["serve"]}}},
            indent=2,
        ) + "\n"
        target.write_text(original, encoding="utf-8")

        # Simulate a disk-full / network-drop / antivirus-block on the
        # final rename step. The tempfile got written, but the rename
        # never completed.
        original_replace = os.replace

        def _failing_replace(_src: str, _dst: str) -> None:
            raise OSError("simulated disk full")

        monkeypatch.setattr("recon_tool.mcp_install.os.replace", _failing_replace)

        with pytest.raises(OSError, match="simulated disk full"):
            install("cursor", "user", config_path_override=target)

        # Original file must still be byte-for-byte intact.
        assert target.read_text(encoding="utf-8") == original
        # No tempfile debris left next to the real config.
        siblings = sorted(p.name for p in tmp_path.iterdir())
        assert siblings == ["mcp.json"], f"tempfile leaked: {siblings}"

        # And recovery: with the simulated failure cleared, the next
        # install run must succeed and produce a clean merged config.
        monkeypatch.setattr("recon_tool.mcp_install.os.replace", original_replace)
        install("cursor", "user", config_path_override=target)
        merged = json.loads(target.read_text(encoding="utf-8"))
        assert "sibling" in merged["mcpServers"]
        assert "recon" in merged["mcpServers"]


class TestPathExpansion:
    """`--config-path` reflexively gets `~`-prefixed paths from operators
    on macOS / Linux. Pathlib doesn't expand them on its own."""

    def test_tilde_expands_in_cli_config_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pretend $HOME is tmp_path so `~/...` resolves under our test sandbox.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                "~/recon-test.json",
            ],
        )
        assert result.exit_code == 0, result.output
        expected = tmp_path / "recon-test.json"
        assert expected.exists()
        data = json.loads(expected.read_text(encoding="utf-8"))
        assert "recon" in data["mcpServers"]

    def test_envvar_expands_in_cli_config_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECON_TEST_DIR", str(tmp_path))

        # ``${RECON_TEST_DIR}`` (curly-brace POSIX form) is expanded by
        # ``os.path.expandvars`` on every platform — Python's stdlib
        # treats both ``$name`` and ``${name}`` as portable, while
        # ``%name%`` is Windows-only. Pick the cross-platform form so
        # the install code path runs the same way under CI on Linux
        # and on Windows-local development.
        import os

        raw = os.path.join("${RECON_TEST_DIR}", "envvar-test.json")

        result = runner.invoke(
            app,
            [
                "mcp",
                "install",
                "--client",
                "cursor",
                "--config-path",
                raw,
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "envvar-test.json").exists()


class TestHomeDirFailure:
    """`Path.home()` raises RuntimeError when neither HOME nor USERPROFILE
    is set. Some Docker images and CI sandboxes hit this. The install
    command should produce an actionable error, not a Python traceback."""

    def test_unresolvable_home_produces_install_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise() -> Path:
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.setattr(Path, "home", staticmethod(_raise))

        with pytest.raises(InstallError, match="cannot resolve user home"):
            resolve_config_path("cursor", "user", platform_name="linux")


class TestSupportedClientsConstantStaysCurrent:
    """Catches the failure where someone adds a new client to the path
    table but forgets to expose it in SUPPORTED_CLIENTS (or vice versa)."""

    def test_every_supported_client_resolves_a_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        for client in SUPPORTED_CLIENTS:
            scope = default_scope(client)
            path = resolve_config_path(client, scope)
            assert path is not None
            assert path.name.endswith(".json")
