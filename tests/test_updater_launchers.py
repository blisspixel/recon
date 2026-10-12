"""Local manager queries preserve launcher dispatch and workspace boundaries."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from recon_tool import updater


def _write_receipt(prefix: Path, method: str) -> None:
    prefix.mkdir(parents=True)
    if method == updater.UV:
        (prefix / "uv-receipt.toml").write_text('[tool]\nrequirements=[{name="recon-tool"}]\n', encoding="utf-8")
    else:
        (prefix / "pipx_metadata.json").write_text(
            json.dumps({"pipx_metadata_version": "0.5", "main_package": {"package": "recon-tool", "suffix": ""}}),
            encoding="utf-8",
        )


@pytest.mark.parametrize("method", [updater.UV, updater.PIPX])
@pytest.mark.parametrize("location", ["home", "nested", "outside"])
def test_home_manager_path_boundary_on_all_platforms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, location: str
) -> None:
    home = tmp_path / "private home"
    root = home / ".local" / "share" / (method + " tools")
    prefix = root / "recon-tool"
    _write_receipt(prefix, method)
    launcher = home / ".local" / "bin" / method
    cwd = {"home": home, "nested": home / ".cache" / "qa", "outside": tmp_path / "outside"}[location]
    cwd.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(sys, "prefix", str(prefix))

    def which(_name: str) -> str:
        return str(launcher)

    monkeypatch.setattr(updater.shutil, "which", which)
    process = Mock(return_value=SimpleNamespace(returncode=0, stdout=str(root) + "\n"))
    monkeypatch.setattr(updater.subprocess, "run", process)

    command = updater.upgrade_command(method, version="2.20.1")

    assert command is not None
    assert command[0] == str(launcher)
    query = ["tool", "dir"] if method == updater.UV else ["environment", "--value", "PIPX_LOCAL_VENVS"]
    assert process.call_args.args[0] == [str(launcher), *query]
    assert process.call_count == 1
    assert process.call_args.kwargs["timeout"] == 5.0


@pytest.mark.parametrize("method", [updater.UV, updater.PIPX])
@pytest.mark.parametrize("location", ["home", "nested", "outside", "git"])
@pytest.mark.parametrize("symlink", [False, True])
def test_home_manager_dispatch_and_destination_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, location: str, symlink: bool
) -> None:
    if os.name == "nt":
        pytest.skip("Unix executable shim dispatch")
    home = tmp_path / "private home" / "maintainer"
    root = home / ".local" / "share" / (method + " tools")
    prefix = root / "recon-tool"
    _write_receipt(prefix, method)
    launcher = home / ".local" / "bin" / method
    launcher.parent.mkdir(parents=True)
    target = home / ".local" / "lib" / "manager-dispatch" if symlink else launcher
    target.parent.mkdir(parents=True, exist_ok=True)
    queries = tmp_path / "queries.jsonl"
    query = ["tool", "dir"] if method == updater.UV else ["environment", "--value", "PIPX_LOCAL_VENVS"]
    target.write_text(
        f"#!{sys.executable}\nimport json, sys\nfrom pathlib import Path\n"
        f"with open({str(queries)!r}, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(sys.argv) + '\\n')\n"
        f"if Path(sys.argv[0]).name != {method!r} or sys.argv[1:] != {query!r}:\n"
        "    raise SystemExit(9)\n"
        f"print({str(root)!r})\n",
        encoding="utf-8",
    )
    target.chmod(0o700)
    if symlink:
        launcher.symlink_to(target)
    cwd = {
        "home": home,
        "nested": home / ".cache" / "qa" / "recon",
        "outside": tmp_path / "outside",
        "git": tmp_path / "separate checkout",
    }[location]
    cwd.mkdir(parents=True, exist_ok=True)
    if location == "git":
        (cwd / ".git").mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(updater, "_is_editable", lambda: False)

    def which(_name: str) -> str:
        return str(launcher)

    monkeypatch.setattr(updater.shutil, "which", which)

    assert updater.detect_install_method() == method
    command = updater.upgrade_command(method, version="2.20.1")

    expected = (
        [str(launcher), "tool", "install", "--upgrade", "recon-tool==2.20.1"]
        if method == updater.UV
        else [str(launcher), "upgrade", "recon-tool"]
    )
    assert command == expected
    # Execute only the real local destination query, never the upgrade argv.
    assert [json.loads(line) for line in queries.read_text(encoding="utf-8").splitlines()] == [[str(launcher), *query]]


@pytest.mark.parametrize("method", [updater.UV, updater.PIPX])
@pytest.mark.parametrize("git", [False, True])
@pytest.mark.parametrize("placement", ["project", "lexical-symlink", "resolved-symlink", "relative"])
def test_project_manager_is_refused_before_ownership_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str, git: bool, placement: str
) -> None:
    home = tmp_path / "home"
    project = home / "project"
    cwd = project / "nested"
    cwd.mkdir(parents=True)
    if git:
        (project / ".git").mkdir()
    internal = project / "bin" / method
    external = home / ".local" / "bin" / method
    internal.parent.mkdir()
    external.parent.mkdir(parents=True)
    if placement == "lexical-symlink":
        if os.name == "nt":
            pytest.skip("Unix executable symlink fixture")
        external.write_text("private target", encoding="utf-8")
        internal.symlink_to(external)
        launcher = str(internal)
    elif placement == "resolved-symlink":
        if os.name == "nt":
            pytest.skip("Unix executable symlink fixture")
        internal.write_text("private target", encoding="utf-8")
        external.symlink_to(internal)
        launcher = str(external)
    else:
        launcher = str(internal) if placement == "project" else "../bin/" + method
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(cwd)

    def which(_name: str) -> str:
        return launcher

    monkeypatch.setattr(updater.shutil, "which", which)
    probe = Mock(side_effect=AssertionError("workspace launchers must not be queried"))
    monkeypatch.setattr(updater, "_manager_targets_current_install", probe)

    assert updater.upgrade_command(method, version="2.20.1") is None
    probe.assert_not_called()


@pytest.mark.parametrize("cwd_is_home", [False, True])
def test_explicit_git_boundary_at_home_still_refuses_its_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cwd_is_home: bool
) -> None:
    home = tmp_path / "home"
    cwd = home if cwd_is_home else home / "nested"
    cwd.mkdir(parents=True)
    (home / ".git").mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(cwd)

    def which(_name: str) -> str:
        return str(home / ".local" / "bin" / "uv")

    monkeypatch.setattr(updater.shutil, "which", which)
    probe = Mock(side_effect=AssertionError("explicit Git boundary must be preserved"))
    monkeypatch.setattr(updater, "_manager_targets_current_install", probe)

    assert updater.upgrade_command(updater.UV, version="2.20.1") is None
    probe.assert_not_called()
