"""Windows launcher handoff and update-worker failure contracts."""

from __future__ import annotations

import os
import subprocess
import sys
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from recon_tool import updater
from recon_tool import updater_windows as worker
from recon_tool.cli import app


@pytest.mark.parametrize("name", ["recon", "recon.exe", "RECON.EXE"])
def test_windows_console_bootstrap_requires_handoff(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "argv", [name, "update"])
    assert worker.requires_handoff()


@pytest.mark.parametrize(("platform", "name"), [("linux", "recon"), ("win32", "__main__.py")])
def test_other_entrypoints_do_not_need_handoff(monkeypatch: pytest.MonkeyPatch, platform: str, name: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(sys, "argv", [name])
    assert not worker.requires_handoff()


def test_launcher_chain_waits_for_both_launchers_but_not_the_shell() -> None:
    records = {1: (2, "python.exe"), 2: (3, "recon.exe"), 3: (4, "RECON.EXE"), 4: (5, "pwsh.exe")}
    assert worker._launcher_chain(1, records) == [1, 2, 3]
    assert worker._launcher_chain(9, records) == [9]
    assert worker._launcher_chain(2, {2: (3, "recon.exe"), 3: (2, "recon.exe")}) == [2, 3]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process API")
def test_process_snapshot_contains_current_interpreter() -> None:
    records = worker._process_table()
    assert records[os.getpid()][0] == os.getppid()
    assert records[os.getpid()][1].casefold().startswith("python")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process API")
def test_wait_for_real_child_exit() -> None:
    with subprocess.Popen([sys.executable, "-I", "-c", "pass"]) as process:
        worker._wait_for_exit([process.pid])
        assert process.wait(timeout=5) == 0


@pytest.mark.parametrize("status", [258, 0xFFFFFFFF])
def test_wait_failure_closes_handle(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    api = SimpleNamespace(
        OpenProcess=Mock(return_value=123), WaitForSingleObject=Mock(return_value=status), CloseHandle=Mock()
    )
    monkeypatch.setattr(worker, "_windows_api", lambda: api)
    monkeypatch.setattr(worker.ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(worker.ctypes, "WinError", Mock(return_value=OSError("Windows API failure")), raising=False)
    with pytest.raises(OSError, match=r"still running|Windows API failure"):
        worker._wait_for_exit([42])
    api.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("error", [87, 5])
def test_wait_distinguishes_exited_from_inaccessible_process(monkeypatch: pytest.MonkeyPatch, error: int) -> None:
    api = SimpleNamespace(OpenProcess=Mock(return_value=None))
    monkeypatch.setattr(worker, "_windows_api", lambda: api)
    monkeypatch.setattr(worker.ctypes, "get_last_error", lambda: error, raising=False)
    monkeypatch.setattr(worker.ctypes, "WinError", Mock(return_value=OSError("Windows API failure")), raising=False)
    if error == 87:
        worker._wait_for_exit([42])
    else:
        with pytest.raises(OSError, match="Windows API failure"):
            worker._wait_for_exit([42])


@pytest.mark.parametrize("returncode", [0, 2])
def test_worker_waits_before_install_and_reports_manager_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, returncode: int
) -> None:
    events: list[str] = []

    def wait(pids: list[int]) -> None:
        assert pids == [42]
        events.append("wait")

    monkeypatch.setattr(worker, "_wait_for_exit", wait)

    def install(command: list[str], *, cwd: str, check: bool) -> SimpleNamespace:
        assert events == ["wait"]
        assert command == ["verified-manager", "upgrade", "recon-tool"]
        assert check is False
        assert cwd == str(tmp_path)
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(worker.subprocess, "run", install)
    assert worker._run_update(["verified-manager", "upgrade", "recon-tool"], [42], str(tmp_path)) == int(
        returncode != 0
    )
    assert ("Update completed" if returncode == 0 else "Update failed") in capsys.readouterr().out


def test_worker_wait_failure_never_runs_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "_wait_for_exit", Mock(side_effect=TimeoutError("still running")))
    install = Mock()
    monkeypatch.setattr(worker.subprocess, "run", install)
    assert worker._run_update(["verified-manager"], [42], str(Path.cwd())) == 1
    install.assert_not_called()


@pytest.mark.parametrize("fail", [False, True])
def test_start_isolated_hidden_worker_and_cleanup_on_spawn_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fail: bool
) -> None:
    original_temp = worker.tempfile.NamedTemporaryFile
    monkeypatch.setattr(worker.tempfile, "NamedTemporaryFile", partial(original_temp, dir=tmp_path))
    monkeypatch.setattr(worker, "_process_table", lambda: {os.getpid(): (os.getppid(), "python.exe")})
    monkeypatch.setattr(worker.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    spawn = Mock(side_effect=OSError("cannot start") if fail else None)
    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    if fail:
        with pytest.raises(OSError, match="cannot start"):
            worker.start_update(["verified-manager"])
        assert list(tmp_path.iterdir()) == []
    else:
        log = worker.start_update(["verified-manager"])
        assert log.parent == tmp_path
        assert log.is_file()
        arguments = spawn.call_args.args[0]
        assert arguments[0] == str(Path(sys._base_executable).resolve())  # type: ignore[attr-defined]
        assert arguments[1] == "-I"
        assert arguments[-1] == str(Path.cwd())
        assert spawn.call_args.kwargs["creationflags"] == 0x08000000
        assert spawn.call_args.kwargs["stdin"] == subprocess.DEVNULL
        assert spawn.call_args.kwargs["cwd"] == tmp_path


@pytest.mark.parametrize("check_only", [False, True])
def test_cli_handoff_is_explicit_and_check_only_never_schedules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, check_only: bool
) -> None:
    monkeypatch.setattr(updater, "fetch_latest_version", lambda: "999.0.0")
    monkeypatch.setattr(updater, "detect_install_method", lambda: updater.UV)
    monkeypatch.setattr(updater, "upgrade_command", Mock(return_value=["verified-manager"]))
    monkeypatch.setattr(worker, "requires_handoff", lambda: True)
    start = Mock(return_value=tmp_path / "update.log")
    monkeypatch.setattr(worker, "start_update", start)
    result = CliRunner().invoke(app, ["update", "--check"] if check_only else ["update"])
    assert result.exit_code == 0, result.output
    if check_only:
        start.assert_not_called()
    else:
        start.assert_called_once_with(["verified-manager"])
        assert "Update scheduled" in result.output
        assert "Upgrade command completed" not in result.output
