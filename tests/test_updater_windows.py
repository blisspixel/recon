"""Windows launcher handoff and update-worker failure contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from recon_tool import updater
from recon_tool import updater_windows as worker
from recon_tool.cli import app


def _no_blockers(_finished: set[int]) -> list[int]:
    return []


def _no_wait(_pids: list[int]) -> None:
    return None


def _verify_ok(*_args: object) -> None:
    return None


def _no_sleep(_seconds: float) -> None:
    return None


def _job(command: list[str], cwd: str, pids: list[int], recovery: list[str] | None = None) -> worker._Job:
    job = worker._Job(command, cwd, pids)
    if recovery is not None:
        job.recovery = recovery
    return job


@pytest.mark.parametrize("name", ["recon", "recon.exe", "RECON.EXE", "recon.cmd", "recon-script.py"])
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

    def install(command: list[str], **kwargs: object) -> SimpleNamespace:
        assert events == ["wait"]
        assert command == ["verified-manager", "upgrade", "recon-tool"]
        assert kwargs["check"] is False
        assert kwargs["cwd"] == str(tmp_path)
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)
    monkeypatch.setattr(worker, "_other_windows_launchers", _no_blockers)
    monkeypatch.setattr(worker, "_verify_install", _verify_ok)
    monkeypatch.setattr(worker.subprocess, "run", install)
    command = ["verified-manager", "upgrade", "recon-tool"]
    assert worker._run_update(_job(command, str(tmp_path), [42])) == int(returncode != 0)
    rendered = capsys.readouterr().out
    assert ("Update completed" if returncode == 0 else "Update failed") in rendered
    if returncode != 0:
        assert "Retry with recon update" not in rendered
        assert "verified-manager" in rendered


def test_worker_wait_failure_never_runs_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "_wait_for_exit", Mock(side_effect=TimeoutError("still running")))
    install = Mock()
    monkeypatch.setattr(worker.subprocess, "run", install)
    assert worker._run_update(_job(["verified-manager"], str(Path.cwd()), [42])) == 1
    install.assert_not_called()


@pytest.mark.parametrize("fail", [False, True])
def test_start_isolated_hidden_worker_and_cleanup_on_spawn_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fail: bool
) -> None:
    job = tmp_path / "job"

    def _mkdtemp(prefix: str) -> str:
        assert prefix == "recon-update-"
        job.mkdir()
        return str(job)

    monkeypatch.setattr(worker.tempfile, "mkdtemp", _mkdtemp)
    monkeypatch.setattr(worker, "_process_table", lambda: {os.getpid(): (os.getppid(), "python.exe")})
    spawn = Mock(side_effect=OSError("cannot start") if fail else None)
    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    if fail:
        with pytest.raises(OSError, match="cannot start"):
            worker.start_update(["verified-manager"])
        assert list(tmp_path.iterdir()) == []
        return
    log = worker.start_update(["verified-manager"])
    assert log.parent == job
    assert log.is_file()
    arguments = spawn.call_args.args[0]
    assert arguments[0] == str(Path(sys._base_executable).resolve())  # type: ignore[attr-defined]
    assert arguments[1:5] == ["-I", "-S", "-X", "utf8"]
    worker_path = Path(arguments[5])
    assert worker_path.is_file()
    assert worker_path.resolve() != Path(worker.__file__).resolve()
    payload = json.loads(arguments[6])
    assert payload["command"] == ["verified-manager"]
    assert payload["cwd"] == str(Path.cwd())
    assert payload["interpreter"] == sys.executable
    assert spawn.call_args.kwargs["creationflags"] == 0x08000000
    assert spawn.call_args.kwargs["stdin"] == subprocess.DEVNULL
    assert spawn.call_args.kwargs["cwd"] == str(job)


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
        start.assert_called_once_with(
            ["verified-manager"],
            wheelhouse=None,
            recovery=["verified-manager"],
            interpreter=sys.executable,
        )
        assert "Update scheduled" in result.output
        assert "Upgrade command completed" not in result.output


def test_other_windows_launcher_blocks_before_the_package_manager(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(worker, "_wait_for_exit", _no_wait)
    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)

    def _blocked(_finished: set[int]) -> list[int]:
        return [99]

    monkeypatch.setattr(worker, "_other_windows_launchers", _blocked)
    run = Mock()
    monkeypatch.setattr(worker.subprocess, "run", run)

    command = ["python", "-m", "pip", "install", "-U", "recon-tool==1.2.3"]
    code = worker._run_update(_job(command, "C:/work", [7], recovery=command))

    assert code == 1
    run.assert_not_called()
    rendered = capsys.readouterr().out
    assert "pid 99" in rendered
    assert "recon-tool==1.2.3" in rendered
    assert "Retry with recon update" not in rendered


def test_file_lock_is_retried_before_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = {"count": 0}

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(
                returncode=1,
                stdout="ERROR: WinError 32 The process cannot access the file\n",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(worker.subprocess, "run", run)
    monkeypatch.setattr(worker, "_verify_install", _verify_ok)
    monkeypatch.setattr(worker.time, "sleep", _no_sleep)
    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)
    monkeypatch.setattr(worker, "_other_windows_launchers", _no_blockers)
    monkeypatch.setattr(worker, "_wait_for_exit", _no_wait)

    command = ["python", "-m", "pip", "install", "-U", "recon-tool==1.2.3"]
    assert worker._run_update(_job(command, "C:/work", [7])) == 0
    assert calls["count"] == 2
    assert "Retrying after a file lock" in capsys.readouterr().out


def test_non_lock_failure_does_not_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    run = Mock(return_value=SimpleNamespace(returncode=1, stdout="No matching distribution\n", stderr=""))
    monkeypatch.setattr(worker.subprocess, "run", run)
    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)
    monkeypatch.setattr(worker, "_other_windows_launchers", _no_blockers)
    monkeypatch.setattr(worker, "_wait_for_exit", _no_wait)

    assert worker._run_update(_job(["verified-manager", "upgrade", "recon-tool"], "C:/work", [7])) == 1
    run.assert_called_once()


def test_successful_manager_still_fails_when_the_install_does_not_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        worker.subprocess, "run", Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
    )

    def _verify_broken(*_args: object) -> str:
        return "recon-tool does not import"

    monkeypatch.setattr(worker, "_verify_install", _verify_broken)
    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)
    monkeypatch.setattr(worker, "_other_windows_launchers", _no_blockers)
    monkeypatch.setattr(worker, "_wait_for_exit", _no_wait)

    command = ["python", "-m", "pip", "install", "-U", "recon-tool==1.2.3"]
    assert worker._run_update(_job(command, "C:/work", [7])) == 1


def test_remove_wheelhouse_is_confined_to_named_temp_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(worker.tempfile, "gettempdir", lambda: str(tmp_path))
    allowed = tmp_path / "recon-update-wheels-ok"
    allowed.mkdir()
    (allowed / "wheel.whl").write_bytes(b"wheel")
    kept = tmp_path / "other-dir"
    kept.mkdir()

    worker.remove_wheelhouse(allowed)
    worker.remove_wheelhouse(kept)
    worker.remove_wheelhouse(tmp_path)
    worker.remove_wheelhouse(None)

    assert not allowed.exists()
    assert kept.is_dir()
    assert tmp_path.is_dir()


def test_incomplete_worker_request_fails_closed() -> None:
    assert worker.main(["worker.py"]) == 1
    assert worker.main(["worker.py", "{"]) == 1


def test_worker_request_round_trip_checks_this_install() -> None:
    command = [sys.executable, "-c", "raise SystemExit(0)"]
    payload = {
        "command": command,
        "pids": [],
        "cwd": str(Path.cwd()),
        "interpreter": sys.executable,
        "wheelhouse": "",
        "recovery": command,
    }

    assert worker.main(["worker.py", json.dumps(payload)]) == 0


@pytest.mark.parametrize("long_path", [False, True])
def test_pip_download_failure_does_not_replace_the_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, long_path: bool
) -> None:
    monkeypatch.setattr(updater, "fetch_latest_version", lambda: "999.0.0")
    monkeypatch.setattr(updater, "detect_install_method", lambda: updater.PIP)

    def _command(_method: str, version: str | None = None) -> list[str]:
        return ["python", "-m", "pip", "install", "-U", f"recon-tool=={version}"]

    monkeypatch.setattr(updater, "upgrade_command", _command)
    monkeypatch.setattr(updater, "stage_pip_wheelhouse", Mock(side_effect=OSError("network down")))
    recovery = updater.interpreter_reinstall_argv("999.0.0")
    if long_path:
        recovery[0] = str(tmp_path / ("install directory " * 12) / "[red]" / "python.exe")

        def _recovery_command(_version: str) -> list[str]:
            return recovery

        monkeypatch.setattr(updater, "interpreter_reinstall_argv", _recovery_command)
    start = Mock()
    monkeypatch.setattr(worker, "start_update", start)
    apply = Mock()
    monkeypatch.setattr(worker, "apply_upgrade", apply)

    result = CliRunner().invoke(app, ["update"])
    rendered = " ".join(result.output.split())

    assert result.exit_code == 1, result.output
    assert "left unchanged" in rendered
    assert "recon-tool==999.0.0" in rendered
    assert updater.format_argv(recovery) in result.stderr
    start.assert_not_called()
    apply.assert_not_called()


def test_externally_managed_python_gets_uv_and_pipx_guidance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        worker.subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=1, stdout="externally-managed-environment\n", stderr="")),
    )
    monkeypatch.setattr(worker, "_pause_after_launcher_exit", lambda: None)
    monkeypatch.setattr(worker, "_other_windows_launchers", _no_blockers)
    monkeypatch.setattr(worker, "_wait_for_exit", _no_wait)

    command = ["python", "-m", "pip", "install", "-U", "recon-tool==1.2.3"]
    assert worker._run_update(_job(command, "C:/work", [7])) == 1
    rendered = capsys.readouterr().out
    assert "uv tool install --upgrade recon-tool" in rendered
    assert "pipx upgrade recon-tool" in rendered
