"""The top-level run() crash / interrupt handler.

An *unexpected* exception must not dump a raw traceback to the terminal: run()
writes the traceback to a file and prints a clean one-liner to stderr, exiting
with the internal-error code. Ctrl-C exits 130 quietly. Normal Typer/Click
SystemExits (help, version, usage errors) pass through untouched.
"""

from __future__ import annotations

import errno
import os
import stat
import sys

import pytest

import recon_tool.cli as cli
from recon_tool.exit_codes import EXIT_INTERNAL


def _raise(exc: BaseException):
    def _app() -> None:
        raise exc

    return _app


def test_unexpected_exception_writes_crash_file_and_clean_message(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(cli, "app", _raise(RuntimeError("boom-secret-xyz")))

    with pytest.raises(SystemExit) as ei:
        cli.run()

    assert ei.value.code == EXIT_INTERNAL
    err = capsys.readouterr().err
    assert "unexpected error" in err
    assert "Traceback" not in err  # no raw stack trace on the terminal
    assert "boom-secret-xyz" not in err  # exception text only in the file
    assert "Review and redact" in err
    assert "local paths" in err
    crash_files = list(tmp_path.glob("recon-crash-*.log"))
    assert len(crash_files) == 1
    assert "boom-secret-xyz" in crash_files[0].read_text(encoding="utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(crash_files[0].stat().st_mode) == 0o600


def test_unexpected_exceptions_use_unique_crash_files(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(cli, "app", _raise(RuntimeError("repeated failure")))

    for _ in range(2):
        with pytest.raises(SystemExit) as exc_info:
            cli.run()
        assert exc_info.value.code == EXIT_INTERNAL
        capsys.readouterr()

    crash_files = list(tmp_path.glob("recon-crash-*.log"))
    assert len(crash_files) == 2
    assert crash_files[0].name != crash_files[1].name


def test_crash_log_write_failure_has_actionable_fallback(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "app", _raise(RuntimeError("boom-secret-xyz")))

    def fail_crash_file(*args: object, **kwargs: object) -> None:
        raise OSError("temporary directory unavailable")

    monkeypatch.setattr("tempfile.NamedTemporaryFile", fail_crash_file)

    with pytest.raises(SystemExit) as exc_info:
        cli.run()

    assert exc_info.value.code == EXIT_INTERNAL
    err = capsys.readouterr().err
    assert "could not create a crash log" in err
    assert "temporary directory is writable" in err
    assert "exit code 4" in err
    assert "Review and redact" not in err
    assert "boom-secret-xyz" not in err


def test_keyboard_interrupt_exits_130(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "app", _raise(KeyboardInterrupt()))
    with pytest.raises(SystemExit) as ei:
        cli.run()
    assert ei.value.code == 130
    assert "Traceback" not in capsys.readouterr().err


def test_normal_systemexit_passes_through(monkeypatch) -> None:
    # Click/Typer signal help/version/usage with SystemExit; run() must not
    # rewrite those into the internal-error code.
    monkeypatch.setattr(cli, "app", _raise(SystemExit(2)))
    with pytest.raises(SystemExit) as ei:
        cli.run()
    assert ei.value.code == 2


@pytest.mark.parametrize("exc", [BrokenPipeError(), OSError(errno.EPIPE, "closed pipe")])
def test_closed_pipe_exits_cleanly_without_crash_log(monkeypatch, capsys, tmp_path, exc) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(cli, "app", _raise(exc))

    with pytest.raises(SystemExit) as exc_info:
        cli.run()

    assert exc_info.value.code == 0
    assert capsys.readouterr().err == ""
    assert list(tmp_path.glob("recon-crash-*.log")) == []
    assert getattr(sys.stdout, "name", None) == os.devnull
    assert getattr(sys.stderr, "name", None) == os.devnull


@pytest.mark.skipif(os.name != "nt", reason="Windows emits EINVAL for an early-closing pipeline")
def test_windows_closed_pipe_einval_exits_without_crash_log(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(cli, "app", _raise(OSError(errno.EINVAL, "invalid argument")))

    with pytest.raises(SystemExit) as exc_info:
        cli.run()

    assert exc_info.value.code == 0
    assert capsys.readouterr().err == ""
    assert list(tmp_path.glob("recon-crash-*.log")) == []
    assert getattr(sys.stdout, "name", None) == os.devnull
    assert getattr(sys.stderr, "name", None) == os.devnull


def test_unrelated_oserror_still_uses_crash_handler(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(cli, "app", _raise(OSError(errno.EACCES, "permission denied")))

    with pytest.raises(SystemExit) as exc_info:
        cli.run()

    assert exc_info.value.code == EXIT_INTERNAL
    assert "unexpected error" in capsys.readouterr().err
    assert len(list(tmp_path.glob("recon-crash-*.log"))) == 1
