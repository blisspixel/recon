"""The top-level run() crash / interrupt handler.

An *unexpected* exception must not dump a raw traceback to the terminal: run()
writes the traceback to a file and prints a clean one-liner to stderr, exiting
with the internal-error code. Ctrl-C exits 130 quietly. Normal Typer/Click
SystemExits (help, version, usage errors) pass through untouched.
"""

from __future__ import annotations

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
    crash_files = list(tmp_path.glob("recon-crash-*.log"))
    assert len(crash_files) == 1
    assert "boom-secret-xyz" in crash_files[0].read_text(encoding="utf-8")


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
