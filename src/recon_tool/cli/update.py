"""Installation-aware update command implementation."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from recon_tool import updater, updater_windows
from recon_tool.exit_codes import EXIT_ERROR
from recon_tool.formatter import get_console, get_err_console, render_error
from recon_tool.validator import strip_control_chars


def _render_update_error(message: str, recovery: list[str]) -> None:
    """Bound untrusted error detail without truncating the executable recovery command."""
    render_error(message)
    command = updater.format_argv(recovery)
    safe = strip_control_chars(command, max_len=len(command))
    get_err_console().print(f"Run manually: {safe}", markup=False, highlight=False, soft_wrap=True)


def _prepare_pip_upgrade(latest: str) -> tuple[list[str], list[str], Path]:
    """Download the pinned release and return the offline install, recovery, and staging dir."""
    spec = updater.pinned_spec(latest)
    wheelhouse = updater.stage_pip_wheelhouse(spec)
    return updater.offline_pip_command(spec, wheelhouse), updater.interpreter_reinstall_argv(latest), wheelhouse


def _run_prepared_upgrade(
    *,
    method: str,
    prepared: list[str],
    recovery: list[str],
    wheelhouse: Path | None,
) -> int | None:
    """Run or hand off an upgrade. None means the Windows worker now owns it."""
    err = get_err_console()
    console = get_console()
    err.print(f"==> upgrading via {method}: {updater.format_argv(prepared)}")
    if updater_windows.requires_handoff():
        log_path = updater_windows.start_update(
            prepared,
            wheelhouse=wheelhouse,
            recovery=recovery,
            interpreter=sys.executable,
        )
        console.print("Update scheduled. Installation starts after this command exits.")
        console.print(f"Progress and result: {log_path}", markup=False)
        console.print("When it finishes, run `recon --version` to confirm.")
        return None
    return updater_windows.apply_upgrade(
        prepared,
        wheelhouse=wheelhouse,
        recovery=recovery,
        interpreter=sys.executable,
    )


def run_update(*, check: bool = False) -> None:
    """Report release status and perform an update through the original manager."""
    console = get_console()
    err = get_err_console()
    current = updater.current_version()

    err.print(f"recon {current}: checking PyPI for updates...")
    latest = updater.fetch_latest_version()
    if latest is None:
        render_error("Could not reach PyPI to check for updates. Try again, or upgrade manually.")
        raise typer.Exit(code=EXIT_ERROR)

    status_message = updater.non_upgrade_status_message(current, latest)
    if status_message is not None:
        console.print(status_message)
        return

    console.print(f"Update available: [bold]{current}[/bold] -> [bold]{latest}[/bold]")
    method = updater.detect_install_method()
    cmd = updater.upgrade_command(method, version=latest)

    if check:
        console.print(f"  install method: {method}")
        if cmd is None:
            console.print(f"  to upgrade:     [cyan]{updater.manual_hint(method)}[/cyan]")
        else:
            console.print(f"  to upgrade:     [cyan]{' '.join(cmd)}[/cyan]   (or just: recon update)")
        return
    if cmd is None:
        console.print(f"Detected a {method} install; manual action needed: [cyan]{updater.manual_hint(method)}[/cyan]")
        return

    prepared = cmd
    recovery = cmd
    wheelhouse: Path | None = None
    if method == updater.PIP:
        err.print("Downloading the checked release before replacing the installation...")
        try:
            prepared, recovery, wheelhouse = _prepare_pip_upgrade(latest)
        except OSError as exc:
            _render_update_error(
                f"Could not download the release ({exc}). The installed copy was left unchanged.",
                updater.interpreter_reinstall_argv(latest),
            )
            raise typer.Exit(code=EXIT_ERROR) from None
    try:
        result = _run_prepared_upgrade(method=method, prepared=prepared, recovery=recovery, wheelhouse=wheelhouse)
    except OSError as exc:
        updater_windows.remove_wheelhouse(wheelhouse)
        _render_update_error(f"Could not start the upgrade ({exc}).", recovery)
        raise typer.Exit(code=EXIT_ERROR) from None
    if result is None:
        return
    if result != 0:
        _render_update_error("Upgrade failed.", prepared)
        raise typer.Exit(code=EXIT_ERROR)
    console.print("[green]Upgrade command completed. Open a new shell and run `recon --version` to confirm.[/green]")
