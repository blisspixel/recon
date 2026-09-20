"""Installation-aware update command implementation."""

from __future__ import annotations

import subprocess

import typer

from recon_tool import updater, updater_windows
from recon_tool.exit_codes import EXIT_ERROR
from recon_tool.formatter import get_console, get_err_console, render_error


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

    err.print(f"==> upgrading via {method}: {' '.join(cmd)}")
    try:
        if updater_windows.requires_handoff():
            log_path = updater_windows.start_update(cmd)
            console.print("Update scheduled. Installation starts after this command exits.")
            console.print(f"Progress and result: {log_path}", markup=False)
            console.print("When it finishes, run `recon --version` to confirm.")
            return
        # cmd is a fixed argv from updater.upgrade_command's install-method
        # table (pipx/uv/pip), never user input, and its program is an absolute
        # path that upgrade_command already refused to take from the current
        # directory. Both halves matter: the arguments are not attacker-facing,
        # and the executable is not resolved by a search that includes the
        # working directory.
        rc = subprocess.run(cmd, check=False).returncode  # noqa: S603
    except OSError as exc:
        render_error(f"Could not start the upgrade ({exc}). Run manually: {updater.manual_hint(method)}")
        raise typer.Exit(code=EXIT_ERROR) from None
    if rc != 0:
        render_error(f"Upgrade failed (exit {rc}). Try manually: {updater.manual_hint(method)}")
        raise typer.Exit(code=EXIT_ERROR)
    console.print("[green]Upgrade command completed. Open a new shell and run `recon --version` to confirm.[/green]")
