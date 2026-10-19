"""The `recon mcp` Typer sub-app (start the stdio server, install client config,
self-check). Split out of cli.py; registered on the main app via `app.add_typer`
there. Heavy dependencies (the MCP server and MCP client installer) are
imported inline in the commands, like the rest of the CLI.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from recon_tool.cli.shared import render_status_row as _render_status_row
from recon_tool.cli.shared import safe_diagnostic_markup as _safe_markup
from recon_tool.exit_codes import EXIT_ERROR, EXIT_INTERNAL, EXIT_VALIDATION
from recon_tool.formatter import get_console, get_err_console
from recon_tool.formatter.theme import ERROR, SUCCESS, WARNING

if TYPE_CHECKING:
    from rich.console import Console

    from recon_tool.mcp_client.doctor import LaunchConfig

mcp_app = typer.Typer(
    help="MCP server commands: start the stdio server, install client config, run a self-check.",
    invoke_without_command=True,
    no_args_is_help=False,
)


def _render_install_verification(client: str, config_path: Path) -> None:
    """Show the ordered checks that complete one client installation."""
    console = get_err_console()
    # PowerShell on Windows, POSIX shells elsewhere. Never interpolate an
    # unquoted operator path into the copyable verification command.
    path_arg = "'" + str(config_path).replace("'", "''") + "'" if os.name == "nt" else shlex.quote(str(config_path))
    client_check = f"recon doctor --client={client} --config-path {path_arg}"
    console.print("  Restart your MCP client to pick up the new server, then verify in order:")
    steps = (
        ("Static registry", "recon doctor --mcp"),
        ("Live tools and resources", "recon mcp doctor"),
        ("This client config", client_check),
    )
    for number, (description, command) in enumerate(steps, start=1):
        console.print(f"    {number}. {description}")
        console.print(f"       [bold]{_safe_markup(command)}[/bold]", soft_wrap=True)


@mcp_app.callback()
def mcp_callback(ctx: typer.Context) -> None:
    """Bare `recon mcp` (no subcommand) starts the stdio server.

    Subcommands (`install`, etc.) get dispatched normally; this callback
    only fires when no subcommand was given.
    """
    if ctx.invoked_subcommand is not None:
        return
    try:
        from recon_tool.server import main as server_main
    except ImportError as exc:
        get_console().print(
            f"[{ERROR}]MCP dependency unavailable in this environment.[/{ERROR}]\n"
            "  Reinstall with: [bold]pip install -U recon-tool[/bold]"
        )
        raise SystemExit(EXIT_ERROR) from exc

    server_main()


@mcp_app.command("install", short_help="Install client config.")
def mcp_install_command(
    client: str = typer.Option(
        ...,
        "--client",
        "-c",
        help="Target MCP client: claude-desktop, claude-code, cursor, vscode, windsurf, kiro.",
    ),
    scope: str = typer.Option(
        "auto",
        "--scope",
        "-s",
        help="`user` (per-user config) or `workspace` (cwd-relative). Default picks the right one for the client.",
    ),
    config_path: str | None = typer.Option(
        None,
        "--config-path",
        help="Override the resolved config file path.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing recon server entry.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the client-specific config stanza and plan without writing.",
    ),
) -> None:
    """Install the recon MCP server config into a client's config file.

    Idempotently merges the recon stanza into the client's
    `mcp.json`-shaped config so a fresh install of a supported AI
    client picks up recon without any copy-paste.
    """
    from recon_tool.mcp_client.install import (
        SUPPORTED_CLIENTS,
        InstallError,
        default_scope,
        expand_config_path,
        install,
        plan_install,
        servers_key,
        warn_if_fallback,
    )

    # Plan and result diagnostics are stderr so a redirect or pipe receives
    # only the client stanza JSON emitted on stdout via typer.echo below.
    console = get_err_console()

    if client not in SUPPORTED_CLIENTS:
        console.print(
            f"[{ERROR}]Unknown client `{_safe_markup(client)}`.[/{ERROR}]\n  Supported: {', '.join(SUPPORTED_CLIENTS)}"
        )
        raise typer.Exit(EXIT_VALIDATION)

    if scope == "auto":
        resolved_scope = default_scope(client)  # pyright: ignore[reportArgumentType]
    elif scope in {"user", "workspace"}:
        resolved_scope = scope
    else:
        console.print(
            f"[{ERROR}]--scope must be `user`, `workspace`, or `auto` (got `{_safe_markup(scope)}`)[/{ERROR}]"
        )
        raise typer.Exit(EXIT_VALIDATION)

    # `--config-path ~/foo.json` is a common reflex on macOS / Linux and
    # PowerShell expands `~` for top-level argv but not for paths embedded
    # in arguments. Expand both `~` and `$HOME`-style env vars so the
    # operator's intent matches what we resolve.
    try:
        override = expand_config_path(config_path) if config_path is not None else None
        plan = plan_install(
            client,  # pyright: ignore[reportArgumentType]
            resolved_scope,  # pyright: ignore[reportArgumentType]
            config_path_override=override,
            force=force,
        )
    except (InstallError, ValueError) as exc:
        console.print(f"[{ERROR}]install refused:[/{ERROR}] {_safe_markup(exc)}")
        raise typer.Exit(EXIT_VALIDATION) from exc

    console.print()
    console.print(f"  client    {_safe_markup(client)}")
    console.print(f"  scope     {_safe_markup(resolved_scope)}")
    console.print(f"  path      {_safe_markup(plan.path)}", soft_wrap=True)
    if plan.target_path is not None and plan.target_path != plan.path:
        console.print(f"  target    {_safe_markup(plan.target_path)}", soft_wrap=True)
    console.print(f"  action    {_safe_markup(plan.action)}")
    if plan.existing_block is not None and plan.action == "replace":
        console.print(
            f"  [{WARNING}]existing recon block will be replaced.[/{WARNING}] Use --dry-run to preview without writing."
        )
    if plan.parent_dirs_to_create:
        console.print(f"  mkdir     {len(plan.parent_dirs_to_create)} new parent dir(s)")
    console.print()
    console.print("  [dim]new client stanza:[/dim]")
    client_stanza = {servers_key(client): {"recon": plan.new_block}}  # pyright: ignore[reportArgumentType]
    typer.echo(json.dumps(client_stanza, indent=2))
    console.print()

    if dry_run:
        console.print("  [dim]--dry-run: no files written.[/dim]")
        return

    try:
        result = install(
            client,  # pyright: ignore[reportArgumentType]
            resolved_scope,  # pyright: ignore[reportArgumentType]
            config_path_override=override,
            force=force,
            dry_run=False,
        )
    except (InstallError, ValueError, OSError) as exc:
        console.print(f"[{ERROR}]install failed:[/{ERROR}] {_safe_markup(exc)}")
        raise typer.Exit(EXIT_INTERNAL) from exc

    console.print(f"  [{SUCCESS}]wrote {_safe_markup(result.path)}[/{SUCCESS}]")
    console.print()

    # Emit the cwd-shadow warning when the fallback launch
    # form was persisted. Informational only - the persisted env
    # carries PYTHONSAFEPATH=1 plus the runtime guard in server.py,
    # so MCP clients on Python 3.11+ are protected.
    fallback_warning = warn_if_fallback()
    if fallback_warning is not None:
        console.print(f"  [{WARNING}]{_safe_markup(fallback_warning)}[/{WARNING}]")
        console.print()

    _render_install_verification(client, result.path.absolute())


def _render_launch_config(console: Console, title: str, scope_note: str, launch: LaunchConfig) -> None:
    """Print which launch a doctor check exercised, before its result rows."""
    env_text = " ".join(f"{key}={value}" for key, value in launch.env) or "(none added)"
    cwd_text = launch.cwd if launch.cwd is not None else "(new empty temporary directory)"
    console.print(f"  [bold]{_safe_markup(title)}[/bold]")
    console.print(f"  [dim]{_safe_markup(scope_note)}[/dim]", soft_wrap=True)
    for label, value in (
        ("command", launch.command),
        ("args", json.dumps(list(launch.args))),
        ("env", env_text),
        ("cwd", cwd_text),
    ):
        console.print(f"    {label:<9}{_safe_markup(value)}", soft_wrap=True)
    console.print()


def _resolve_launch_cwd(launch_cwd: str | None) -> Path | None:
    """Expand ``--launch-cwd`` and require an existing directory."""
    if launch_cwd is None:
        return None
    launch_dir: Path | None = None
    try:
        launch_dir = Path(os.path.expandvars(launch_cwd)).expanduser().absolute()
        is_dir = launch_dir.is_dir()
    except (OSError, RuntimeError, ValueError):
        is_dir = False
    if not is_dir or launch_dir is None:
        get_err_console().print(
            f"[{ERROR}]--launch-cwd is not an existing directory:[/{ERROR}] {_safe_markup(launch_cwd)}",
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_VALIDATION)
    return launch_dir


@mcp_app.command("doctor", short_help="Check MCP tools and resources.")
def mcp_doctor_command(
    launch_cwd: str | None = typer.Option(
        None,
        "--launch-cwd",
        help=(
            "Directory to start the generated client launch from. Defaults to the current "
            "directory; set it to the working directory your MCP client uses."
        ),
    ),
) -> None:
    """Check local MCP startup, discovery, tools, and JSON resources.

    Runs two launches: an isolated check in an empty temporary directory, and
    the exact launcher `recon mcp install` writes, started from --launch-cwd.
    """
    try:
        from recon_tool.mcp_client.doctor import REQUIRED_RESOURCES, run_doctor, run_generated_launch_check
    except ImportError as exc:
        get_console().print(
            f"[{ERROR}]MCP dependency unavailable in this environment.[/{ERROR}]\n"
            "  Reinstall with: [bold]pip install -U recon-tool[/bold]"
        )
        raise SystemExit(EXIT_ERROR) from exc

    launch_dir = _resolve_launch_cwd(launch_cwd)

    console = get_console()
    console.print()
    console.print("  Checking local MCP startup, discovery, tools, and JSON resources...")
    console.print()

    isolated = run_doctor()
    generated = run_generated_launch_check(launch_dir)
    sections = (
        (
            "Isolated install check",
            "Scope: this interpreter in an empty temporary directory. It verifies the install, not a client launch.",
            isolated,
        ),
        (
            "Generated client launch check",
            "Scope: the command, args, and env that `recon mcp install` writes, started from the cwd below.",
            generated,
        ),
    )

    for title, scope_note, report in sections:
        if report.launch is not None:
            _render_launch_config(console, title, scope_note, report.launch)
        else:
            console.print(f"  [bold]{_safe_markup(title)}[/bold]")
        for check in report.checks:
            _render_status_row(console, check.status, check.name, check.detail)
        console.print()

    console.print(f"  elapsed: {isolated.elapsed_seconds + generated.elapsed_seconds:.2f}s")
    console.print()

    if not (isolated.ok and generated.ok):
        failed = sum(1 for check in (*isolated.checks, *generated.checks) if check.status == "fail")
        noun = "check" if failed == 1 else "checks"
        console.print(
            f"  [{ERROR}]MCP self-check failed: {failed} {noun} failed. "
            "Next: recon doctor --mcp for the static-shape diagnostics, "
            f"or check stderr from the spawned server.[/{ERROR}]",
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_INTERNAL)

    exercised = generated.launch.cwd if generated.launch is not None else None
    console.print(f"  [{SUCCESS}]All checks passed.[/{SUCCESS}]")
    console.print(f"  Verified: canonical tool registrations and {len(REQUIRED_RESOURCES)} local JSON resource reads.")
    console.print(
        f"  Generated launch verified from {_safe_markup(exercised or 'the current directory')} only; "
        "a client that starts elsewhere can differ. Use --launch-cwd to check its directory.",
        soft_wrap=True,
    )
    console.print("  [dim]Client config was not checked; run recon doctor --client=<name>.[/dim]")
