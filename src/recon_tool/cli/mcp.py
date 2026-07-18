"""The `recon mcp` Typer sub-app (start the stdio server, install client config,
self-check). Split out of cli.py; registered on the main app via `app.add_typer`
there. Heavy dependencies (the MCP server and MCP client installer) are
imported inline in the commands, like the rest of the CLI.
"""

from __future__ import annotations

import json
import os

import typer

from recon_tool.cli.shared import render_diagnostic_status_row as _render_status_row
from recon_tool.cli.shared import safe_diagnostic_markup as _safe_markup
from recon_tool.exit_codes import EXIT_ERROR, EXIT_INTERNAL, EXIT_VALIDATION
from recon_tool.formatter import get_console

mcp_app = typer.Typer(
    help="MCP server commands: start the stdio server, install client config, run a self-check.",
    invoke_without_command=True,
    no_args_is_help=False,
)


def _render_install_verification(client: str) -> None:
    """Show the ordered checks that complete one client installation."""
    console = get_console()
    console.print("  Restart your MCP client to pick up the new server, then verify in order:")
    steps = (
        ("Static registry", "recon doctor --mcp"),
        ("Live tools and resources", "recon mcp doctor"),
        ("This client config", f"recon doctor --client={client}"),
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
            "[red]MCP dependency unavailable in this environment.[/red]\n"
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
    from pathlib import Path

    from recon_tool.mcp_client.install import (
        SUPPORTED_CLIENTS,
        InstallError,
        default_scope,
        install,
        plan_install,
        servers_key,
        warn_if_fallback,
    )

    console = get_console()

    if client not in SUPPORTED_CLIENTS:
        console.print(
            f"[red]Unknown client `{_safe_markup(client)}`.[/red]\n  Supported: {', '.join(SUPPORTED_CLIENTS)}"
        )
        raise typer.Exit(EXIT_VALIDATION)

    if scope == "auto":
        resolved_scope = default_scope(client)  # pyright: ignore[reportArgumentType]
    elif scope in {"user", "workspace"}:
        resolved_scope = scope
    else:
        console.print(f"[red]--scope must be `user`, `workspace`, or `auto` (got `{_safe_markup(scope)}`)[/red]")
        raise typer.Exit(EXIT_VALIDATION)

    # `--config-path ~/foo.json` is a common reflex on macOS / Linux and
    # PowerShell expands `~` for top-level argv but not for paths embedded
    # in arguments. Expand both `~` and `$HOME`-style env vars so the
    # operator's intent matches what we resolve.
    override = Path(os.path.expandvars(config_path)).expanduser() if config_path else None

    try:
        plan = plan_install(
            client,  # pyright: ignore[reportArgumentType]
            resolved_scope,  # pyright: ignore[reportArgumentType]
            config_path_override=override,
            force=force,
        )
    except (InstallError, ValueError) as exc:
        console.print(f"[red]install refused:[/red] {_safe_markup(exc)}")
        raise typer.Exit(EXIT_VALIDATION) from exc

    console.print()
    console.print(f"  client    {_safe_markup(client)}")
    console.print(f"  scope     {_safe_markup(resolved_scope)}")
    console.print(f"  path      {_safe_markup(plan.path)}")
    console.print(f"  action    {_safe_markup(plan.action)}")
    if plan.existing_block is not None and plan.action == "replace":
        console.print(
            "  [yellow]existing recon block will be replaced.[/yellow] Use --dry-run to preview without writing."
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
        console.print(f"[red]install failed:[/red] {_safe_markup(exc)}")
        raise typer.Exit(EXIT_INTERNAL) from exc

    console.print(f"  [green]wrote {_safe_markup(result.path)}[/green]")
    console.print()

    # Emit the cwd-shadow warning when the fallback launch
    # form was persisted. Informational only — the persisted env
    # carries PYTHONSAFEPATH=1 plus the runtime guard in server.py,
    # so MCP clients on Python 3.11+ are protected.
    fallback_warning = warn_if_fallback()
    if fallback_warning is not None:
        console.print(f"  [yellow]{_safe_markup(fallback_warning)}[/yellow]")
        console.print()

    _render_install_verification(client)


@mcp_app.command("doctor", short_help="Check MCP tools and resources.")
def mcp_doctor_command() -> None:
    """Check local MCP startup, discovery, tools, and JSON resources."""
    try:
        from recon_tool.mcp_client.doctor import run_doctor
    except ImportError as exc:
        get_console().print(
            "[red]MCP dependency unavailable in this environment.[/red]\n"
            "  Reinstall with: [bold]pip install -U recon-tool[/bold]"
        )
        raise SystemExit(EXIT_ERROR) from exc

    console = get_console()
    console.print()
    console.print("  Checking local MCP startup, discovery, tools, and JSON resources...")
    console.print()

    report = run_doctor()

    for check in report.checks:
        mark = "ok" if check.status == "ok" else "FAIL"
        style = "green" if check.status == "ok" else "red"
        _render_status_row(
            console,
            mark=mark,
            style=style,
            name=check.name,
            detail=check.detail,
        )

    console.print()
    console.print(f"  elapsed: {report.elapsed_seconds:.2f}s")
    console.print()

    if not report.ok:
        console.print(
            "  [red]MCP self-check failed.[/red] Run "
            "[bold]recon doctor --mcp[/bold] for the static-shape "
            "diagnostics, or check stderr from the spawned server."
        )
        raise typer.Exit(EXIT_INTERNAL)

    console.print("  [green]All checks passed.[/green]")
    console.print("  Verified: canonical tool registrations and five local JSON resource reads.")
    console.print("  [dim]Client config was not checked; run recon doctor --client=<name>.[/dim]")
