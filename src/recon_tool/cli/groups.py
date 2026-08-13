"""Registration for the recon CLI's nested command groups."""

from __future__ import annotations

import typer

from recon_tool.cli.cache import cache_app
from recon_tool.cli.capsule import capsule_app
from recon_tool.cli.fingerprints import fingerprints_app
from recon_tool.cli.mcp import mcp_app
from recon_tool.cli.signals import signals_app


def register_command_groups(app: typer.Typer) -> None:
    """Attach every nested command group to the root application."""
    app.add_typer(mcp_app, name="mcp", short_help="Run or configure MCP.")
    app.add_typer(cache_app, name="cache", short_help="Manage local caches.")
    app.add_typer(capsule_app, name="capsule", short_help="Manage observation capsules.")
    app.add_typer(fingerprints_app, name="fingerprints", short_help="Browse fingerprints.")
    app.add_typer(signals_app, name="signals", short_help="Browse signals.")
