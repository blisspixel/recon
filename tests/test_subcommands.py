"""Pin ``_SUBCOMMANDS`` to the registered command tree.

The root callback uses ``_SUBCOMMANDS`` to tell a bare domain argument
(``recon alpha.invalid``) apart from a subcommand. If a new command is added
without updating the set, a dotted first argument matching that command could
be mis-routed to ``lookup``. This test fails when the two drift, so the set
stays in lockstep with the Typer app.
"""

from __future__ import annotations

from recon_tool.cli import _SUBCOMMANDS, app  # pyright: ignore[reportPrivateUsage]


def _registered_command_names() -> set[str]:
    names: set[str] = set()
    for cmd in app.registered_commands:
        name = cmd.name
        if name is None and cmd.callback is not None:
            name = cmd.callback.__name__.replace("_", "-")
        if name:
            names.add(name)
    for group in app.registered_groups:
        if group.name:
            names.add(group.name)
    return names


def test_subcommands_match_registered_tree() -> None:
    assert set(_SUBCOMMANDS) == _registered_command_names()


def test_discover_is_recognized() -> None:
    """Regression guard for the v1.9.x fix: discover was previously omitted."""
    assert "discover" in _SUBCOMMANDS
