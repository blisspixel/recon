"""Small shared helpers for the cli modules.

Helpers used by more than one package-local CLI module live here so sibling
sub-app modules can import them without reaching back into the CLI facade,
which would be a circular import. Public names because they cross a module
boundary (pyright-strict flags cross-module underscore access); callers alias
them back to their historical `_name` where convenient.
"""

from __future__ import annotations

import typer

from recon_tool.exit_codes import EXIT_VALIDATION


def fmt_exc(exc: BaseException) -> str:
    """Render an exception for user display, falling back to the type name.

    httpx.ReadTimeout and similar raise with an empty message, which used
    to render as an empty failure detail.
    """
    return str(exc) or type(exc).__name__


def lookup_validate(
    domain: str,
    *,
    json_output: bool,
    markdown: bool,
    plain: bool = False,
    chain_mode: bool,
    compare_file: str | None,
    show_exposure: bool,
    show_gaps: bool,
    chain_depth: int,
    exact: bool = False,
) -> str:
    """Check the mutually-exclusive flag combinations and validate the domain.

    Returns the validated domain or raises ``typer.Exit`` with EXIT_VALIDATION.
    By default the domain is reduced to its registrable apex (eTLD+1); with
    ``exact`` the literal host is kept and a sub-host reduction note is shown.

    Lives here rather than in ``cli.py`` so the lookup entry point stays under
    the file-size ratchet; all of its dependencies (``render_error`` /
    ``get_err_console`` from formatter, ``validate_domain``, ``to_apex``,
    ``EXIT_VALIDATION``) are non-cli modules, so there is no circular import.
    """
    from recon_tool.formatter import get_err_console, render_error
    from recon_tool.validator import validate_domain

    if chain_mode and compare_file:
        render_error("--chain and --compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if show_exposure and (chain_mode or compare_file):
        render_error("--exposure and --chain/--compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if show_gaps and (chain_mode or compare_file):
        render_error("--gaps and --chain/--compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if sum([json_output, markdown, plain]) > 1:
        render_error("--json, --md, and --plain are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if plain and (chain_mode or compare_file or show_exposure or show_gaps):
        # --plain only governs the standard lookup render; the chain / compare /
        # exposure / gaps modes have their own output. Reject rather than
        # silently ignore --plain and fall back to the colored panel.
        render_error("--plain cannot be combined with --chain/--compare/--exposure/--gaps")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if markdown and (chain_mode or compare_file or show_exposure or show_gaps):
        # Same reason as --plain above: these modes render their own output and
        # do not honor --md, so reject it rather than silently drop the flag.
        render_error("--md cannot be combined with --chain/--compare/--exposure/--gaps")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if chain_depth > 1 and not chain_mode:
        render_error("--depth requires --chain")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Validate the literal host first (apex=False), then decide whether to
    # reduce. --exact keeps the literal host; otherwise we reduce to the
    # registrable apex and tell the operator what was actually analyzed.
    try:
        literal = validate_domain(domain, apex=False)
    except ValueError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if exact:
        return literal

    from recon_tool.psl import to_apex

    apex = to_apex(literal)
    # Surface a genuine sub-host reduction so the operator knows what was
    # analyzed. Stay silent for the trivial www. case (it always collapses to
    # the apex and surprises nobody), matching recon's prior behavior.
    if apex != literal and literal != f"www.{apex}":
        get_err_console().print(
            f"[dim]Analyzing apex {apex} (from {literal}). Use --exact to query {literal} directly.[/dim]"
        )
    return apex
