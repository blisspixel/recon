"""Small shared helpers for the cli modules.

Helpers used by more than one package-local CLI module live here so sibling
sub-app modules can import them without reaching back into the CLI facade,
which would be a circular import. Public names because they cross a module
boundary (pyright-strict flags cross-module underscore access); callers alias
them back to their historical `_name` where convenient.
"""

from __future__ import annotations

import math
from typing import Never

import typer

from recon_tool.cli.options import LookupOptions
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_NO_DATA, EXIT_VALIDATION
from recon_tool.models import ReconLookupError


def positive_finite_float(value: float) -> float:
    """Validate a positive, finite timeout-style option for Typer."""
    if not math.isfinite(value) or value <= 0.0:
        raise typer.BadParameter("must be a finite positive number")
    return value


def fmt_exc(exc: BaseException) -> str:
    """Render an exception for user display, falling back to the type name.

    httpx.ReadTimeout and similar raise with an empty message, which used
    to render as an empty failure detail.
    """
    return str(exc) or type(exc).__name__


def raise_lookup_error(error: ReconLookupError, *, domain: str | None = None) -> Never:
    """Render one structured resolver failure and raise its CLI exit.

    ``no_data`` means collection completed but produced no reportable data.
    Timeouts, all-source failures, and unknown structured failures mean the
    collection pipeline did not complete and use the documented internal-error
    exit instead of being mislabeled as an empty observation.
    """
    from recon_tool.formatter import render_error, render_warning

    if error.error_type == "no_data":
        render_warning(domain or error.domain, error)
        raise typer.Exit(code=EXIT_NO_DATA) from None

    render_error(fmt_exc(error))
    raise typer.Exit(code=EXIT_INTERNAL) from None


def lookup_validate(
    domain: str,
    *,
    options: LookupOptions,
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

    if error := options.validation_error():
        render_error(error)
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Validate the literal host first (apex=False), then decide whether to
    # reduce. --exact keeps the literal host; otherwise we reduce to the
    # registrable apex and tell the operator what was actually analyzed.
    try:
        literal = validate_domain(domain, apex=False)
    except ValueError as exc:
        render_error(fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if options.exact:
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
