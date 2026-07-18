"""Small shared helpers for the cli modules.

Helpers used by more than one package-local CLI module live here so sibling
sub-app modules can import them without reaching back into the CLI facade,
which would be a circular import. Public names because they cross a module
boundary (pyright-strict flags cross-module underscore access); callers alias
them back to their historical `_name` where convenient.
"""

from __future__ import annotations

import math
import shutil
import textwrap
from collections.abc import Sequence
from typing import Literal, Never

import typer
from rich.console import Console
from rich.markup import escape

from recon_tool.cli.options import LookupOptions
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_NO_DATA, EXIT_VALIDATION
from recon_tool.models import ReconLookupError
from recon_tool.validator import strip_control_chars

_MAX_DIAGNOSTIC_LEN = 2000
_NARROW_HELP_COLUMNS = 70


def help_markup_mode() -> Literal["rich"] | None:
    """Use complete linear help when Rich tables cannot preserve tokens."""
    columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    return None if columns < _NARROW_HELP_COLUMNS else "rich"


def render_usage_rows(console: Console, rows: Sequence[tuple[str, str]]) -> None:
    """Render welcome commands without detaching narrow descriptions."""
    command_width = max((len(command) for command, _description in rows), default=0)
    longest_row = max(
        (2 + command_width + 3 + len(description) for _command, description in rows),
        default=0,
    )
    if console.width >= _NARROW_HELP_COLUMNS and longest_row <= console.width:
        for command, description in rows:
            console.print(f"  {command:<{command_width}s} → {description}")
        return

    description_width = max(1, console.width - 4)
    for command, description in rows:
        console.print(f"  {command}", highlight=False)
        wrapped = textwrap.wrap(
            description,
            width=description_width,
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        for line in wrapped:
            console.print(f"    {line}", highlight=False)


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


def safe_diagnostic_markup(value: object) -> str:
    """Return bounded literal text safe to interpolate into Rich markup."""
    raw = str(value)
    cleaned = strip_control_chars(raw, max_len=_MAX_DIAGNOSTIC_LEN)
    if len(raw) > _MAX_DIAGNOSTIC_LEN:
        cleaned = f"{cleaned} [truncated]"
    return escape(cleaned)


def render_diagnostic_status_row(
    console: Console,
    *,
    mark: str,
    style: str,
    name: object,
    detail: object,
) -> None:
    """Render a safe status row with associated detail at narrow widths."""
    safe_name = safe_diagnostic_markup(name)
    safe_detail = safe_diagnostic_markup(detail)
    header = f"  [{style}]{mark:>4}[/{style}]  {safe_name}:"
    visible_header_length = 2 + 4 + 2 + len(str(name)) + 1
    if visible_header_length > console.width:
        console.print(f"  [{style}]{mark:>4}[/{style}]")
        name_indent = "        "
        name_lines = textwrap.wrap(
            safe_name,
            width=max(1, console.width - len(name_indent)),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        for index, line in enumerate(name_lines):
            suffix = ":" if index == len(name_lines) - 1 else ""
            console.print(f"{name_indent}{line}{suffix}", soft_wrap=True)
        detail_indent = "            "
        detail_lines = textwrap.wrap(
            safe_detail,
            width=max(1, console.width - len(detail_indent)),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        for line in detail_lines:
            console.print(f"{detail_indent}{line}", soft_wrap=True)
        return
    if visible_header_length + 1 + len(str(detail)) <= console.width:
        console.print(f"{header} {safe_detail}")
        return

    console.print(header)
    continuation = "        "
    wrapped = textwrap.wrap(
        safe_detail,
        width=max(1, console.width - len(continuation)),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    for line in wrapped:
        console.print(f"{continuation}{line}", soft_wrap=True)


def raise_lookup_error(error: ReconLookupError, *, domain: str | None = None) -> Never:
    """Render one structured resolver failure and raise its CLI exit.

    ``no_data`` means collection completed but produced no reportable data.
    Timeouts, all-source failures, and unknown structured failures mean the
    collection pipeline did not complete and use the documented internal-error
    exit instead of being mislabeled as an empty observation.
    """
    from recon_tool.formatter import get_err_console, render_error, render_warning

    if error.error_type == "no_data":
        render_warning(domain or error.domain, error)
        raise typer.Exit(code=EXIT_NO_DATA) from None

    render_error(fmt_exc(error))
    if error.error_type in {"timeout", "all_sources_failed"}:
        get_err_console().print("Run recon doctor to check online source connectivity, then retry.")
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
        get_err_console().print(
            "Expected a domain with a public suffix, such as contoso.com. Run recon with no arguments for examples."
        )
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
