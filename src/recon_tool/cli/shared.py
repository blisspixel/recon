"""Small shared helpers for the cli modules.

Helpers used by more than one package-local CLI module live here so sibling
sub-app modules can import them without reaching back into the CLI facade,
which would be a circular import. Public names because they cross a module
boundary (pyright-strict flags cross-module underscore access); callers alias
them back to their historical `_name` where convenient.
"""

from __future__ import annotations

import contextlib
import math
import shutil
import textwrap
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Literal, Never

import typer
from rich.console import Console
from rich.markup import escape

from recon_tool.cli.options import LookupOptions
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_NO_DATA, EXIT_VALIDATION
from recon_tool.formatter.layout import wrap_plain_text
from recon_tool.formatter.theme import ERROR, INFO, SUCCESS, WARNING
from recon_tool.models import ReconLookupError
from recon_tool.validator import strip_control_chars

_MAX_DIAGNOSTIC_LEN = 2000
_NARROW_HELP_COLUMNS = 70
# Diagnostic rows: the indent of the block form, and the narrowest detail
# column worth hanging beside the name before falling back to that block.
_BLOCK_INDENT = 8
_MIN_HANGING_DETAIL = 24


_ENCRYPTED_DNS_GUIDE = "https://github.com/blisspixel/recon/blob/main/docs/getting-started.md#encrypted-dns"


def cli_collection_context() -> AbstractContextManager[None]:
    """Bind the opt-in encrypted DNS view for this CLI process, if requested.

    Without an explicit ``RECON_DNS_VIEW=caller-safe`` the CLI keeps trusted
    host resolution, so the default experience is unchanged.
    """
    from recon_tool.network_policy import cli_collection_policy, collection_scope

    policy = cli_collection_policy()
    return collection_scope(policy) if policy is not None else contextlib.nullcontext()


def reject_unavailable_dns_view() -> None:
    """Refuse a whole multi-domain run before work when the bound view is unusable."""
    from recon_tool.formatter import get_err_console, render_error
    from recon_tool.network_policy import current_policy

    if current_policy().available:
        return
    render_error(
        "The encrypted DNS view is disabled or its RECON_DNS_* settings are invalid; "
        "fix them, or unset RECON_DNS_VIEW to use the system resolver"
    )
    _print_unbroken(get_err_console(), f"See {_ENCRYPTED_DNS_GUIDE}")
    raise typer.Exit(code=EXIT_VALIDATION)


def encrypted_dns_active() -> bool:
    """Report whether this process collects through the opt-in encrypted view."""
    from recon_tool.network_policy import current_policy

    policy = current_policy()
    return policy.mode == "caller-safe" and policy.available


def help_markup_mode() -> Literal["rich"] | None:
    """Use complete linear help when Rich tables cannot preserve tokens."""
    columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    return None if columns < _NARROW_HELP_COLUMNS else "rich"


def resolve_fusion_transition(ctx: typer.Context, fusion: bool) -> bool:
    """Honor explicit fusion flags and keep the v2 implicit default enabled.

    Click's parameter source distinguishes an omitted flag from ``--fusion`` /
    ``--no-fusion``. An omitted flag stays enabled for v2 compatibility. The
    default run stays silent: operators who want a pin use the flags, and
    ``--explain-dag`` already requests the diagnostic.
    """
    source = ctx.get_parameter_source("fusion")
    if source is None or source.name != "DEFAULT":
        return fusion
    return True


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


def non_negative_int(value: int) -> int:
    """Validate a non-negative integer option such as ``--cache-ttl``."""
    if isinstance(value, bool) or value < 0:
        raise typer.BadParameter("must be a non-negative integer")
    return value


def preflight_artifact_output(path: Path | None, *, force: bool, label: str) -> None:
    """Reject known unusable destinations before collection, without writing.

    The artifact writer must still enforce no-clobber at publication time.
    """
    if path is None:
        return
    if not path.parent.is_dir():
        raise ValueError(f"{label} output directory does not exist: {path.parent}")
    exists = path.exists() or path.is_symlink()
    if path.exists() and not path.is_file():
        raise ValueError(f"{label} output must be a file path: {path}")
    if exists and not force:
        raise FileExistsError(f"{label} output already exists: {path}")


def fmt_exc(exc: BaseException) -> str:
    """Render an exception for user display, falling back to the type name.

    httpx.ReadTimeout and similar raise with an empty message, which used
    to render as an empty failure detail.
    """
    return str(exc) or type(exc).__name__


def diagnostic_text(value: object) -> str:
    """Return bounded, control-stripped literal text for a diagnostic row."""
    raw = str(value)
    cleaned = strip_control_chars(raw, max_len=_MAX_DIAGNOSTIC_LEN)
    if len(raw) > _MAX_DIAGNOSTIC_LEN:
        cleaned = f"{cleaned} [truncated]"
    return cleaned


def safe_diagnostic_markup(value: object) -> str:
    """Return bounded literal text safe to interpolate into Rich markup."""
    return escape(diagnostic_text(value))


DiagnosticStatus = Literal["ok", "warn", "fail", "info"]

# The one status vocabulary shared by `recon doctor`, `recon doctor --mcp`,
# `recon doctor --client`, and `recon mcp doctor`. Each word is lowercase and
# carries its meaning without color; the style is the theme role for that
# state (success, warning, error, info) from formatter.theme.
DIAGNOSTIC_STATUS_STYLES: dict[DiagnosticStatus, str] = {
    "ok": SUCCESS,
    "warn": WARNING,
    "fail": ERROR,
    "info": INFO,
}


def render_status_row(console: Console, status: DiagnosticStatus, name: object, detail: object) -> None:
    """Render one diagnostic row in the shared status vocabulary."""
    render_diagnostic_status_row(
        console,
        mark=status,
        style=DIAGNOSTIC_STATUS_STYLES[status],
        name=name,
        detail=detail,
    )


def render_diagnostic_status_row(
    console: Console,
    *,
    mark: str,
    style: str,
    name: object,
    detail: object,
) -> None:
    """Render a safe status row whose detail wraps once under the detail column.

    The row follows the panel's hanging-indent rule (formatter/layout.py): the
    detail wraps at the console width, every continuation line starts at the
    detail column, and a path or hostname never breaks. When the name leaves
    too little room beside it, the detail moves to an indented block below.
    """
    name_text = diagnostic_text(name)
    detail_text = diagnostic_text(detail)
    header = f"  [{style}]{mark:>4}[/{style}]  {escape(name_text)}:"
    visible_header_length = 2 + 4 + 2 + len(name_text) + 1
    if visible_header_length > console.width:
        console.print(f"  [{style}]{mark:>4}[/{style}]")
        name_lines = wrap_plain_text(name_text, max(1, console.width - _BLOCK_INDENT))
        for index, line in enumerate(name_lines):
            suffix = ":" if index == len(name_lines) - 1 else ""
            console.print(f"{' ' * _BLOCK_INDENT}{escape(line)}{suffix}", soft_wrap=True)
        _print_detail_block(console, detail_text, _BLOCK_INDENT + 4)
        return
    detail_column = visible_header_length + 1
    if detail_column + len(detail_text) <= console.width:
        console.print(f"{header} {escape(detail_text)}")
        return
    if console.width - detail_column >= _MIN_HANGING_DETAIL:
        lines = wrap_plain_text(detail_text, console.width - detail_column)
        console.print(f"{header} {escape(lines[0])}", soft_wrap=True)
        for line in lines[1:]:
            console.print(f"{' ' * detail_column}{escape(line)}", soft_wrap=True)
        return
    console.print(header)
    _print_detail_block(console, detail_text, _BLOCK_INDENT)


def _print_detail_block(console: Console, detail_text: str, indent: int) -> None:
    """Print a detail wrapped once, with every line starting at ``indent``."""
    for line in wrap_plain_text(detail_text, max(1, console.width - indent)):
        console.print(f"{' ' * indent}{escape(line)}", soft_wrap=True)


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
    if error.error_type == "dns_view_unavailable":
        _print_unbroken(get_err_console(), f"See {_ENCRYPTED_DNS_GUIDE}")
        raise typer.Exit(code=EXIT_VALIDATION) from None
    if error.error_type in {"timeout", "all_sources_failed"}:
        get_err_console().print("Run recon doctor to check online source connectivity, then retry.")
        if encrypted_dns_active():
            _print_unbroken(
                get_err_console(),
                "Encrypted DNS is on (RECON_DNS_VIEW=caller-safe). If this network blocks it, "
                f"save a resolver it permits or unset RECON_DNS_VIEW: {_ENCRYPTED_DNS_GUIDE}",
            )
    raise typer.Exit(code=EXIT_INTERNAL) from None


def _print_unbroken(console: Console, text: str) -> None:
    """Wrap at word boundaries only, so a link stays whole and copyable."""
    for line in wrap_plain_text(text, max(1, console.width)):
        console.print(escape(line), soft_wrap=True)


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

    # An unknown --profile was only caught after the lookup resolved, so a typo
    # spent a full collection round against the target before exit 2. recon's
    # collection boundary is a promise about what leaves the machine, and a
    # misspelled flag is not consent to contact anyone. Resolving the profile
    # catalog is a local YAML read, so it belongs here rather than in the pure
    # option model. `_lookup_compute_observations` keeps its own check for the
    # paths that do not route through here.
    if profile_name := options.display.profile_name:
        from recon_tool.profiles import list_profiles, load_profile

        if load_profile(profile_name) is None:
            names = ", ".join(p.name for p in list_profiles())
            render_error(f"Unknown profile {profile_name!r}. Available profiles: {names or '(none)'}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    # Validate the literal host first (apex=False), then decide whether to
    # reduce. --exact keeps the literal host; otherwise we reduce to the
    # registrable apex and tell the operator what was actually analyzed.
    try:
        literal = validate_domain(domain, apex=False)
    except ValueError as exc:
        render_error(fmt_exc(exc))
        get_err_console().print(
            "Expected a domain with a public suffix, such as example.com. Run recon with no arguments for examples."
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


def is_closed_pipe(exc: BaseException | None) -> bool:
    """Return True when *exc* is a downstream consumer closing the output pipe."""
    import errno
    import os

    if isinstance(exc, BrokenPipeError):
        return True
    return isinstance(exc, OSError) and (exc.errno == errno.EPIPE or (os.name == "nt" and exc.errno == errno.EINVAL))


def silence_closed_standard_streams() -> None:
    """Prevent interpreter-shutdown flush noise after a closed output pipe."""
    import os
    import sys

    # Python flushes the current standard streams again during interpreter
    # shutdown. Point both at the null device after the original pipe failure.
    for stream_name in ("stdout", "stderr"):
        try:
            replacement = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
        except OSError:
            continue
        setattr(sys, stream_name, replacement)


def color_callback(value: bool | None) -> None:
    """Force (--color) or disable (--no-color) colored output."""
    if value is None:
        return
    from recon_tool.formatter import set_color_override

    set_color_override(value)


def ascii_callback(value: bool) -> None:
    """Record --ascii (or its absence) for this invocation.

    Click runs the callback with the default too, so a flag from an earlier
    in-process invocation never carries over. The root callback resolves the
    glyph set once every eager option has been seen.
    """
    from recon_tool.formatter import set_ascii_override

    set_ascii_override(value)
