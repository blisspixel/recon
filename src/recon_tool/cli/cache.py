"""The `recon cache` Typer sub-app (CT + result cache management).

Split out of cli.py; registered on the main app via `app.add_typer` there. The
commands use inline imports for their heavy dependencies, like the rest of the
CLI, so this module only needs the small shared surface below.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer
from rich.markup import escape

from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_VALIDATION
from recon_tool.formatter import get_console
from recon_tool.validator import strip_control_chars

if TYPE_CHECKING:
    from recon_tool.cache_values import CacheClearResult

cache_app = typer.Typer(help="Manage the CT subdomain cache and TenantInfo result cache.")


def _report_clear_all(ct_result: CacheClearResult, result: CacheClearResult) -> None:
    """Report both cache-layer outcomes and fail visibly after partial work."""
    from recon_tool.formatter import render_error

    console = get_console()
    console.print(f"  Cleared {ct_result.removed} CT cache entr{'ies' if ct_result.removed != 1 else 'y'}.")
    console.print(f"  Cleared {result.removed} result cache entr{'ies' if result.removed != 1 else 'y'}.")
    if ct_result.failed:
        render_error("Some CT cache entries could not be cleared. Retry: recon --debug cache clear ...")
    if result.failed:
        render_error("Some result cache entries could not be cleared. Retry: recon --debug cache clear ...")
    if ct_result.failed or result.failed:
        raise typer.Exit(code=EXIT_INTERNAL)


def _report_clear_domain(
    domain: str,
    ct_result: CacheClearResult,
    result: CacheClearResult,
) -> None:
    """Report one domain's cache-layer outcomes without claiming false absence."""
    from recon_tool.formatter import render_error

    console = get_console()
    if ct_result.removed or result.removed:
        parts: list[str] = []
        if ct_result.removed:
            parts.append("CT cache")
        if result.removed:
            parts.append("result cache")
        console.print(f"  Cleared {' and '.join(parts)} for [bold]{domain}[/bold].")
    elif not ct_result.failed and not result.failed:
        console.print(f"  No cache entry for [bold]{domain}[/bold].")
    if ct_result.failed:
        render_error(f"{domain}: CT cache clear failed. Retry: recon --debug cache clear ...")
    if result.failed:
        render_error(f"{domain}: result cache clear failed. Retry: recon --debug cache clear ...")
    if ct_result.failed or result.failed:
        raise typer.Exit(code=EXIT_INTERNAL)


@cache_app.command("show")
def cache_show(
    domain: str = typer.Argument(None, help="Domain to inspect (omit to list all)"),
    exact: bool = typer.Option(False, "--exact", help="Inspect the literal host cache key instead of its apex."),
) -> None:
    """Show CT cache state for a domain, or list all cached domains.

    Only surfaces the CT subdomain cache. The TenantInfo result cache
    under ``~/.recon/cache/`` is managed opaquely.
    """
    from recon_tool.ct_cache import ct_cache_list, ct_cache_show
    from recon_tool.formatter import render_error
    from recon_tool.validator import validate_domain

    console = get_console()

    if domain:
        try:
            validated = validate_domain(domain, apex=not exact)
        except ValueError as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from None

        info = ct_cache_show(validated)
        if info is None:
            console.print(f"  No CT cache entry for [bold]{validated}[/bold]")
            return
        age_str = "today" if info.age_days == 0 else f"{info.age_days} day{'s' if info.age_days != 1 else ''} old"
        console.print()
        console.print(f"  [bold]{info.domain}[/bold]")
        # provider_used / cached_at come from the cache file; escape markup
        # and strip control bytes so a poisoned entry cannot inject ANSI or
        # Rich markup (or crash the command on unbalanced tags).
        console.print(f"    Provider:   {escape(strip_control_chars(str(info.provider_used)))}")
        console.print(f"    Subdomains: {info.subdomain_count}")
        console.print(f"    Cached:     {escape(strip_control_chars(str(info.cached_at)))}")
        console.print(f"    Age:        {age_str}")
        console.print(f"    Size:       {info.file_size_bytes:,} bytes")
        console.print()
    else:
        entries = ct_cache_list()
        if not entries:
            console.print("  CT cache is empty.")
            return
        console.print()
        console.print(f"  [bold]{len(entries)} cached domain{'s' if len(entries) != 1 else ''}[/bold]")
        console.print()
        for e in entries:
            age_str = "today" if e.age_days == 0 else f"{e.age_days}d"
            console.print(
                f"    {e.domain:<30s}  {e.subdomain_count:>4d} subs  {age_str:>5s}  "
                f"{escape(strip_control_chars(str(e.provider_used)))}"
            )
        console.print()


@cache_app.command("clear")
def cache_clear(
    domain: str = typer.Argument(None, help="Domain to clear (omit with --all for everything)"),
    all_domains: bool = typer.Option(False, "--all", help="Clear all cached data"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip the confirmation prompt for --all."),
    exact: bool = typer.Option(False, "--exact", help="Clear the literal host cache key instead of its apex."),
) -> None:
    """Clear both CT subdomain cache and TenantInfo result cache.

    Earlier this only cleared the CT cache, which left stale
    TenantInfo results silently served from ``~/.recon/cache/`` even
    after a ``recon cache clear``.

    ``--all`` wipes everything, so it confirms first when run interactively and
    requires ``--force`` in a non-interactive (scripted) context.
    """
    import sys

    from recon_tool.cache import (
        _cache_clear_all_detailed as result_cache_clear_all,  # pyright: ignore[reportPrivateUsage]
    )
    from recon_tool.cache import (
        _cache_clear_detailed as result_cache_clear,  # pyright: ignore[reportPrivateUsage]
    )
    from recon_tool.ct_cache import (
        _ct_cache_clear_all_detailed as ct_cache_clear_all,  # pyright: ignore[reportPrivateUsage]
    )
    from recon_tool.ct_cache import (
        _ct_cache_clear_detailed as ct_cache_clear,  # pyright: ignore[reportPrivateUsage]
    )
    from recon_tool.formatter import render_error
    from recon_tool.validator import validate_domain

    console = get_console()

    if all_domains:
        if not force:
            try:
                interactive = sys.stdin is not None and sys.stdin.isatty()
            except (ValueError, OSError):  # detached / closed stdin → treat as non-interactive
                interactive = False
            if interactive:
                if not typer.confirm("Clear ALL cached CT and result data?", err=True):
                    console.print("  Aborted.")
                    raise typer.Exit()
            else:
                render_error("Refusing to clear all cached data without confirmation; re-run with --force.")
                raise typer.Exit(code=EXIT_VALIDATION)
        ct_result = ct_cache_clear_all()
        result = result_cache_clear_all()
        _report_clear_all(ct_result, result)
    elif domain:
        try:
            validated = validate_domain(domain, apex=not exact)
        except ValueError as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from None

        ct_result = ct_cache_clear(validated)
        result = result_cache_clear(validated)
        _report_clear_domain(validated, ct_result, result)
    else:
        console.print("  Specify a domain or use --all.")
        raise typer.Exit(code=EXIT_VALIDATION)
