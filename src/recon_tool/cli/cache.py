"""The `recon cache` Typer sub-app (CT + result cache management).

Split out of cli.py; registered on the main app via `app.add_typer` there. The
commands use inline imports for their heavy dependencies, like the rest of the
CLI, so this module only needs the small shared surface below.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import typer
from rich.cells import cell_len
from rich.console import Console
from rich.markup import escape

from recon_tool.cli.catalog_rendering import print_field, print_indented
from recon_tool.exit_codes import EXIT_INTERNAL, EXIT_VALIDATION
from recon_tool.formatter import get_console
from recon_tool.validator import strip_control_chars

if TYPE_CHECKING:
    from recon_tool.cache_inspection import ResultCacheInfo
    from recon_tool.cache_values import CacheClearResult, CacheInspection, CacheListing
    from recon_tool.ct_cache import CTCacheInfo

cache_app = typer.Typer(help="Manage the CT subdomain cache and TenantInfo result cache.")


def _plain_field(value: object) -> str:
    """Return persisted metadata without terminal controls."""
    return strip_control_chars(str(value))


def _safe_field(value: object) -> str:
    """Render persisted metadata without control or Rich-markup injection."""
    return escape(_plain_field(value))


def _result_row_fits(console: Console, entry: ResultCacheInfo, status: str) -> bool:
    """Return whether the compact result-cache row fits without wrapping."""
    age = _age_label(entry.age_seconds)
    size = f"{entry.file_size_bytes:,}"
    width = (
        4
        + max(30, cell_len(_plain_field(entry.domain)))
        + 2
        + max(8, cell_len(status))
        + 2
        + max(14, cell_len(age))
        + 2
        + max(8, cell_len(size))
        + len(" bytes")
    )
    return width <= console.width


def _ct_row_fits(console: Console, entry: CTCacheInfo, status: str) -> bool:
    """Return whether the compact CT-cache row fits without wrapping."""
    age = _age_label(entry.age_seconds)
    subdomains = str(entry.subdomain_count)
    width = (
        4
        + max(24, cell_len(_plain_field(entry.domain)))
        + 2
        + max(8, cell_len(status))
        + 2
        + max(4, cell_len(subdomains))
        + len(" subs")
        + 2
        + max(14, cell_len(age))
        + 2
        + cell_len(_plain_field(entry.provider_used))
    )
    return width <= console.width


def _age_label(age_seconds: float) -> str:
    """Return a compact, readable cache age without false precision."""
    if age_seconds < 60:
        return "under 1 minute"
    if age_seconds < 3600:
        minutes = int(age_seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    if age_seconds < 86400:
        hours = int(age_seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = int(age_seconds // 86400)
    return f"{days} day{'s' if days != 1 else ''}"


def _entry_count_label(count: int, *, incomplete: bool = False) -> str:
    if incomplete:
        return f"{count} readable entr{'y' if count == 1 else 'ies'}"
    return "empty" if count == 0 else f"{count} entr{'y' if count == 1 else 'ies'}"


def _listing_count_label(listing: CacheListing[Any]) -> str:
    """Describe only the readable entries actually rendered."""
    if listing.inspected < listing.total:
        return f"{len(listing.entries)} readable entr{'y' if len(listing.entries) == 1 else 'ies'} shown"
    return _entry_count_label(len(listing.entries), incomplete=listing.failed > 0)


def _render_listing_state(console: Console, listing: CacheListing[Any]) -> None:
    """Render exact bounded-inspection and interrupted-write state."""
    if listing.inspected < listing.total:
        omitted = listing.total - listing.inspected
        print_indented(
            console,
            f"Overview limit: inspected {listing.inspected} of {listing.total} files; {omitted} not inspected.",
            indent=4,
            style="yellow",
        )
        print_indented(console, "Inspect every completed entry:", indent=4, style="yellow")
        print_indented(console, "recon cache show --all", indent=6, style="yellow")
    if listing.failed:
        console.print(f"    [red]Inspection failures: {listing.failed}[/red]")
    if listing.temporary_files:
        console.print(
            f"    [red]Temporary write artifacts: {listing.temporary_files} "
            "(payload not inspected; remove with `recon cache clear --all`).[/red]"
        )


def _render_result_inspection(
    console: Console,
    inspection: CacheInspection[ResultCacheInfo],
) -> bool:
    from recon_tool.cache_contract import DEFAULT_TTL

    console.print("  [bold]Result cache[/bold]")
    if inspection.failed:
        console.print("    Status:     [red]could not inspect[/red]")
    elif inspection.entry is None:
        console.print("    Status:     no entry")
    else:
        entry = inspection.entry
        status = "reusable" if entry.reusable else "expired; next lookup refreshes"
        console.print(f"    Status:     {status}")
        console.print(f"    Cached:     {_safe_field(entry.cached_at)}")
        console.print(f"    Resolved:   {_safe_field(entry.resolved_at)}")
        console.print(f"    Age:        {_age_label(entry.age_seconds)}")
        console.print(f"    Size:       {entry.file_size_bytes:,} bytes")
    console.print(f"    TTL:        {DEFAULT_TTL // 3600} hours")
    return inspection.failed


def _render_ct_inspection(console: Console, inspection: CacheInspection[CTCacheInfo]) -> bool:
    from recon_tool.ct_cache import CT_CACHE_TTL

    console.print("  [bold]CT cache[/bold]")
    if inspection.failed:
        console.print("    Status:     [red]could not inspect[/red]")
    elif inspection.entry is None:
        console.print("    Status:     no entry")
    else:
        entry = inspection.entry
        reusable = entry.age_seconds <= CT_CACHE_TTL
        status = "reusable" if reusable else "expired; next CT lookup refreshes"
        console.print(f"    Status:     {status}")
        console.print(f"    Provider:   {_safe_field(entry.provider_used)}")
        console.print(f"    Subdomains: {entry.subdomain_count}")
        console.print(f"    Cached:     {_safe_field(entry.cached_at)}")
        console.print(f"    Age:        {_age_label(entry.age_seconds)}")
        console.print(f"    Size:       {entry.file_size_bytes:,} bytes")
    console.print(f"    TTL:        {CT_CACHE_TTL // 86400} days")
    return inspection.failed


def _render_result_listing(console: Console, listing: CacheListing[ResultCacheInfo]) -> None:
    label = _listing_count_label(listing)
    console.print(f"  [bold]Result cache ({label})[/bold]")
    for entry in listing.entries:
        status = "reusable" if entry.reusable else "expired"
        if not _result_row_fits(console, entry, status):
            print_indented(console, entry.domain, indent=4, style="bold")
            print_field(console, "Status", status, indent=6)
            print_field(console, "Age", _age_label(entry.age_seconds), indent=6)
            print_field(console, "Size", f"{entry.file_size_bytes:,} bytes", indent=6)
        else:
            console.print(
                f"    {_safe_field(entry.domain):<30s}  {status:<8s}  "
                f"{_age_label(entry.age_seconds):>14s}  {entry.file_size_bytes:>8,d} bytes"
            )
    _render_listing_state(console, listing)


def _render_ct_listing(console: Console, listing: CacheListing[CTCacheInfo]) -> None:
    from recon_tool.ct_cache import CT_CACHE_TTL

    label = _listing_count_label(listing)
    console.print(f"  [bold]CT cache ({label})[/bold]")
    for entry in listing.entries:
        status = "reusable" if entry.age_seconds <= CT_CACHE_TTL else "expired"
        if not _ct_row_fits(console, entry, status):
            print_indented(console, entry.domain, indent=4, style="bold")
            print_field(console, "Status", status, indent=6)
            print_field(console, "Subdomains", str(entry.subdomain_count), indent=6)
            print_field(console, "Age", _age_label(entry.age_seconds), indent=6)
            print_field(console, "Provider", entry.provider_used, indent=6)
        else:
            console.print(
                f"    {_safe_field(entry.domain):<24s}  {status:<8s}  {entry.subdomain_count:>4d} subs  "
                f"{_age_label(entry.age_seconds):>14s}  {_safe_field(entry.provider_used)}"
            )
    _render_listing_state(console, listing)


def _report_clear_all(ct_result: CacheClearResult, result: CacheClearResult) -> None:
    """Report both cache-layer outcomes and fail visibly after partial work."""
    from recon_tool.formatter import render_error

    console = get_console()
    console.print(f"  Cleared {ct_result.removed} CT cache entr{'ies' if ct_result.removed != 1 else 'y'}.")
    console.print(f"  Cleared {result.removed} result cache entr{'ies' if result.removed != 1 else 'y'}.")
    if ct_result.temporary_removed:
        console.print(
            f"  Cleared {ct_result.temporary_removed} CT temporary write "
            f"artifact{'s' if ct_result.temporary_removed != 1 else ''}."
        )
    if result.temporary_removed:
        console.print(
            f"  Cleared {result.temporary_removed} result-cache temporary write "
            f"artifact{'s' if result.temporary_removed != 1 else ''}."
        )
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


@cache_app.command("show", short_help="Show cache metadata.")
def cache_show(
    domain: str = typer.Argument(None, help="Domain to inspect (omit to list all)"),
    exact: bool = typer.Option(
        False,
        "--exact",
        help="Inspect literal-host result and CT cache keys instead of their apex.",
    ),
    all_entries: bool = typer.Option(
        False,
        "--all",
        help="Inspect every completed JSON cache file instead of the bounded overview.",
    ),
) -> None:
    """Show payload-free metadata for the result and CT cache layers."""
    from recon_tool.cache_inspection import inspect_result_cache, list_result_cache
    from recon_tool.cache_values import DEFAULT_CACHE_OVERVIEW_LIMIT
    from recon_tool.ct_cache import (
        _ct_cache_inspect,  # pyright: ignore[reportPrivateUsage]
        _ct_cache_list_detailed,  # pyright: ignore[reportPrivateUsage]
    )
    from recon_tool.formatter import render_error
    from recon_tool.validator import validate_domain

    console = get_console()

    if domain:
        if all_entries:
            render_error("--all cannot be combined with a domain.")
            raise typer.Exit(code=EXIT_VALIDATION) from None
        try:
            validated = validate_domain(domain, apex=not exact)
        except ValueError as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from None

        console.print()
        console.print(f"  [bold]{validated}[/bold]")
        console.print()
        failed = _render_result_inspection(console, inspect_result_cache(validated))
        console.print()
        failed = _render_ct_inspection(console, _ct_cache_inspect(validated)) or failed
        console.print()
        if failed:
            render_error("Cache inspection failed. Retry: recon --debug cache show ...")
            raise typer.Exit(code=EXIT_INTERNAL)
    else:
        limit = None if all_entries else DEFAULT_CACHE_OVERVIEW_LIMIT
        result_listing = list_result_cache(limit=limit)
        ct_listing = _ct_cache_list_detailed(limit=limit)
        console.print()
        _render_result_listing(console, result_listing)
        console.print()
        _render_ct_listing(console, ct_listing)
        console.print()
        inspection_failed = result_listing.failed > 0 or ct_listing.failed > 0
        temporary_files = result_listing.temporary_files + ct_listing.temporary_files
        if inspection_failed:
            render_error("Some cache entries could not be inspected. Retry: recon --debug cache show ...")
        if temporary_files:
            render_error(
                "Temporary cache write artifacts remain. Review the counts, then remove them with "
                "`recon cache clear --all`."
            )
        if inspection_failed or temporary_files:
            raise typer.Exit(code=EXIT_INTERNAL)


@cache_app.command("clear", short_help="Clear both cache layers.")
def cache_clear(
    domain: str = typer.Argument(None, help="Domain to clear (omit with --all for everything)"),
    all_domains: bool = typer.Option(False, "--all", help="Clear all cached data"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip the confirmation prompt for --all."),
    exact: bool = typer.Option(False, "--exact", help="Clear the literal host cache key instead of its apex."),
) -> None:
    """Clear both CT subdomain cache and TenantInfo result cache.

    Earlier this only cleared the CT cache, which left stale
    TenantInfo results silently served from ~/.recon/cache/ even
    after a recon cache clear.

    --all wipes everything, so it confirms first when run interactively and
    requires --force in a non-interactive scripted context.
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
