"""CLI application — recon: domain intelligence from the command line.

Supports both:
  recon pepsi.com          (shorthand — domain has a dot)
  recon lookup pepsi.com   (explicit subcommand)
  recon doctor
  recon batch domains.txt

NOTE on _preprocess_args: This mutates sys.argv to support the shorthand
syntax. If you import and call app() directly (as a library), the
preprocessing won't run — use run() instead. This is a known limitation
of the shorthand syntax approach.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import typer

from recon_tool.formatter import get_console

__all__ = [
    "EXIT_INTERNAL",
    "EXIT_NO_DATA",
    "EXIT_VALIDATION",
    "app",
    "run",
]

# Structured exit codes for scripting:
#   0 = success
#   1 = general error (fallback)
#   2 = input validation error (bad domain format, missing file)
#   3 = no data found (domain resolved but no information available)
#   4 = internal/network error
EXIT_VALIDATION = 2
EXIT_NO_DATA = 3
EXIT_INTERNAL = 4

# Known subcommands — used by _preprocess_args to distinguish domains from commands.
# UPDATE THIS SET when adding new subcommands.
_SUBCOMMANDS = frozenset({"doctor", "batch", "lookup"})

# Maximum number of domains in a batch file to prevent OOM from huge files.
_MAX_BATCH_DOMAINS = 10000

# Spinner messages — one is picked at random for each lookup.
# Keeps the CLI feeling alive without being gimmicky.
_STATUS_MESSAGES = (
    "Querying public DNS records...",
    "Following CNAME breadcrumbs...",
    "Reading the TXT record tea leaves...",
    "Fingerprinting the SaaS stack...",
    "Checking Microsoft's public tenant registry...",
    "Mapping the organizational footprint...",
    "Extracting signal from the public noise...",
    "Tracing domain verification trails...",
    "Scoring the email security posture...",
    "Assembling the tech stack mosaic...",
    "No credentials were harmed in this lookup...",
)


_preprocessed = False


def _preprocess_args() -> None:
    """Insert 'lookup' subcommand when first arg looks like a domain.

    This enables `recon pepsi.com` as shorthand for `recon lookup pepsi.com`.
    Only triggers when the first positional arg contains a dot and isn't a
    known subcommand or flag.

    Guarded against double-invocation — safe to call multiple times per process.
    Use _reset_preprocess() in tests to clear the guard between test runs.
    """
    global _preprocessed  # noqa: PLW0603
    if _preprocessed:
        return
    _preprocessed = True

    if len(sys.argv) > 1:
        first = sys.argv[1]
        if not first.startswith("-") and "." in first and first not in _SUBCOMMANDS:
            sys.argv.insert(1, "lookup")


def _reset_preprocess() -> None:  # pyright: ignore[reportUnusedFunction]
    """Reset the preprocessing guard — for test use only."""
    global _preprocessed  # noqa: PLW0603
    _preprocessed = False


app = typer.Typer(
    name="recon",
    help="Domain intelligence from the command line.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from recon_tool import __version__
        get_console().print(f"recon [bold]{__version__}[/bold]")
        raise typer.Exit()


def _debug_callback(value: bool) -> None:
    """Enable debug logging when --debug is passed."""
    if value:
        import logging
        logger = logging.getLogger("recon")
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
            logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
    debug: bool = typer.Option(
        False, "--debug", callback=_debug_callback, is_eager=True,
        help="Enable debug logging.",
    ),
) -> None:
    """
    [bold]recon[/bold] — domain intelligence from the command line.

    Give it any domain. Get back company name, email provider, tenant ID,
    tech stack, email security score, and signal intelligence.
    All from public sources. No credentials needed.

    [dim]Usage:[/dim]
      recon pepsi.com
      recon microsoft.com --services
      recon tesla.com --full
      recon softchoice.com --md > report.md
      recon batch domains.txt --json
      recon doctor
    """


@app.command()
def lookup(
    domain: str = typer.Argument(help="Domain to look up"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
    markdown: bool = typer.Option(False, "--md", help="Markdown report"),
    services: bool = typer.Option(
        False, "--services", "-s", help="M365 vs tech stack breakdown"
    ),
    domains: bool = typer.Option(
        False, "--domains", "-d", help="All tenant domains"
    ),
    full: bool = typer.Option(
        False, "--full", "-f", help="Everything (verbose + services + domains)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Per-source resolution status"
    ),
    sources: bool = typer.Option(
        False, "--sources", help="Detailed source breakdown table"
    ),
    timeout: float = typer.Option(
        60.0, "--timeout", "-t", help="Max seconds for resolution (default: 60)",
    ),
) -> None:
    """
    Look up a domain. This is the default command.

    [dim]recon pepsi.com is the same as recon lookup pepsi.com[/dim]
    """
    asyncio.run(_lookup(domain, json_output, markdown, verbose, services, domains, full, sources, timeout))


@app.command()
def batch(
    file: str = typer.Argument(help="File with one domain per line"),
    json_output: bool = typer.Option(False, "--json", help="JSON array output"),
    markdown: bool = typer.Option(False, "--md", help="Markdown report per domain"),
    concurrency: int = typer.Option(
        5, "--concurrency", "-c", help="Max concurrent lookups (1-20)",
    ),
) -> None:
    """
    Look up multiple domains from a file.

    [dim]One domain per line. Lines starting with # are skipped.[/dim]
    """
    concurrency = max(1, min(20, concurrency))
    asyncio.run(_batch(file, json_output, markdown, concurrency))


@app.command()
def doctor() -> None:
    """
    Check connectivity to all data sources.
    """
    asyncio.run(_doctor())


async def _doctor() -> None:
    """Run diagnostic checks."""
    import dns.exception
    import dns.resolver
    import httpx

    from recon_tool import __version__

    console = get_console()
    console.print()
    console.print(f"  recon [bold]v{__version__}[/bold]")
    console.print(f"  Python [bold]{sys.version.split()[0]}[/bold]")
    console.print()

    checks: list[tuple[str, bool, str]] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(
                "https://login.microsoftonline.com/common/.well-known/openid-configuration"
            )
            checks.append(("OIDC discovery", resp.status_code == 200, f"HTTP {resp.status_code}"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("OIDC discovery", False, str(exc)))

        # Synthetic non-existent address — avoids probing a real account.
        try:
            resp = await client.get(
                "https://login.microsoftonline.com/GetUserRealm.srf",
                params={"login": "recon-connectivity-check@example.com", "json": "1"},
            )
            checks.append(("GetUserRealm", resp.status_code == 200, f"HTTP {resp.status_code}"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("GetUserRealm", False, str(exc)))

        try:
            resp = await client.post(
                "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
                content="<test/>",
                headers={"Content-Type": "text/xml"},
            )
            checks.append(("Autodiscover", True, f"HTTP {resp.status_code} (reachable)"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("Autodiscover", False, str(exc)))

    try:
        answers = dns.resolver.resolve("example.com", "TXT")
        checks.append(("DNS resolution", True, f"{len(list(answers))} TXT records"))  # pyright: ignore[reportArgumentType]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, OSError) as exc:
        checks.append(("DNS resolution", False, str(exc)))

    # Check crt.sh connectivity (certificate transparency)
    try:
        resp = await httpx.AsyncClient(timeout=8.0).get("https://crt.sh/?q=%.example.com&output=json")
        checks.append(("crt.sh (cert transparency)", resp.status_code == 200, f"HTTP {resp.status_code}"))
    except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
        checks.append(("crt.sh (cert transparency)", False, str(exc)))

    try:
        from recon_tool.server import mcp  # noqa: F401  # pyright: ignore[reportUnusedImport]
        checks.append(("MCP server module", True, "loaded"))
    except Exception as exc:
        checks.append(("MCP server module", False, str(exc)))

    # Check fingerprint database loading
    try:
        from recon_tool.fingerprints import load_fingerprints
        fps = load_fingerprints()
        if fps:
            checks.append(("Fingerprint database", True, f"{len(fps)} fingerprints loaded"))
        else:
            checks.append(("Fingerprint database", False, "no fingerprints loaded — detection will not work"))
    except Exception as exc:
        checks.append(("Fingerprint database", False, str(exc)))

    # Check custom fingerprint path
    import os
    from pathlib import Path
    custom_dir = os.environ.get("RECON_CONFIG_DIR")
    custom_path = Path(custom_dir) / "fingerprints.yaml" if custom_dir else Path.home() / ".recon" / "fingerprints.yaml"
    if custom_path.exists():
        try:
            import yaml
            data = yaml.safe_load(custom_path.read_text(encoding="utf-8"))
            count = 0
            if isinstance(data, dict) and "fingerprints" in data:
                count = len(data["fingerprints"])
            elif isinstance(data, list):
                count = len(data)
            checks.append(("Custom fingerprints", True, f"{count} entries in {custom_path}"))
        except Exception as exc:
            checks.append(("Custom fingerprints", False, str(exc)))
    else:
        checks.append(("Custom fingerprints", True, f"none ({custom_path} not found)"))

    # Check signal database loading
    try:
        from recon_tool.signals import load_signals
        sigs = load_signals()
        if sigs:
            checks.append(("Signal database", True, f"{len(sigs)} signals loaded"))
        else:
            checks.append(("Signal database", False, "no signals loaded — signal intelligence will not work"))
    except Exception as exc:
        checks.append(("Signal database", False, str(exc)))

    # Check custom signals path
    custom_signals_path = Path(custom_dir) / "signals.yaml" if custom_dir else Path.home() / ".recon" / "signals.yaml"
    if custom_signals_path.exists():
        try:
            import yaml as _yaml
            data = _yaml.safe_load(custom_signals_path.read_text(encoding="utf-8"))
            count = 0
            if isinstance(data, dict) and "signals" in data:
                count = len(data["signals"])
            checks.append(("Custom signals", True, f"{count} entries in {custom_signals_path}"))
        except Exception as exc:
            checks.append(("Custom signals", False, str(exc)))
    else:
        checks.append(("Custom signals", True, f"none ({custom_signals_path} not found)"))

    all_ok = True
    for name, ok, detail in checks:
        mark = "ok" if ok else "FAIL"
        style = "green" if ok else "red"
        console.print(f"  [{style}]{mark:>4}[/{style}]  {name} — {detail}")
        if not ok:
            all_ok = False

    console.print()
    if all_ok:
        console.print("  [green]All checks passed.[/green]")
    else:
        console.print("  [yellow]Some checks failed. Lookups may be incomplete.[/yellow]")
    console.print()


async def _lookup(
    domain: str,
    json_output: bool,
    markdown: bool,
    verbose: bool,
    show_services: bool,
    show_domains: bool,
    full: bool,
    show_sources: bool,
    timeout: float = 60.0,
) -> None:
    """Async lookup implementation."""
    # Lazy imports: formatter, resolver, validator are imported here (not at module
    # level) to keep CLI startup fast. Typer parses args before any command runs,
    # so top-level imports of heavy modules (httpx, dns, yaml) would slow down
    # even `recon --help`. The doctor and batch functions do the same.
    from recon_tool.formatter import (
        format_tenant_json,
        format_tenant_markdown,
        render_error,
        render_sources_detail,
        render_tenant_panel,
        render_verbose_sources,
        render_warning,
    )
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    console = get_console()

    if full:
        show_services = True
        show_domains = True
        verbose = True

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(str(exc))
        # `from None` suppresses the ValueError chain in the traceback.
        # The user already sees the error message via render_error();
        # showing the full traceback for a validation error is noise.
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        if not json_output and not markdown:
            import random
            msg = random.choice(_STATUS_MESSAGES)  # noqa: S311 — not security-sensitive
            with console.status(msg):
                info, results = await resolve_tenant(validated, timeout=timeout)
        else:
            info, results = await resolve_tenant(validated, timeout=timeout)

        if verbose:
            render_verbose_sources(results)

        if json_output:
            typer.echo(format_tenant_json(info))
            return

        if markdown:
            typer.echo(format_tenant_markdown(info))
            return

        console.print(render_tenant_panel(
            info,
            show_services=show_services,
            show_domains=show_domains,
        ))

        if show_sources:
            console.print(render_sources_detail(results))

    except ReconLookupError:
        render_warning(domain)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


async def _batch(file: str, json_output: bool, markdown: bool, concurrency: int) -> None:
    """Process multiple domains from a file with controlled concurrency.

    Rate limiting: Each domain hits 3+ external endpoints concurrently.
    The semaphore caps domain-level concurrency, and the HTTP transport
    retries on 429/503 with exponential backoff. For large batch files,
    an inter-domain delay prevents burst-flooding upstream endpoints.
    """
    import json as json_mod
    from pathlib import Path

    from recon_tool.formatter import (
        format_tenant_dict,
        format_tenant_markdown,
        render_error,
        render_tenant_panel,
    )
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    console = get_console()

    path = Path(file)
    if not path.exists():
        render_error(f"File not found: {file}")
        raise typer.Exit(code=EXIT_VALIDATION)

    # Stream lines instead of reading entire file to avoid OOM on huge files
    domain_list: list[str] = []
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    domain_list.append(stripped)
                    if len(domain_list) > _MAX_BATCH_DOMAINS:
                        render_error(
                            f"Batch file exceeds maximum of {_MAX_BATCH_DOMAINS} domains"
                        )
                        raise typer.Exit(code=EXIT_VALIDATION)
    except OSError as exc:
        render_error(f"Cannot read file: {exc}")
        raise typer.Exit(code=EXIT_INTERNAL) from None

    if not domain_list:
        render_error("No domains found in file")
        raise typer.Exit(code=EXIT_VALIDATION)

    # Deduplicate while preserving input order
    seen: set[str] = set()
    unique_domains: list[str] = []
    for d in domain_list:
        d_lower = d.lower().strip()
        if d_lower not in seen:
            seen.add(d_lower)
            unique_domains.append(d)
    if len(unique_domains) < len(domain_list) and not json_output and not markdown:
        skipped = len(domain_list) - len(unique_domains)
        console.print(f"  [dim]{skipped} duplicate(s) removed[/dim]")
    domain_list = unique_domains

    semaphore = asyncio.Semaphore(concurrency)

    # Sentinel prefix for error messages returned from _process_one.
    # Errors are collected as strings and printed in order after all tasks complete,
    # preventing interleaved output from concurrent coroutines.
    _ERROR_PREFIX = "\x00ERR:"

    async def _process_one(domain: str) -> object:
        """Process a single domain with semaphore-controlled concurrency.

        Returns:
            - dict for JSON mode (success or error)
            - str for markdown mode (rendered markdown)
            - Panel for display mode
            - Error sentinel string for display-mode errors
            - None when nothing to show
        """
        try:
            validated = validate_domain(domain)
        except ValueError as exc:
            if json_output:
                return {"domain": domain, "error": str(exc)}
            if markdown:
                return None
            return f"{_ERROR_PREFIX}{domain}: {exc}"

        async with semaphore:
            try:
                # Small delay between domains to avoid burst-flooding
                # upstream endpoints (Microsoft, DNS). The semaphore limits
                # concurrency, but without a delay all N domains fire at once.
                await asyncio.sleep(0.1)
                info, _results = await resolve_tenant(validated)

                if json_output:
                    return format_tenant_dict(info)
                if markdown:
                    return format_tenant_markdown(info)
                return render_tenant_panel(info)

            except ReconLookupError as exc:
                if json_output:
                    return {"domain": domain, "error": str(exc)}
                return f"{_ERROR_PREFIX}{domain}: {exc}"
            except Exception as exc:
                if json_output:
                    return {"domain": domain, "error": str(exc)}
                return f"{_ERROR_PREFIX}{domain}: {exc}"

    # Gather all results concurrently, then output in input-file order.
    # This prevents interleaved output from concurrent coroutines.
    total = len(domain_list)
    completed = 0

    async def _tracked(domain: str) -> object:
        nonlocal completed
        result = await _process_one(domain)
        completed += 1
        if not json_output and not markdown:
            console.print(f"  [{completed}/{total}] {domain}", style="dim", highlight=False)
        return result

    tasks = [_tracked(d) for d in domain_list]
    results = await asyncio.gather(*tasks)

    if json_output:
        json_results: list[dict[str, Any]] = [r for r in results if r is not None]  # type: ignore[misc]
        typer.echo(json_mod.dumps(json_results, indent=2))
    elif markdown:
        for r in results:
            if r is not None:
                typer.echo(r)
                typer.echo("---\n")
    else:
        for r in results:
            if r is None:
                continue
            if isinstance(r, str) and r.startswith(_ERROR_PREFIX):
                render_error(r[len(_ERROR_PREFIX):])
            else:
                console.print(r)
                console.print()


def run() -> None:
    """Entry point — preprocess args before typer runs.

    Use this instead of app() directly to get shorthand domain syntax.
    """
    _preprocess_args()
    app()


if __name__ == "__main__":
    run()
