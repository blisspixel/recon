"""CLI application — recon: domain intelligence from the command line.

Supports both:
  recon contoso.com          (shorthand — domain has a dot)
  recon lookup contoso.com   (explicit subcommand)
  recon doctor
  recon batch domains.txt
  recon mcp                (start MCP server)

The shorthand syntax uses Typer's invoke_without_command callback to route
domain-like arguments to the lookup command. No sys.argv mutation needed.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import click
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

# Known subcommands — used by the callback to distinguish domains from commands.
# UPDATE THIS SET when adding new subcommands.
_SUBCOMMANDS = frozenset({"doctor", "batch", "lookup", "mcp"})

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


class _DomainGroup(typer.core.TyperGroup):  # pyright: ignore[reportUntypedBaseClass, reportAttributeAccessIssue]
    """Custom Click group that routes domain-like args to the lookup command.

    When the first positional arg contains a dot and isn't a known subcommand
    or flag, it's treated as a domain and routed to `lookup`.
    """

    def resolve_command(
        self,
        ctx: click.Context,
        args: list[str],
    ) -> tuple[str | None, click.Command | None, list[str]]:
        # Try normal subcommand resolution first
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            # If the first arg looks like a domain, route to lookup
            if args and "." in args[0] and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
                return super().resolve_command(ctx, ["lookup"] + args)
            raise


app = typer.Typer(
    name="recon",
    help="Domain intelligence from the command line.",
    rich_markup_mode="rich",
    cls=_DomainGroup,
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


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        callback=_debug_callback,
        is_eager=True,
        help="Enable debug logging.",
    ),
) -> None:
    """
    [bold]recon[/bold] — domain intelligence from the command line.

    Give it any domain. Get back company name, email provider, tenant ID,
    tech stack, email security score, and signal intelligence.
    All from public sources. No credentials needed.

    [dim]Usage:[/dim]
      recon contoso.com
      recon northwindtraders.com --services
      recon fabrikam.com --full
      recon contoso.com --md > report.md
      recon batch domains.txt --json
      recon doctor
      recon mcp
    """
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def lookup(
    domain: str = typer.Argument(help="Domain to look up"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
    markdown: bool = typer.Option(False, "--md", help="Markdown report"),
    services: bool = typer.Option(False, "--services", "-s", help="M365 vs tech stack breakdown"),
    domains: bool = typer.Option(False, "--domains", "-d", help="All tenant domains"),
    full: bool = typer.Option(False, "--full", "-f", help="Everything (verbose + services + domains + posture)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Per-source resolution status"),
    sources: bool = typer.Option(False, "--sources", help="Detailed source breakdown table"),
    timeout: float = typer.Option(
        60.0,
        "--timeout",
        "-t",
        help="Max seconds for resolution (default: 60)",
    ),
    posture: bool = typer.Option(False, "--posture", "-p", help="Show posture observations"),
    compare: str | None = typer.Option(None, "--compare", help="Compare against previous JSON export"),
    chain: bool = typer.Option(False, "--chain", help="Recursively follow related domains"),
    depth: int = typer.Option(1, "--depth", help="Chain depth (1-3, requires --chain)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass disk cache entirely"),
    cache_ttl: int = typer.Option(86400, "--cache-ttl", help="Cache TTL in seconds (default: 86400)"),
    exposure: bool = typer.Option(False, "--exposure", help="Show exposure assessment"),
    gaps: bool = typer.Option(False, "--gaps", help="Show hardening gap analysis"),
) -> None:
    """
    Look up a domain. This is the default command.

    [dim]recon contoso.com is the same as recon lookup contoso.com[/dim]
    """
    asyncio.run(
        _lookup(
            domain,
            json_output,
            markdown,
            verbose,
            services,
            domains,
            full,
            sources,
            timeout,
            show_posture=posture,
            compare_file=compare,
            chain_mode=chain,
            chain_depth=depth,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            show_exposure=exposure,
            show_gaps=gaps,
        )
    )


@app.command()
def batch(
    file: str = typer.Argument(help="File with one domain per line"),
    json_output: bool = typer.Option(False, "--json", help="JSON array output"),
    markdown: bool = typer.Option(False, "--md", help="Markdown report per domain"),
    csv_output: bool = typer.Option(False, "--csv", help="CSV output"),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Max concurrent lookups (1-20)",
    ),
) -> None:
    """
    Look up multiple domains from a file.

    [dim]One domain per line. Lines starting with # are skipped.[/dim]
    """
    concurrency = max(1, min(20, concurrency))
    asyncio.run(_batch(file, json_output, markdown, concurrency, csv_output=csv_output))


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Scaffold template config files"),
) -> None:
    """
    Check connectivity to all data sources.
    """
    if fix:
        _doctor_fix()
        return
    asyncio.run(_doctor())


# ── Template content for doctor --fix ────────────────────────────────────

_FINGERPRINTS_TEMPLATE = """\
# Custom fingerprints — merged with built-in fingerprints at load time.
# Each entry adds a new SaaS/service detection rule.
#
# Fields:
#   name:           Human-readable service name (shown in output)
#   slug:           Unique identifier (lowercase, hyphens)
#   type:           Detection type — txt, mx, cname, ns, caa, http
#   pattern:        Regex pattern to match against DNS record value
#   category:       Service category — email, security, identity, saas, infrastructure
#   provider_group: (optional) Group for display — microsoft365, google-workspace
#   display_group:  (optional) Override display grouping
#
# Example:
# fingerprints:
#   - name: "Acme SSO"
#     slug: "acme-sso"
#     type: "txt"
#     pattern: "acme-domain-verification="
#     category: "identity"

fingerprints: []
"""

_SIGNALS_TEMPLATE = """\
# Custom signals — merged with built-in signals at load time.
# Each entry defines a derived intelligence signal.
#
# Fields:
#   name:           Signal display name
#   category:       Signal category — security, identity, infrastructure, saas
#   confidence:     Signal confidence — high, medium, low
#   description:    Human-readable description (use hedged language for inferences)
#   requires:       List of fingerprint slugs required (all must match)
#   min_matches:    (optional) Minimum number of required slugs that must match
#   metadata:       (optional) Additional conditions on metadata fields
#     - field:      Metadata field — dmarc_policy, auth_type, email_security_score
#       operator:   Comparison — eq, neq, gte, lte
#       value:      Value to compare against
#
# Example:
# signals:
#   - name: "Custom Security Signal"
#     category: "security"
#     confidence: "medium"
#     description: "Custom security tooling indicators"
#     requires:
#       - "acme-sso"
#     min_matches: 1

signals: []
"""


def _doctor_fix() -> None:
    """Scaffold template fingerprints.yaml and signals.yaml in config dir."""
    import os
    from pathlib import Path

    console = get_console()
    config_dir_env = os.environ.get("RECON_CONFIG_DIR")
    config_dir = Path(config_dir_env) if config_dir_env else Path.home() / ".recon"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[red]Cannot create config directory {config_dir}: {exc}[/red]")
        return

    templates = [
        ("fingerprints.yaml", _FINGERPRINTS_TEMPLATE),
        ("signals.yaml", _SIGNALS_TEMPLATE),
    ]

    for filename, content in templates:
        target = config_dir / filename
        if target.exists():
            console.print(f"  already exists: {target}")
        else:
            try:
                target.write_text(content, encoding="utf-8")
                console.print(f"  [green]created:[/green] {target}")
            except OSError as exc:
                console.print(f"  [red]failed to create {target}: {exc}[/red]")


@app.command()
def mcp() -> None:
    """Start the MCP server (stdio transport)."""
    from recon_tool.server import main as server_main

    server_main()


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
            resp = await client.get("https://login.microsoftonline.com/common/.well-known/openid-configuration")
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
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        OSError,
    ) as exc:
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
    show_posture: bool = False,
    compare_file: str | None = None,
    chain_mode: bool = False,
    chain_depth: int = 1,
    no_cache: bool = False,
    cache_ttl: int = 86400,
    show_exposure: bool = False,
    show_gaps: bool = False,
) -> None:
    """Async lookup implementation."""
    # Lazy imports: formatter, resolver, validator are imported here (not at module
    # level) to keep CLI startup fast. Typer parses args before any command runs,
    # so top-level imports of heavy modules (httpx, dns, yaml) would slow down
    # even `recon --help`. The doctor and batch functions do the same.
    from recon_tool.formatter import (
        format_tenant_dict,
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
        show_posture = True

    # Mutual exclusion: --chain and --compare cannot be used together
    if chain_mode and compare_file:
        render_error("--chain and --compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Mutual exclusion: --exposure and --gaps are mutually exclusive with --chain and --compare
    if show_exposure and (chain_mode or compare_file):
        render_error("--exposure and --chain/--compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if show_gaps and (chain_mode or compare_file):
        render_error("--gaps and --chain/--compare are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Mutual exclusion: only one output format allowed
    if sum([json_output, markdown]) > 1:
        render_error("--json and --md are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # --depth > 1 requires --chain
    if chain_depth > 1 and not chain_mode:
        render_error("--depth requires --chain")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # ── Compare mode ─────────────────────────────────────────────────
    if compare_file:
        from pathlib import Path

        from recon_tool.delta import compute_delta, load_previous
        from recon_tool.formatter import format_delta_json, render_delta_panel

        try:
            previous = load_previous(Path(compare_file))
        except (FileNotFoundError, ValueError) as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from None

        try:
            if not json_output and not markdown:
                import random

                msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
                with console.status(msg):
                    info, results = await resolve_tenant(validated, timeout=timeout)
            else:
                info, results = await resolve_tenant(validated, timeout=timeout)
        except ReconLookupError:
            render_warning(domain)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from None

        delta = compute_delta(previous, info)

        if json_output:
            typer.echo(format_delta_json(delta))
        else:
            console.print(render_delta_panel(delta))
        return

    # ── Chain mode ───────────────────────────────────────────────────
    if chain_mode:
        from recon_tool.chain import chain_resolve
        from recon_tool.formatter import format_chain_json, render_chain_panel

        try:
            if not json_output and not markdown:
                import random

                msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
                with console.status(msg):
                    report = await chain_resolve(validated, depth=chain_depth)
            else:
                report = await chain_resolve(validated, depth=chain_depth)
        except Exception as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from None

        if json_output:
            typer.echo(format_chain_json(report))
        else:
            console.print(render_chain_panel(report))
        return

    # ── Exposure mode ────────────────────────────────────────────────
    if show_exposure:
        from recon_tool.exposure import assess_exposure_from_info
        from recon_tool.formatter import format_exposure_json, render_exposure_panel

        try:
            info_exp: Any = None
            if not no_cache:
                from recon_tool.cache import cache_get

                cached = cache_get(validated, ttl=cache_ttl)
                if cached is not None:
                    info_exp = cached

            if info_exp is None:
                if not json_output and not markdown:
                    import random

                    msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
                    with console.status(msg):
                        info_exp, _results = await resolve_tenant(validated, timeout=timeout)
                else:
                    info_exp, _results = await resolve_tenant(validated, timeout=timeout)

                if not no_cache:
                    from recon_tool.cache import cache_put

                    cache_put(validated, info_exp)

            assessment = assess_exposure_from_info(info_exp)

            if json_output:
                typer.echo(format_exposure_json(assessment))
            else:
                console.print(render_exposure_panel(assessment))
        except ReconLookupError:
            render_warning(domain)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from None
        return

    # ── Gaps mode ────────────────────────────────────────────────────
    if show_gaps:
        from recon_tool.exposure import find_gaps_from_info
        from recon_tool.formatter import format_gaps_json, render_gaps_panel

        try:
            info_gaps: Any = None
            if not no_cache:
                from recon_tool.cache import cache_get

                cached = cache_get(validated, ttl=cache_ttl)
                if cached is not None:
                    info_gaps = cached

            if info_gaps is None:
                if not json_output and not markdown:
                    import random

                    msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
                    with console.status(msg):
                        info_gaps, _results = await resolve_tenant(validated, timeout=timeout)
                else:
                    info_gaps, _results = await resolve_tenant(validated, timeout=timeout)

                if not no_cache:
                    from recon_tool.cache import cache_put

                    cache_put(validated, info_gaps)

            report = find_gaps_from_info(info_gaps)

            if json_output:
                typer.echo(format_gaps_json(report))
            else:
                console.print(render_gaps_panel(report))
        except ReconLookupError:
            render_warning(domain)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(str(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from None
        return

    # ── Standard lookup ──────────────────────────────────────────────
    try:
        # Check cache before hitting upstream
        info: Any = None
        results: list[Any] = []
        if not no_cache:
            from recon_tool.cache import cache_get

            cached = cache_get(validated, ttl=cache_ttl)
            if cached is not None:
                info = cached

        if info is None:
            if not json_output and not markdown:
                import random

                msg = random.choice(_STATUS_MESSAGES)  # noqa: S311 — not security-sensitive
                with console.status(msg):
                    info, results = await resolve_tenant(validated, timeout=timeout)
            else:
                info, results = await resolve_tenant(validated, timeout=timeout)

            # Write to cache after fresh lookup
            if not no_cache:
                from recon_tool.cache import cache_put

                cache_put(validated, info)

        if verbose:
            render_verbose_sources(results)

        # Compute posture observations if requested
        observations = ()
        if show_posture:
            from recon_tool.posture import analyze_posture

            observations = analyze_posture(info)

        if json_output:
            from recon_tool.formatter import format_posture_observations

            tenant_dict = format_tenant_dict(info)
            if show_posture:
                tenant_dict["posture"] = format_posture_observations(observations)
            typer.echo(json.dumps(tenant_dict, indent=2))
            return

        if markdown:
            md = format_tenant_markdown(info)
            if show_posture and observations:
                md += "\n## Posture Analysis\n\n"
                for obs in observations:
                    indicator = {"high": "●", "medium": "◐", "low": "○"}.get(obs.salience, "○")
                    md += f"- {indicator} **[{obs.category}]** {obs.statement}\n"
                md += "\n"
            typer.echo(md)
            return

        console.print(
            render_tenant_panel(
                info,
                show_services=show_services,
                show_domains=show_domains,
                verbose=verbose,
            )
        )

        if show_sources:
            console.print(render_sources_detail(results))

        # Posture panel after main output
        if show_posture and observations:
            from recon_tool.formatter import render_posture_panel

            posture_panel = render_posture_panel(observations)
            if posture_panel:
                console.print(posture_panel)

    except ReconLookupError:
        render_warning(domain)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


async def _batch(file: str, json_output: bool, markdown: bool, concurrency: int, csv_output: bool = False) -> None:
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
    from recon_tool.models import TenantInfo as _TenantInfo  # noqa: F811
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    console = get_console()

    # Mutual exclusion: only one output format allowed
    if sum([json_output, markdown, csv_output]) > 1:
        render_error("--json, --md, and --csv are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION)

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
                        render_error(f"Batch file exceeds maximum of {_MAX_BATCH_DOMAINS} domains")
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
    if len(unique_domains) < len(domain_list) and not json_output and not markdown and not csv_output:
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
            - tuple (domain, TenantInfo, None) or (domain, None, error) for CSV mode
            - Panel for display mode
            - Error sentinel string for display-mode errors
            - None when nothing to show
        """
        try:
            validated = validate_domain(domain)
        except ValueError as exc:
            if json_output:
                return {"domain": domain, "error": str(exc)}
            if csv_output:
                return (domain, None, str(exc))
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
                if csv_output:
                    return (domain, info, None)
                if markdown:
                    return format_tenant_markdown(info)
                return render_tenant_panel(info)

            except ReconLookupError as exc:
                if json_output:
                    return {"domain": domain, "error": str(exc)}
                if csv_output:
                    return (domain, None, str(exc))
                return f"{_ERROR_PREFIX}{domain}: {exc}"
            except Exception as exc:
                if json_output:
                    return {"domain": domain, "error": str(exc)}
                if csv_output:
                    return (domain, None, str(exc))
                return f"{_ERROR_PREFIX}{domain}: {exc}"

    # Gather all results concurrently, then output in input-file order.
    # This prevents interleaved output from concurrent coroutines.
    total = len(domain_list)
    completed = 0

    async def _tracked(domain: str) -> object:
        nonlocal completed
        result = await _process_one(domain)
        completed += 1
        if not json_output and not markdown and not csv_output:
            console.print(f"  [{completed}/{total}] {domain}", style="dim", highlight=False)
        return result

    tasks = [_tracked(d) for d in domain_list]
    results = await asyncio.gather(*tasks)

    if json_output:
        json_results: list[dict[str, Any]] = [r for r in results if r is not None]  # type: ignore[misc]
        typer.echo(json_mod.dumps(json_results, indent=2))
    elif csv_output:
        from recon_tool.formatter import format_batch_csv

        csv_rows: list[tuple[str, _TenantInfo | None, str | None]] = []
        for r in results:
            if isinstance(r, tuple) and len(r) == 3:
                csv_rows.append(r)  # type: ignore[arg-type]
        typer.echo(format_batch_csv(csv_rows), nl=False)
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
                render_error(r[len(_ERROR_PREFIX) :])
            else:
                console.print(r)
                console.print()


def run() -> None:
    """Entry point — invokes the Typer app.

    The callback handles shorthand domain syntax (e.g., `recon contoso.com`)
    via invoke_without_command routing. No preprocessing needed.
    """
    app()


if __name__ == "__main__":
    run()
