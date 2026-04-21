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
_SUBCOMMANDS = frozenset({"doctor", "batch", "lookup", "mcp", "cache", "delta", "fingerprints", "signals"})

# Maximum number of domains in a batch file to prevent OOM from huge files.
_MAX_BATCH_DOMAINS = 10000


def _fmt_exc(exc: BaseException) -> str:
    """Render an exception for user display, falling back to the type name.

    httpx.ReadTimeout and similar raise with an empty message, which used
    to render as ``FAIL  crt.sh — `` with nothing after the em-dash.
    """
    return str(exc) or type(exc).__name__


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
                return super().resolve_command(ctx, ["lookup", *args])
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
    """
    if ctx.invoked_subcommand is None:
        _print_welcome_banner()
        raise typer.Exit()


def _print_welcome_banner() -> None:
    """Print the curated onboarding banner shown when ``recon`` is run
    with no arguments. Replaces the raw Typer help dump that was
    shown prior to v0.9.3.

    Kept tight — fits on ~15 lines — with a one-line value prop, the
    recommended first command, progressive disclosure, three real
    examples, and a doctor hint. No emojis, no hype, no wall of
    flags. Users who want the full flag list can run
    ``recon lookup --help`` or ``recon --help <subcommand>``.
    """
    from recon_tool import __version__

    console = get_console()
    # Subtle cyan for the header and section labels — matches the
    # panel redesign tone. No red, no yellow, no alarmism.
    console.print(f"[bold cyan]recon {__version__}[/bold cyan] — Passive domain intelligence")
    console.print()
    console.print(
        "Tell me what technology stack an organization is running — from public DNS\n"
        "and identity endpoints only. Zero credentials. Zero scanning."
    )
    console.print()
    console.print("[bold cyan]Usage[/bold cyan]")
    console.print("  recon <domain>                    → clean summary (recommended)")
    console.print("  recon <domain> --verbose          → + posture analysis")
    console.print("  recon <domain> --full             → everything")
    console.print("  recon <domain> --explain          → full reasoning and evidence")
    console.print("  recon batch domains.txt           → process multiple domains")
    console.print("  recon doctor                      → check connectivity")
    console.print("  recon mcp                         → start the MCP server")
    console.print()
    console.print("[bold cyan]Common examples[/bold cyan]")
    console.print("  recon contoso.com")
    console.print("  recon northwindtraders.com --verbose")
    console.print("  recon fabrikam.com --full --json")
    console.print()
    console.print('[dim]Run "recon doctor" first if you see degraded sources or partial results.[/dim]')


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
        120.0,
        "--timeout",
        "-t",
        help="Max seconds for the full resolve pipeline (default: 120)",
    ),
    posture: bool = typer.Option(False, "--posture", "-p", help="Show posture observations"),
    compare: str | None = typer.Option(None, "--compare", help="Compare against previous JSON export"),
    chain: bool = typer.Option(False, "--chain", help="Recursively follow related domains"),
    depth: int = typer.Option(1, "--depth", help="Chain depth (1-3, requires --chain)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass disk cache entirely"),
    cache_ttl: int = typer.Option(86400, "--cache-ttl", help="Cache TTL in seconds (default: 86400)"),
    exposure: bool = typer.Option(False, "--exposure", help="Show exposure assessment"),
    gaps: bool = typer.Option(False, "--gaps", help="Show hardening gap analysis"),
    explain: bool = typer.Option(False, "--explain", help="Show why each insight and signal was produced"),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Apply a profile lens to posture observations (e.g. fintech, healthcare, high-value-target)",
    ),
    confidence_mode: str = typer.Option(
        "hedged",
        "--confidence-mode",
        help=("Language style: 'hedged' (default) or 'strict' (drops hedging qualifiers on dense-evidence targets)"),
    ),
    fusion: bool = typer.Option(
        False,
        "--fusion",
        help="[EXPERIMENTAL] Compute Bayesian per-slug posteriors from evidence",
    ),
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
            show_explain=explain,
            profile_name=profile,
            confidence_mode=confidence_mode,
            fusion=fusion,
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
    mcp: bool = typer.Option(False, "--mcp", help="Validate MCP server setup and emit copy-pasteable client config"),
) -> None:
    """
    Check connectivity to all data sources.
    """
    if fix:
        _doctor_fix()
        return
    if mcp:
        _doctor_mcp()
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


def _doctor_mcp() -> None:
    """Validate MCP server setup and emit copy-pasteable client config."""
    import shutil
    import sys

    console = get_console()
    console.print()

    checks: list[tuple[str, bool, str]] = []

    # 1. MCP package importable
    import importlib

    try:
        importlib.import_module("mcp")
        importlib.import_module("mcp.server.fastmcp")
        checks.append(("MCP package", True, "mcp>=1.0 installed"))
    except ImportError as exc:
        checks.append(("MCP package", False, f"not installed: {exc}"))
        checks.append(("Install hint", False, "pip install recon-tool[mcp]"))
        _render_mcp_checks(checks)
        return

    # 2. Server module imports cleanly
    try:
        from recon_tool.server import mcp as server_mcp

        checks.append(("Server module", True, "loaded"))
    except Exception as exc:
        checks.append(("Server module", False, f"import failed: {exc}"))
        _render_mcp_checks(checks)
        return

    # 3. FastMCP has instructions
    instructions = getattr(server_mcp, "instructions", None)
    if instructions:
        checks.append(("Server Instructions", True, f"{len(instructions)} chars"))
    else:
        checks.append(("Server Instructions", False, "missing — agents may misuse tools"))

    # 4. Enumerate tools (via the internal tool manager)
    try:
        tool_mgr = server_mcp._tool_manager  # pyright: ignore[reportPrivateUsage]
        tools = list(tool_mgr.list_tools())
        if tools:
            checks.append(("Tools enumerated", True, f"{len(tools)} tools registered"))
        else:
            checks.append(("Tools enumerated", False, "no tools registered"))
    except Exception as exc:
        checks.append(("Tools enumerated", False, f"{exc}"))

    # 5. recon executable on PATH (important for GUI clients)
    recon_path = shutil.which("recon")
    if recon_path:
        checks.append(("recon on PATH", True, recon_path))
    else:
        checks.append(("recon on PATH", False, "not found — GUI clients will fail"))

    _render_mcp_checks(checks)

    # Emit copy-pasteable config
    cmd = recon_path if recon_path else "recon"
    console.print()
    console.print("  [bold]Copy-paste config for your AI client[/bold]")
    console.print()
    console.print("  [dim]# Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json[/dim]")
    console.print("  [dim]# Cursor: ~/.cursor/mcp.json or <project>/.cursor/mcp.json[/dim]")
    console.print("  [dim]# VS Code + Copilot: <project>/.vscode/mcp.json[/dim]")
    console.print("  [dim]# Windsurf: ~/.codeium/windsurf/mcp_config.json[/dim]")
    console.print()
    snippet = (
        "  {\n"
        '    "mcpServers": {\n'
        '      "recon": {\n'
        f'        "command": "{cmd}",\n'
        '        "args": ["mcp"],\n'
        '        "autoApprove": ["lookup_tenant", "analyze_posture",\n'
        '                        "assess_exposure", "find_hardening_gaps"]\n'
        "      }\n"
        "    }\n"
        "  }"
    )
    console.print(snippet)
    console.print()
    if not recon_path:
        console.print(
            "  [yellow]Tip:[/yellow] GUI clients (Claude Desktop, Windsurf) often don't\n"
            "  inherit your shell PATH. If the client can't find `recon`, replace\n"
            "  the command above with the absolute path printed by `which recon`\n"
            f"  (or `python -m recon_tool.server` via `{sys.executable}`)."
        )
        console.print()


def _render_mcp_checks(checks: list[tuple[str, bool, str]]) -> None:
    """Render MCP check results with ok/FAIL labels."""
    console = get_console()
    for name, ok, detail in checks:
        mark = "ok" if ok else "FAIL"
        style = "green" if ok else "red"
        console.print(f"  [{style}]{mark:>4}[/{style}]  {name} — {detail}")


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
    """Start the MCP server (stdio transport). Requires: pip install recon-tool[mcp]"""
    try:
        from recon_tool.server import main as server_main
    except ImportError as exc:
        get_console().print(
            "[red]MCP dependencies not installed.[/red]\n  Install with: [bold]pip install recon-tool\\[mcp][/bold]"
        )
        raise SystemExit(1) from exc

    server_main()


# ── Cache CLI ─────────────────────────────────────────────────────────

cache_app = typer.Typer(help="Manage the CT subdomain cache and TenantInfo result cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("show")
def cache_show(
    domain: str = typer.Argument(None, help="Domain to inspect (omit to list all)"),
) -> None:
    """Show CT cache state for a domain, or list all cached domains.

    Only surfaces the CT subdomain cache. The TenantInfo result cache
    under ``~/.recon/cache/`` is managed opaquely.
    """
    from recon_tool.ct_cache import ct_cache_list, ct_cache_show

    console = get_console()

    if domain:
        info = ct_cache_show(domain)
        if info is None:
            console.print(f"  No CT cache entry for [bold]{domain}[/bold]")
            return
        age_str = "today" if info.age_days == 0 else f"{info.age_days} day{'s' if info.age_days != 1 else ''} old"
        console.print()
        console.print(f"  [bold]{info.domain}[/bold]")
        console.print(f"    Provider:   {info.provider_used}")
        console.print(f"    Subdomains: {info.subdomain_count}")
        console.print(f"    Cached:     {info.cached_at}")
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
            console.print(f"    {e.domain:<30s}  {e.subdomain_count:>4d} subs  {age_str:>5s}  {e.provider_used}")
        console.print()


@cache_app.command("clear")
def cache_clear(
    domain: str = typer.Argument(None, help="Domain to clear (omit with --all for everything)"),
    all_domains: bool = typer.Option(False, "--all", help="Clear all cached data"),
) -> None:
    """Clear both CT subdomain cache and TenantInfo result cache.

    Prior to v1.0.3 this only cleared the CT cache, which left stale
    TenantInfo results silently served from ``~/.recon/cache/`` even
    after a ``recon cache clear``.
    """
    from recon_tool.cache import cache_clear as result_cache_clear
    from recon_tool.cache import cache_clear_all as result_cache_clear_all
    from recon_tool.ct_cache import ct_cache_clear, ct_cache_clear_all

    console = get_console()

    if all_domains:
        ct_count = ct_cache_clear_all()
        result_count = result_cache_clear_all()
        console.print(f"  Cleared {ct_count} CT cache entr{'ies' if ct_count != 1 else 'y'}.")
        console.print(f"  Cleared {result_count} result cache entr{'ies' if result_count != 1 else 'y'}.")
    elif domain:
        ct_removed = ct_cache_clear(domain)
        result_removed = result_cache_clear(domain)
        if ct_removed or result_removed:
            parts: list[str] = []
            if ct_removed:
                parts.append("CT cache")
            if result_removed:
                parts.append("result cache")
            console.print(f"  Cleared {' and '.join(parts)} for [bold]{domain}[/bold].")
        else:
            console.print(f"  No cache entry for [bold]{domain}[/bold].")
    else:
        console.print("  Specify a domain or use --all.")
        raise typer.Exit(code=2)


# ── Fingerprints CLI ──────────────────────────────────────────────────

fingerprints_app = typer.Typer(help="Inspect the built-in fingerprint catalog.")
app.add_typer(fingerprints_app, name="fingerprints")


@fingerprints_app.command("list")
def fingerprints_list(
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter by category (substring, case-insensitive)"
    ),
    detection_type: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by detection type (txt, mx, spf, cname, srv, caa, ns, subdomain_txt, dkim)",
    ),
    all_entries: bool = typer.Option(False, "--all", "-a", help="Print the full table even with no filters (227 rows)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """List built-in fingerprints.

    With no filters, shows a per-category summary — 227 fingerprints is
    too much to dump at a prompt. Use ``--category`` to scope to one
    file (e.g. ``-c ai``, ``-c security``) or ``--all`` to force the
    full table. For free-text lookups (slug / name / pattern), prefer
    ``recon fingerprints search <query>``.
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    had_filter = category is not None or detection_type is not None
    if category:
        needle = category.lower()

        # Word-prefix matching instead of raw substring — ``-c ai`` should
        # match "AI & Generative" but not "Email" (which contains the
        # substring ``ai``). Split the category into alpha-word tokens
        # and match against the start of each token. Falls back to a
        # full substring match for multi-word queries (``-c "data &"``).
        def _match(cat: str) -> bool:
            cat_lower = cat.lower()
            if " " in needle:
                return needle in cat_lower
            import re

            return any(word.startswith(needle) for word in re.findall(r"[a-z0-9]+", cat_lower))

        fps = tuple(fp for fp in fps if _match(fp.category))
    if detection_type:
        dtype = detection_type.lower()
        fps = tuple(fp for fp in fps if any(d.type.lower() == dtype for d in fp.detections))

    if json_output:
        payload = [
            {
                "slug": fp.slug,
                "name": fp.name,
                "category": fp.category,
                "confidence": fp.confidence,
                "detection_types": sorted({d.type for d in fp.detections}),
                "detection_count": len(fp.detections),
            }
            for fp in fps
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not fps:
        console.print("  No fingerprints match those filters.")
        return

    # Compact summary when the user asked for the full catalog — 227
    # rows of table is not a useful answer to "what's in here". A
    # category breakdown with counts plus a filter hint is.
    if not had_filter and not all_entries:
        from collections import Counter

        by_cat = Counter(fp.category for fp in fps)
        console.print()
        console.print(f"  [bold]{len(fps)} fingerprints across {len(by_cat)} categories[/bold]")
        console.print()
        width = max(len(cat) for cat in by_cat)
        for cat, n in sorted(by_cat.items(), key=lambda x: (-x[1], x[0])):
            console.print(f"    {cat:<{width}s}  {n:>4d}")
        console.print()
        console.print(
            "  [dim]Next:[/dim]  recon fingerprints list --category <name>     "
            "recon fingerprints search <query>     recon fingerprints show <slug>"
        )
        console.print()
        return

    console.print()
    console.print(f"  [bold]{len(fps)} fingerprint{'s' if len(fps) != 1 else ''}[/bold]")
    console.print()
    slug_w = max(len(fp.slug) for fp in fps)
    cat_w = max(len(fp.category) for fp in fps)
    for fp in sorted(fps, key=lambda f: (f.category, f.slug)):
        types = ",".join(sorted({d.type for d in fp.detections}))
        console.print(f"    {fp.slug:<{slug_w}s}  {fp.category:<{cat_w}s}  {types:<18s}  {fp.name}")
    console.print()


@fingerprints_app.command("search")
def fingerprints_search(
    query: str = typer.Argument(..., help="Search term — matched against slug, name, category, and detection patterns"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search fingerprints by slug, name, category, or detection pattern.

    Case-insensitive substring across four fields simultaneously —
    the primary discovery command for "does this exist" / "what does
    recon know about X". Results are ranked: slug-prefix matches
    first, then slug/name substring matches, then pattern matches.

    Examples::

        recon fingerprints search okta          # slug + name hits
        recon fingerprints search "verification" # matches all *-verification= TXT tokens
        recon fingerprints search pardot         # what slug does Pardot live under
    """
    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    needle = query.lower().strip()
    if not needle:
        from recon_tool.formatter import render_error

        render_error("Empty search query.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Rank each fingerprint by how strong the match is. Slug-prefix is
    # the strongest signal ("they know exactly what they're looking
    # for"); a hit only in a detection pattern is weakest. We don't use
    # fuzzy matching — substring is enough for the 227-entry catalog
    # and doesn't pull in a dependency.
    ranked: list[tuple[int, Any]] = []
    for fp in fps:
        rank: int | None = None
        if fp.slug.lower().startswith(needle):
            rank = 0
        elif needle in fp.slug.lower():
            rank = 1
        elif needle in fp.name.lower():
            rank = 2
        elif needle in fp.category.lower():
            rank = 3
        else:
            for d in fp.detections:
                if needle in d.pattern.lower() or needle in d.description.lower():
                    rank = 4
                    break
        if rank is not None:
            ranked.append((rank, fp))

    ranked.sort(key=lambda x: (x[0], x[1].slug))
    matches = [fp for _, fp in ranked]

    if json_output:
        payload = [
            {
                "slug": fp.slug,
                "name": fp.name,
                "category": fp.category,
                "confidence": fp.confidence,
                "detection_types": sorted({d.type for d in fp.detections}),
                "detection_count": len(fp.detections),
            }
            for fp in matches
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not matches:
        console.print(f"  No fingerprints match {query!r}.")
        console.print("  [dim]Try a shorter or differently-spelled query, or browse by category:[/dim]")
        console.print("  [dim]  recon fingerprints list[/dim]")
        return

    console.print()
    console.print(f"  [bold]{len(matches)} match{'es' if len(matches) != 1 else ''} for {query!r}[/bold]")
    console.print()
    slug_w = max(len(fp.slug) for fp in matches)
    cat_w = max(len(fp.category) for fp in matches)
    for fp in matches:
        types = ",".join(sorted({d.type for d in fp.detections}))
        console.print(f"    {fp.slug:<{slug_w}s}  {fp.category:<{cat_w}s}  {types:<18s}  {fp.name}")
    console.print()
    console.print("  [dim]Next:[/dim]  recon fingerprints show <slug>")
    console.print()


@fingerprints_app.command("show")
def fingerprints_show(
    slug: str = typer.Argument(..., help="Slug to inspect (e.g. `cloudflare`, `exchange-onprem`)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Show the full definition of a single fingerprint.

    Some slugs in recon output are *synthetic* — they're emitted by the
    source layer rather than loaded from YAML (e.g. ``exchange-onprem``
    from the OWA/autodiscover probe, ``self-hosted-mail`` from the MX
    fallback). Those are documented here too so users who see a slug
    in their output can always find its provenance.
    """
    # Synthetic slugs aren't in fingerprints.yaml — they're emitted
    # by source-layer probes. Document provenance so users aren't left
    # grepping the code.
    _SYNTHETIC_SLUGS: dict[str, tuple[str, str]] = {
        "exchange-onprem": (
            "Exchange Server (on-prem / hybrid)",
            "Emitted by recon_tool.sources.dns._detect_exchange_onprem when "
            "owa./outlook./exchange./mail-ex./autodiscover. subdomains resolve "
            "(wildcard-guarded). Indicates self-hosted or hybrid Exchange — "
            "not Exchange Online.",
        ),
        "self-hosted-mail": (
            "Self-hosted mail",
            "Emitted by recon_tool.sources.dns._detect_mx when MX records "
            "exist and no known cloud-provider or gateway fingerprint matched. "
            "The raw_value field carries the actual MX hosts so the user can "
            "see the underlying infrastructure.",
        ),
    }

    from recon_tool.fingerprints import load_fingerprints

    fps = load_fingerprints()
    match = next((fp for fp in fps if fp.slug == slug), None)
    if match is None and slug in _SYNTHETIC_SLUGS:
        name, note = _SYNTHETIC_SLUGS[slug]
        if json_output:
            typer.echo(json.dumps({"slug": slug, "name": name, "synthetic": True, "note": note}, indent=2))
            return
        console = get_console()
        console.print()
        console.print(f"  [bold]{name}[/bold]  ({slug})")
        console.print("    [dim]synthetic slug — emitted by source probe, not in fingerprints.yaml[/dim]")
        console.print()
        console.print(f"  {note}")
        console.print()
        return
    if match is None:
        from recon_tool.formatter import render_error

        candidates = [fp.slug for fp in fps if slug.lower() in fp.slug.lower()][:5]
        render_error(f"No fingerprint with slug {slug!r}.")
        if candidates:
            get_console().print(f"  Did you mean: {', '.join(candidates)}?")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if json_output:
        payload = {
            "slug": match.slug,
            "name": match.name,
            "category": match.category,
            "confidence": match.confidence,
            "m365": match.m365,
            "provider_group": match.provider_group,
            "display_group": match.display_group,
            "match_mode": match.match_mode,
            "detections": [
                {
                    "type": d.type,
                    "pattern": d.pattern,
                    "description": d.description,
                    "reference": d.reference,
                    "weight": d.weight,
                }
                for d in match.detections
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    console.print()
    console.print(f"  [bold]{match.name}[/bold]  ({match.slug})")
    console.print(f"    Category:    {match.category}")
    console.print(f"    Confidence:  {match.confidence}")
    if match.m365:
        console.print("    M365 tenant: yes")
    if match.provider_group:
        console.print(f"    Provider group: {match.provider_group}")
    if match.match_mode != "any":
        console.print(f"    Match mode:  {match.match_mode} (all rules must match)")
    console.print()
    console.print(f"  [bold]Detection rules ({len(match.detections)})[/bold]")
    for i, d in enumerate(match.detections, 1):
        console.print(f"    {i}. [{d.type}] {d.pattern}")
        if d.description:
            console.print(f"         {d.description}")
        if d.reference:
            console.print(f"         ref: {d.reference}")
    console.print()


@fingerprints_app.command("new")
def fingerprints_new(
    slug: str = typer.Argument(..., help="Unique slug for the new fingerprint (lowercase, hyphen-separated)"),
    name: str = typer.Option(..., "--name", "-n", help="Human-readable service name (e.g. 'Acme Security')"),
    category: str = typer.Option(
        "Misc",
        "--category",
        "-c",
        help="Category — must match an existing one (use `fingerprints list` to see options)",
    ),
    detection_type: str = typer.Option(
        "txt",
        "--type",
        "-t",
        help="Detection type: txt, spf, mx, cname, srv, caa, ns, subdomain_txt, dmarc_rua",
    ),
    pattern: str = typer.Option(..., "--pattern", "-p", help="Regex pattern to match"),
    description: str = typer.Option("", "--description", help="One-line description of what this record means"),
    reference: str = typer.Option("", "--reference", help="URL to the vendor's verification docs"),
    confidence: str = typer.Option("high", "--confidence", help="high, medium, or low"),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write YAML to this file (default: print to stdout)"
    ),
) -> None:
    """Scaffold a new fingerprint entry, run checks, print YAML.

    Contributor onramp. Runs three guards before emitting:
    1. Slug uniqueness against the built-in catalog.
    2. Schema validation (same one the loader uses at runtime).
    3. Specificity gate — rejects regexes matching >1% of the
       synthetic adversarial corpus.

    If all three pass, prints the entry as YAML you can paste into the
    appropriate ``data/fingerprints/<category>.yaml``. Use ``--output``
    to write it to a file for review.
    """
    from recon_tool.fingerprints import _validate_fingerprint, load_fingerprints  # pyright: ignore[reportPrivateUsage]
    from recon_tool.formatter import render_error
    from recon_tool.specificity import evaluate_pattern

    console = get_console()

    # 1. Slug uniqueness
    existing = load_fingerprints()
    if any(fp.slug == slug for fp in existing):
        render_error(
            f"Slug {slug!r} already exists in the built-in catalog. "
            f"Use `recon fingerprints show {slug}` to inspect the existing entry."
        )
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # 2. Specificity
    verdict = evaluate_pattern(pattern, detection_type)
    if verdict.threshold_exceeded:
        render_error(
            f"Pattern too broad — matched {verdict.matches}/{verdict.corpus_size} "
            f"({verdict.match_rate:.1%}) of the synthetic adversarial corpus. "
            f"Tighten the regex (anchor to ^, add vendor-specific tokens, use word "
            "boundaries) before submitting."
        )
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # 3. Schema — build the entry dict and run the runtime validator
    entry: dict[str, object] = {
        "name": name,
        "slug": slug,
        "category": category,
        "confidence": confidence,
        "detections": [
            {
                "type": detection_type,
                "pattern": pattern,
                **({"description": description} if description else {}),
                **({"reference": reference} if reference else {}),
            }
        ],
    }
    validated = _validate_fingerprint(entry, "<wizard>")  # pyright: ignore[reportPrivateUsage]
    if validated is None:
        render_error("Schema validation failed — see warnings above.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # Emit YAML
    import yaml as _yaml

    snippet = _yaml.safe_dump(
        {"fingerprints": [entry]},
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=120,
    )

    if output:
        from pathlib import Path as _Path

        _Path(output).write_text(snippet, encoding="utf-8")
        console.print(f"  Wrote {output}")
        console.print(
            "  [dim]Next:[/dim]  merge into the matching data/fingerprints/<category>.yaml, "
            "then run [bold]recon fingerprints check[/bold]"
        )
    else:
        console.print()
        console.print("  [green]OK[/green]  Slug, schema, and specificity all pass.")
        console.print()
        console.print("  [dim]Paste into data/fingerprints/<category>.yaml:[/dim]")
        console.print()
        for line in snippet.rstrip().splitlines():
            console.print(f"    {line}")
        console.print()


@fingerprints_app.command("test")
def fingerprints_test(
    slug: str = typer.Argument(..., help="Slug to test against the public validation corpus"),
    corpus: str | None = typer.Option(
        None,
        "--corpus",
        help=(
            "Path to a newline-delimited file of domains to test against. "
            "Defaults to the bundled public corpus at tests/fixtures/corpus-public.txt."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Run one fingerprint against a domain corpus and report which match.

    Contributor utility: after editing a fingerprint (or before PRing a
    new one), run ``recon fingerprints test <slug>`` to see which
    domains in the corpus it matches. Helps answer "is my regex too
    loose (matches noise) or too tight (misses known customers)"
    without hand-resolving DNS.

    The bundled public corpus contains well-known apex domains chosen
    to give high-confidence fingerprints a reasonable chance of firing.
    Contributors can override with ``--corpus path/to/file``.
    """
    import asyncio
    from pathlib import Path as _Path

    from recon_tool.fingerprints import load_fingerprints
    from recon_tool.resolver import resolve_tenant

    fps = load_fingerprints()
    if not any(fp.slug == slug for fp in fps):
        from recon_tool.formatter import render_error

        render_error(f"No fingerprint with slug {slug!r} in the built-in catalog.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if corpus is None:
        default = _Path(__file__).parent.parent / "tests" / "fixtures" / "corpus-public.txt"
        if not default.exists():
            from recon_tool.formatter import render_error

            render_error(f"No corpus specified and bundled corpus not found at {default}. Pass --corpus path/to/file.")
            raise typer.Exit(code=EXIT_VALIDATION) from None
        corpus_path = default
    else:
        corpus_path = _Path(corpus)
        if not corpus_path.exists():
            from recon_tool.formatter import render_error

            render_error(f"Corpus file not found: {corpus_path}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    domains = [
        line.strip()
        for line in corpus_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    async def _resolve_all() -> list[tuple[str, bool, str]]:
        out: list[tuple[str, bool, str]] = []
        for domain in domains:
            try:
                info, _ = await resolve_tenant(domain, timeout=60.0)
                matched = slug in info.slugs
                detail = ""
                if matched:
                    detail = ", ".join(f"{e.source_type}:{e.raw_value[:40]}" for e in info.evidence if e.slug == slug)[
                        :120
                    ]
                out.append((domain, matched, detail))
            except Exception as exc:
                out.append((domain, False, f"error: {_fmt_exc(exc)}"))
        return out

    console = get_console()
    console.print()
    console.print(f"  [bold]Testing {slug!r} against {len(domains)} domain{'s' if len(domains) != 1 else ''}[/bold]")
    console.print()
    with console.status(f"Resolving {len(domains)} domains..."):
        results = asyncio.run(_resolve_all())

    if json_output:
        payload = [{"domain": d, "matched": m, "detail": detail} for d, m, detail in results]
        typer.echo(json.dumps(payload, indent=2))
        return

    hits = [(d, detail) for d, m, detail in results if m]
    misses = [d for d, m, _ in results if not m]
    for d, detail in hits:
        console.print(f"    [green]MATCH[/green]  {d}    {detail}")
    console.print()
    console.print(f"  [bold]{len(hits)} of {len(domains)} matched[/bold]  ({len(misses)} did not)")
    if hits:
        console.print(f"  [dim]Next:[/dim]  recon fingerprints show {slug}")
    console.print()


@fingerprints_app.command("check")
def fingerprints_check(
    path: str | None = typer.Argument(
        None,
        help="Path to a fingerprints YAML file or directory (default: the built-in data).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print failures and the summary"),
) -> None:
    """Validate fingerprint YAML files and flag duplicate slugs.

    Contributor utility: run this before opening a PR to confirm your new
    fingerprint validates against the same schema recon uses at runtime
    (regex safety, required fields, allowed detection types, weight
    range, match_mode) and doesn't collide with an existing slug.

    Without an argument, validates the built-in catalog at
    ``recon_tool/data/fingerprints.yaml`` (or ``recon_tool/data/fingerprints/``
    once the split lands). Pass a path to validate a candidate file
    before committing it.
    """
    import subprocess
    from pathlib import Path as _Path

    if path is None:
        # Prefer the directory layout if it exists (v1.1+); fall back to
        # the monolith while both coexist.
        base = _Path(__file__).parent / "data"
        split_dir = base / "fingerprints"
        target = split_dir if split_dir.is_dir() else base / "fingerprints.yaml"
    else:
        target = _Path(path)

    if not target.exists():
        from recon_tool.formatter import render_error

        render_error(f"Path not found: {target}")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    script = _Path(__file__).parent.parent / "scripts" / "validate_fingerprint.py"
    if not script.exists():
        from recon_tool.formatter import render_error

        render_error(f"Validator script missing: {script}")
        raise typer.Exit(code=EXIT_INTERNAL) from None

    cmd = [sys.executable, str(script), str(target)]
    if quiet:
        cmd.append("--quiet")
    result = subprocess.run(cmd, check=False)  # noqa: S603
    raise typer.Exit(code=result.returncode)


# ── Signals CLI ───────────────────────────────────────────────────────

signals_app = typer.Typer(help="Inspect the built-in signal catalog.")
app.add_typer(signals_app, name="signals")


@signals_app.command("list")
def signals_list(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category (substring)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """List every built-in signal, grouped by category."""
    from recon_tool.signals import load_signals

    sigs = load_signals()
    if category:
        needle = category.lower()
        import re

        def _match_cat(cat: str) -> bool:
            cat_lower = cat.lower()
            if " " in needle:
                return needle in cat_lower
            return any(word.startswith(needle) for word in re.findall(r"[a-z0-9]+", cat_lower))

        sigs = tuple(s for s in sigs if _match_cat(s.category))

    if json_output:
        payload = [
            {
                "name": s.name,
                "category": s.category,
                "confidence": s.confidence,
                "candidate_count": len(s.candidates),
                "min_matches": s.min_matches,
                "description": s.description,
            }
            for s in sigs
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not sigs:
        console.print("  No signals match those filters.")
        return
    console.print()
    console.print(f"  [bold]{len(sigs)} signal{'s' if len(sigs) != 1 else ''}[/bold]")
    console.print()
    name_w = max(len(s.name) for s in sigs)
    for s in sorted(sigs, key=lambda x: (x.category, x.name)):
        console.print(f"    {s.name:<{name_w}s}  {s.category:<20s}  {s.confidence}")
    console.print()


@signals_app.command("search")
def signals_search(
    query: str = typer.Argument(
        ..., help="Search term — matched against signal name, category, description, and candidate slugs"
    ),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Search signals by name, category, description, or candidate slug.

    Case-insensitive substring. Useful for "which signals look at my
    new slug?" (``search <slug>``) and "what signals fire on email
    posture?" (``search email``).
    """
    from recon_tool.signals import load_signals

    sigs = load_signals()
    needle = query.lower().strip()
    if not needle:
        from recon_tool.formatter import render_error

        render_error("Empty search query.")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    ranked: list[tuple[int, Any]] = []
    for s in sigs:
        rank: int | None = None
        if needle in s.name.lower():
            rank = 0
        elif needle in s.category.lower():
            rank = 1
        elif any(needle in c.lower() for c in s.candidates):
            rank = 2
        elif needle in s.description.lower():
            rank = 3
        if rank is not None:
            ranked.append((rank, s))

    ranked.sort(key=lambda x: (x[0], x[1].name))
    matches = [s for _, s in ranked]

    if json_output:
        payload = [
            {
                "name": s.name,
                "category": s.category,
                "confidence": s.confidence,
                "candidate_count": len(s.candidates),
                "description": s.description,
            }
            for s in matches
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    if not matches:
        console.print(f"  No signals match {query!r}.")
        return
    console.print()
    console.print(f"  [bold]{len(matches)} match{'es' if len(matches) != 1 else ''} for {query!r}[/bold]")
    console.print()
    name_w = max(len(s.name) for s in matches)
    for s in matches:
        console.print(f"    {s.name:<{name_w}s}  {s.category:<20s}  {s.confidence}")
    console.print()


@signals_app.command("show")
def signals_show(
    name: str = typer.Argument(..., help="Signal name (quote if it contains spaces)"),
    json_output: bool = typer.Option(False, "--json", help="Structured JSON output"),
) -> None:
    """Show the full definition of a single signal."""
    from recon_tool.signals import load_signals

    sigs = load_signals()
    match = next((s for s in sigs if s.name == name), None)
    if match is None:
        from recon_tool.formatter import render_error

        needle = name.lower()
        candidates = [s.name for s in sigs if needle in s.name.lower()][:5]
        render_error(f"No signal named {name!r}.")
        if candidates:
            get_console().print(f"  Did you mean: {', '.join(repr(c) for c in candidates)}?")
        raise typer.Exit(code=EXIT_VALIDATION) from None

    if json_output:
        payload = {
            "name": match.name,
            "category": match.category,
            "confidence": match.confidence,
            "description": match.description,
            "candidates": list(match.candidates),
            "min_matches": match.min_matches,
            "metadata_conditions": [
                {"field": m.field, "operator": m.operator, "value": m.value} for m in match.metadata
            ],
            "contradicts": list(match.contradicts),
            "requires_signals": list(match.requires_signals),
            "expected_counterparts": list(match.expected_counterparts),
            "positive_when_absent": list(match.positive_when_absent),
            "explain": match.explain,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console = get_console()
    console.print()
    console.print(f"  [bold]{match.name}[/bold]")
    console.print(f"    Category:    {match.category}")
    console.print(f"    Confidence:  {match.confidence}")
    if match.description:
        console.print(f"    Description: {match.description}")
    if match.candidates:
        console.print()
        console.print(f"  [bold]Candidate slugs ({len(match.candidates)}, min_matches={match.min_matches})[/bold]")
        for c in match.candidates:
            console.print(f"    - {c}")
    if match.metadata:
        console.print()
        console.print("  [bold]Metadata conditions[/bold]")
        for m in match.metadata:
            console.print(f"    - {m.field} {m.operator} {m.value!r}")
    if match.contradicts:
        console.print()
        console.print("  [bold]Contradicts[/bold]")
        for c in match.contradicts:
            console.print(f"    - {c}")
    if match.requires_signals:
        console.print()
        console.print("  [bold]Requires other signals[/bold]")
        for r in match.requires_signals:
            console.print(f"    - {r}")
    if match.expected_counterparts:
        console.print()
        console.print("  [bold]Expected counterparts (absence engine)[/bold]")
        for c in match.expected_counterparts:
            console.print(f"    - {c}")
    if match.positive_when_absent:
        console.print()
        console.print("  [bold]Positive-when-absent (hedged hardening observation)[/bold]")
        for c in match.positive_when_absent:
            console.print(f"    - {c}")
    if match.explain:
        console.print()
        console.print(f"  [bold]Explain[/bold] {match.explain}")
    console.print()


# ── Delta CLI ─────────────────────────────────────────────────────────


@app.command()
def delta(
    domain: str = typer.Argument(..., help="Domain to diff against cached snapshot"),
    json_output: bool = typer.Option(False, "--json", help="Output structured JSON"),
    timeout: float = typer.Option(120.0, "--timeout", help="Resolution timeout (seconds)"),
) -> None:
    """Compare the current lookup against the last cached TenantInfo.

    Surfaces what changed since the previous run — new services, removed
    services, auth/DMARC/confidence changes. Uses the main TenantInfo cache
    (~/.recon/cache/) automatically; no manual export file required.
    """
    from recon_tool.cache import cache_get, cache_put, tenant_info_to_dict
    from recon_tool.delta import compute_delta
    from recon_tool.formatter import format_delta_json, render_delta_panel
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    console = get_console()
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=EXIT_VALIDATION) from exc

    cached = cache_get(validated, ttl=30 * 86400)
    if cached is None:
        console.print(
            f"  No cached snapshot for [bold]{validated}[/bold].\n"
            f"  Run `recon {validated}` first — the next `recon delta` "
            f"call will compare against that baseline."
        )
        raise typer.Exit(code=EXIT_NO_DATA)

    previous_dict = tenant_info_to_dict(cached)

    async def _run() -> None:
        try:
            info, _results = await resolve_tenant(validated, timeout=timeout)
        except Exception as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=EXIT_INTERNAL) from exc

        diff = compute_delta(previous_dict, info)
        if json_output:
            typer.echo(format_delta_json(diff))
        else:
            console.print(render_delta_panel(diff))
        # Update cache with fresh snapshot so the next delta compares
        # against today's state, not the baseline from two runs ago.
        cache_put(validated, info)

    asyncio.run(_run())


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
            checks.append(("OIDC discovery", False, _fmt_exc(exc)))

        # Synthetic non-existent address — avoids probing a real account.
        try:
            resp = await client.get(
                "https://login.microsoftonline.com/GetUserRealm.srf",
                params={"login": "recon-connectivity-check@example.com", "json": "1"},
            )
            checks.append(("GetUserRealm", resp.status_code == 200, f"HTTP {resp.status_code}"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("GetUserRealm", False, _fmt_exc(exc)))

        try:
            resp = await client.post(
                "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
                content="<test/>",
                headers={"Content-Type": "text/xml"},
            )
            checks.append(("Autodiscover", True, f"HTTP {resp.status_code} (reachable)"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("Autodiscover", False, _fmt_exc(exc)))

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
        checks.append(("DNS resolution", False, _fmt_exc(exc)))

    # Check crt.sh connectivity (certificate transparency)
    try:
        resp = await httpx.AsyncClient(timeout=8.0).get("https://crt.sh/?q=%.example.com&output=json")
        checks.append(("crt.sh (cert transparency)", resp.status_code == 200, f"HTTP {resp.status_code}"))
    except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
        checks.append(("crt.sh (cert transparency)", False, _fmt_exc(exc)))

    try:
        from recon_tool.server import mcp  # noqa: F401  # pyright: ignore[reportUnusedImport]

        checks.append(("MCP server module", True, "loaded"))
    except Exception as exc:
        checks.append(("MCP server module", False, _fmt_exc(exc)))

    # Check fingerprint database loading
    try:
        from recon_tool.fingerprints import load_fingerprints

        fps = load_fingerprints()
        if fps:
            checks.append(("Fingerprint database", True, f"{len(fps)} fingerprints loaded"))
        else:
            checks.append(("Fingerprint database", False, "no fingerprints loaded — detection will not work"))
    except Exception as exc:
        checks.append(("Fingerprint database", False, _fmt_exc(exc)))

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
            checks.append(("Custom fingerprints", False, _fmt_exc(exc)))
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
        checks.append(("Signal database", False, _fmt_exc(exc)))

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
            checks.append(("Custom signals", False, _fmt_exc(exc)))
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


def _build_explanations(
    info: Any,
    results: list[Any],
) -> list[Any]:
    """Build ExplanationRecords for a TenantInfo using the explanation engine.

    Generates explanations for signals, insights, confidence, and observations.
    """
    from recon_tool.absence import evaluate_absence_signals, evaluate_positive_absence
    from recon_tool.explanation import (
        explain_confidence,
        explain_insights,
        explain_observations,
        explain_signals,
    )
    from recon_tool.merger import compute_evidence_confidence, compute_inference_confidence
    from recon_tool.models import ExplanationRecord, SignalContext
    from recon_tool.posture import analyze_posture, load_posture_rules
    from recon_tool.signals import evaluate_signals, load_signals

    explanations: list[ExplanationRecord] = []

    # Build signal context from info
    context = SignalContext(
        detected_slugs=frozenset(info.slugs),
        dmarc_policy=info.dmarc_policy,
        auth_type=info.auth_type,
    )
    signals = load_signals()
    signal_matches = evaluate_signals(context)

    # Third pass: absence signals + positive hardening observations (v0.9.3)
    absence_matches = evaluate_absence_signals(signal_matches, signals, frozenset(info.slugs))
    positive_matches = evaluate_positive_absence(signal_matches, signals, frozenset(info.slugs))
    all_signal_matches = signal_matches + absence_matches + positive_matches

    # Signal explanations
    signal_recs = explain_signals(
        all_signal_matches,
        signals,
        frozenset(info.slugs),
        {},
        info.evidence,
        info.detection_scores,
    )
    explanations.extend(signal_recs)

    # Insight explanations
    insight_recs = explain_insights(
        list(info.insights),
        frozenset(info.slugs),
        frozenset(info.services),
        info.evidence,
        info.detection_scores,
    )
    explanations.extend(insight_recs)

    # Confidence explanation
    if results:
        evidence_conf = compute_evidence_confidence(results)
        inference_conf = compute_inference_confidence(results)
        conf_rec = explain_confidence(results, evidence_conf, inference_conf, info.confidence)
        explanations.append(conf_rec)

    # Observation explanations
    observations = analyze_posture(info)
    posture_rules = load_posture_rules()
    obs_recs = explain_observations(observations, posture_rules, info.evidence, info.detection_scores)
    explanations.extend(obs_recs)

    return explanations


async def _lookup(
    domain: str,
    json_output: bool,
    markdown: bool,
    verbose: bool,
    show_services: bool,
    show_domains: bool,
    full: bool,
    show_sources: bool,
    timeout: float = 120.0,
    show_posture: bool = False,
    compare_file: str | None = None,
    chain_mode: bool = False,
    chain_depth: int = 1,
    no_cache: bool = False,
    cache_ttl: int = 86400,
    show_exposure: bool = False,
    show_gaps: bool = False,
    show_explain: bool = False,
    profile_name: str | None = None,
    confidence_mode: str = "hedged",
    fusion: bool = False,
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

    # ``--profile`` is a no-op unless posture output is shown. If the user
    # specified a profile, they want to see the profile-filtered posture
    # observations — turn on posture automatically rather than silently
    # dropping the flag.
    if profile_name and not show_posture:
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
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    # ── Compare mode ─────────────────────────────────────────────────
    if compare_file:
        from pathlib import Path

        from recon_tool.delta import compute_delta, load_previous
        from recon_tool.formatter import format_delta_json, render_delta_panel

        try:
            previous = load_previous(Path(compare_file))
        except (FileNotFoundError, ValueError) as exc:
            render_error(_fmt_exc(exc))
            raise typer.Exit(code=EXIT_VALIDATION) from None

        try:
            if not json_output and not markdown:
                import random

                msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
                with console.status(msg):
                    info, results = await resolve_tenant(validated, timeout=timeout)
            else:
                info, results = await resolve_tenant(validated, timeout=timeout)
        except ReconLookupError as exc:
            render_warning(domain, exc)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(_fmt_exc(exc))
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
            render_error(_fmt_exc(exc))
            raise typer.Exit(code=EXIT_INTERNAL) from None

        if json_output:
            chain_dict = json.loads(format_chain_json(report))
            if show_explain:
                from recon_tool.formatter import format_explanations_list

                for i, domain_entry in enumerate(chain_dict.get("domains", [])):
                    if i < len(report.results):
                        chain_info = report.results[i].info
                        explanations = _build_explanations(chain_info, [])
                        domain_entry["explanations"] = format_explanations_list(explanations)
                        if chain_info.merge_conflicts and chain_info.merge_conflicts.has_conflicts:
                            from recon_tool.models import serialize_conflicts

                            domain_entry["conflicts"] = serialize_conflicts(chain_info.merge_conflicts)
            typer.echo(json.dumps(chain_dict, indent=2))
        else:
            console.print(render_chain_panel(report))
            if show_explain:
                from recon_tool.formatter import render_explanations_panel

                for r in report.results:
                    explanations = _build_explanations(r.info, [])
                    if explanations:
                        console.print(render_explanations_panel(explanations))
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
        except ReconLookupError as exc:
            render_warning(domain, exc)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(_fmt_exc(exc))
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
        except ReconLookupError as exc:
            render_warning(domain, exc)
            raise typer.Exit(code=EXIT_NO_DATA) from None
        except Exception as exc:
            render_error(_fmt_exc(exc))
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

            # v0.11: apply Bayesian fusion when opted in. Computes per-slug
            # posteriors from the existing evidence chain — no network calls.
            if fusion:
                from dataclasses import replace

                from recon_tool.fusion import compute_slug_posteriors

                info = replace(info, slug_confidences=compute_slug_posteriors(info.evidence))

            # Write to cache after fresh lookup
            if not no_cache:
                from recon_tool.cache import cache_put

                cache_put(validated, info)

        if verbose:
            render_verbose_sources(results)

        # Compute posture observations if requested
        observations: tuple[Any, ...] = ()
        profile = None
        if profile_name:
            from recon_tool.profiles import load_profile

            profile = load_profile(profile_name)
            if profile is None:
                from recon_tool.profiles import list_profiles

                names = ", ".join(p.name for p in list_profiles())
                render_error(f"Unknown profile {profile_name!r}. Available profiles: {names or '(none)'}")
                raise typer.Exit(code=EXIT_VALIDATION) from None
        if show_posture:
            from recon_tool.posture import analyze_posture
            from recon_tool.profiles import apply_profile

            raw_observations = analyze_posture(info)
            observations = apply_profile(tuple(raw_observations), profile)

        if json_output:
            from recon_tool.formatter import format_posture_observations

            tenant_dict = format_tenant_dict(info)
            if show_posture:
                tenant_dict["posture"] = format_posture_observations(observations)
            if show_explain:
                from recon_tool.explanation import build_explanation_dag
                from recon_tool.formatter import format_explanations_list
                from recon_tool.models import serialize_conflicts

                explanations = _build_explanations(info, results)
                tenant_dict["explanations"] = format_explanations_list(explanations)
                # v0.9.3: structured provenance DAG for programmatic
                # consumers. Lives alongside the flat list — both are
                # emitted so existing tooling doesn't break.
                tenant_dict["explanation_dag"] = build_explanation_dag(explanations, info.evidence)
                if info.merge_conflicts and info.merge_conflicts.has_conflicts:
                    tenant_dict["conflicts"] = serialize_conflicts(info.merge_conflicts)
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
            if show_explain:
                from recon_tool.formatter import format_explanations_markdown

                explanations = _build_explanations(info, results)
                md += "\n" + format_explanations_markdown(explanations)
            typer.echo(md)
            return

        console.print(
            render_tenant_panel(
                info,
                show_services=show_services,
                show_domains=show_domains,
                verbose=verbose,
                explain=show_explain,
                confidence_mode=confidence_mode,
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

        # Explanations panel after posture
        if show_explain:
            from recon_tool.formatter import (
                render_explanations_panel,
                render_source_status_panel,
            )
            from recon_tool.models import SourceResult

            # U1 (v0.9.2): always render per-source status under --explain
            # so users can see which sources succeeded, which failed, and
            # why. Previously this was only available via --verbose.
            #
            # On cache hit, the original SourceResult list isn't available
            # (cache stores TenantInfo, not raw source results). Reconstruct
            # minimal SourceResults from info.sources (successes) and
            # info.degraded_sources (failures) so the panel still renders
            # something useful for cached lookups.
            status_results: list[SourceResult] = results
            if not status_results and info is not None:
                _m365_sources = {"oidc_discovery", "user_realm", "dns_records"}
                synthetic: list[SourceResult] = []
                for src_name in info.sources:
                    synthetic.append(
                        SourceResult(
                            source_name=src_name,
                            tenant_id=info.tenant_id if src_name == "oidc_discovery" else None,
                            display_name=info.display_name if src_name == "user_realm" else None,
                            auth_type=info.auth_type if src_name == "user_realm" else None,
                            m365_detected=bool(info.tenant_id) and src_name in _m365_sources,
                            dmarc_policy=info.dmarc_policy if src_name == "dns_records" else None,
                        )
                    )
                for deg in info.degraded_sources:
                    synthetic.append(
                        SourceResult(
                            source_name=deg,
                            error="unavailable during original lookup",
                        )
                    )
                status_results = synthetic

            status_panel = render_source_status_panel(status_results)
            if status_panel:
                console.print(status_panel)

            explanations = _build_explanations(info, results)
            if explanations:
                console.print(render_explanations_panel(explanations))

    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
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
    from recon_tool.models import TenantInfo as _TenantInfo
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

    # v0.9.3: batch-scope token clustering. Each successful resolution
    # stashes its TenantInfo here keyed by the *input* domain string,
    # so the post-processing pass can compute `shared_verification_tokens`
    # across every domain in the batch. Scoped to this batch run — never
    # persisted to disk cache, never shared between batch invocations.
    batch_infos: dict[str, _TenantInfo] = {}

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

                # v0.9.3: capture TenantInfo for post-batch token clustering.
                # Keyed by queried_domain so the post-processing pass can
                # correlate back to tenant dict entries using the same key
                # that format_tenant_dict emits.
                batch_infos[info.queried_domain] = info

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

        # v0.9.3: attach shared_verification_tokens to each entry when
        # at least two domains in the batch share the same token. Keyed
        # by queried_domain which is the canonical normalized form.
        if batch_infos:
            from recon_tool.clustering import compute_shared_tokens

            domain_tokens = {d: info.site_verification_tokens for d, info in batch_infos.items()}
            clusters = compute_shared_tokens(domain_tokens)
            if clusters:
                for entry in json_results:
                    key = entry.get("queried_domain")
                    if not isinstance(key, str):
                        continue
                    peers = clusters.get(key)
                    if peers:
                        entry["shared_verification_tokens"] = [{"token": e.token, "peer": e.peer} for e in peers]

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
