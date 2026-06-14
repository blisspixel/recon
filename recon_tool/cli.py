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
from pathlib import Path
from typing import Any, Literal, TextIO, TypeAlias

import click
import typer
from rich.markup import escape

from recon_tool.cli_cache import cache_app
from recon_tool.cli_fingerprints import fingerprints_app
from recon_tool.cli_mcp import mcp_app
from recon_tool.cli_shared import fmt_exc as _fmt_exc
from recon_tool.cli_shared import lookup_validate
from recon_tool.cli_signals import signals_app
from recon_tool.formatter import get_console, get_err_console
from recon_tool.validator import strip_control_chars

McpCheck: TypeAlias = tuple[str, bool, str]
DoctorStatus: TypeAlias = Literal["ok", "warn", "fail"]
DoctorCheck: TypeAlias = tuple[str, DoctorStatus, str]

__all__ = [
    "EXIT_ERROR",
    "EXIT_INTERNAL",
    "EXIT_NO_DATA",
    "EXIT_SUCCESS",
    "EXIT_VALIDATION",
    "app",
    "run",
]

# Structured exit codes for scripting live in one module so the CLI and the
# MCP server entry point share a single contract. Documented for consumers in
# docs/schema.md ("Exit codes"). Re-exported here for back-compat with callers
# that import them from recon_tool.cli.
from recon_tool.exit_codes import (  # noqa: E402
    EXIT_ERROR,
    EXIT_INTERNAL,
    EXIT_NO_DATA,
    EXIT_SUCCESS,
    EXIT_VALIDATION,
)

# Known subcommands — used by the callback to distinguish domains from commands.
# Must equal the registered command tree; `tests/test_subcommands.py` pins it,
# so a new command that is not added here fails CI rather than silently
# mis-routing a dotted first argument.
_SUBCOMMANDS = frozenset(
    {"doctor", "update", "batch", "lookup", "mcp", "cache", "delta", "discover", "fingerprints", "signals"}
)

# Batch-input safety bounds. Cap the per-line read (so a newline-free
# multi-GB "line" cannot be buffered whole), the cumulative bytes (so a stream
# of millions of blank/comment lines, which never increments the domain count,
# cannot loop unbounded), and the domain count itself (to prevent OOM).
_MAX_BATCH_DOMAINS = 10000
_MAX_BATCH_LINE_BYTES = 1024
_MAX_BATCH_FILE_BYTES = 10 * 1024 * 1024


class _BatchInputError(ValueError):
    """Batch input exceeded a safety bound (size or domain count)."""


def _read_batch_domains(stream: TextIO) -> list[str]:
    """Stream domain lines from a text stream under the batch safety bounds.

    Reads line by line so a huge input is never buffered whole, skips blank
    and ``#``-comment lines, and raises :class:`_BatchInputError` if the input
    exceeds the cumulative-size or domain-count cap. Shared by the file path
    and the stdin path (``recon batch -``).
    """
    domains: list[str] = []
    total_bytes = 0
    while True:
        line = stream.readline(_MAX_BATCH_LINE_BYTES)
        if not line:
            break
        total_bytes += len(line)
        if total_bytes > _MAX_BATCH_FILE_BYTES:
            msg = f"Batch input exceeds maximum size of {_MAX_BATCH_FILE_BYTES // (1024 * 1024)} MB"
            raise _BatchInputError(msg)
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            domains.append(stripped)
            if len(domains) > _MAX_BATCH_DOMAINS:
                msg = f"Batch input exceeds maximum of {_MAX_BATCH_DOMAINS} domains"
                raise _BatchInputError(msg)
    return domains


# Spinner messages. A lookup shuffles these and rotates through them while
# it waits, so the CLI feels alive without being gimmicky. They are grouped
# by what recon is actually doing (DNS, CT, identity endpoints, the
# inference layer, posture) plus a few that wink at the passive-only ethos;
# all stay honest about the method.
_STATUS_MESSAGES = (
    # DNS and records
    "Querying public DNS records...",
    "Following CNAME breadcrumbs...",
    "Reading the TXT record tea leaves...",
    "Asking the MX records who handles the mail...",
    "Untangling the SPF include chain...",
    "Reading DMARC policy, strictly as published...",
    # Certificate transparency
    "Sifting certificate transparency logs...",
    "Clustering SAN sets into communities...",
    "Watching for certificate issuance bursts...",
    # Identity endpoints
    "Checking Microsoft's public tenant registry...",
    "Asking Google Workspace, no credentials required...",
    "Knocking politely on the OIDC discovery endpoint...",
    # Fingerprinting / stack
    "Fingerprinting the SaaS stack...",
    "Matching slugs against the catalog...",
    "Assembling the tech stack mosaic...",
    "Tracing domain verification trails...",
    # The inference layer (a wink at the Bayesian core)
    "Updating priors, declining to overclaim...",
    "Propagating beliefs through the network...",
    "Widening the interval where evidence is thin...",
    "Letting absent evidence stay absent...",
    "Computing credible intervals, not false certainties...",
    # Posture and footprint
    "Scoring the email security posture...",
    "Mapping the organizational footprint...",
    "Extracting signal from the public noise...",
    # Passive-only ethos
    "No credentials were harmed in this lookup...",
    "Strictly passive; nobody on the other end noticed...",
    "Reading only what was left out in the open...",
    "Observing from a respectful distance...",
)

# How long each spinner message lingers before the next one rotates in.
_STATUS_ROTATE_SECONDS = 2.5


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
        # Route a domain-like first arg to ``lookup`` *before* normal
        # resolution, rather than catching a "no such command" error and
        # retrying. The catch-and-retry form depended on which Click raised
        # the error: Typer >=0.25 vendors its own Click, so the UsageError is
        # ``typer._click``'s, not the top-level ``click``'s, and an
        # ``except click.UsageError`` silently misses it (the regression that
        # broke ``recon <domain>`` on fresh installs). Rewriting up front has
        # no such dependency. A domain always contains a dot and no subcommand
        # does, so a dotted, non-flag arg that is not a known subcommand is a
        # domain.
        if args and "." in args[0] and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
            args = ["lookup", *args]
        return super().resolve_command(ctx, args)


app = typer.Typer(
    name="recon",
    help="Domain intelligence from the command line.",
    rich_markup_mode="rich",
    cls=_DomainGroup,
    # `-h` as a help alias everywhere (Click propagates help_option_names to
    # every subcommand context), matching the near-universal CLI convention.
    context_settings={"help_option_names": ["-h", "--help"]},
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from recon_tool import __version__

        get_console().print(f"recon [bold]{__version__}[/bold]")
        raise typer.Exit()


def _color_callback(value: bool | None) -> None:
    """Force (--color) or disable (--no-color) colored output."""
    if value is None:
        return
    from recon_tool.formatter import set_color_override

    set_color_override(value)


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
        "-V",
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
    color: bool | None = typer.Option(
        None,
        "--color/--no-color",
        callback=_color_callback,
        is_eager=True,
        help="Force or disable colored output (overrides NO_COLOR / TTY detection).",
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
    shown before.

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
    plain: bool = typer.Option(False, "--plain", help="Plain linear text (greppable, screen-reader-friendly)"),
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
        True,
        "--fusion/--no-fusion",
        help=(
            "Compute Bayesian per-slug posteriors and credible intervals from "
            "evidence (on by default from v2.0; --no-fusion to skip)"
        ),
    ),
    explain_dag: bool = typer.Option(
        False,
        "--explain-dag",
        help=(
            "Render the Bayesian evidence DAG as plain English (default) "
            "or DOT (with --explain-dag-format dot). Implies --fusion."
        ),
    ),
    explain_dag_format: str = typer.Option(
        "text",
        "--explain-dag-format",
        help=(
            "Output format for --explain-dag: 'text' (default), 'dot' "
            "(Graphviz), or 'mermaid' (renders inline in GitHub, "
            "Notion, and most AI chat clients)."
        ),
    ),
    include_unclassified: bool = typer.Option(
        False,
        "--include-unclassified",
        help=(
            "Include unclassified CNAME chains in --json output. Surfaces "
            "candidates for new fingerprints. Feeds the discovery loop in "
            "validation/ and the /recon-fingerprint-triage Claude skill."
        ),
    ),
    no_ct: bool = typer.Option(
        False,
        "--no-ct",
        help=(
            "Skip cert-transparency providers (crt.sh, CertSpotter). "
            "Discovery falls back to common-subdomain probes + apex CNAME "
            "walks. Use for high-volume validation runs where you want "
            "zero load on public CT services."
        ),
    ),
    direct_probes: bool = typer.Option(
        False,
        "--direct-probes",
        help=(
            "Opt in to direct HTTPS probes of target-controlled endpoints "
            "(the Google CSE discovery probe at cse.<domain>, and the BIMI VMC "
            "certificate fetch). Off by default: recon stays passive and the only "
            "request the queried domain's own servers see is the standard MTA-STS "
            "policy fetch. BIMI presence is detected from DNS either way."
        ),
    ),
    exact: bool = typer.Option(
        False,
        "--exact",
        help=(
            "Analyze the exact host given instead of reducing to the "
            "registrable apex. By default a pasted URL or sub-host "
            "(mail.acme.co.uk) is reduced to its apex (acme.co.uk), where "
            "recon's signal lives; --exact keeps the literal host for the "
            "narrow case of wanting DNS facts about that one sub-host."
        ),
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
            plain,
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
            explain_dag=explain_dag,
            explain_dag_format=explain_dag_format,
            include_unclassified=include_unclassified,
            skip_ct=no_ct,
            active_probes=direct_probes,
            exact=exact,
        )
    )


@app.command()
def batch(
    file: str = typer.Argument(help="File with one domain per line, or - to read domains from stdin"),
    json_output: bool = typer.Option(False, "--json", help="JSON array output"),
    markdown: bool = typer.Option(False, "--md", help="Markdown report per domain"),
    csv_output: bool = typer.Option(False, "--csv", help="CSV output"),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Max concurrent lookups (1-20)",
    ),
    include_unclassified: bool = typer.Option(
        False,
        "--include-unclassified",
        help=("Include unclassified CNAME chains in JSON output for the fingerprint-discovery loop. Off by default."),
    ),
    no_ct: bool = typer.Option(
        False,
        "--no-ct",
        help=(
            "Skip cert-transparency providers (crt.sh, CertSpotter) for every "
            "domain in the batch. For high-volume corpus runs."
        ),
    ),
    ndjson: bool = typer.Option(
        False,
        "--ndjson",
        help=(
            "Stream one JSON object per line, flushed as each domain completes. "
            "Recommended for large corpora — gives visible progress and lower memory "
            "use vs the default --json array. Mutually exclusive with --json/--md/--csv."
        ),
    ),
    include_ecosystem: bool = typer.Option(
        False,
        "--include-ecosystem",
        help=(
            "(v1.8+) Compute the cross-domain ecosystem hypergraph and attach it "
            "to JSON output as ``ecosystem_hyperedges``. Requires --json. "
            "Hyperedges describe shared infrastructure / fingerprint / BIMI / "
            "parent-vendor signatures across the batch — observable structure, "
            "not ownership."
        ),
    ),
    fusion: bool = typer.Option(
        True,
        "--fusion/--no-fusion",
        help=(
            "Compute Bayesian-network posteriors and credible intervals "
            "over high-level claims for every domain. On by default from v2.0; "
            "--no-fusion skips it. Adds the ``posterior_observations`` field to "
            "each domain's JSON. Pure post-processing, no extra network calls."
        ),
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help=(
            "Emit one aggregate-only cohort summary over the whole batch instead "
            "of per-domain records: observability-adjusted prevalence, posterior "
            "mass, and provider / cloud concentration. Stateless, ships no "
            "baselines, names no domain. Add --json for machine output. For "
            "caller-grouped analysis, see docs/aggregate-state.md."
        ),
    ),
) -> None:
    """
    Look up multiple domains from a file.

    [dim]One domain per line. Lines starting with # are skipped.[/dim]
    """
    concurrency = max(1, min(20, concurrency))
    asyncio.run(
        _batch(
            file,
            json_output,
            markdown,
            concurrency,
            csv_output=csv_output,
            include_unclassified=include_unclassified,
            skip_ct=no_ct,
            ndjson=ndjson,
            include_ecosystem=include_ecosystem,
            fusion=fusion,
            summary=summary,
        )
    )


@app.command()
def discover(
    domain: str = typer.Argument(help="Domain to mine for fingerprint candidates"),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write candidates JSON here. Default: stdout.",
    ),
    no_ct: bool = typer.Option(False, "--no-ct", help="Skip cert-transparency providers."),
    timeout: float = typer.Option(120.0, "--timeout", "-t", help="Resolve timeout in seconds."),
    keep_intra_org: bool = typer.Option(
        False,
        "--keep-intra-org",
        help="Don't filter chains that look intra-organizational (false-positive prone but more inclusive).",
    ),
    min_count: int = typer.Option(
        1,
        "--min-count",
        help="Drop suffixes seen fewer than N times. Default 1 — single domain runs, every distinct chain matters.",
    ),
) -> None:
    """
    Mine a single domain for fingerprint candidates in one shot.

    Bundles ``recon <domain> --json --include-unclassified`` with the
    bucket / intra-org / already-covered filters. Output is the same shape
    consumed by the ``/recon-fingerprint-triage`` Claude Code skill, ready
    for human or LLM judgment.
    """
    asyncio.run(
        _discover(
            domain,
            output_path=output,
            skip_ct=no_ct,
            timeout=timeout,
            drop_intra_org=not keep_intra_org,
            min_count=min_count,
        )
    )


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Scaffold template config files"),
    mcp: bool = typer.Option(False, "--mcp", help="Validate MCP server setup and emit copy-pasteable client config"),
    client: str | None = typer.Option(
        None,
        "--client",
        help="Check whether a client's MCP config has the recon stanza "
        "(claude-code, claude-desktop, cursor, vscode, windsurf, kiro). "
        "Reads the config file the client loads. The config-side complement "
        "to --mcp, which validates the server itself.",
    ),
) -> None:
    """
    Check connectivity to all data sources.
    """
    if fix:
        _doctor_fix()
        return
    if client is not None:
        _doctor_client(client)
        return
    if mcp:
        _doctor_mcp()
        return
    asyncio.run(_doctor())


@app.command()
def update(
    check: bool = typer.Option(False, "--check", help="Only report whether a newer version exists; do not install."),
) -> None:
    """Check for and install the latest recon release.

    Detects how recon was installed (pipx / uv / pip / Homebrew / editable) and
    runs the matching upgrade, or prints the exact command when it can't safely
    self-upgrade. ``--check`` only reports. Status goes to stderr; the result
    line to stdout, so `recon update --check` is scriptable.
    """
    import subprocess

    from recon_tool import updater
    from recon_tool.formatter import render_error

    console = get_console()
    err = get_err_console()
    current = updater.current_version()

    err.print(f"recon {current} — checking PyPI for updates...")
    latest = updater.fetch_latest_version()
    if latest is None:
        render_error("Could not reach PyPI to check for updates. Try again, or upgrade manually.")
        raise typer.Exit(code=EXIT_ERROR)

    if updater.compare_versions(current, latest) >= 0:
        suffix = f" (latest on PyPI: {latest})" if current != latest else "."
        console.print(f"[green]recon {current} is up to date{suffix}[/green]")
        return

    console.print(f"Update available: [bold]{current}[/bold] -> [bold]{latest}[/bold]")
    method = updater.detect_install_method()
    cmd = updater.upgrade_command(method)

    if check:
        hint = " ".join(cmd) if cmd else updater.manual_hint(method)
        console.print(f"  install method: {method}")
        console.print(f"  to upgrade:     [cyan]{hint}[/cyan]   (or just: recon update)")
        return
    if cmd is None:
        console.print(f"Detected a {method} install — upgrade with: [cyan]{updater.manual_hint(method)}[/cyan]")
        return

    err.print(f"==> upgrading via {method}: {' '.join(cmd)}")
    try:
        # cmd is a fixed argv from updater.upgrade_command's install-method
        # table (pipx/uv/pip), never user input.
        rc = subprocess.run(cmd, check=False).returncode  # noqa: S603
    except OSError as exc:
        render_error(f"Could not start the upgrade ({exc}). Run manually: {updater.manual_hint(method)}")
        raise typer.Exit(code=EXIT_ERROR) from None
    if rc != 0:
        render_error(f"Upgrade failed (exit {rc}). Try manually: {updater.manual_hint(method)}")
        raise typer.Exit(code=EXIT_ERROR)
    console.print(f"[green]Updated to {latest}. Open a new shell and run `recon --version` to confirm.[/green]")


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

    checks: list[McpCheck] = []

    # 1. MCP package importable
    import importlib

    try:
        importlib.import_module("mcp")
        importlib.import_module("mcp.server.fastmcp")
        checks.append(("MCP package", True, "mcp>=1.0 installed"))
    except ImportError as exc:
        checks.append(("MCP package", False, f"not installed: {exc}"))
        checks.append(("Install hint", False, "pip install -U recon-tool"))
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
    console.print(
        "  [yellow]Security note:[/yellow] `recon mcp` runs with the privileges of\n"
        "  the calling user. Start with manual approvals and only expand\n"
        "  `autoApprove` if you fully understand the risk."
    )
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
        '        "autoApprove": []\n'
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


def _doctor_client(client: str) -> None:
    """Read a client's MCP config and report whether recon is registered.

    Complements `--mcp` (which validates the server) by answering the
    other half of "did the install work": does the client's own config
    file carry an `mcpServers.recon` stanza the client would load.
    """
    from recon_tool.client_doctor import ClientCheck, check_client
    from recon_tool.mcp_install import SUPPORTED_CLIENTS

    console = get_console()
    console.print()

    if client not in SUPPORTED_CLIENTS:
        console.print(f"  [red]unknown client '{escape(client)}'[/red]\n  Supported: {', '.join(SUPPORTED_CLIENTS)}")
        raise typer.Exit(EXIT_VALIDATION)

    report = check_client(client)  # pyright: ignore[reportArgumentType]
    console.print(f"  [bold]MCP client config check — {client}[/bold]")
    console.print()

    _style = {"ok": "green", "warn": "yellow", "fail": "red", "info": "dim"}
    _mark = {"ok": "ok", "warn": "warn", "fail": "FAIL", "info": "·"}
    check: ClientCheck
    for check in report.checks:
        style = _style[check.status]
        mark = _mark[check.status]
        console.print(f"  [{style}]{mark:>4}[/{style}]  {check.name} — {escape(strip_control_chars(check.detail))}")

    if report.notes:
        console.print()
        for note in report.notes:
            console.print(f"  [dim]note:[/dim] {escape(strip_control_chars(note))}")

    console.print()
    if report.ok:
        console.print("  [green]recon is registered in this client's config.[/green]")
        console.print()
        return
    console.print(
        f"  [yellow]recon was not found (or a config file is broken).[/yellow] "
        f"See the notes above, or run `recon mcp install --client={client}`."
    )
    console.print()
    raise typer.Exit(EXIT_NO_DATA)


def _doctor_fix() -> None:
    """Scaffold template fingerprints.yaml and signals.yaml in config dir."""

    from recon_tool.paths import config_dir as _config_dir

    console = get_console()
    config_dir = _config_dir()

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


# ── MCP CLI ───────────────────────────────────────────────────────────

app.add_typer(mcp_app, name="mcp")


# ── Cache CLI ─────────────────────────────────────────────────────────

app.add_typer(cache_app, name="cache")


# ── Fingerprints CLI ──────────────────────────────────────────────────

app.add_typer(fingerprints_app, name="fingerprints")

# ── Signals CLI ───────────────────────────────────────────────────────

app.add_typer(signals_app, name="signals")

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
    from recon_tool.formatter import format_delta_json, render_delta_panel, render_error
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    console = get_console()
    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(_fmt_exc(exc))
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
            render_error(_fmt_exc(exc))
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


def _doctor_print_header(console: Any) -> None:
    """Print the version line with the schema-stability indicator, plus Python.

    The substring "v2.0 stable schema" (vs "pre-v2.0 schema") lets an
    operator see at a glance whether Bayesian fusion is opt-in (pre-v2.0) or
    stable per the schema-lock disposition table; the v2.0 quality bar requires
    that text.
    """
    from recon_tool import __version__

    console.print()
    schema_label = "v2.0 stable schema" if __version__.startswith("2.") else "pre-v2.0 schema"
    console.print(f"  recon [bold]v{__version__}[/bold] [dim]({schema_label})[/dim]")
    console.print(f"  Python [bold]{sys.version.split()[0]}[/bold]")
    console.print()


async def _doctor_identity_checks() -> list[DoctorCheck]:
    """Probe the Microsoft identity-discovery endpoints (OIDC, GetUserRealm, Autodiscover)."""
    import httpx

    checks: list[DoctorCheck] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get("https://login.microsoftonline.com/common/.well-known/openid-configuration")
            checks.append(("OIDC discovery", "ok" if resp.status_code == 200 else "fail", f"HTTP {resp.status_code}"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("OIDC discovery", "fail", _fmt_exc(exc)))

        # Synthetic non-existent address — avoids probing a real account.
        try:
            resp = await client.get(
                "https://login.microsoftonline.com/GetUserRealm.srf",
                params={"login": "recon-connectivity-check@example.com", "json": "1"},
            )
            checks.append(("GetUserRealm", "ok" if resp.status_code == 200 else "fail", f"HTTP {resp.status_code}"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("GetUserRealm", "fail", _fmt_exc(exc)))

        try:
            resp = await client.post(
                "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
                content="<test/>",
                headers={"Content-Type": "text/xml"},
            )
            checks.append(("Autodiscover", "ok", f"HTTP {resp.status_code} (reachable)"))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            checks.append(("Autodiscover", "fail", _fmt_exc(exc)))
    return checks


def _doctor_dns_check() -> DoctorCheck:
    """Resolve a known-good TXT record to confirm DNS works."""
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve("example.com", "TXT")
        return ("DNS resolution", "ok", f"{len(list(answers))} TXT records")  # pyright: ignore[reportArgumentType]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        OSError,
    ) as exc:
        return ("DNS resolution", "fail", _fmt_exc(exc))


async def _doctor_ct_check() -> DoctorCheck:
    """Check crt.sh connectivity (certificate transparency, optional enrichment)."""
    import httpx

    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            resp = await client.get("https://crt.sh/?q=%.example.com&output=json")
            if resp.status_code == 200:
                return ("crt.sh (cert transparency)", "ok", "HTTP 200")
            return (
                "crt.sh (cert transparency)",
                "warn",
                f"HTTP {resp.status_code} (optional enrichment degraded)",
            )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout, OSError) as exc:
            return ("crt.sh (cert transparency)", "warn", f"{_fmt_exc(exc)} (optional enrichment degraded)")


def _doctor_mcp_check() -> DoctorCheck:
    """Confirm the MCP server module imports cleanly."""
    try:
        from recon_tool.server import mcp  # noqa: F401  # pyright: ignore[reportUnusedImport]

        return ("MCP server module", "ok", "loaded")
    except Exception as exc:
        return ("MCP server module", "fail", _fmt_exc(exc))


def _doctor_fingerprint_db_check() -> DoctorCheck:
    """Confirm the built-in fingerprint database loads."""
    try:
        from recon_tool.fingerprints import load_fingerprints

        fps = load_fingerprints()
        if fps:
            return ("Fingerprint database", "ok", f"{len(fps)} fingerprints loaded")
        return ("Fingerprint database", "fail", "no fingerprints loaded — detection will not work")
    except Exception as exc:
        return ("Fingerprint database", "fail", _fmt_exc(exc))


def _doctor_custom_path(filename: str) -> Path:
    """Resolve a custom config file path in the config dir (env / legacy / XDG)."""
    from recon_tool.paths import config_dir

    return config_dir() / filename


def _doctor_custom_fingerprints_check() -> DoctorCheck:
    """Report on the optional user fingerprints.yaml overlay."""
    custom_path = _doctor_custom_path("fingerprints.yaml")
    if not custom_path.exists():
        return ("Custom fingerprints", "ok", f"none ({custom_path} not found)")
    try:
        import yaml

        data = yaml.safe_load(custom_path.read_text(encoding="utf-8"))
        count = 0
        if isinstance(data, dict) and "fingerprints" in data:
            count = len(data["fingerprints"])
        elif isinstance(data, list):
            count = len(data)
        return ("Custom fingerprints", "ok", f"{count} entries in {custom_path}")
    except Exception as exc:
        return ("Custom fingerprints", "fail", _fmt_exc(exc))


def _doctor_signal_db_check() -> DoctorCheck:
    """Confirm the built-in signal database loads."""
    try:
        from recon_tool.signals import load_signals

        sigs = load_signals()
        if sigs:
            return ("Signal database", "ok", f"{len(sigs)} signals loaded")
        return ("Signal database", "fail", "no signals loaded — signal intelligence will not work")
    except Exception as exc:
        return ("Signal database", "fail", _fmt_exc(exc))


def _doctor_schema_fields_check() -> DoctorCheck:
    """Verify the locked-schema top-level fields are still emitted by ``format_tenant_json``.

    The v2.0 quality bar: synthesise a minimal TenantInfo, render it
    through the JSON formatter, and confirm every required top-level field from
    ``recon_tool.schema_contract.REQUIRED_TOP_LEVEL_FIELDS`` appears. Drift
    between that tuple and ``docs/recon-schema.json#/required`` is caught at PR
    time by ``tests/test_json_schema_file.py``.
    """
    try:
        import json as _json

        from recon_tool.formatter import format_tenant_json
        from recon_tool.models import ConfidenceLevel, TenantInfo
        from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS

        sample = TenantInfo(
            tenant_id="recon-doctor-sample",
            display_name="recon doctor synthetic",
            default_domain="example.invalid",
            queried_domain="example.invalid",
            confidence=ConfidenceLevel.LOW,
        )
        payload = _json.loads(format_tenant_json(sample))
        missing = sorted(set(REQUIRED_TOP_LEVEL_FIELDS) - set(payload.keys()))
        if missing:
            return ("Schema fields", "fail", f"{len(missing)} locked field(s) missing from emitter output: {missing}")
        return ("Schema fields", "ok", f"{len(REQUIRED_TOP_LEVEL_FIELDS)} locked top-level fields present")
    except Exception as exc:
        return ("Schema fields", "fail", _fmt_exc(exc))


def _doctor_custom_signals_check() -> DoctorCheck:
    """Report on the optional user signals.yaml overlay."""
    custom_signals_path = _doctor_custom_path("signals.yaml")
    if not custom_signals_path.exists():
        return ("Custom signals", "ok", f"none ({custom_signals_path} not found)")
    try:
        import yaml as _yaml

        data = _yaml.safe_load(custom_signals_path.read_text(encoding="utf-8"))
        count = 0
        if isinstance(data, dict) and "signals" in data:
            count = len(data["signals"])
        return ("Custom signals", "ok", f"{count} entries in {custom_signals_path}")
    except Exception as exc:
        return ("Custom signals", "fail", _fmt_exc(exc))


def _doctor_render(console: Any, checks: list[DoctorCheck]) -> None:
    """Print each check row and the closing summary line."""
    has_failures = False
    has_warnings = False
    for name, status, detail in checks:
        mark = {"ok": "ok", "warn": "WARN", "fail": "FAIL"}[status]
        style = {"ok": "green", "warn": "yellow", "fail": "red"}[status]
        console.print(f"  [{style}]{mark:>4}[/{style}]  {name} — {detail}")
        if status == "fail":
            has_failures = True
        elif status == "warn":
            has_warnings = True

    console.print()
    if has_failures:
        console.print("  [yellow]Some checks failed. Lookups may be incomplete.[/yellow]")
    elif has_warnings:
        console.print("  [yellow]Core checks passed. Optional enrichment sources are degraded.[/yellow]")
    else:
        console.print("  [green]All checks passed.[/green]")
    console.print()


async def _doctor() -> None:
    """Run diagnostic checks.

    The check order is load-bearing: ``tests/test_doctor.py`` drives the
    httpx mock with a positional side-effect list, so identity probes must
    run before the crt.sh probe.
    """
    console = get_console()
    _doctor_print_header(console)

    checks: list[DoctorCheck] = []
    checks.extend(await _doctor_identity_checks())
    checks.append(_doctor_dns_check())
    checks.append(await _doctor_ct_check())
    checks.append(_doctor_mcp_check())
    checks.append(_doctor_fingerprint_db_check())
    checks.append(_doctor_custom_fingerprints_check())
    checks.append(_doctor_signal_db_check())
    checks.append(_doctor_schema_fields_check())
    checks.append(_doctor_custom_signals_check())

    _doctor_render(console, checks)


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

    # Third pass: absence signals + positive hardening observations
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


async def _resolve_with_spinner(
    console: Any, validated: str, *, timeout: float, skip_ct: bool, quiet: bool, active_probes: bool = False
) -> tuple[Any, list[Any]]:
    """Resolve a tenant, showing a status spinner unless output is machine-readable."""
    from recon_tool.resolver import resolve_tenant

    if quiet:
        return await resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct, active_probes=active_probes)

    coro = resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct, active_probes=active_probes)
    # Spinner goes to stderr so it never contaminates the stdout data stream.
    return await _run_with_rotating_status(get_err_console(), coro)


async def _run_with_rotating_status(console: Any, coro: Any) -> Any:
    """Await ``coro`` while rotating spinner messages, so a slow lookup shows
    a shuffled sequence of status lines rather than one static message.

    The rotation is purely cosmetic: the awaited coroutine runs to completion
    regardless, and any exception it raises propagates unchanged. Falls back to
    a single static status if anything about the rotation goes wrong, so the
    spinner can never break a lookup.
    """
    import asyncio
    import random

    order = list(_STATUS_MESSAGES)
    random.shuffle(order)
    task = asyncio.ensure_future(coro)
    with console.status(order[0]) as status:
        idx = 0
        while True:
            try:
                return await asyncio.wait_for(asyncio.shield(task), timeout=_STATUS_ROTATE_SECONDS)
            except TimeoutError:
                # The lookup is still running; advance to the next message.
                idx += 1
                try:
                    status.update(order[idx % len(order)])
                except Exception:  # a status-update failure must not abort the lookup
                    return await task


async def _resolve_cached(
    console: Any,
    validated: str,
    *,
    no_cache: bool,
    cache_ttl: int,
    timeout: float,
    skip_ct: bool,
    quiet: bool,
    active_probes: bool = False,
) -> Any:
    """Return a cached TenantInfo if present, else resolve fresh and cache it."""
    info: Any = None
    if not no_cache:
        from recon_tool.cache import cache_get

        cached = cache_get(validated, ttl=cache_ttl)
        if cached is not None:
            info = cached
    if info is None:
        info, _results = await _resolve_with_spinner(
            console, validated, timeout=timeout, skip_ct=skip_ct, quiet=quiet, active_probes=active_probes
        )
        if not no_cache:
            from recon_tool.cache import cache_put

            cache_put(validated, info)
    return info


async def _lookup_compare(
    console: Any,
    validated: str,
    domain: str,
    compare_file: str,
    *,
    json_output: bool,
    markdown: bool,
    timeout: float,
    skip_ct: bool,
    active_probes: bool = False,
) -> None:
    """Resolve and diff against a saved snapshot (`--compare`)."""
    from pathlib import Path as _Path

    from recon_tool.delta import compute_delta, load_previous
    from recon_tool.formatter import format_delta_json, render_delta_panel, render_error, render_warning
    from recon_tool.models import ReconLookupError

    try:
        previous = load_previous(_Path(compare_file))
    except (FileNotFoundError, ValueError) as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        info, _results = await _resolve_with_spinner(
            console,
            validated,
            timeout=timeout,
            skip_ct=skip_ct,
            quiet=json_output or markdown,
            active_probes=active_probes,
        )
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


async def _lookup_chain(
    console: Any,
    validated: str,
    *,
    chain_depth: int,
    skip_ct: bool,
    active_probes: bool = False,
    json_output: bool,
    markdown: bool,
    show_explain: bool,
) -> None:
    """Follow related-domain breadcrumbs (`--chain`)."""
    from recon_tool.chain import chain_resolve
    from recon_tool.formatter import format_chain_json, render_chain_panel, render_error

    try:
        if not json_output and not markdown:
            import random

            msg = random.choice(_STATUS_MESSAGES)  # noqa: S311
            with get_err_console().status(msg):
                report = await chain_resolve(validated, depth=chain_depth, skip_ct=skip_ct, active_probes=active_probes)
        else:
            report = await chain_resolve(validated, depth=chain_depth, skip_ct=skip_ct, active_probes=active_probes)
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


async def _lookup_exposure(
    console: Any,
    validated: str,
    domain: str,
    *,
    no_cache: bool,
    cache_ttl: int,
    json_output: bool,
    markdown: bool,
    timeout: float,
    skip_ct: bool,
    active_probes: bool = False,
) -> None:
    """Resolve (cache-aware) and render the exposure score (`--exposure`)."""
    from recon_tool.exposure import assess_exposure_from_info
    from recon_tool.formatter import format_exposure_json, render_error, render_exposure_panel, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info_exp = await _resolve_cached(
            console,
            validated,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            timeout=timeout,
            skip_ct=skip_ct,
            quiet=json_output or markdown,
            active_probes=active_probes,
        )
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


async def _lookup_gaps(
    console: Any,
    validated: str,
    domain: str,
    *,
    no_cache: bool,
    cache_ttl: int,
    json_output: bool,
    markdown: bool,
    timeout: float,
    skip_ct: bool,
    active_probes: bool = False,
) -> None:
    """Resolve (cache-aware) and render the detection-gap report (`--gaps`)."""
    from recon_tool.exposure import find_gaps_from_info
    from recon_tool.formatter import format_gaps_json, render_error, render_gaps_panel, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info_gaps = await _resolve_cached(
            console,
            validated,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            timeout=timeout,
            skip_ct=skip_ct,
            quiet=json_output or markdown,
            active_probes=active_probes,
        )
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


def _lookup_apply_fusion(info: Any) -> Any:
    """Recompute slug posteriors and the Bayesian network marginals onto ``info``.

    Purely deterministic over the existing ``TenantInfo`` (no network calls), so
    it runs on both cache hits and misses when ``--fusion`` / ``--explain-dag``
    is set. ``--explain-dag`` implies ``--fusion`` because the DAG renderer needs
    the posteriors present.
    """
    from dataclasses import replace

    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.models import NodeConflict, NodeEvidence, NodeUnitCounterfactual, PosteriorObservation

    bayesian_result = infer_from_tenant_info(info)
    bayesian_observations = tuple(
        PosteriorObservation(
            name=p.name,
            description=p.description,
            posterior=p.posterior,
            interval_low=p.interval_low,
            interval_high=p.interval_high,
            evidence_used=p.evidence_used,
            n_eff=p.n_eff,
            sparse=p.sparse,
            conflict_provenance=tuple(
                NodeConflict(field=c.field, sources=c.sources, magnitude=c.magnitude) for c in p.conflict_provenance
            ),
            evidence_ranked=tuple(
                NodeEvidence(
                    kind=e.kind,
                    name=e.name,
                    llr=e.llr,
                    influence_pct=e.influence_pct,
                )
                for e in p.evidence_ranked
            ),
            entropy_reduction_nats=p.entropy_reduction_nats,
            unit_counterfactuals=tuple(
                NodeUnitCounterfactual(
                    unit=c.unit,
                    kind=c.kind,
                    observed=c.observed,
                    posterior_without=c.posterior_without,
                    delta=c.delta,
                )
                for c in p.unit_counterfactuals
            ),
        )
        for p in bayesian_result.posteriors
    )
    return replace(
        info,
        slug_confidences=compute_slug_posteriors(info.evidence),
        posterior_observations=bayesian_observations,
    )


async def _lookup_resolve_standard(
    console: Any,
    validated: str,
    *,
    json_output: bool,
    markdown: bool,
    fusion: bool,
    explain_dag: bool,
    no_cache: bool,
    cache_ttl: int,
    timeout: float,
    skip_ct: bool,
    active_probes: bool = False,
) -> tuple[Any, list[Any]]:
    """Cache read, resolve on miss, apply fusion, write back. Returns (info, results)."""
    info: Any = None
    results: list[Any] = []
    if not no_cache:
        from recon_tool.cache import cache_get

        cached = cache_get(validated, ttl=cache_ttl)
        if cached is not None:
            info = cached

    cache_miss = info is None
    if cache_miss:
        info, results = await _resolve_with_spinner(
            console,
            validated,
            timeout=timeout,
            skip_ct=skip_ct,
            quiet=json_output or markdown,
            active_probes=active_probes,
        )

    if fusion or explain_dag:
        info = _lookup_apply_fusion(info)
    else:
        # --no-fusion: a cache hit may carry fusion fields written by an earlier
        # default-on run. Clear them so the opt-out is honored (fusion_enabled is
        # derived from posterior_observations downstream).
        from dataclasses import replace as _replace

        info = _replace(info, slug_confidences={}, posterior_observations=())

    # Cache hits don't write back: the entry hasn't changed except for fusion
    # output, which is recomputed on read anyway.
    if cache_miss and not no_cache:
        from recon_tool.cache import cache_put

        cache_put(validated, info)
    return info, results


def _lookup_compute_observations(info: Any, profile_name: str | None, show_posture: bool) -> tuple[Any, ...]:
    """Resolve the requested posture profile and compute posture observations."""
    from recon_tool.formatter import render_error

    profile = None
    if profile_name:
        from recon_tool.profiles import load_profile

        profile = load_profile(profile_name)
        if profile is None:
            from recon_tool.profiles import list_profiles

            names = ", ".join(p.name for p in list_profiles())
            render_error(f"Unknown profile {profile_name!r}. Available profiles: {names or '(none)'}")
            raise typer.Exit(code=EXIT_VALIDATION) from None

    observations: tuple[Any, ...] = ()
    if show_posture:
        from recon_tool.posture import analyze_posture
        from recon_tool.profiles import apply_profile, compute_baseline_anomalies

        raw_observations = analyze_posture(info)
        # Append vertical-baseline anomalies before profile reweighting so
        # profile boosts apply uniformly. Empty tuple when no profile or when the
        # profile has no expectations.
        anomalies = compute_baseline_anomalies(
            profile,
            info.slugs,
            tuple(cm.motif_name for cm in info.chain_motifs),
        )
        combined_obs = tuple(raw_observations) + anomalies
        observations = apply_profile(combined_obs, profile)
    return observations


def _lookup_emit_explain_dag(validated: str, info: Any, explain_dag_format: str) -> None:
    """Render the Bayesian evidence DAG in the requested format (`--explain-dag`)."""
    from recon_tool.bayesian import infer_from_tenant_info, load_network
    from recon_tool.bayesian_dag import render_dag_dot, render_dag_mermaid, render_dag_text
    from recon_tool.formatter import render_error

    network = load_network()
    inference = infer_from_tenant_info(info, network=network)
    fmt = (explain_dag_format or "text").lower()
    if fmt == "dot":
        typer.echo(render_dag_dot(network, inference, domain=validated))
    elif fmt == "mermaid":
        typer.echo(render_dag_mermaid(network, inference, domain=validated))
    elif fmt == "text":
        typer.echo(render_dag_text(network, inference, domain=validated))
    else:
        render_error(f"--explain-dag-format must be 'text', 'dot', or 'mermaid', got {explain_dag_format!r}")
        raise typer.Exit(code=EXIT_VALIDATION) from None


def _lookup_emit_json(
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_posture: bool,
    show_explain: bool,
    include_unclassified: bool,
) -> None:
    """Emit the tenant dict as JSON, with optional posture and explanation blocks."""
    from recon_tool.formatter import format_posture_observations, format_tenant_dict

    tenant_dict = format_tenant_dict(info, include_unclassified=include_unclassified)
    if show_posture:
        tenant_dict["posture"] = format_posture_observations(observations)
    if show_explain:
        from recon_tool.explanation import build_explanation_dag
        from recon_tool.formatter import format_explanations_list
        from recon_tool.models import serialize_conflicts

        explanations = _build_explanations(info, results)
        tenant_dict["explanations"] = format_explanations_list(explanations)
        # Structured provenance DAG for programmatic consumers. Lives
        # alongside the flat list; both are emitted so existing tooling doesn't
        # break.
        tenant_dict["explanation_dag"] = build_explanation_dag(explanations, info.evidence)
        if info.merge_conflicts and info.merge_conflicts.has_conflicts:
            tenant_dict["conflicts"] = serialize_conflicts(info.merge_conflicts)
    typer.echo(json.dumps(tenant_dict, indent=2))


def _lookup_emit_markdown(
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_posture: bool,
    show_explain: bool,
) -> None:
    """Emit the tenant report as Markdown, with optional posture and explanations."""
    from recon_tool.formatter import format_tenant_markdown

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


def _lookup_emit_plain(info: Any, *, include_unclassified: bool) -> None:
    """Emit the tenant report as plain, linear, greppable text (no panel)."""
    from recon_tool.formatter import format_tenant_plain

    typer.echo(format_tenant_plain(info, include_unclassified=include_unclassified))


def _synthetic_source_results(info: Any) -> list[Any]:
    """Reconstruct minimal SourceResults from a cached TenantInfo.

    On a cache hit the raw SourceResult list isn't available (the cache stores
    TenantInfo, not source results), so the `--explain` status panel rebuilds
    what it can from ``info.sources`` (successes) and ``info.degraded_sources``
    (failures).
    """
    from recon_tool.models import SourceResult

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
    return synthetic


def _lookup_emit_panel(
    console: Any,
    info: Any,
    results: list[Any],
    observations: tuple[Any, ...],
    *,
    show_services: bool,
    show_domains: bool,
    verbose: bool,
    show_explain: bool,
    show_sources: bool,
    show_posture: bool,
    confidence_mode: str,
) -> None:
    """Render the default human-readable panel, plus optional sources/posture/explain."""
    from recon_tool.formatter import render_sources_detail, render_tenant_panel

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
        from recon_tool.formatter import render_explanations_panel, render_source_status_panel

        # U1: always render per-source status under --explain so users
        # can see which sources succeeded, which failed, and why. Previously this
        # was only available via --verbose.
        status_results: list[Any] = results
        if not status_results and info is not None:
            status_results = _synthetic_source_results(info)

        status_panel = render_source_status_panel(status_results)
        if status_panel:
            console.print(status_panel)

        explanations = _build_explanations(info, results)
        if explanations:
            console.print(render_explanations_panel(explanations))


async def _lookup_standard(
    console: Any,
    validated: str,
    domain: str,
    *,
    json_output: bool,
    markdown: bool,
    plain: bool,
    verbose: bool,
    show_services: bool,
    show_domains: bool,
    show_sources: bool,
    show_posture: bool,
    profile_name: str | None,
    confidence_mode: str,
    fusion: bool,
    explain_dag: bool,
    explain_dag_format: str,
    include_unclassified: bool,
    show_explain: bool,
    no_cache: bool,
    cache_ttl: int,
    timeout: float,
    skip_ct: bool,
    active_probes: bool = False,
) -> None:
    """The default lookup path: resolve, fuse, then emit DAG / JSON / Markdown / panel."""
    from recon_tool.formatter import render_error, render_verbose_sources, render_warning
    from recon_tool.models import ReconLookupError

    try:
        info, results = await _lookup_resolve_standard(
            console,
            validated,
            json_output=json_output,
            markdown=markdown,
            fusion=fusion,
            explain_dag=explain_dag,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            timeout=timeout,
            skip_ct=skip_ct,
            active_probes=active_probes,
        )

        if verbose:
            render_verbose_sources(results)

        observations = _lookup_compute_observations(info, profile_name, show_posture)

        if explain_dag:
            _lookup_emit_explain_dag(validated, info, explain_dag_format)
            return
        if json_output:
            _lookup_emit_json(
                info,
                results,
                observations,
                show_posture=show_posture,
                show_explain=show_explain,
                include_unclassified=include_unclassified,
            )
            return
        if markdown:
            _lookup_emit_markdown(info, results, observations, show_posture=show_posture, show_explain=show_explain)
            return
        if plain:
            _lookup_emit_plain(info, include_unclassified=include_unclassified)
            return

        _lookup_emit_panel(
            console,
            info,
            results,
            observations,
            show_services=show_services,
            show_domains=show_domains,
            verbose=verbose,
            show_explain=show_explain,
            show_sources=show_sources,
            show_posture=show_posture,
            confidence_mode=confidence_mode,
        )
    except ReconLookupError as exc:
        render_warning(domain, exc)
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None


async def _lookup(
    domain: str,
    json_output: bool,
    markdown: bool,
    plain: bool,
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
    explain_dag: bool = False,
    explain_dag_format: str = "text",
    include_unclassified: bool = False,
    skip_ct: bool = False,
    active_probes: bool = False,
    exact: bool = False,
) -> None:
    """Async lookup implementation.

    A thin dispatcher: normalize the output flags, validate the domain and the
    mutually-exclusive flag combinations, then hand off to the mode helper for
    compare / chain / exposure / gaps, or to the standard panel path.
    """
    console = get_console()

    if full:
        show_services = True
        show_domains = True
        verbose = True
        show_posture = True

    # ``--profile`` is a no-op unless posture output is shown. If the user
    # specified a profile, they want the profile-filtered posture observations,
    # so turn on posture automatically rather than silently dropping the flag.
    if profile_name and not show_posture:
        show_posture = True

    validated = lookup_validate(
        domain,
        json_output=json_output,
        markdown=markdown,
        plain=plain,
        chain_mode=chain_mode,
        compare_file=compare_file,
        show_exposure=show_exposure,
        show_gaps=show_gaps,
        chain_depth=chain_depth,
        exact=exact,
    )

    if compare_file:
        await _lookup_compare(
            console,
            validated,
            domain,
            compare_file,
            json_output=json_output,
            markdown=markdown,
            timeout=timeout,
            skip_ct=skip_ct,
            active_probes=active_probes,
        )
        return

    if chain_mode:
        await _lookup_chain(
            console,
            validated,
            chain_depth=chain_depth,
            skip_ct=skip_ct,
            active_probes=active_probes,
            json_output=json_output,
            markdown=markdown,
            show_explain=show_explain,
        )
        return

    if show_exposure:
        await _lookup_exposure(
            console,
            validated,
            domain,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            json_output=json_output,
            markdown=markdown,
            timeout=timeout,
            skip_ct=skip_ct,
            active_probes=active_probes,
        )
        return

    if show_gaps:
        await _lookup_gaps(
            console,
            validated,
            domain,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            json_output=json_output,
            markdown=markdown,
            timeout=timeout,
            skip_ct=skip_ct,
            active_probes=active_probes,
        )
        return

    await _lookup_standard(
        console,
        validated,
        domain,
        json_output=json_output,
        markdown=markdown,
        plain=plain,
        verbose=verbose,
        show_services=show_services,
        show_domains=show_domains,
        show_sources=show_sources,
        show_posture=show_posture,
        profile_name=profile_name,
        confidence_mode=confidence_mode,
        fusion=fusion,
        explain_dag=explain_dag,
        explain_dag_format=explain_dag_format,
        include_unclassified=include_unclassified,
        show_explain=show_explain,
        no_cache=no_cache,
        cache_ttl=cache_ttl,
        timeout=timeout,
        skip_ct=skip_ct,
        active_probes=active_probes,
    )


async def _discover(
    domain: str,
    *,
    output_path: str | None,
    skip_ct: bool,
    timeout: float,
    drop_intra_org: bool,
    min_count: int,
) -> None:
    """Single-domain fingerprint-discovery pipeline.

    Resolves the domain, walks the unclassified CNAME chains the surface
    classifier captured, applies the intra-org and already-covered filters,
    and emits the candidate list in the same shape as the corpus-scale
    ``triage_candidates.py``. Output is consumable by the
    ``/recon-fingerprint-triage`` Claude Code skill.
    """
    import json as json_mod
    from pathlib import Path

    from recon_tool.discovery import find_candidates
    from recon_tool.formatter import render_error
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None

    try:
        info, _results = await resolve_tenant(validated, timeout=timeout, skip_ct=skip_ct)
    except ReconLookupError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_NO_DATA) from None
    except Exception as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_INTERNAL) from None

    # Convert TenantInfo's unclassified_cname_chains into the (apex, [{subdomain, chain}])
    # shape ``find_candidates`` consumes. Same data, different transport.
    unclassified_records = [
        {"subdomain": uc.subdomain, "chain": list(uc.chain)} for uc in info.unclassified_cname_chains
    ]
    fingerprints_dir = Path(__file__).resolve().parent / "data" / "fingerprints"
    candidates = find_candidates(
        [(info.queried_domain, unclassified_records)],
        fingerprints_dir=fingerprints_dir,
        min_count=min_count,
        drop_intra_org=drop_intra_org,
    )

    payload = json_mod.dumps(candidates, indent=2)
    if output_path is None:
        typer.echo(payload)
    else:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        typer.echo(f"wrote {out} ({len(candidates)} candidates)", err=True)


def _batch_validate_flags(
    *,
    json_output: bool,
    markdown: bool,
    csv_output: bool,
    ndjson: bool,
    include_ecosystem: bool,
    summary: bool = False,
) -> None:
    """Reject mutually-exclusive output flags and the --include-ecosystem constraint."""
    from recon_tool.formatter import render_error

    if sum([json_output, markdown, csv_output, ndjson]) > 1:
        render_error("--json, --md, --csv, and --ndjson are mutually exclusive")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --summary is a batch-scope aggregate. It pairs with --json (machine
    # output) or stands alone (panel); the per-domain formats have no cohort view.
    if summary and (markdown or csv_output or ndjson):
        render_error("--summary cannot combine with --md, --csv, or --ndjson")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --summary and --include-ecosystem are different batch-scope aggregates; the
    # summary path returns before the ecosystem envelope is emitted, so combining
    # them would silently drop the hypergraph. Reject rather than mislead.
    if summary and include_ecosystem:
        render_error("--summary cannot combine with --include-ecosystem")
        raise typer.Exit(code=EXIT_VALIDATION)
    # --include-ecosystem requires --json. The hypergraph is a batch-scope
    # envelope sibling to the per-domain entries with no natural place in the
    # panel, markdown, CSV, or NDJSON outputs (NDJSON streams per-domain and the
    # hypergraph needs the full set).
    if include_ecosystem and not json_output:
        render_error("--include-ecosystem requires --json")
        raise typer.Exit(code=EXIT_VALIDATION)


def _batch_load_domains(file: str, console: Any, *, announce_dupes: bool) -> list[str]:
    """Read the domain list (file path or "-" for stdin), dedupe in input order.

    Raises ``typer.Exit`` on a missing/unreadable/malformed file or an empty list.
    """
    import sys as sys_mod
    from pathlib import Path

    from recon_tool.formatter import render_error

    # A literal "-" reads the domain list from stdin (cat domains.txt | recon
    # batch -); otherwise treat the argument as a file path. Both go through the
    # same bounded line reader.
    from_stdin = file == "-"
    try:
        if from_stdin:
            domain_list = _read_batch_domains(sys_mod.stdin)
        else:
            path = Path(file)
            if not path.exists():
                render_error(f"File not found: {file}")
                raise typer.Exit(code=EXIT_VALIDATION)
            with path.open(encoding="utf-8") as f:
                domain_list = _read_batch_domains(f)
    except _BatchInputError as exc:
        render_error(str(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from None
    except OSError as exc:
        render_error(f"Cannot read file: {exc}")
        raise typer.Exit(code=EXIT_INTERNAL) from None

    if not domain_list:
        source = "stdin" if from_stdin else "file"
        render_error(f"No domains found in {source}")
        raise typer.Exit(code=EXIT_VALIDATION)

    # Deduplicate while preserving input order
    seen: set[str] = set()
    unique_domains: list[str] = []
    for d in domain_list:
        d_lower = d.lower().strip()
        if d_lower not in seen:
            seen.add(d_lower)
            unique_domains.append(d)
    if len(unique_domains) < len(domain_list) and announce_dupes:
        skipped = len(domain_list) - len(unique_domains)
        console.print(f"  [dim]{skipped} duplicate(s) removed[/dim]")
    return unique_domains


def _batch_apply_fusion(info: Any) -> Any:
    """Bayesian fusion for batch results: ``posterior_observations`` + ``slug_confidences``.

    Pure post-processing over the already-resolved TenantInfo, no extra network
    calls. Unlike ``_lookup_apply_fusion`` this omits ``evidence_ranked`` on each
    posterior, preserving the batch JSON shape that shipped before this refactor.
    """
    from dataclasses import replace

    from recon_tool.bayesian import infer_from_tenant_info
    from recon_tool.fusion import compute_slug_posteriors
    from recon_tool.models import NodeConflict, NodeUnitCounterfactual, PosteriorObservation

    result = infer_from_tenant_info(info)
    return replace(
        info,
        slug_confidences=compute_slug_posteriors(info.evidence),
        posterior_observations=tuple(
            PosteriorObservation(
                name=p.name,
                description=p.description,
                posterior=p.posterior,
                interval_low=p.interval_low,
                interval_high=p.interval_high,
                evidence_used=p.evidence_used,
                n_eff=p.n_eff,
                sparse=p.sparse,
                conflict_provenance=tuple(
                    NodeConflict(field=c.field, sources=c.sources, magnitude=c.magnitude) for c in p.conflict_provenance
                ),
                # evidence_ranked stays deliberately omitted here (the batch
                # JSON shape freeze predates it); the 2.2.0 diagnostics are
                # additive and carried in both lookup and batch shapes.
                entropy_reduction_nats=p.entropy_reduction_nats,
                unit_counterfactuals=tuple(
                    NodeUnitCounterfactual(
                        unit=c.unit,
                        kind=c.kind,
                        observed=c.observed,
                        posterior_without=c.posterior_without,
                        delta=c.delta,
                    )
                    for c in p.unit_counterfactuals
                ),
            )
            for p in result.posteriors
        ),
    )


def _batch_attach_shared_tokens(json_results: list[dict[str, Any]], batch_infos: dict[str, Any]) -> None:
    """Attach ``shared_verification_tokens`` peer lists in place.

    Keyed by ``queried_domain`` (the canonical normalized form) when at least two
    domains in the batch publish the same site-verification token.
    """
    from recon_tool.clustering import compute_shared_tokens

    domain_tokens = {d: info.site_verification_tokens for d, info in batch_infos.items()}
    clusters = compute_shared_tokens(domain_tokens)
    if not clusters:
        return
    for entry in json_results:
        key = entry.get("queried_domain")
        if not isinstance(key, str):
            continue
        peers = clusters.get(key)
        if peers:
            entry["shared_verification_tokens"] = [{"token": e.token, "peer": e.peer} for e in peers]


def _batch_attach_peers(json_results: list[dict[str, Any]], batch_infos: dict[str, Any]) -> None:
    """Attach ``shared_tenant`` and ``shared_display_name`` peer lists in place.

    Tenant-ID sharing is cryptographically strong (same M365 customer account);
    display-name overlap is hedged (same brand / likely related, but
    customer-supplied so not cryptographic). Both surface as a per-domain peer
    list so batch consumers can pull related apexes without re-resolving them.
    """
    from recon_tool.clustering import compute_display_name_clusters, compute_tenant_clusters

    domain_tenants = {d: info.tenant_id for d, info in batch_infos.items()}
    domain_names = {d: info.display_name for d, info in batch_infos.items()}
    tenant_clusters = compute_tenant_clusters(domain_tenants)
    display_clusters = compute_display_name_clusters(domain_names)

    # Build per-domain peer indexes for quick lookup.
    tenant_peers: dict[str, list[dict[str, object]]] = {}
    for tc in tenant_clusters:
        for d in tc.domains:
            tenant_peers.setdefault(d, []).append(
                {
                    "tenant_id": tc.tenant_id,
                    "peers": [p for p in tc.domains if p != d],
                }
            )
    display_peers: dict[str, list[dict[str, object]]] = {}
    for dc in display_clusters:
        for d, raw in zip(dc.domains, dc.raw_names, strict=True):
            display_peers.setdefault(d, []).append(
                {
                    "display_name": raw,
                    "normalized_name": dc.normalized_name,
                    "peers": [p for p in dc.domains if p != d],
                }
            )

    if not (tenant_peers or display_peers):
        return
    for entry in json_results:
        key = entry.get("queried_domain")
        if not isinstance(key, str):
            continue
        if key in tenant_peers:
            entry["shared_tenant"] = tenant_peers[key]
        if key in display_peers:
            entry["shared_display_name"] = display_peers[key]


def _batch_emit_json(results: list[object], batch_infos: dict[str, Any], *, include_ecosystem: bool) -> None:
    """Assemble the batch JSON array (with cross-domain enrichment) and emit it."""
    import json as json_mod

    json_results: list[dict[str, Any]] = [r for r in results if r is not None]  # type: ignore[misc]

    if batch_infos:
        _batch_attach_shared_tokens(json_results, batch_infos)
        _batch_attach_peers(json_results, batch_infos)

    # Ecosystem hypergraph. Off by default. When opted in via
    # --include-ecosystem, emit hyperedges over the batch's TenantInfo set as a
    # top-level envelope sibling to the per-domain entries.
    if include_ecosystem:
        # SH9: when --include-ecosystem is set, always emit the BatchResult
        # wrapper, even when no domain resolved. Previously this fell back to a
        # bare array on an all-failed batch, flipping the top-level type exactly
        # when a consumer's error path is already stressed. Errors ride under
        # domains; hyperedges are empty when there were no resolved infos.
        hyperedges: list[Any] = []
        if batch_infos:
            from recon_tool.ecosystem import build_ecosystem_hyperedges

            hyperedges = list(build_ecosystem_hyperedges(batch_infos))
        ecosystem_payload = {
            "record_type": "batch_result",  # SH7 discriminator
            "ecosystem_hyperedges": [
                {
                    "edge_type": e.edge_type,
                    "key": e.key,
                    "members": list(e.members),
                }
                for e in hyperedges
            ],
            "domains": json_results,
        }
        typer.echo(json_mod.dumps(ecosystem_payload, indent=2))
        return

    typer.echo(json_mod.dumps(json_results, indent=2))


def _batch_emit_summary(batch_infos: dict[str, Any], attempted: int, console: Any, *, as_json: bool) -> None:
    """Emit one aggregate-only cohort summary over the resolved batch.

    Stateless: computed live from the resolved records, stores nothing, ships no
    baselines, names no domain. The richer caller-grouped analysis lives in the
    downstream reducer under ``validation/aggregate/``.
    """
    import json as json_mod

    from recon_tool.cohort_summary import build_summary_document, render_cohort_summary
    from recon_tool.formatter import format_tenant_dict

    records = [format_tenant_dict(info) for info in batch_infos.values()]
    document = build_summary_document(records, attempted=attempted)
    if as_json:
        typer.echo(json_mod.dumps(document, indent=2))
    else:
        console.print(render_cohort_summary(document))


async def _batch_emit_ndjson(domain_list: list[str], process_one: Any, error_prefix: str) -> None:
    """Stream one JSON object per line, flushed as each domain completes.

    Skips the post-batch enrichment (shared tokens, tenant peers, display-name
    clusters) because those need every result before any can be emitted. Trades
    batch-wide enrichment for constant memory and visible progress on large
    corpora.
    """
    import json as json_mod
    import sys as sys_mod

    tasks = [asyncio.create_task(process_one(d)) for d in domain_list]
    for fut in asyncio.as_completed(tasks):
        result = await fut
        if isinstance(result, dict):
            typer.echo(json_mod.dumps(result))
            # Flush stdout so downstream pipelines see each line as it lands.
            sys_mod.stdout.flush()
        elif isinstance(result, str) and result.startswith(error_prefix):
            typer.echo(result.removeprefix(error_prefix), err=True)


def _batch_render_results(
    results: list[object],
    batch_infos: dict[str, Any],
    console: Any,
    *,
    json_output: bool,
    csv_output: bool,
    markdown: bool,
    include_ecosystem: bool,
    error_prefix: str,
) -> None:
    """Render gathered batch results in input order for the chosen output mode."""
    from recon_tool.formatter import render_error

    if json_output:
        _batch_emit_json(results, batch_infos, include_ecosystem=include_ecosystem)
    elif csv_output:
        from recon_tool.formatter import format_batch_csv

        csv_rows: list[Any] = [r for r in results if isinstance(r, tuple) and len(r) == 3]
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
            if isinstance(r, str) and r.startswith(error_prefix):
                render_error(r[len(error_prefix) :])
            else:
                console.print(r)
                console.print()


def _batch_error_result(
    domain: str,
    message: str,
    *,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    markdown_skips: bool,
    error_prefix: str,
) -> object:
    """Shape a per-domain error for the active output mode.

    ``markdown_skips`` distinguishes the validate-error path (markdown yields
    nothing) from the resolve-error path (markdown falls through to the display
    sentinel), preserving the pre-refactor behaviour exactly.
    """
    if json_output or ndjson:
        # SH8: machine-readable error_kind so a consumer can route on a code
        # rather than the free-text message. markdown_skips marks the
        # validate-error path; otherwise it is a lookup error (timeout split out).
        if markdown_skips:
            error_kind = "validation"
        elif "timeout" in message.lower() or "timed out" in message.lower():
            error_kind = "timeout"
        else:
            error_kind = "lookup"
        # SH7: record_type discriminator (this is the error shape).
        return {"domain": domain, "error": message, "error_kind": error_kind, "record_type": "error"}
    if csv_output:
        return (domain, None, message)
    if markdown and markdown_skips:
        return None
    return f"{error_prefix}{domain}: {message}"


def _batch_success_result(
    info: Any,
    domain: str,
    *,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    include_unclassified: bool,
) -> object:
    """Shape a successful per-domain result for the active output mode."""
    from recon_tool.formatter import format_tenant_dict, format_tenant_markdown, render_tenant_panel

    if json_output or ndjson:
        return format_tenant_dict(info, include_unclassified=include_unclassified)
    if csv_output:
        return (domain, info, None)
    if markdown:
        return format_tenant_markdown(info)
    return render_tenant_panel(info)


async def _batch_process_one(
    domain: str,
    *,
    semaphore: asyncio.Semaphore,
    batch_infos: dict[str, Any],
    skip_ct: bool,
    fusion: bool,
    json_output: bool,
    ndjson: bool,
    csv_output: bool,
    markdown: bool,
    include_unclassified: bool,
    error_prefix: str,
) -> object:
    """Resolve a single domain under the semaphore and shape its result.

    Stashes the TenantInfo in ``batch_infos`` (keyed by queried_domain) so the
    post-batch token / tenant / display-name clustering can run.
    """
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant
    from recon_tool.validator import validate_domain

    try:
        validated = validate_domain(domain)
    except ValueError as exc:
        return _batch_error_result(
            domain,
            str(exc),
            json_output=json_output,
            ndjson=ndjson,
            csv_output=csv_output,
            markdown=markdown,
            markdown_skips=True,
            error_prefix=error_prefix,
        )

    async with semaphore:
        try:
            # Small delay between domains to avoid burst-flooding upstream
            # endpoints (Microsoft, DNS). The semaphore caps concurrency, but
            # without a delay all N domains fire at once.
            await asyncio.sleep(0.1)
            info, _results = await resolve_tenant(validated, skip_ct=skip_ct)
            if fusion:
                info = _batch_apply_fusion(info)
            batch_infos[info.queried_domain] = info
            return _batch_success_result(
                info,
                domain,
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                include_unclassified=include_unclassified,
            )
        except ReconLookupError as exc:
            return _batch_error_result(
                domain,
                str(exc),
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                markdown_skips=False,
                error_prefix=error_prefix,
            )
        except Exception as exc:
            return _batch_error_result(
                domain,
                str(exc),
                json_output=json_output,
                ndjson=ndjson,
                csv_output=csv_output,
                markdown=markdown,
                markdown_skips=False,
                error_prefix=error_prefix,
            )


async def _batch(
    file: str,
    json_output: bool,
    markdown: bool,
    concurrency: int,
    csv_output: bool = False,
    *,
    include_unclassified: bool = False,
    skip_ct: bool = False,
    ndjson: bool = False,
    include_ecosystem: bool = False,
    fusion: bool = False,
    summary: bool = False,
) -> None:
    """Process multiple domains from a file with controlled concurrency.

    Rate limiting: Each domain hits 3+ external endpoints concurrently.
    The semaphore caps domain-level concurrency, and the HTTP transport
    retries on 429/503 with exponential backoff. For large batch files,
    an inter-domain delay prevents burst-flooding upstream endpoints.

    Output modes:
      * default — rendered tenant panel per domain
      * ``json_output`` — single JSON array at the end (back-compat shape)
      * ``markdown`` — rendered markdown per domain
      * ``csv_output`` — flat CSV of headline fields
      * ``ndjson`` — one JSON object per line, flushed as each domain
        completes. Recommended for large corpora where ``json_output`` would
        buffer the entire result set in memory.
    """
    from recon_tool.models import TenantInfo as _TenantInfo

    console = get_console()

    _batch_validate_flags(
        json_output=json_output,
        markdown=markdown,
        csv_output=csv_output,
        ndjson=ndjson,
        include_ecosystem=include_ecosystem,
        summary=summary,
    )

    domain_list = _batch_load_domains(file, console, announce_dupes=not json_output and not markdown and not csv_output)

    semaphore = asyncio.Semaphore(concurrency)

    # Batch-scope token clustering. Each successful resolution
    # stashes its TenantInfo here keyed by the *input* domain string,
    # so the post-processing pass can compute `shared_verification_tokens`
    # across every domain in the batch. Scoped to this batch run — never
    # persisted to disk cache, never shared between batch invocations.
    batch_infos: dict[str, _TenantInfo] = {}

    # Sentinel prefix for error messages returned from _process_one.
    # Errors are collected as strings and printed in order after all tasks complete,
    # preventing interleaved output from concurrent coroutines.
    _ERROR_PREFIX = "\x00ERR:"

    async def _run_one(domain: str) -> object:
        """Bind the batch-scoped state and delegate to ``_batch_process_one``."""
        return await _batch_process_one(
            domain,
            semaphore=semaphore,
            batch_infos=batch_infos,
            skip_ct=skip_ct,
            fusion=fusion,
            json_output=json_output,
            ndjson=ndjson,
            csv_output=csv_output,
            markdown=markdown,
            include_unclassified=include_unclassified,
            error_prefix=_ERROR_PREFIX,
        )

    # Gather all results concurrently, then output in input-file order.
    # This prevents interleaved output from concurrent coroutines.
    total = len(domain_list)
    completed = 0

    async def _tracked(domain: str) -> object:
        nonlocal completed
        result = await _run_one(domain)
        completed += 1
        if not summary and not json_output and not markdown and not csv_output:
            safe = escape(strip_control_chars(domain))
            get_err_console().print(f"  [{completed}/{total}] {safe}", style="dim", highlight=False)
        return result

    # NDJSON streaming path, flushed per-domain (see helper for the trade-off).
    if ndjson:
        await _batch_emit_ndjson(domain_list, _run_one, _ERROR_PREFIX)
        return

    tasks = [_tracked(d) for d in domain_list]
    results = await asyncio.gather(*tasks)

    # --summary collapses the batch into one aggregate-only cohort summary.
    if summary:
        _batch_emit_summary(batch_infos, len(domain_list), console, as_json=json_output)
        return

    _batch_render_results(
        results,
        batch_infos,
        console,
        json_output=json_output,
        csv_output=csv_output,
        markdown=markdown,
        include_ecosystem=include_ecosystem,
        error_prefix=_ERROR_PREFIX,
    )


def run() -> None:
    """Entry point — invokes the Typer app.

    The callback handles shorthand domain syntax (e.g., `recon contoso.com`)
    via invoke_without_command routing. No preprocessing needed.

    Wraps the app in a last-resort handler so an *unexpected* crash writes its
    full traceback to a file and prints a clean one-liner (no raw stack trace on
    the terminal), and a Ctrl-C exits quietly with code 130. Normal Typer/Click
    exits (help, version, usage errors) pass through untouched.
    """
    try:
        app()
    except KeyboardInterrupt:
        get_err_console().print("[yellow]Interrupted.[/yellow]")
        raise SystemExit(130) from None
    except SystemExit:
        raise
    except Exception:  # top-level last-resort crash handler (catch-all is intentional)
        import tempfile
        import traceback
        from datetime import UTC, datetime

        from recon_tool.exit_codes import EXIT_INTERNAL

        try:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            crash_path = Path(tempfile.gettempdir()) / f"recon-crash-{stamp}.log"
            crash_path.write_text(traceback.format_exc(), encoding="utf-8")
            where = f"[link={crash_path.as_uri()}]{escape(str(crash_path))}[/link]"
        except Exception:  # never fail inside the crash handler
            where = "(could not write a crash log)"
        get_err_console().print(
            f"[red]recon hit an unexpected error.[/red] Details written to {where}\n"
            "Please report it at https://github.com/blisspixel/recon/issues and attach that file."
        )
        raise SystemExit(EXIT_INTERNAL) from None


if __name__ == "__main__":
    run()
