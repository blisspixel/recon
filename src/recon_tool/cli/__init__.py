"""CLI application facade for recon.

Supports shorthand ``recon DOMAIN``, explicit lookup, doctor, batch, and MCP.
Non-command first arguments route to lookup so domain validation owns diagnostics.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.markup import escape

from recon_tool.cli import batch as cli_batch
from recon_tool.cli import doctor as cli_doctor
from recon_tool.cli import lookup as cli_lookup
from recon_tool.cli.cache import cache_app
from recon_tool.cli.fingerprints import fingerprints_app
from recon_tool.cli.mcp import mcp_app
from recon_tool.cli.options import (
    LookupDisplayOptions,
    LookupExecutionOptions,
    LookupInferenceOptions,
    LookupOperationOptions,
    LookupOptions,
    LookupOutputOptions,
)
from recon_tool.cli.shared import fmt_exc as _fmt_exc
from recon_tool.cli.shared import help_markup_mode as _help_markup_mode
from recon_tool.cli.shared import positive_finite_float, raise_lookup_error
from recon_tool.cli.shared import render_usage_rows as _render_usage_rows
from recon_tool.cli.signals import signals_app
from recon_tool.formatter import get_console, get_err_console

# Command-implementation re-export facade (see cli_lookup / cli_batch / cli_doctor).
_lookup = cli_lookup.lookup
_batch = cli_batch.batch
_discover = cli_batch.discover
_read_batch_domains = cli_batch.read_batch_domains
_batch_validate_flags = cli_batch.batch_validate_flags
_batch_emit_summary = cli_batch.batch_emit_summary
_batch_emit_json = cli_batch.batch_emit_json
_doctor = cli_doctor.doctor
_doctor_fix = cli_doctor.doctor_fix
_doctor_client = cli_doctor.doctor_client
_doctor_mcp = cli_doctor.doctor_mcp

if TYPE_CHECKING:
    import click


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

_OUTPUT_HELP_PANEL = "Output"
_REPORT_HELP_PANEL = "Report detail and wording"
_COLLECTION_HELP_PANEL = "Collection, cache, and scope"
_ANALYSIS_HELP_PANEL = "Analysis modes"
_EVIDENCE_HELP_PANEL = "Evidence model"
_HELP_TERMINAL_WIDTH = shutil.get_terminal_size(fallback=(80, 24)).columns


class _DomainGroup(typer.core.TyperGroup):  # pyright: ignore[reportUntypedBaseClass, reportAttributeAccessIssue]
    """Custom Click group that routes bare domain args to the lookup command.

    When the first positional arg is not a known subcommand or flag, treat it
    as a domain and route to ``lookup`` so validation can speak in domain
    language. Requiring a dot used to force undotted attempts such as
    ``recon alpha`` into Click's "No such command" path.
    """

    def resolve_command(
        self,
        ctx: click.Context,
        args: list[str],
    ) -> tuple[str | None, click.Command | None, list[str]]:
        # Route a bare first arg to ``lookup`` *before* normal resolution,
        # rather than catching a "no such command" error and retrying. The
        # catch-and-retry form depended on which Click raised the error:
        # Typer >=0.25 vendors its own Click, so the UsageError is
        # ``typer._click``'s, not the top-level ``click``'s, and an
        # ``except click.UsageError`` silently misses it (the regression that
        # broke ``recon <domain>`` on fresh installs). Rewriting up front has
        # no such dependency. Known subcommands and flags are left alone;
        # every other non-empty first token is domain input for lookup.
        if args and args[0] not in _SUBCOMMANDS and not args[0].startswith("-"):
            args = ["lookup", *args]
        return super().resolve_command(ctx, args)


app = typer.Typer(
    name="recon",
    help=(
        "Passive domain intelligence from public sources. "
        "Start with recon DOMAIN; run recon with no arguments for examples."
    ),
    rich_markup_mode=_help_markup_mode(),
    cls=_DomainGroup,
    subcommand_metavar="[DOMAIN | COMMAND [ARGS]...]",
    # `-h` as a help alias everywhere (Click propagates help_option_names to
    # every subcommand context), matching the near-universal CLI convention.
    context_settings={"help_option_names": ["-h", "--help"], "terminal_width": _HELP_TERMINAL_WIDTH},
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

        for namespace in ("recon", "recon_tool"):
            logger = logging.getLogger(namespace)
            if not any(handler.get_name() == "recon-cli-debug" for handler in logger.handlers):
                handler = logging.StreamHandler()
                handler.set_name("recon-cli-debug")
                handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
                logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
            logger.propagate = False


def _confidence_mode_callback(value: str) -> str:
    """Normalize and validate lookup output confidence language mode."""
    normalized = value.strip().lower()
    if normalized not in {"hedged", "strict"}:
        raise typer.BadParameter("must be 'hedged' or 'strict'")
    return normalized


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
        help=("Enable diagnostic logging. Review before sharing; logs may contain domain inputs and local details."),
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
    recon - passive domain intelligence from public sources.

    Give it any domain. Get back public identity responses, email-routing
    observations, domain-control indicators, and their provenance.
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
    console.print(f"[bold cyan]recon {__version__}[/bold cyan] - Passive domain intelligence")
    console.print()
    console.print(
        "Observe what a domain publishes through public DNS and identity endpoints.\n"
        "Evidence is role-scoped and hedged. Zero credentials. Zero scanning."
    )
    console.print(
        "DNS queries may be observed by recursive and authoritative infrastructure.\n"
        "The only default target-owned HTTP request fetches the MTA-STS policy.\n"
        "Google CSE and BIMI direct probes run only with --direct-probes."
    )
    console.print()
    console.print("[bold cyan]Usage[/bold cyan]")
    _render_usage_rows(
        console,
        (
            ("recon <domain>", "clean summary (recommended)"),
            ("recon <domain> --plain", "linear output for screen readers and grep"),
            ("recon <domain> --json", "structured automation"),
            ("recon <domain> --explain", "evidence and explanation"),
            ("recon batch domains.txt", "process multiple domains"),
            ("recon doctor", "check online source connectivity"),
            ("recon mcp install --help", "connect an MCP client"),
        ),
    )
    console.print()
    console.print("[bold cyan]Common examples[/bold cyan]")
    console.print("  recon alpha.invalid")
    console.print("  recon gamma.invalid --verbose")
    console.print("  recon beta.invalid --full --json")
    console.print()
    console.print(
        "[dim]Pass a public-suffix domain (for example, example.com). Bare hostnames without a "
        "dot are rejected as invalid domain format.[/dim]"
    )
    console.print(
        '[dim]Use "recon --version" or "python -m recon_tool --version" for an offline '
        'install check; "recon doctor" tests online sources.[/dim]'
    )


@app.command(short_help="Look up a domain.")
def lookup(
    domain: str = typer.Argument(help="Domain to look up"),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Structured JSON output",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    markdown: bool = typer.Option(
        False,
        "--md",
        help="Markdown report",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    plain: bool = typer.Option(
        False,
        "--plain",
        help="Plain linear text for grep and screen readers",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    services: bool = typer.Option(
        False,
        "--services",
        "-s",
        help="Services are shown by default; retained for compatibility",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    domains: bool = typer.Option(
        False,
        "--domains",
        "-d",
        help="All tenant domains",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Expanded evidence, all domains, and posture",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Expanded evidence and per-source status",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    sources: bool = typer.Option(
        False,
        "--sources",
        help="Detailed source breakdown table",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Max seconds for the full resolve pipeline (default: 120)",
        callback=positive_finite_float,
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    posture: bool = typer.Option(
        False,
        "--posture",
        "-p",
        help="Show posture observations",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    compare: str | None = typer.Option(
        None,
        "--compare",
        help="Compare against previous JSON export",
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    chain: bool = typer.Option(
        False,
        "--chain",
        help="Recursively follow related domains",
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    depth: int = typer.Option(
        1,
        "--depth",
        help="Chain depth (1-3, requires --chain)",
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass disk cache entirely",
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    cache_ttl: int = typer.Option(
        86400,
        "--cache-ttl",
        help="Cache TTL in seconds (default: 86400)",
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    exposure: bool = typer.Option(
        False,
        "--exposure",
        help="Show exposure assessment",
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    gaps: bool = typer.Option(
        False,
        "--gaps",
        help="Show hardening gap analysis",
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Show why each insight and signal was produced",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Apply a profile lens to posture observations (e.g. fintech, healthcare, high-value-target)",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    confidence_mode: str = typer.Option(
        "hedged",
        "--confidence-mode",
        callback=_confidence_mode_callback,
        help=(
            "Wording style: 'hedged' (default) or 'strict'. Strict removes qualifiers from panel "
            "insights only on results at High confidence with at least three sources; underlying evidence, "
            "validation, and confidence are unchanged."
        ),
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Shortcut for strict wording; underlying evidence and confidence are unchanged.",
        rich_help_panel=_REPORT_HELP_PANEL,
    ),
    fusion: bool = typer.Option(
        True,
        "--fusion/--no-fusion",
        help=(
            "Compute per-slug evidence strength plus model-relative Bayesian "
            "posteriors and uncertainty bands (on by default from v2.0; "
            "--no-fusion to skip)"
        ),
        rich_help_panel=_EVIDENCE_HELP_PANEL,
    ),
    explain_dag: bool = typer.Option(
        False,
        "--explain-dag",
        help=(
            "Render the Bayesian evidence DAG as plain English (default) "
            "or DOT (with --explain-dag-format dot). Implies --fusion."
        ),
        rich_help_panel=_EVIDENCE_HELP_PANEL,
    ),
    explain_dag_format: str = typer.Option(
        "text",
        "--explain-dag-format",
        help=(
            "Output format for --explain-dag: 'text' (default), 'dot' "
            "(Graphviz), or 'mermaid' (renders inline in GitHub, "
            "Notion, and most AI chat clients)."
        ),
        rich_help_panel=_EVIDENCE_HELP_PANEL,
    ),
    include_unclassified: bool = typer.Option(
        False,
        "--include-unclassified",
        help=(
            "Include bounded typed catalog coverage and unmatched DNS values "
            "in --json output for private fingerprint discovery."
        ),
        rich_help_panel=_OUTPUT_HELP_PANEL,
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
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    direct_probes: bool = typer.Option(
        False,
        "--direct-probes",
        help=(
            "Opt in to direct HTTPS probes of target-controlled endpoints "
            "(the Google CSE discovery probe at cse.<domain>, and the BIMI VMC "
            "certificate fetch). Off by default, DNS queries use the configured "
            "recursive resolver, and authoritative DNS may observe the resulting "
            "traffic. The standard MTA-STS policy fetch is the only default "
            "target-owned HTTP/application request. BIMI presence is detected from "
            "DNS either way."
        ),
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    exact: bool = typer.Option(
        False,
        "--exact",
        help=(
            "Analyze the exact host given instead of reducing to the "
            "registrable apex. By default a pasted URL or sub-host "
            "(mail.example.co.uk) is reduced to its apex (example.co.uk), where "
            "recon's signal lives; --exact keeps the literal host for the "
            "narrow case of wanting DNS facts about that one sub-host."
        ),
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
) -> None:
    """
    Look up a domain. This is the default command.

    Start with recon DOMAIN. Add --full for detail, --explain for evidence,
    or --json for automation. Google CSE and BIMI probes require --direct-probes;
    MTA-STS is the only default target-owned HTTP request.
    """
    effective_confidence_mode = "strict" if strict else confidence_mode
    options = LookupOptions(
        output=LookupOutputOptions(
            json_output=json_output,
            markdown=markdown,
            plain=plain,
            include_unclassified=include_unclassified,
        ),
        display=LookupDisplayOptions.from_flags(
            services=services,
            domains=domains,
            full=full,
            verbose=verbose,
            sources=sources,
            posture=posture,
            explain=explain,
            profile=profile,
            confidence_mode=effective_confidence_mode,
        ),
        operation=LookupOperationOptions(
            compare_file=compare,
            chain_mode=chain,
            chain_depth=depth,
            show_exposure=exposure,
            show_gaps=gaps,
        ),
        inference=LookupInferenceOptions(
            fusion=fusion,
            explain_dag=explain_dag,
            explain_dag_format=explain_dag_format,
        ),
        execution=LookupExecutionOptions(
            timeout=timeout,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            skip_ct=no_ct,
            active_probes=direct_probes,
            exact=exact,
        ),
    )
    asyncio.run(
        _lookup(
            domain,
            options,
        )
    )


@app.command(short_help="Look up domains in a file.")
def batch(
    file: str = typer.Argument(help="File with one domain per line, or - to read domains from stdin"),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="JSON array output",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    markdown: bool = typer.Option(
        False,
        "--md",
        help="Markdown report per domain",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    csv_output: bool = typer.Option(
        False,
        "--csv",
        help="CSV output",
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Max concurrent lookups. Concurrency is clamped to 1-20.",
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Max seconds for each domain's full resolve pipeline.",
        callback=positive_finite_float,
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    include_unclassified: bool = typer.Option(
        False,
        "--include-unclassified",
        help=(
            "Include bounded typed catalog coverage and unmatched DNS values "
            "in JSON output for the private fingerprint-discovery loop. Off by default."
        ),
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    no_ct: bool = typer.Option(
        False,
        "--no-ct",
        help=(
            "Skip cert-transparency providers (crt.sh, CertSpotter) for every "
            "domain in the batch. For high-volume corpus runs."
        ),
        rich_help_panel=_COLLECTION_HELP_PANEL,
    ),
    ndjson: bool = typer.Option(
        False,
        "--ndjson",
        help=(
            "Stream one JSON object per line, flushed as each domain completes. "
            "Recommended for large corpora; gives visible progress and lower memory "
            "use vs the default --json array. Mutually exclusive with --json/--md/--csv."
        ),
        rich_help_panel=_OUTPUT_HELP_PANEL,
    ),
    include_ecosystem: bool = typer.Option(
        False,
        "--include-ecosystem",
        help=(
            "(v1.8+) Compute the cross-domain ecosystem hypergraph and attach it "
            "to JSON output as ecosystem_hyperedges. Requires --json. "
            "Hyperedges describe shared infrastructure / fingerprint / BIMI / "
            "parent-vendor signatures across the batch; observable structure, "
            "not ownership."
        ),
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    fusion: bool = typer.Option(
        True,
        "--fusion/--no-fusion",
        help=(
            "Compute model-relative Bayesian-network posteriors and "
            "evidence-responsive uncertainty bands "
            "over high-level claims for every domain. On by default from v2.0; "
            "--no-fusion skips it. Adds the posterior_observations field to "
            "each domain's JSON. Pure post-processing, no extra network calls."
        ),
        rich_help_panel=_EVIDENCE_HELP_PANEL,
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help=(
            "Emit one aggregate-only cohort summary over the whole batch instead "
            "of per-domain records: declarative public-claim rates, hideable "
            "model support coverage, model-score mass, and provider / cloud "
            "concentration. Stateless, ships no "
            "baselines, names no domain. Add --json for machine output. For "
            "caller-grouped analysis, see docs/aggregate-state.md."
        ),
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
    summary_schema: str = typer.Option(
        "2.1",
        "--summary-schema",
        help=(
            "Cohort summary contract: 2.1 preserves the released behavior; "
            "2.2 opts into raw-evidence-bound public claims and corrected missingness. "
            "The nondefault 2.2 value requires --summary."
        ),
        rich_help_panel=_ANALYSIS_HELP_PANEL,
    ),
) -> None:
    """
    Look up multiple domains from a file.

    One domain per line. Lines starting with # are skipped.

    Per-domain failures are output records and keep exit 0. In JSON or NDJSON,
    inspect record_type; in CSV, inspect error.
    """
    concurrency = max(1, min(20, concurrency))
    asyncio.run(
        _batch(
            file,
            json_output,
            markdown,
            concurrency,
            timeout,
            csv_output=csv_output,
            include_unclassified=include_unclassified,
            skip_ct=no_ct,
            ndjson=ndjson,
            include_ecosystem=include_ecosystem,
            fusion=fusion,
            summary=summary,
            summary_schema=summary_schema,
        )
    )


@app.command(short_help="Find fingerprint candidates.")
def discover(
    domain: str = typer.Argument(help="Domain to mine for fingerprint candidates"),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write candidates JSON here. Default: stdout.",
    ),
    no_ct: bool = typer.Option(False, "--no-ct", help="Skip cert-transparency providers."),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Resolve timeout in seconds.",
        callback=positive_finite_float,
    ),
    keep_intra_org: bool = typer.Option(
        False,
        "--keep-intra-org",
        help="Don't filter chains that look intra-organizational (false-positive prone but more inclusive).",
    ),
    min_count: int = typer.Option(
        1,
        "--min-count",
        help="Drop suffixes seen fewer than N times. Default 1: single domain runs, every distinct chain matters.",
    ),
) -> None:
    """
    Mine a single domain for fingerprint candidates in one shot.

    Bundles recon DOMAIN --json --include-unclassified with the
    bucket / intra-org / already-covered filters. Output is the same shape
    consumed by the /recon-fingerprint-triage skill, ready for human or
    LLM judgment.
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


@app.command(short_help="Check source health.")
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Scaffold template config files"),
    mcp: bool = typer.Option(False, "--mcp", help="Validate MCP server setup and emit an mcpServers reference config"),
    client: str | None = typer.Option(
        None,
        "--client",
        help="Check whether a client's MCP config has the recon stanza "
        "(claude-code, claude-desktop, cursor, vscode, windsurf, kiro). "
        "Reads the config file the client loads. The config-side complement "
        "to --mcp, which validates the server itself.",
    ),
) -> None:
    """Check installation health and online source connectivity.
    Synthetic checks: Microsoft identity endpoints, DNS for example.com, and crt.sh. No user-supplied target is queried.
    --fix, --mcp, and --client are local-only modes."""
    mode_count = int(fix) + int(mcp) + int(client is not None)
    if mode_count > 1:
        get_console().print("[red]Choose exactly one of --fix, --mcp, or --client.[/red]")
        raise typer.Exit(code=EXIT_VALIDATION)
    if fix:
        if not _doctor_fix():
            raise typer.Exit(code=EXIT_ERROR)
        return
    if client is not None:
        _doctor_client(client)
        return
    if mcp:
        _doctor_mcp()
        return
    asyncio.run(_doctor())


@app.command(short_help="Check for updates.")
def update(
    check: bool = typer.Option(False, "--check", help="Only report whether a newer version exists; do not install."),
) -> None:
    """Check for and install the latest recon release.

    Detects how recon was installed (pipx / uv / pip / editable) and
    runs the matching upgrade, or prints the exact command when it can't safely
    self-upgrade. --check only reports. Status goes to stderr; the result
    line to stdout, so `recon update --check` is scriptable.
    """
    import subprocess

    from recon_tool import updater
    from recon_tool.formatter import render_error

    console = get_console()
    err = get_err_console()
    current = updater.current_version()

    err.print(f"recon {current}: checking PyPI for updates...")
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
        console.print(f"  install method: {method}")
        if cmd is None:
            console.print(f"  to upgrade:     [cyan]{updater.manual_hint(method)}[/cyan]")
        else:
            console.print(f"  to upgrade:     [cyan]{' '.join(cmd)}[/cyan]   (or just: recon update)")
        return
    if cmd is None:
        console.print(f"Detected a {method} install; manual action needed: [cyan]{updater.manual_hint(method)}[/cyan]")
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


# ── MCP CLI ───────────────────────────────────────────────────────────

app.add_typer(mcp_app, name="mcp", short_help="Run or configure MCP.")


# ── Cache CLI ─────────────────────────────────────────────────────────

app.add_typer(cache_app, name="cache", short_help="Manage local caches.")


# ── Fingerprints CLI ──────────────────────────────────────────────────

app.add_typer(fingerprints_app, name="fingerprints", short_help="Browse fingerprints.")

# ── Signals CLI ───────────────────────────────────────────────────────

app.add_typer(signals_app, name="signals", short_help="Browse signals.")

# ── Delta CLI ─────────────────────────────────────────────────────────


@app.command(short_help="Compare cached state.")
def delta(
    domain: str = typer.Argument(..., help="Domain to diff against cached snapshot"),
    json_output: bool = typer.Option(False, "--json", help="Output structured JSON"),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        help="Resolution timeout (seconds)",
        callback=positive_finite_float,
    ),
) -> None:
    """Compare the current lookup against the last cached TenantInfo.

    Surfaces confirmed changes since the previous run: services, slugs,
    signals, auth, DMARC, email control count (0-5), and confidence.
    Incomplete collections suppress unconfirmable additions, removals, and
    dependent scalar changes. Uses the main TenantInfo cache
    (~/.recon/cache/) automatically; no manual export file required.
    """
    from recon_tool.cache import cache_get, cache_put, tenant_info_to_dict
    from recon_tool.delta import compute_delta, validate_snapshot_domain
    from recon_tool.formatter import format_delta_json, render_delta_panel, render_error
    from recon_tool.models import ReconLookupError
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
        output_console = get_err_console() if json_output else console
        output_console.print(
            f"  No cached snapshot for [bold]{validated}[/bold].\n"
            f"  Run `recon {validated}` first; the next `recon delta` "
            f"call will compare against that baseline."
        )
        raise typer.Exit(code=EXIT_NO_DATA)

    previous_dict = tenant_info_to_dict(cached)
    try:
        validate_snapshot_domain(previous_dict, validated)
    except ValueError as exc:
        render_error(_fmt_exc(exc))
        raise typer.Exit(code=EXIT_VALIDATION) from exc

    async def _run() -> None:
        try:
            info, _results = await resolve_tenant(validated, timeout=timeout)
        except ReconLookupError as exc:
            raise_lookup_error(exc, domain=validated)
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


def _silence_closed_standard_streams() -> None:
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


def run() -> None:
    """Entry point — invokes the Typer app.

    The callback handles shorthand domain syntax (e.g., `recon alpha.invalid`)
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
    except Exception as exc:  # top-level last-resort crash handler (catch-all is intentional)
        import errno
        import os

        closed_pipe = isinstance(exc, BrokenPipeError) or (
            isinstance(exc, OSError) and (exc.errno == errno.EPIPE or (os.name == "nt" and exc.errno == errno.EINVAL))
        )
        if closed_pipe:
            _silence_closed_standard_streams()
            raise SystemExit(0) from None

        import tempfile
        import traceback

        from recon_tool.exit_codes import EXIT_INTERNAL

        crash_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="recon-crash-",
                suffix=".log",
                dir=tempfile.gettempdir(),
                delete=False,
            ) as crash_file:
                crash_file.write(traceback.format_exc())
                crash_path = Path(crash_file.name)
        except Exception:  # never fail inside the crash handler
            crash_path = None
        if crash_path is None:
            get_err_console().print(
                "[red]recon hit an unexpected error and could not create a crash log.[/red]\n"
                "Confirm the system temporary directory is writable, then rerun the command. "
                "If the failure persists, report the command shape and exit code 4 at "
                "https://github.com/blisspixel/recon/issues without including private inputs."
            )
        else:
            where = f"[link={crash_path.as_uri()}]{escape(str(crash_path))}[/link]"
            get_err_console().print(
                f"[red]recon hit an unexpected error.[/red] Details written to {where}\n"
                "Review and redact the log before sharing it at "
                "https://github.com/blisspixel/recon/issues; it may contain local paths, "
                "domain inputs, configuration values, or exception details."
            )
        raise SystemExit(EXIT_INTERNAL) from None


if __name__ == "__main__":
    run()
