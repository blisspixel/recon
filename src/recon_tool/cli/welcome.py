"""Onboarding banner shown when ``recon`` runs with no arguments."""

from __future__ import annotations

from recon_tool.cli.shared import render_usage_rows
from recon_tool.formatter import get_console
from recon_tool.formatter.theme import ACCENT


def print_welcome_banner() -> None:
    """Print the curated onboarding banner shown when ``recon`` is run
    with no arguments. Replaces the raw Typer help dump that was
    shown before.

    Kept tight - fits on ~15 lines - with a one-line value prop, the
    recommended first command, progressive disclosure, three real
    examples, and a doctor hint. No emojis, no hype, no wall of
    flags. Users who want the full flag list can run
    ``recon lookup --help`` or ``recon --help <subcommand>``.
    """
    from recon_tool import __version__

    console = get_console()
    # Subtle cyan for the header and section labels - matches the
    # panel redesign tone. No red, no yellow, no alarmism.
    console.print(f"[bold {ACCENT}]recon {__version__}[/bold {ACCENT}] - Passive domain intelligence")
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
    console.print(f"[bold {ACCENT}]Usage[/bold {ACCENT}]")
    render_usage_rows(
        console,
        (
            ("recon <domain>", "clean summary (recommended)"),
            ("recon <domain> --plain", "panel as linear text for screen readers and grep"),
            ("recon <domain> --md", "grouped Markdown; --full is the connection map"),
            ("recon <domain> --json", "structured automation"),
            ("recon <domain> --explain", "evidence and explanation"),
            ("recon review <domain>", "fresh evidence-linked review handoff"),
            ("recon batch domains.txt", "process multiple domains"),
            ("recon doctor", "check online source connectivity"),
            ("recon mcp install --help", "connect an MCP client"),
        ),
    )
    console.print()
    console.print(f"[bold {ACCENT}]Common examples[/bold {ACCENT}]")
    console.print("  recon example.com")
    console.print("  recon review example.com")
    console.print("  recon example.com --verbose")
    console.print("  recon example.com --full --json")
    console.print(
        "[dim]These are real lookup commands, not an offline demo. Ordinary lookups may "
        "reuse the default 24-hour result cache; pass --no-cache for fresh collection. "
        "These examples use reserved example.com to show flag shapes. Reserved names return "
        "stray public residue at High confidence, not a company result. Point recon at a "
        "domain you want to review.[/dim]"
    )
    console.print(
        "[dim]Pass a public-suffix domain (for example, example.com). Bare hostnames without a "
        "dot are rejected as invalid domain format.[/dim]"
    )
    console.print(
        '[dim]Use "recon --version" or "python -m recon_tool --version" for an offline '
        'install check; "recon doctor" tests online sources.[/dim]'
    )
