"""Rich terminal output formatting for domain intelligence.

Console management: All output goes through get_console(). The CLI module
should use get_console() instead of creating its own Console instance, so
that set_console() in tests captures everything.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

__all__ = [
    "detect_provider",
    "format_tenant_dict",
    "format_tenant_json",
    "format_tenant_markdown",
    "get_console",
    "render_error",
    "render_sources_detail",
    "render_tenant_panel",
    "render_verbose_sources",
    "render_warning",
    "set_console",
]

# Default console — can be overridden via get_console/set_console for testing.
# Why a global instead of dependency injection? Because Rich's Console is used
# by dozens of call sites (render_*, cli status spinners, etc.) and threading
# a console parameter through every function would be noisy. The global is
# effectively a singleton with a test seam via set_console().
_console: Console | None = None


def get_console() -> Console:
    """Return the active console instance, creating a default if needed."""
    global _console  # noqa: PLW0603
    if _console is None:
        _console = Console()
    return _console


def set_console(console: Console) -> None:
    """Replace the active console (for testing)."""
    global _console  # noqa: PLW0603
    _console = console


CONFIDENCE_COLORS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "green",
    ConfidenceLevel.MEDIUM: "yellow",
    ConfidenceLevel.LOW: "red",
}

CONFIDENCE_DOTS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "●●●",
    ConfidenceLevel.MEDIUM: "●●○",
    ConfidenceLevel.LOW: "●○○",
}

# M365-specific service keywords for display categorization (--services, markdown).
# COUPLING WARNING: If you add a new M365 service to fingerprints.yaml, you may
# need to add a keyword here too, or it will show up under "Tech Stack" instead
# of "M365" in the --services view. Detection logic uses slugs (not these keywords).
_M365_KEYWORDS = frozenset({
    "exchange", "teams", "skype", "intune", "mdm", "dkim",
    "microsoft", "domain verified",
})

# Services filtered from the compact (default) view because they appear
# in insights instead. Uses exact prefix matching to avoid false positives
# (e.g. a service named "Advanced DNS Security" won't be hidden).
_SKIP_COMPACT_PREFIXES = (
    "dmarc", "domain verified", "spf:", "spf complexity",
    "dns:", "cdn:", "hosting:", "waf:", "domain connect",
)

# Exact substrings that must appear as standalone tokens in the service name.
_SKIP_COMPACT_EXACT = frozenset({"(SPF)", "(site verified)"})


def _is_m365_service(svc: str) -> bool:
    """Check if a service name should be categorized as M365."""
    svc_lower = svc.lower()
    return any(kw in svc_lower for kw in _M365_KEYWORDS)


def _is_compact_noise(svc: str) -> bool:
    """Check if a service should be hidden from compact view.

    Uses prefix matching for category-style labels (DNS:, CDN:, etc.)
    and exact matching for specific tokens to avoid false positives.
    """
    svc_lower = svc.lower()
    if svc_lower.startswith(_SKIP_COMPACT_PREFIXES):
        return True
    return svc in _SKIP_COMPACT_EXACT


def detect_provider(services: tuple[str, ...] | set[str], slugs: tuple[str, ...] | set[str] = ()) -> str:
    """Detect the primary email/identity provider from slugs (preferred) or services."""
    slug_set = set(slugs)
    providers = []
    if "microsoft365" in slug_set:
        providers.append("Microsoft 365")
    if "google-workspace" in slug_set:
        providers.append("Google Workspace")
    if "zoho" in slug_set:
        providers.append("Zoho Mail")
    if "protonmail" in slug_set:
        providers.append("ProtonMail")
    if not providers and "aws-ses" in slug_set:
        providers.append("AWS SES")
    return " + ".join(providers) if providers else "Unknown"


def render_tenant_panel(
    info: TenantInfo,
    show_services: bool = False,
    show_domains: bool = False,
) -> Panel:
    """Render TenantInfo as a rich Panel — adapts to provider."""
    color = CONFIDENCE_COLORS[info.confidence]
    dots = CONFIDENCE_DOTS[info.confidence]
    source_count = len(info.sources)
    provider = detect_provider(info.services, info.slugs)
    is_m365 = "Microsoft" in provider

    text = Text()
    text.append("  Company:    ", style="bold")
    text.append(f"{info.display_name}\n")
    text.append("  Domain:     ", style="bold")
    text.append(f"{info.default_domain}\n")
    text.append("  Provider:   ", style="bold")
    text.append(f"{provider}\n")

    # M365-specific fields — only shown when provider is Microsoft
    if is_m365 and info.tenant_id:
        text.append("  Tenant ID:  ", style="bold")
        text.append(f"{info.tenant_id}\n")
    if info.region:
        text.append("  Region:     ", style="bold")
        text.append(f"{info.region}\n")
    if info.auth_type:
        text.append("  Auth:       ", style="bold")
        text.append(f"{info.auth_type}\n")

    text.append("  Confidence: ", style="bold")
    text.append(f"{dots} {info.confidence.value.capitalize()} ({source_count} sources)", style=color)

    # Always show services — compact by default, split into M365/Tech Stack with --services
    if info.services:
        if show_services:
            m365_svcs = [svc for svc in info.services if _is_m365_service(svc)]
            other_svcs = [svc for svc in info.services if not _is_m365_service(svc)]
            if m365_svcs:
                text.append("\n")
                text.append("  M365:       ", style="bold")
                text.append(", ".join(m365_svcs))
            if other_svcs:
                text.append("\n")
                text.append("  Tech Stack: ", style="bold")
                text.append(", ".join(other_svcs))
        else:
            compact = [svc for svc in info.services if not _is_compact_noise(svc)]
            if compact:
                text.append("\n")
                text.append("  Services:   ", style="bold")
                text.append(", ".join(compact), style="dim")

    # Always show insights
    if info.insights:
        text.append("\n")
        for insight in info.insights:
            text.append("\n  ")
            if "gap" in insight.lower() or "not enforced" in insight.lower() or "not configured" in insight.lower():
                text.append(insight, style="red")
            elif "hybrid" in insight.lower() or "migration" in insight.lower():
                text.append(insight, style="yellow")
            else:
                text.append(insight, style="dim")

    # Domains (opt-in via --domains or --full)
    if show_domains and info.tenant_domains:
        text.append("\n\n")
        text.append(f"  Domains ({info.domain_count}):", style="bold")
        for d in info.tenant_domains:
            text.append(f"\n    {d}")

    # Related domains — always shown when present (they're high-value intel)
    if info.related_domains:
        text.append("\n\n")
        text.append("  Related:    ", style="bold")
        text.append(", ".join(info.related_domains), style="cyan")

    return Panel(text, title=info.display_name)


def render_verbose_sources(results: list[SourceResult]) -> None:
    """Print per-source status lines to console."""
    c = get_console()
    for result in results:
        if result.is_success:
            description = _source_success_description(result)
            c.print(f"  [green]✓[/green] {result.source_name} — {description}")
        else:
            error_msg = result.error or "no data returned"
            c.print(f"  [red]✗[/red] {result.source_name} — {error_msg}")


def _source_success_description(result: SourceResult) -> str:
    """Build a brief description for a successful source result."""
    parts: list[str] = []
    if result.tenant_id:
        parts.append("tenant ID found")
    if result.region:
        parts.append("region confirmed")
    if result.m365_detected and not result.tenant_id:
        parts.append("M365 association detected")
    if result.display_name:
        parts.append("display name found")
    if result.auth_type:
        parts.append(f"auth: {result.auth_type}")
    if result.tenant_domains:
        parts.append(f"{len(result.tenant_domains)} domains")
    if result.dmarc_policy:
        parts.append(f"DMARC: {result.dmarc_policy}")
    return ", ".join(parts) if parts else "data returned"


def render_sources_detail(results: list[SourceResult]) -> Table:
    """Return a rich Table with detailed per-source data."""
    table = Table(title="Source Details")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Tenant ID")
    table.add_column("Region")
    table.add_column("Details")

    for result in results:
        status = Text("✓ success", style="green") if result.is_success else Text("✗ failed", style="red")
        tenant_id = result.tenant_id or "—"
        region = result.region or "—"
        details = result.error or ("M365 detected" if result.m365_detected else "—")
        table.add_row(result.source_name, status, tenant_id, region, details)

    return table


def render_warning(domain: str) -> None:
    """Print a yellow warning for not-found domains."""
    get_console().print(f"[yellow]No information found for {domain}[/yellow]")


def render_error(message: str) -> None:
    """Print a red error message."""
    get_console().print(f"[red]{message}[/red]")


def format_tenant_dict(info: TenantInfo) -> dict[str, Any]:
    """Build a dict representation of TenantInfo (shared by JSON and batch)."""
    provider = detect_provider(info.services, info.slugs)
    return {
        "tenant_id": info.tenant_id,
        "display_name": info.display_name,
        "default_domain": info.default_domain,
        "queried_domain": info.queried_domain,
        "provider": provider,
        "confidence": info.confidence.value,
        "region": info.region,
        "auth_type": info.auth_type,
        "dmarc_policy": info.dmarc_policy,
        "domain_count": info.domain_count,
        "sources": list(info.sources),
        "services": list(info.services),
        "insights": list(info.insights),
        "tenant_domains": list(info.tenant_domains),
        "related_domains": list(info.related_domains),
    }


def format_tenant_json(info: TenantInfo) -> str:
    """Format TenantInfo as a JSON string."""
    return json.dumps(format_tenant_dict(info), indent=2)


def format_tenant_markdown(info: TenantInfo) -> str:
    """Format TenantInfo as a markdown report."""
    lines: list[str] = []
    lines.append(f"# Tenant Report: {info.display_name}")
    lines.append("")
    lines.append(f"**Domain:** {info.queried_domain}  ")
    if info.tenant_id:
        lines.append(f"**Tenant ID:** `{info.tenant_id}`  ")
    lines.append(f"**Default Domain:** {info.default_domain}  ")
    if info.region:
        lines.append(f"**Region:** {info.region}  ")
    if info.auth_type:
        lines.append(f"**Auth Type:** {info.auth_type}  ")
    lines.append(f"**Confidence:** {info.confidence.value} ({len(info.sources)} sources)  ")
    lines.append("")

    # Services split
    if info.services:
        m365_svcs = [s for s in info.services if _is_m365_service(s)]
        other_svcs = [s for s in info.services if not _is_m365_service(s)]

        if m365_svcs:
            lines.append("## Microsoft 365 Services")
            lines.append("")
            for svc in m365_svcs:
                lines.append(f"- {svc}")
            lines.append("")

        if other_svcs:
            lines.append("## Tech Stack")
            lines.append("")
            for svc in other_svcs:
                lines.append(f"- {svc}")
            lines.append("")

    # Insights
    if info.insights:
        lines.append("## Insights")
        lines.append("")
        for insight in info.insights:
            lines.append(f"- {insight}")
        lines.append("")

    # Domains
    if info.tenant_domains:
        lines.append(f"## Tenant Domains ({info.domain_count})")
        lines.append("")
        for d in info.tenant_domains:
            lines.append(f"- {d}")
        lines.append("")

    # Related domains
    if info.related_domains:
        lines.append("## Related Domains")
        lines.append("")
        for d in info.related_domains:
            lines.append(f"- {d}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Sources: {', '.join(info.sources)}*")
    lines.append("")

    return "\n".join(lines)
