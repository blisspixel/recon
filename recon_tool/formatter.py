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

from recon_tool.models import (
    ChainReport,
    ConfidenceLevel,
    DeltaReport,
    Observation,
    SourceResult,
    TenantInfo,
)

__all__ = [
    "detect_provider",
    "format_chain_dict",
    "format_chain_json",
    "format_delta_dict",
    "format_delta_json",
    "format_posture_observations",
    "format_tenant_dict",
    "format_tenant_json",
    "format_tenant_markdown",
    "get_console",
    "render_chain_panel",
    "render_delta_panel",
    "render_error",
    "render_posture_panel",
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
    ConfidenceLevel.HIGH: "#a3d9a5",     # soft sage green
    ConfidenceLevel.MEDIUM: "#7ec8e3",   # muted sky blue
    ConfidenceLevel.LOW: "#e07a5f",      # warm terracotta
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
    "exchange", "teams", "intune", "mdm", "dkim",
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


def _wrap_service_list(
    services: list[str],
    label_width: int = 14,
    panel_width: int = 80,
    panel_pad: int = 2,
) -> str:
    """Join services with comma-separation, wrapping lines to align under the label.

    The available content width inside a Rich Panel is:
        panel_width - 2 (border chars) - 2 * panel_pad (left + right padding)

    The first line starts after the label (e.g. "  Services:   "), so it has
    fewer chars available than continuation lines.  Continuation lines are
    indented with spaces so text aligns with the first service name.
    """
    content_width = panel_width - 2 - 2 * panel_pad
    # First line: "  " prefix + label already consumed by caller
    first_line_max = content_width - 2 - label_width
    # Continuation lines: indented by label_width (no "  " prefix needed)
    cont_line_max = content_width - label_width
    continuation_indent = " " * label_width

    joined = ", ".join(services)
    # If it fits on one line, just return it
    if len(joined) <= first_line_max:
        return joined

    # Word-wrap at comma boundaries.
    # Account for trailing comma (1 char) on non-final lines when checking fit.
    lines: list[str] = []
    current_line = ""
    for svc in services:
        candidate = svc if not current_line else f"{current_line}, {svc}"
        limit = first_line_max if not lines else cont_line_max
        # Reserve 1 char for the trailing comma on non-final lines
        if current_line and len(candidate) + 1 > limit:
            lines.append(current_line + ",")
            current_line = svc
        else:
            current_line = candidate
    if current_line:
        lines.append(current_line)

    return ("\n" + continuation_indent).join(lines)


def _wrap_text(text: str, max_width: int) -> list[str]:
    """Word-wrap a plain text string to fit within max_width characters."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) > max_width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [text]


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
    text.append("  Company:    ", style="dim")
    text.append(f"{info.display_name}\n")
    text.append("  Domain:     ", style="dim")
    text.append(f"{info.default_domain}\n")
    text.append("  Provider:   ", style="dim")
    text.append(f"{provider}\n")

    # M365-specific fields — only shown when provider is Microsoft
    if is_m365 and info.tenant_id:
        text.append("  Tenant ID:  ", style="dim")
        text.append(f"{info.tenant_id}\n")
    if info.region:
        text.append("  Region:     ", style="dim")
        text.append(f"{info.region}\n")
    if info.auth_type:
        text.append("  Auth:       ", style="dim")
        text.append(f"{info.auth_type}\n")

    text.append("  Confidence: ", style="dim")
    text.append(f"{dots} {info.confidence.value.capitalize()} ({source_count} sources)", style=color)

    # Always show services — compact by default, split into M365/Tech Stack with --services
    if info.services:
        if show_services:
            m365_svcs = [svc for svc in info.services if _is_m365_service(svc)]
            other_svcs = [svc for svc in info.services if not _is_m365_service(svc)]
            if m365_svcs:
                text.append("\n")
                text.append("  M365:       ", style="dim")
                text.append(_wrap_service_list(m365_svcs, label_width=14, panel_width=80, panel_pad=2))
            if other_svcs:
                text.append("\n")
                text.append("  Tech Stack: ", style="dim")
                text.append(_wrap_service_list(other_svcs, label_width=14, panel_pad=2))
        else:
            compact = [svc for svc in info.services if not _is_compact_noise(svc)]
            if compact:
                text.append("\n")
                text.append("  Services:   ", style="dim")
                text.append(_wrap_service_list(compact, label_width=14, panel_width=80, panel_pad=2))

    # Insights — separated by a blank line, same label:value alignment as other fields
    if info.insights:
        indent = " " * 14  # align with value column
        max_width = 80 - 2 - 4 - 14  # panel - borders - padding - label
        for i, insight in enumerate(info.insights):
            if i == 0:
                text.append("\n\n")
                text.append("  Insights:   ", style="dim")
            else:
                text.append("\n")
                text.append(indent)

            # Determine style for this insight
            if "gap" in insight.lower() or "not enforced" in insight.lower() or "not configured" in insight.lower():
                style = "#e07a5f"  # warm terracotta for warnings
            elif "hybrid" in insight.lower() or "migration" in insight.lower():
                style = "#e6c07b"  # soft amber for transitions
            else:
                style = None

            # Wrap long insights to stay within the panel
            if len(insight) <= max_width:
                text.append(insight, style=style)
            else:
                wrapped = _wrap_text(insight, max_width)
                for j, line in enumerate(wrapped):
                    if j > 0:
                        text.append("\n")
                        text.append(indent)
                    text.append(line, style=style)

    # Certificate summary — after insights, before domains
    if info.cert_summary is not None:
        cs = info.cert_summary
        issuer_list = ", ".join(cs.top_issuers) if cs.top_issuers else "unknown"
        text.append("\n\n")
        text.append("  Certs:      ", style="dim")
        text.append(
            f"{cs.cert_count} total, {cs.issuance_velocity} in last 90d, "
            f"{cs.issuer_diversity} issuers ({issuer_list})"
        )

    # Domains (opt-in via --domains or --full)
    if show_domains and info.tenant_domains:
        text.append("\n\n")
        text.append(f"  Domains ({info.domain_count}):", style="dim")
        for d in info.tenant_domains:
            text.append(f"\n    {d}", style="dim")

    # Related domains — supplementary, shown dim
    if info.related_domains:
        text.append("\n\n")
        text.append("  Related:    ", style="dim")
        text.append(", ".join(info.related_domains), style="dim")

    # crt.sh degraded notice — subtle hint that results may be partial
    if info.crtsh_degraded:
        text.append("\n\n")
        text.append("  Note:       ", style="dim")
        text.append(
            "crt.sh was unreachable — some subdomains may be missing. "
            "Try again later for fuller results.",
            style="dim italic",
        )

    return Panel(
        text,
        title=info.display_name,
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


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
    d: dict[str, Any] = {
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
        "partial": info.crtsh_degraded,
    }
    if info.cert_summary is not None:
        d["cert_summary"] = {
            "cert_count": info.cert_summary.cert_count,
            "issuer_diversity": info.cert_summary.issuer_diversity,
            "issuance_velocity": info.cert_summary.issuance_velocity,
            "newest_cert_age_days": info.cert_summary.newest_cert_age_days,
            "oldest_cert_age_days": info.cert_summary.oldest_cert_age_days,
            "top_issuers": list(info.cert_summary.top_issuers),
        }
    return d


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

    # Certificate Intelligence
    if info.cert_summary is not None:
        cs = info.cert_summary
        lines.append("## Certificate Intelligence")
        lines.append("")
        lines.append(f"- **Total Certificates:** {cs.cert_count}")
        lines.append(f"- **Issuer Diversity:** {cs.issuer_diversity} distinct issuers")
        lines.append(f"- **Issuance Velocity:** {cs.issuance_velocity} certs in last 90 days")
        lines.append(f"- **Newest Cert Age:** {cs.newest_cert_age_days} days")
        lines.append(f"- **Oldest Cert Age:** {cs.oldest_cert_age_days} days")
        if cs.top_issuers:
            lines.append(f"- **Top Issuers:** {', '.join(cs.top_issuers)}")
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
    if info.crtsh_degraded:
        lines.append(
            "*Note: crt.sh was unreachable — some subdomains may be missing."
            " Try again later for fuller results.*  "
        )
    lines.append(f"*Sources: {', '.join(info.sources)}*")
    lines.append("")

    return "\n".join(lines)


# ── Posture observation rendering ────────────────────────────────────────

_SALIENCE_INDICATORS: dict[str, str] = {
    "high": "●",
    "medium": "◐",
    "low": "○",
}


def format_posture_observations(observations: tuple[Observation, ...]) -> list[dict[str, Any]]:
    """Format observations as a list of dicts for JSON output."""
    return [
        {
            "category": obs.category,
            "salience": obs.salience,
            "statement": obs.statement,
            "related_slugs": list(obs.related_slugs),
        }
        for obs in observations
    ]


def render_posture_panel(observations: tuple[Observation, ...]) -> Panel | None:
    """Render posture observations as a Rich panel grouped by category."""
    if not observations:
        return None

    # Group by category, preserving order of first appearance
    groups: dict[str, list[Observation]] = {}
    for obs in observations:
        groups.setdefault(obs.category, []).append(obs)

    text = Text()
    first_group = True
    for category, obs_list in groups.items():
        if not first_group:
            text.append("\n\n")
        first_group = False

        text.append(f"  {category.replace('_', ' ').title()}\n", style="bold")
        for obs in obs_list:
            indicator = _SALIENCE_INDICATORS.get(obs.salience, "○")
            text.append(f"  {indicator} ", style="dim")
            text.append(obs.statement)
            text.append("\n")

    return Panel(
        text,
        title="Posture Analysis",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Delta rendering ─────────────────────────────────────────────────────


def format_delta_dict(report: DeltaReport) -> dict[str, Any]:
    """Format DeltaReport as a dict for JSON output."""
    from datetime import datetime, timezone

    d: dict[str, Any] = {
        "domain": report.domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "has_changes": report.has_changes,
        "added_services": list(report.added_services),
        "removed_services": list(report.removed_services),
        "added_slugs": list(report.added_slugs),
        "removed_slugs": list(report.removed_slugs),
        "added_signals": list(report.added_signals),
        "removed_signals": list(report.removed_signals),
    }
    if report.changed_auth_type is not None:
        d["changed_auth_type"] = {"from": report.changed_auth_type[0], "to": report.changed_auth_type[1]}
    if report.changed_dmarc_policy is not None:
        d["changed_dmarc_policy"] = {"from": report.changed_dmarc_policy[0], "to": report.changed_dmarc_policy[1]}
    if report.changed_email_security_score is not None:
        d["changed_email_security_score"] = {
            "from": report.changed_email_security_score[0],
            "to": report.changed_email_security_score[1],
        }
    if report.changed_confidence is not None:
        d["changed_confidence"] = {"from": report.changed_confidence[0], "to": report.changed_confidence[1]}
    if report.changed_domain_count is not None:
        d["changed_domain_count"] = {"from": report.changed_domain_count[0], "to": report.changed_domain_count[1]}
    return d


def format_delta_json(report: DeltaReport) -> str:
    """Format DeltaReport as a JSON string."""
    return json.dumps(format_delta_dict(report), indent=2)


def render_delta_panel(report: DeltaReport) -> Panel:
    """Render delta report as a Rich panel with +/- markers."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{report.domain}\n")

    if not report.has_changes:
        text.append("\n  No changes detected.", style="dim italic")
    else:
        # Services
        for svc in report.added_services:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Service: {svc}", style="green")
        for svc in report.removed_services:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Service: {svc}", style="red")

        # Slugs
        for slug in report.added_slugs:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Slug: {slug}", style="green")
        for slug in report.removed_slugs:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Slug: {slug}", style="red")

        # Signals
        for sig in report.added_signals:
            text.append("\n  ")
            text.append("+ ", style="green bold")
            text.append(f"Signal: {sig}", style="green")
        for sig in report.removed_signals:
            text.append("\n  ")
            text.append("- ", style="red bold")
            text.append(f"Signal: {sig}", style="red")

        # Scalar changes
        if report.changed_auth_type is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(f"Auth: {report.changed_auth_type[0]} → {report.changed_auth_type[1]}", style="yellow")
        if report.changed_dmarc_policy is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"DMARC: {report.changed_dmarc_policy[0]} → {report.changed_dmarc_policy[1]}", style="yellow"
            )
        if report.changed_email_security_score is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"Email Security Score: {report.changed_email_security_score[0]} → "
                f"{report.changed_email_security_score[1]}",
                style="yellow",
            )
        if report.changed_confidence is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"Confidence: {report.changed_confidence[0]} → {report.changed_confidence[1]}", style="yellow"
            )
        if report.changed_domain_count is not None:
            text.append("\n  ")
            text.append("~ ", style="yellow bold")
            text.append(
                f"Domain Count: {report.changed_domain_count[0]} → {report.changed_domain_count[1]}",
                style="yellow",
            )

    return Panel(
        text,
        title="Delta Report",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Chain rendering ──────────────────────────────────────────────────────


def format_chain_dict(report: ChainReport) -> dict[str, Any]:
    """Format ChainReport as a dict for JSON output."""
    return {
        "total_domains": len(report.results),
        "max_depth_reached": report.max_depth_reached,
        "truncated": report.truncated,
        "domains": [
            {
                **format_tenant_dict(r.info),
                "chain_depth": r.chain_depth,
            }
            for r in report.results
        ],
    }


def format_chain_json(report: ChainReport) -> str:
    """Format ChainReport as a JSON string."""
    return json.dumps(format_chain_dict(report), indent=2)


def render_chain_panel(report: ChainReport) -> Panel:
    """Render chain report as a Rich panel with domain tree."""
    text = Text()

    text.append("  Total Domains: ", style="dim")
    text.append(f"{len(report.results)}\n")
    text.append("  Max Depth:     ", style="dim")
    text.append(f"{report.max_depth_reached}\n")
    if report.truncated:
        text.append("  Status:        ", style="dim")
        text.append("Truncated (cap reached)", style="yellow")
        text.append("\n")

    # Domain tree grouped by depth
    if report.results:
        text.append("\n")
        current_depth = -1
        for r in report.results:
            if r.chain_depth != current_depth:
                current_depth = r.chain_depth
                text.append(f"  Depth {current_depth}:\n", style="bold")
            indent = "    " + "  " * r.chain_depth
            provider = detect_provider(r.info.services, r.info.slugs)
            text.append(f"{indent}{r.domain}", style="cyan")
            text.append(f" — {r.info.display_name}", style="dim")
            if provider != "Unknown":
                text.append(f" ({provider})", style="dim")
            text.append("\n")

    return Panel(
        text,
        title="Chain Resolution",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )
