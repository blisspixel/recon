"""Structured and terminal rendering for snapshot deltas."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from rich.panel import Panel
from rich.text import Text

from recon_tool.models import DeltaReport
from recon_tool.validator import strip_control_chars


def format_delta_dict(report: DeltaReport) -> dict[str, Any]:
    """Format a delta using the stable machine-readable output shape."""

    def _change_pair(value: tuple[Any, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return {"from": value[0], "to": value[1]}

    limitation = report.incomplete_comparison
    incomplete_comparison = None
    if limitation is not None:
        previous_sources = limitation.previous_degraded_sources
        current_sources = limitation.current_degraded_sources
        if not previous_sources and not current_sources:
            # Compatibility for callers constructing the original two-field model.
            current_sources = limitation.degraded_sources
        incomplete_comparison = {
            "degraded_sources": list(limitation.degraded_sources),
            "suppressed_fields": list(limitation.suppressed_fields),
            "previous_degraded_sources": list(previous_sources),
            "current_degraded_sources": list(current_sources),
        }

    return {
        "record_type": "delta",
        "domain": report.domain,
        "timestamp": datetime.now(UTC).isoformat(),
        "has_changes": report.has_changes,
        "added_services": list(report.added_services),
        "removed_services": list(report.removed_services),
        "added_slugs": list(report.added_slugs),
        "removed_slugs": list(report.removed_slugs),
        "added_signals": list(report.added_signals),
        "removed_signals": list(report.removed_signals),
        "changed_auth_type": _change_pair(report.changed_auth_type),
        "changed_dmarc_policy": _change_pair(report.changed_dmarc_policy),
        "changed_email_security_score": _change_pair(report.changed_email_security_score),
        "changed_confidence": _change_pair(report.changed_confidence),
        "changed_domain_count": _change_pair(report.changed_domain_count),
        "incomplete_comparison": incomplete_comparison,
    }


def format_delta_json(report: DeltaReport) -> str:
    """Format a DeltaReport as JSON."""
    return json.dumps(format_delta_dict(report), indent=2)


def _append_incomplete_warning(text: Text, report: DeltaReport) -> None:
    limitation = report.incomplete_comparison
    if limitation is None:
        return
    text.append(
        "\n  Warning: one or both snapshot collections were incomplete. ",
        style="yellow bold",
    )
    text.append("Unconfirmable additions, removals, and dependent changes were withheld.\n", style="yellow")
    previous_sources = limitation.previous_degraded_sources
    current_sources = limitation.current_degraded_sources
    if not previous_sources and not current_sources:
        # Compatibility for callers constructing the original two-field model.
        current_sources = limitation.degraded_sources
    if previous_sources:
        text.append("  Previous degraded sources: ", style="dim")
        text.append(", ".join(strip_control_chars(source) for source in previous_sources))
        text.append("\n")
    if current_sources:
        text.append("  Current degraded sources: ", style="dim")
        text.append(", ".join(strip_control_chars(source) for source in current_sources))
        text.append("\n")
    text.append("\n  Suppressed comparisons: ", style="dim")
    text.append(", ".join(limitation.suppressed_fields))


def _append_scalar_changes(text: Text, report: DeltaReport) -> None:
    changes = (
        ("Auth", report.changed_auth_type),
        ("DMARC", report.changed_dmarc_policy),
        ("Email Security Score", report.changed_email_security_score),
        ("Confidence", report.changed_confidence),
        ("Domain Count", report.changed_domain_count),
    )
    for label, change in changes:
        if change is None:
            continue
        before = strip_control_chars(str(change[0]))
        after = strip_control_chars(str(change[1]))
        text.append("\n  ")
        text.append("~ ", style="yellow bold")
        text.append(f"{label}: {before} → {after}", style="yellow")


def render_delta_panel(report: DeltaReport) -> Panel:
    """Render a delta report with explicit incomplete-comparison state."""
    text = Text()
    text.append("  Domain: ", style="dim")
    text.append(f"{report.domain}\n")
    _append_incomplete_warning(text, report)

    if not report.has_changes:
        message = (
            "No confirmed changes detected." if report.incomplete_comparison is not None else "No changes detected."
        )
        text.append(f"\n  {message}", style="dim italic")
    else:
        collections = (
            ("Service", report.added_services, "green", "+ "),
            ("Service", report.removed_services, "red", "- "),
            ("Slug", report.added_slugs, "green", "+ "),
            ("Slug", report.removed_slugs, "red", "- "),
            ("Signal", report.added_signals, "green", "+ "),
            ("Signal", report.removed_signals, "red", "- "),
        )
        for label, values, color, marker in collections:
            for value in values:
                text.append("\n  ")
                text.append(marker, style=f"{color} bold")
                text.append(f"{label}: {value}", style=color)
        _append_scalar_changes(text, report)

    return Panel(
        text,
        title="Delta Report",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )
