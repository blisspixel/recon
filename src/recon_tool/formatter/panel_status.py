"""Small status helpers shared by the Rich terminal panel."""

from __future__ import annotations

from rich.text import Text

from recon_tool.formatter.collection_status import low_confidence_guidance, name_nxdomain_statement
from recon_tool.models import ConfidenceLevel, TenantInfo


def confidence_is_high(level: ConfidenceLevel) -> bool:
    """Return whether the disciplined palette may use its positive color."""
    return level == ConfidenceLevel.HIGH


def render_low_confidence_guidance(info: TenantInfo, verbose: bool, explain: bool) -> Text | None:
    """Point default low-confidence output to existing diagnostic surfaces."""
    note = low_confidence_guidance(info, detailed=verbose or explain)
    if note is None:
        return None
    guidance = Text()
    guidance.append("Next", style="bold")
    guidance.append("\n  ")
    guidance.append(note, style="dim")
    return guidance


def render_name_nxdomain(info: TenantInfo) -> Text | None:
    """State an observed queried-name NXDOMAIN so it is not read as a quiet domain."""
    statement = name_nxdomain_statement(info)
    return None if statement is None else Text(statement, style="bold")
