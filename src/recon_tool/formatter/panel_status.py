"""Small status helpers shared by the Rich terminal panel."""

from __future__ import annotations

from rich.text import Text

from recon_tool.models import ConfidenceLevel, TenantInfo


def confidence_is_high(level: ConfidenceLevel) -> bool:
    """Return whether the disciplined palette may use its positive color."""
    return level == ConfidenceLevel.HIGH


def render_low_confidence_guidance(info: TenantInfo, verbose: bool, explain: bool) -> Text | None:
    """Point default low-confidence output to existing diagnostic surfaces."""
    if info.confidence != ConfidenceLevel.LOW or verbose or explain:
        return None
    guidance = Text()
    guidance.append("Next", style="bold")
    guidance.append("\n  ")
    guidance.append(
        "Use --explain to inspect evidence or --verbose to review source status.",
        style="dim",
    )
    return guidance
