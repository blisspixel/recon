"""Flat JSON and Rich renderers for explanation records."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.text import Text

from recon_tool.explanation import serialize_explanation
from recon_tool.explanation_lineage import explanation_lineage_label
from recon_tool.models import ExplanationRecord


def render_explanations_panel(explanations: list[ExplanationRecord]) -> Panel:
    """Render explanation records with an explicit lineage qualification."""
    text = Text()
    for index, record in enumerate(explanations):
        if index:
            text.append("\n\n")
        text.append(f"  [{record.item_type.capitalize()}] ", style="bold")
        text.append(f"{record.item_name}\n")
        if record.curated_explanation:
            text.append(f"    {record.curated_explanation}\n", style="dim italic")
        text.append("    Lineage: ", style="dim")
        text.append(f"{explanation_lineage_label(record.lineage_status)}\n")
        if record.fired_rules:
            text.append("    Rules: ", style="dim")
            text.append(", ".join(record.fired_rules))
            text.append("\n")
        if record.confidence_derivation:
            text.append("    Confidence: ", style="dim")
            text.append(f"{record.confidence_derivation}\n")
        if record.matched_evidence:
            text.append(f"    Evidence: {len(record.matched_evidence)} record(s)\n", style="dim")
        if record.weakening_conditions:
            text.append("    Weakening:\n", style="dim")
            for condition in record.weakening_conditions:
                text.append(f"      • {condition}\n", style="dim")
    return Panel(
        text,
        title="Explanations",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def format_explanations_list(explanations: list[ExplanationRecord]) -> list[dict[str, Any]]:
    """Serialize explanation records for JSON output."""
    return [serialize_explanation(record) for record in explanations]
