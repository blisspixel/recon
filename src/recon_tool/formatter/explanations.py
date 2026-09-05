"""Flat JSON and Rich renderers for explanation records."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.text import Text

from recon_tool.explanation import serialize_explanation
from recon_tool.explanation_lineage import explanation_lineage_label
from recon_tool.models import ExplanationRecord
from recon_tool.validator import strip_control_chars


def _explanation_text(explanations: list[ExplanationRecord]) -> Text:
    """Build the same lineage-qualified body for Rich and plain text."""
    text = Text()
    for index, record in enumerate(explanations):
        if index:
            text.append("\n\n")
        text.append(f"  [{record.item_type.capitalize()}] ", style="bold")
        text.append(f"{strip_control_chars(record.item_name, max_len=len(record.item_name))}\n")
        if record.curated_explanation:
            description = strip_control_chars(record.curated_explanation, max_len=len(record.curated_explanation))
            text.append(f"    {description}\n", style="dim italic")
        text.append("    Lineage: ", style="dim")
        text.append(f"{explanation_lineage_label(record.lineage_status)}\n")
        if record.fired_rules:
            text.append("    Rules: ", style="dim")
            text.append(", ".join(strip_control_chars(rule, max_len=len(rule)) for rule in record.fired_rules))
            text.append("\n")
        if record.confidence_derivation:
            text.append("    Confidence: ", style="dim")
            derivation = strip_control_chars(record.confidence_derivation, max_len=len(record.confidence_derivation))
            text.append(f"{derivation}\n")
        if record.matched_evidence:
            text.append(f"    Evidence: {len(record.matched_evidence)} record(s)\n", style="dim")
        if record.weakening_conditions:
            text.append("    Weakening:\n", style="dim")
            for condition in record.weakening_conditions:
                text.append(f"      • {strip_control_chars(condition, max_len=len(condition))}\n", style="dim")
    return text


def format_explanations_text(explanations: list[ExplanationRecord]) -> str:
    """Render existing explanation detail without ANSI escapes or Rich boxes."""
    return "Explanations\n" + _explanation_text(explanations).plain


def render_explanations_panel(explanations: list[ExplanationRecord]) -> Panel:
    """Render explanation records with an explicit lineage qualification."""
    return Panel(
        _explanation_text(explanations),
        title="Explanations",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def format_explanations_list(explanations: list[ExplanationRecord]) -> list[dict[str, Any]]:
    """Serialize explanation records for JSON output."""
    return [serialize_explanation(record) for record in explanations]
