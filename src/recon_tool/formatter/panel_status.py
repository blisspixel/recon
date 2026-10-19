"""Small status helpers shared by the Rich terminal panel."""

from __future__ import annotations

from rich.text import Text

from recon_tool.formatter.collection_status import cache_reuse_note, low_confidence_guidance
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


def render_cache_reuse_note(info: TenantInfo) -> Text | None:
    """One muted line naming a result reused from the result cache.

    Plain text in the ``dim`` style, so the qualification is carried by its
    words rather than color alone (docs/design-language.md). Rich wraps it at
    the console width like the other notes.
    """
    note = cache_reuse_note(info)
    if note is None:
        return None
    return Text(note, style="dim")
