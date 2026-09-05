"""Small text-layout helpers shared by formatter renderers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from rich.cells import cell_len
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.text import Text


def wrap_plain_text(text: str, max_width: int) -> list[str]:
    """Word-wrap plain text, retaining the panel's established long-word behavior."""
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


def _hanging_prefix(line: Text) -> int:
    """Locate a padded label or existing continuation indent without parsing values."""
    plain = line.plain
    indent = len(plain) - len(plain.lstrip(" "))
    for span in line.spans:
        if span.start == indent and span.end < len(plain) and plain[span.end - 1 : span.end] == " ":
            return span.end
    return indent


def wrap_indented_text(text: Text, console: Console, width: int) -> Text:
    """Adapt already styled panel rows to a narrow console without dropping text."""
    if text.plain and not text.plain.strip("─"):
        return text[:width]
    lines: list[Text] = []
    for line in text.split("\n", allow_blank=True):
        if line.cell_len <= width:
            lines.append(line)
            continue
        prefix_end = _hanging_prefix(line)
        prefix = line[:prefix_end]
        widest_character = max((cell_len(character) for character in line.plain), default=1)
        if width - prefix.cell_len < widest_character:
            prefix_end = 0
            prefix = Text()
        available = max(widest_character, width - prefix.cell_len)
        wrapped = line[prefix_end:].wrap(console, available, overflow="fold", no_wrap=False)
        for index, part in enumerate(wrapped):
            lines.append((prefix if index == 0 else Text(" " * prefix.cell_len)) + part)
    return Text("\n").join(lines)


class ResponsiveTextGroup(Group):
    """Keep the established wide layout, adapting text to the actual render width."""

    def __init__(self, *renderables: RenderableType, preferred_width: int) -> None:
        super().__init__(*renderables)
        self.preferred_width = preferred_width

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(1, options.max_width)
        for renderable in self.renderables:
            if width < self.preferred_width and isinstance(renderable, Text):
                yield wrap_indented_text(renderable, console, width)
            else:
                yield renderable


class SurfaceSummaryAttribution(Protocol):
    """Subset of SurfaceAttribution needed for provider-count summaries."""

    @property
    def primary_slug(self) -> str: ...

    @property
    def primary_name(self) -> str: ...

    @property
    def infra_slug(self) -> str | None: ...

    @property
    def infra_name(self) -> str | None: ...


def pack_comma_items(items: list[str], width: int) -> list[str]:
    """Pack comma-separated items into width-bounded lines."""
    lines: list[str] = []
    current: list[str] = []
    for item in items:
        safe_item = item if len(item) <= width else item[: max(1, width - 2)] + ".."
        candidate = ", ".join((*current, safe_item))
        if len(candidate) <= width:
            current.append(safe_item)
            continue
        if current:
            lines.append(", ".join(current))
        current = [safe_item]
    if current:
        lines.append(", ".join(current))
    return lines


def compact_subdomain_summary_lines(items: list[str], width: int, max_lines: int = 3) -> list[str]:
    """Return a compact provider-count summary for the default panel.

    The summary gets three aligned rows at most. That keeps the default panel
    compact while avoiding the misleading case where one high-count provider
    hides every other named provider behind a bare "+N more" suffix.
    """
    if not items:
        return []
    for keep_count in range(len(items), 0, -1):
        display_items = list(items[:keep_count])
        if keep_count < len(items):
            display_items.append(f"+{len(items) - keep_count} more")
        lines = pack_comma_items(display_items, width)
        if len(lines) <= max_lines:
            return lines
    return pack_comma_items([items[0], f"+{len(items) - 1} more"], width)[:max_lines]


def subdomain_surface_summary_items(attributions: Iterable[SurfaceSummaryAttribution]) -> list[str]:
    """Return deterministic ``Provider (count)`` items for subdomain attributions.

    Counts the primary attribution per subdomain, falling back to the infra tier
    only when there is no primary. That keeps agent-facing summaries aligned
    with the panel's ``Subdomain`` row without duplicating ranking logic.
    """
    name_counts: dict[str, int] = {}
    for attribution in attributions:
        name = attribution.primary_name
        if not attribution.primary_slug or not name:
            name = attribution.infra_name
            if not attribution.infra_slug or not name:
                continue
        name_counts[name] = name_counts.get(name, 0) + 1
    ranked = sorted(name_counts.items(), key=lambda pair: (-pair[1], pair[0]))
    return [f"{name} ({count})" for name, count in ranked]
