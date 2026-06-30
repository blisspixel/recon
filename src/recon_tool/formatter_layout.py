"""Small text-layout helpers shared by formatter renderers."""

from __future__ import annotations


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
