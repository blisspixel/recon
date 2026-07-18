"""Small rendering primitives shared by CLI catalog surfaces."""

from __future__ import annotations

import textwrap
from typing import Any

from rich.text import Text

from recon_tool.validator import strip_control_chars

MAX_CATALOG_DISPLAY_LENGTH = 1024
MIN_FIELD_VALUE_WIDTH = 20


def _safe_catalog_text(value: str) -> str:
    """Remove terminal controls and visibly bound locally extended catalog text."""
    cleaned = strip_control_chars(value, max_len=MAX_CATALOG_DISPLAY_LENGTH + 1)
    if len(cleaned) > MAX_CATALOG_DISPLAY_LENGTH:
        return f"{cleaned[:MAX_CATALOG_DISPLAY_LENGTH]} [truncated after {MAX_CATALOG_DISPLAY_LENGTH} characters]"
    return cleaned


def print_indented(console: Any, value: str, *, indent: int, style: str | None = None) -> None:
    """Print plain text with a left margin retained on wrapped lines."""
    value = _safe_catalog_text(value)
    available = max(1, int(console.width) - indent)
    lines = textwrap.wrap(value, width=available, break_long_words=False, break_on_hyphens=False) or [""]
    for line in lines:
        rendered = Text(f"{' ' * indent}{line}", style=style) if style is not None else Text(f"{' ' * indent}{line}")
        console.print(rendered, soft_wrap=True)


def print_field(console: Any, label: str, value: str, *, indent: int) -> None:
    """Print a labeled plain-text field with a stable hanging indent."""
    value = _safe_catalog_text(value)
    prefix = f"{label}: "
    width = int(console.width)
    available = width - indent - len(prefix)
    if available < MIN_FIELD_VALUE_WIDTH:
        print_indented(console, prefix.rstrip(), indent=indent, style="bold")
        print_indented(console, value, indent=min(indent + 2, width - 1))
        return
    lines = textwrap.wrap(value, width=available, break_long_words=False, break_on_hyphens=False) or [""]
    first = Text(" " * indent)
    first.append(prefix, style="bold")
    first.append(lines[0])
    console.print(first, soft_wrap=True)
    continuation = " " * (indent + len(prefix))
    for line in lines[1:]:
        console.print(Text(f"{continuation}{line}"), soft_wrap=True)
