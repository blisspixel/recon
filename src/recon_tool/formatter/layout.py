"""Small text-layout helpers shared by formatter renderers."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Generator, Iterable, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol

from rich.cells import cell_len
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

# Width rule (docs/design-language.md, "Width"). The flat lookup panel keeps
# its established 78-column layout on any console at least that wide, so wide
# output and its golden renders do not change. Below that, the panel is laid
# out once at the console's real width instead of being laid out at 78 and
# re-wrapped, which is what left orphan words. FittedPanel keeps an 80-column
# box when it fits and renders flat below it. ResponsivePanel grows review
# reports up to 100 columns and also turns flat for an oversized identifier.
PANEL_WIDTH = 78
BORDERED_PANEL_WIDTH = 80
LABEL_FLOOR = 13
LABEL_CAP = 16

_ACTIVE_PANEL_WIDTH: ContextVar[int] = ContextVar("recon_panel_width", default=PANEL_WIDTH)


def panel_width() -> int:
    """Return the width the flat panel is being laid out at."""
    return _ACTIVE_PANEL_WIDTH.get()


@contextmanager
def panel_width_scope(width: int) -> Generator[None]:
    """Lay out flat panel sections at ``width``, never wider than the panel."""
    token = _ACTIVE_PANEL_WIDTH.set(max(1, min(width, PANEL_WIDTH)))
    try:
        yield
    finally:
        _ACTIVE_PANEL_WIDTH.reset(token)


def label_column(labels: Iterable[str]) -> int:
    """Return the shared label column: longest label plus one, floor 13, cap 16.

    The floor keeps the established wide layout; the cap keeps one long label
    from pushing every value right. A label too long for the cap puts its
    value on the next line at the value indent instead.
    """
    longest = max((cell_len(label) for label in labels), default=0)
    return min(LABEL_CAP, max(LABEL_FLOOR, longest + 1))


_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
# A separator between word characters marks a hostname, URL, email address,
# path or key=value token: example.com, https://a.example/x, ops@example.com.
_JOINED = re.compile(r"\w[.:/\\@=]\w")
_EDGE_PUNCTUATION = "()[]{}<>,;'\"`"
_WORD = re.compile(r"\S+\s*")


def is_identifier(token: str) -> bool:
    """Return True for a token that must stay whole when copied.

    UUIDs, hostnames, URLs, email addresses and paths are identifiers. They
    never break across lines; one that does not fit gets its own line at the
    value indent and may run past the edge.
    """
    core = token.strip(_EDGE_PUNCTUATION).rstrip(".:")
    if not core or any(character.isspace() for character in core):
        return False
    return bool(_UUID.search(core) or _JOINED.search(core))


def wrap_plain_text(text: str, max_width: int) -> list[str]:
    """Word-wrap plain text once. Words, and so identifiers, never break."""
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


def pack_service_items(items: Sequence[str], width: int) -> list[str]:
    """Pack a comma list into lines of at most ``width``, wrapping once.

    Lines break between items where they can. An item longer than a whole line
    wraps at its own spaces, so the console never has to re-wrap the row.
    """
    pieces = [f"{item}," for item in items[:-1]] + list(items[-1:])
    lines: list[str] = []
    current = ""
    for piece in pieces:
        candidate = f"{current} {piece}" if current else piece
        if len(candidate) <= width:
            current = candidate
            continue
        if len(piece) <= width:
            lines.append(current)
            current = piece
            continue
        # The item breaks whatever happens, so it continues the current line.
        parts = wrap_plain_text(candidate, max(1, width))
        lines.extend(parts[:-1])
        current = parts[-1]
    if current:
        lines.append(current)
    return lines


def _hanging_prefix(line: Text) -> int:
    """Locate a padded label or existing continuation indent without parsing values."""
    plain = line.plain
    indent = len(plain) - len(plain.lstrip(" "))
    for span in line.spans:
        if span.start <= indent < span.end < len(plain) and plain[span.end - 1 : span.end] == " ":
            return span.end
    return indent


def _wrap_keeping_identifiers(text: Text, console: Console, width: int) -> list[Text]:
    """Word-wrap ``text`` once; fold only an over-long token that is not an identifier."""
    offsets: list[int] = []
    line_cells = 0
    for word in _WORD.finditer(text.plain):
        if line_cells and line_cells + cell_len(word.group().rstrip()) > width:
            offsets.append(word.start())
            line_cells = 0
        line_cells += cell_len(word.group())
    lines: list[Text] = []
    for part in text.divide(offsets):
        part.rstrip()
        if part.cell_len > width and not is_identifier(part.plain.strip()):
            lines.extend(part.wrap(console, width, overflow="fold", no_wrap=False))
        else:
            lines.append(part)
    return lines


def wrap_indented_text(text: Text, console: Console, width: int) -> Text:
    """Adapt styled panel rows to a narrow console without dropping text.

    Rows that fit pass through untouched. A longer row wraps once under its
    label (the hanging indent). Identifiers stay whole, so the result is marked
    ``no_wrap`` with ``overflow="ignore"``: Rich must not fold a line holding
    a single identifier wider than the console.
    """
    if text.plain and not text.plain.strip("─-"):  # the divider, in either glyph set
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
        wrapped = _wrap_keeping_identifiers(line[prefix_end:], console, available)
        for index, part in enumerate(wrapped):
            lines.append((prefix if index == 0 else Text(" " * prefix.cell_len)) + part)
    result = Text("\n").join(lines)
    result.no_wrap = True
    result.overflow = "ignore"
    return result


class ResponsiveTextGroup(Group):
    """Keep the established wide layout; narrower, lay text out once at the real width.

    ``renderables`` hold the wide layout. When the console is narrower than
    ``preferred_width`` and a ``rebuild`` callable is given, the sections are
    laid out again at the real width, so prose wraps once instead of twice;
    ``wrap_indented_text`` then catches any row that still does not fit.
    """

    def __init__(
        self,
        *renderables: RenderableType,
        preferred_width: int,
        rebuild: Callable[[int], Sequence[RenderableType]] | None = None,
    ) -> None:
        super().__init__(*renderables)
        self.preferred_width = preferred_width
        self.rebuild = rebuild

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(1, options.max_width)
        if width >= self.preferred_width:
            yield from self.renderables
            return
        renderables = self.rebuild(width) if self.rebuild is not None else self.renderables
        for renderable in renderables:
            yield wrap_indented_text(renderable, console, width) if isinstance(renderable, Text) else renderable


class FittedPanel(Panel):
    """A bordered panel that keeps its box when it fits and turns flat when not.

    At or above its preferred width the panel renders exactly as a Rich
    ``Panel``. Narrower, it renders as a bold heading over the body, wrapped
    once at the console width with hanging indents like the flat lookup panel,
    so an identifier is neither folded nor cropped at a border.
    """

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        preferred = self.width or options.max_width
        if options.max_width >= preferred or not isinstance(self.renderable, Text):
            yield from super().__rich_console__(console, options)
            return
        width = max(1, options.max_width)
        yield Text("")
        if self.title:
            title = Text.from_markup(self.title) if isinstance(self.title, str) else copy.copy(self.title)
            title.stylize("bold")
            yield title
        body = self.renderable.copy()
        body.rstrip()
        yield wrap_indented_text(body, console, width)
        yield Text("")


class ResponsivePanel(FittedPanel):
    """Use up to 100 columns and one hanging wrap for boxed review reports."""

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        if options.max_width < BORDERED_PANEL_WIDTH or not isinstance(self.renderable, Text):
            yield from super().__rich_console__(console, options)
            return
        panel = copy.copy(self)
        panel.width = min(options.max_width, 100)
        _, right, _, left = Padding.unpack(self.padding)
        content_width = max(1, panel.width - left - right - 2)
        body = wrap_indented_text(self.renderable, console, content_width)
        if any(line.cell_len > content_width for line in body.split("\n")):
            # An identifier that cannot fit inside the box must stay whole.
            # The existing flat layout preserves it without border cropping.
            panel.width = options.max_width + 1
            yield from FittedPanel.__rich_console__(panel, console, options)
            return
        panel.renderable = body
        yield from Panel.__rich_console__(panel, console, options)


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
