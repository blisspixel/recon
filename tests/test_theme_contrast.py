# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none
"""Panel contrast on real Omarchy themes (issue #226).

The panel is rendered with color, every styled span is resolved to the color a
theme would draw it in, and the WCAG 2.x contrast ratio against the theme
background is measured.

Palettes are the published Omarchy theme files at a pinned commit:

    https://github.com/basecamp/omarchy/blob/81fd2d23ca6e3462183a4dc8360de3113fa8d80c/themes/<theme>/colors.toml

Omarchy's terminal templates (``default/themed/foot.ini.tpl``,
``alacritty.toml.tpl``, ``ghostty.conf.tpl`` at the same commit) map ANSI 1-7
straight to ``red``, ``green``, ``yellow``, ``blue``, magenta, ``cyan`` and
``foreground``, and ANSI 0 to ``background``, which is why no role uses ANSI 0.

Faint (SGR 2, the muted role) follows foot, Omarchy's default terminal
(``default/xdg-terminal-exec/hyprland-xdg-terminals.list``). foot dims a color
by blending it toward black by a factor of 1.5 unless dim colors are set, and
Omarchy's foot template sets none and only defines ``[colors-dark]``.

The rule the test enforces (``docs/design-language.md``):

* Words render in the default foreground, bold, or muted. Role colors appear
  only on markers (dots, source marks, the warning mark), and every line with
  a colored marker also carries the word that names the state.
* Default-foreground text meets 4.5:1 on every theme.
* Every role color meets 4.5:1 on the dark theme.
* Markers are held to the 3:1 non-text level. Where a theme's own palette
  falls short, the shortfall is listed below, so a palette or role change
  forces a review instead of passing silently.
"""

from __future__ import annotations

import io
from typing import Any

import pytest
from rich.console import Console
from rich.segment import Segment

from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.panel import render_source_status_panel
from recon_tool.formatter.theme import ROLES
from recon_tool.models import SourceResult, TenantInfo
from tests.test_golden_renders import _hardened_info, _sparse_info

OMARCHY_COMMIT = "81fd2d23ca6e3462183a4dc8360de3113fa8d80c"

PALETTES: dict[str, dict[str, str]] = {
    # Omarchy's default theme (dark).
    "tokyo-night": {
        "background": "#1a1b26",
        "foreground": "#a9b1d6",
        "red": "#f7768e",
        "green": "#9ece6a",
        "yellow": "#e0af68",
        "blue": "#7aa2f7",
        "cyan": "#449dab",
    },
    "catppuccin-latte": {
        "background": "#eff1f5",
        "foreground": "#4c4f69",
        "red": "#d20f39",
        "green": "#40a02b",
        "yellow": "#df8e1d",
        "blue": "#1e66f5",
        "cyan": "#179299",
    },
    "flexoki-light": {
        "background": "#FFFCF0",
        "foreground": "#100F0F",
        "red": "#D14D41",
        "green": "#879A39",
        "yellow": "#D0A215",
        "blue": "#205EA6",
        "cyan": "#3AA99F",
    },
}
DARK_THEME = "tokyo-night"
FOOT_DIM_FACTOR = 1.5

# Measured ratios against each theme background, two decimals. Recorded here so
# the documented numbers stay tied to the arithmetic.
MEASURED: dict[str, dict[str, float]] = {
    "tokyo-night": {
        "foreground": 8.1,
        "muted": 3.8,
        "red": 6.46,
        "green": 9.35,
        "yellow": 8.55,
        "blue": 6.79,
        "cyan": 5.42,
    },
    "catppuccin-latte": {
        "foreground": 7.06,
        "muted": 10.83,
        "red": 4.8,
        "green": 2.96,
        "yellow": 2.31,
        "blue": 4.34,
        "cyan": 3.31,
    },
    "flexoki-light": {
        "foreground": 18.62,
        "muted": 19.26,
        "red": 4.21,
        "green": 3.04,
        "yellow": 2.31,
        "blue": 6.36,
        "cyan": 2.78,
    },
}

# Marker roles that render below 3:1 because of the theme's own palette. Each
# such marker is redundant with the word beside it, which is default foreground.
KNOWN_MARKER_SHORTFALLS = {
    ("catppuccin-latte", "green"),
    ("catppuccin-latte", "yellow"),
    ("flexoki-light", "yellow"),
}
# Muted text below 4.5:1: foot's faint rendering on the dark theme. Muted is
# reserved for labels and provenance that repeat structure, never the only copy
# of a finding.
KNOWN_MUTED_SHORTFALLS = {"tokyo-night"}


def _rgb(value: str) -> tuple[float, float, float]:
    value = value.lstrip("#")
    red, green, blue = (int(value[index : index + 2], 16) for index in (0, 2, 4))
    return red / 255, green / 255, blue / 255


def _luminance(rgb: tuple[float, float, float]) -> float:
    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    red, green, blue = (channel(c) for c in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast(foreground: tuple[float, float, float], background: tuple[float, float, float]) -> float:
    lighter, darker = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _foot_dim(rgb: tuple[float, float, float]) -> tuple[float, float, float]:
    # foot keeps integer channels; truncate like its 8-bit arithmetic.
    return tuple(int(c * 255 / FOOT_DIM_FACTOR) / 255 for c in rgb)  # type: ignore[return-value]


def _ratio(theme: str, role: str) -> float:
    palette = PALETTES[theme]
    background = _rgb(palette["background"])
    if role == "muted":
        return contrast(_foot_dim(_rgb(palette["foreground"])), background)
    return contrast(_rgb(palette[role]), background)


def test_measured_ratios_match_the_record() -> None:
    measured = {theme: {role: round(_ratio(theme, role), 2) for role in MEASURED[theme]} for theme in PALETTES}
    assert measured == MEASURED


# ── Rendered panel segments ─────────────────────────────────────────────────


def _surfaces(info: TenantInfo) -> list[Any]:
    sources = render_source_status_panel(
        [
            SourceResult(source_name="alpha_source", tenant_id="a1b2c3d4-0000-0000-0000-000000000000"),
            SourceResult(source_name="beta_source", error="no match"),
            SourceResult(source_name="gamma_source", error="timed out"),
        ]
    )
    return [
        render_tenant_panel(info),
        render_tenant_panel(info, explain=True),
        render_tenant_panel(info, show_services=True, show_domains=True, verbose=True),
        render_tenant_panel(_hardened_info()),
        render_tenant_panel(_sparse_info()),
        sources,
    ]


def _lines(renderable: Any) -> list[list[Segment]]:
    console = Console(file=io.StringIO(), width=100, force_terminal=True, color_system="standard", legacy_windows=False)
    return [list(line) for line in console.render_lines(renderable, pad=False)]


@pytest.fixture
def rendered_lines(fully_populated_tenant_info: TenantInfo) -> list[list[Segment]]:
    lines: list[list[Segment]] = []
    for surface in _surfaces(fully_populated_tenant_info):
        lines.extend(_lines(surface))
    assert lines
    return lines


def _color_name(segment: Segment) -> str | None:
    style = segment.style
    if style is None or style.color is None:
        return None
    return style.color.name


def test_role_color_never_carries_words(rendered_lines: list[list[Segment]]) -> None:
    role_colors = {value for value in ROLES.values() if value != "dim"}
    colored_markers = 0
    for line in rendered_lines:
        line_has_word = False
        line_has_marker = False
        for segment in line:
            name = _color_name(segment)
            text = segment.text.strip()
            if not text:
                continue
            if name is None:
                line_has_word = line_has_word or any(char.isalnum() for char in text)
                continue
            assert name in role_colors, f"color {name!r} outside the role table on {text!r}"
            assert not any(char.isalnum() for char in text), f"role color on words: {text!r}"
            line_has_marker = True
            colored_markers += 1
        if line_has_marker:
            plain = "".join(segment.text for segment in line)
            assert line_has_word, f"colored marker without a state word: {plain!r}"
    assert colored_markers >= 5


def test_default_foreground_text_meets_four_point_five_everywhere(rendered_lines: list[list[Segment]]) -> None:
    uses_default_text = any(
        _color_name(segment) is None
        and not (segment.style and segment.style.dim)
        and any(char.isalnum() for char in segment.text)
        for line in rendered_lines
        for segment in line
    )
    assert uses_default_text
    for theme in PALETTES:
        assert _ratio(theme, "foreground") >= 4.5, theme


def test_every_role_meets_four_point_five_on_the_dark_theme() -> None:
    for role in ("red", "green", "yellow", "blue", "cyan"):
        assert _ratio(DARK_THEME, role) >= 4.5, role


def test_marker_shortfalls_are_exactly_the_documented_ones(rendered_lines: list[list[Segment]]) -> None:
    marker_roles = {name for line in rendered_lines for segment in line if (name := _color_name(segment))}
    shortfalls = {(theme, role) for theme in PALETTES for role in marker_roles if _ratio(theme, role) < 3.0}
    assert shortfalls == KNOWN_MARKER_SHORTFALLS
    assert {theme for theme, _role in shortfalls} <= {"catppuccin-latte", "flexoki-light"}


def test_muted_shortfalls_are_exactly_the_documented_ones(rendered_lines: list[list[Segment]]) -> None:
    assert any(segment.style and segment.style.dim for line in rendered_lines for segment in line)
    shortfalls = {theme for theme in PALETTES if _ratio(theme, "muted") < 4.5}
    assert shortfalls == KNOWN_MUTED_SHORTFALLS
    assert all(_ratio(theme, "muted") >= 3.0 for theme in PALETTES)
