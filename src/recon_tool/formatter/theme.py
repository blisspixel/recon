"""Color roles and functional glyphs for every human-facing renderer.

One table maps each semantic role to a named color from the terminal's
16-color palette, so a theme switch (Omarchy, or any terminal theme) recolors
recon along with everything else on screen. A hex or 256-color value would be
downsampled to a fixed index and ignore the theme, so none appear here.

Role colors mark state. They never carry meaning alone: every colored marker
sits beside a word that names the state, and readable text stays in the
default foreground, bold, or muted. ``docs/design-language.md`` states the rule
and ``tests/test_theme_contrast.py`` measures it against real Omarchy palettes.

The functional glyphs (confidence dots, source marks, salience indicators, the
divider) each have an ASCII fallback. The terminal module decides when ASCII is
active (``--ascii``, ``TERM=dumb``, or an output encoding that cannot carry the
glyphs); renderers ask this module for the glyph and never decide themselves.
"""

from __future__ import annotations

import unicodedata
from types import MappingProxyType
from typing import Final, TypedDict

from recon_tool.models import ConfidenceLevel

__all__ = [
    "ACCENT",
    "ASCII_FALLBACKS",
    "CONFIDENCE_ROLE",
    "DIFF_ADDED",
    "DIFF_CHANGED",
    "DIFF_REMOVED",
    "ERROR",
    "FILL_ROLE",
    "GAP_SEVERITY_ROLE",
    "INFO",
    "MUTED",
    "ROLES",
    "SUCCESS",
    "WARNING",
    "ascii_active",
    "confidence_marker",
    "dots",
    "fill_marker",
    "glyph",
    "rule",
    "set_ascii_active",
    "spinner_kwargs",
    "to_ascii",
]

# ── Roles ───────────────────────────────────────────────────────────────────
# Named ANSI colors only. ANSI 0 (black) is excluded because several theme
# generators, Omarchy's included, map it to the background color. Magenta is
# excluded so each remaining hue keeps exactly one meaning.
ACCENT: Final = "cyan"  # headings, the queried domain, commands in hints
SUCCESS: Final = "green"  # ok, match, High confidence marker
WARNING: Final = "yellow"  # warn, partial, cache recovered, unverified, Low confidence marker
ERROR: Final = "red"  # fail, source unavailable
INFO: Final = "blue"  # Medium confidence marker, vantage, mode
MUTED: Final = "dim"  # labels, provenance, clean no-match (dim default foreground)

ROLES: Final = MappingProxyType(
    {
        "accent": ACCENT,
        "success": SUCCESS,
        "warning": WARNING,
        "error": ERROR,
        "info": INFO,
        "muted": MUTED,
    }
)

# Low confidence is a caution, not a failure, so it takes the warning role.
CONFIDENCE_ROLE: Final = MappingProxyType(
    {
        ConfidenceLevel.HIGH: SUCCESS,
        ConfidenceLevel.MEDIUM: INFO,
        ConfidenceLevel.LOW: WARNING,
    }
)

# Model-support display fill (1 to 3 solid dots) uses the same scale.
FILL_ROLE: Final = MappingProxyType({3: SUCCESS, 2: INFO, 1: WARNING})

# Hardening-gap severity. Each indicator is printed with its severity word.
GAP_SEVERITY_ROLE: Final = MappingProxyType({"high": ERROR, "medium": WARNING, "low": INFO})

# Snapshot-delta markers follow the diff convention, and only the +, - and ~
# markers take the color. A removal is a change, not a failure; the marker
# and the label beside it say which.
DIFF_ADDED: Final = SUCCESS
DIFF_REMOVED: Final = ERROR
DIFF_CHANGED: Final = WARNING

# ── Glyphs ──────────────────────────────────────────────────────────────────
# name -> (unicode, ascii). The ASCII forms are chosen to read on their own:
# a status word for the source marks, a level letter for salience.
_GLYPHS: Final = MappingProxyType(
    {
        "dot_filled": ("●", "#"),
        "dot_empty": ("○", "-"),
        "ok": ("\u2713", "ok"),
        "neutral": ("\u2013", "-"),
        "fail": ("\u2717", "x"),
        "warn": ("!", "!"),
        "salience_high": ("●", "H"),
        "salience_medium": ("◐", "M"),
        "salience_low": ("○", "L"),
        "rule": ("─", "-"),
        "bullet": ("•", "*"),
        "arrow": ("→", "->"),
    }
)

# Character-level fallbacks applied to whole output lines in ASCII mode, so
# glyphs that come from data or shared copy (an em dash in an insight, a
# bullet in a hint, a Rich box border) also degrade to readable ASCII.
ASCII_FALLBACKS: Final = MappingProxyType(
    {
        "●": "*",
        "○": "o",
        "◐": "*",
        "\u2713": "ok",
        "\u2717": "x",
        "•": "*",
        "·": "-",
        "…": "...",
        "\u2014": "-",  # em dash
        "\u2013": "-",  # en dash
        "\u2012": "-",  # figure dash
        "\u2212": "-",  # minus sign
        "→": "->",
        "←": "<-",
        "↔": "<->",
        "⇒": "=>",
        "≈": "~",
        "≥": ">=",
        "≤": "<=",
        "×": "x",
        "§": "S",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "\u00a0": " ",
        "─": "-",
        "━": "-",
        "═": "=",
        "│": "|",
        "┃": "|",
        "║": "|",
        "┌": "+",
        "┐": "+",
        "└": "+",
        "┘": "+",
        "├": "+",
        "┤": "+",
        "┬": "+",
        "┴": "+",
        "┼": "+",
        "╭": "+",
        "╮": "+",
        "╰": "+",
        "╯": "+",
        "▲": "^",
        "▼": "v",
        "█": "#",
        "░": ".",
    }
)
_TRANSLATION: Final = str.maketrans(dict(ASCII_FALLBACKS))

_ascii_active = False


def set_ascii_active(value: bool) -> None:
    """Select ASCII (True) or Unicode (False) glyphs for subsequent renders."""
    global _ascii_active  # noqa: PLW0603
    _ascii_active = value


def ascii_active() -> bool:
    """Return whether renderers should emit the ASCII glyph forms."""
    return _ascii_active


def glyph(name: str) -> str:
    """Return the functional glyph ``name`` in the active character set."""
    unicode_form, ascii_form = _GLYPHS[name]
    return ascii_form if _ascii_active else unicode_form


def dots(filled: int, total: int = 3) -> str:
    """Return a dot scale: ``●●○`` in Unicode, ``[##-]`` in ASCII."""
    filled = max(0, min(total, filled))
    body = glyph("dot_filled") * filled + glyph("dot_empty") * (total - filled)
    return f"[{body}]" if _ascii_active else body


_CONFIDENCE_FILL: Final = MappingProxyType({ConfidenceLevel.HIGH: 3, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.LOW: 1})


def confidence_marker(level: ConfidenceLevel) -> str:
    """Return the dot scale for a deterministic confidence level."""
    return dots(_CONFIDENCE_FILL[level])


def fill_marker(fill: int) -> str:
    """Return the dot scale for a model-support fill level (1 to 3)."""
    return dots(fill)


def rule(width: int) -> str:
    """Return the panel divider at ``width`` cells."""
    return glyph("rule") * width


class StatusKwargs(TypedDict, total=False):
    """Keyword arguments for ``Console.status``."""

    spinner: str


def spinner_kwargs() -> StatusKwargs:
    """Return ``Console.status`` keywords that keep the spinner in the active
    character set. Empty in Unicode mode, so Rich's default spinner applies."""
    return StatusKwargs(spinner="line") if _ascii_active else StatusKwargs()


def to_ascii(text: str) -> str:
    """Transliterate ``text`` to pure ASCII for ASCII-mode output.

    Known glyphs use the table above; accented letters fold to their base
    letter; anything left becomes ``?`` so the stream stays pure ASCII.
    """
    if text.isascii():
        return text
    translated = text.translate(_TRANSLATION)
    if translated.isascii():
        return translated
    folded = unicodedata.normalize("NFKD", translated)
    return "".join(char if char.isascii() else ("" if unicodedata.combining(char) else "?") for char in folded)
