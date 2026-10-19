"""Console construction: color precedence and the ASCII fallback.

Every human-facing renderer prints through the two consoles built here, one on
stdout for data and one on stderr for diagnostics, so a pipe consumer never
sees a spinner or an error line in the data stream.

Color precedence, highest first (``docs/design-language.md``):

1. ``--color`` / ``--no-color``. An explicit flag on this command line; when
   both are given the last one wins.
2. ``NO_COLOR`` when present and non-empty (no-color.org).
3. ``TERM=dumb``.
4. ``FORCE_COLOR`` when non-empty and not ``0`` (force-color.org).
5. Terminal detection on the output stream.

Disabled color means no SGR sequence at all, bold and dim included. Rich reads
``FORCE_COLOR`` and ``NO_COLOR`` itself with a different order, so every
console here receives an explicit decision instead of Rich's own detection.

ASCII glyphs replace the Unicode ones under ``--ascii``, ``TERM=dumb``, or a
terminal whose encoding cannot represent them. In ASCII mode the console
writes through a filter that transliterates anything a renderer did not
already choose an ASCII form for, so the stream stays pure ASCII.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import IO, Any, cast

from rich.console import Console

from recon_tool.formatter import theme

logger = logging.getLogger("recon")

__all__ = [
    "ColorDecision",
    "get_console",
    "get_err_console",
    "prepare_output",
    "resolve_ascii",
    "resolve_color",
    "set_ascii_override",
    "set_color_override",
    "set_console",
    "set_err_console",
]

# Default consoles. A module global rather than an injected parameter because
# dozens of call sites print through them; set_console()/set_err_console() are
# the test seam.
_console: Console | None = None
_err_console: Console | None = None
# --color (True) / --no-color (False) / neither (None).
_color_override: bool | None = None
# --ascii given on this command line.
_ascii_override = False

# Glyphs the Unicode forms rely on; an encoding that cannot carry all of them
# selects the ASCII forms.
_PROBE_GLYPHS = "●○◐\u2713\u2717\u2013─•→"


@dataclass(frozen=True)
class ColorDecision:
    """Whether a console may emit SGR styling, and which rule decided it."""

    enabled: bool
    source: str


def _env_set(environ: Mapping[str, str], name: str) -> bool:
    return environ.get(name, "") != ""


def _is_dumb(environ: Mapping[str, str]) -> bool:
    return environ.get("TERM", "").strip().lower() == "dumb"


def resolve_color(flag: bool | None, environ: Mapping[str, str], is_tty: bool) -> ColorDecision:
    """Apply recon's color precedence. Pure, so every rule is directly testable."""
    if flag is not None:
        return ColorDecision(flag, "--color" if flag else "--no-color")
    if _env_set(environ, "NO_COLOR"):
        return ColorDecision(False, "NO_COLOR")
    if _is_dumb(environ):
        return ColorDecision(False, "TERM=dumb")
    force = environ.get("FORCE_COLOR", "")
    if force not in ("", "0"):
        return ColorDecision(True, "FORCE_COLOR")
    return ColorDecision(is_tty, "tty")


def _can_encode(encoding: str | None) -> bool:
    if not encoding:
        return True
    try:
        _PROBE_GLYPHS.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def resolve_ascii(flag: bool, environ: Mapping[str, str], encoding: str | None, is_tty: bool) -> bool:
    """Return whether glyphs fall back to ASCII.

    A pipe keeps Unicode: get_console() re-encodes it as UTF-8 and the reader
    decides. Only a terminal that cannot show the glyphs forces ASCII.
    """
    if flag or _is_dumb(environ):
        return True
    return is_tty and not _can_encode(encoding)


def _stream_is_tty(stream: Any, environ: Mapping[str, str]) -> bool:
    # TTY_COMPATIBLE is Rich's documented override for terminal detection.
    compatible = environ.get("TTY_COMPATIBLE", "")
    if compatible in ("0", "1"):
        return compatible == "1"
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        return False


class _AsciiStream:
    """Text stream that transliterates to ASCII before writing.

    Resolves the real stream at write time, so a test runner that swaps
    ``sys.stdout`` still receives the output. Reports an ASCII encoding, which
    also makes Rich draw ASCII box borders.
    """

    encoding = "ascii"

    def __init__(self, *, stderr: bool) -> None:
        self._stderr = stderr

    def _target(self) -> IO[str]:
        return sys.stderr if self._stderr else sys.stdout

    def write(self, text: str) -> int:
        return self._target().write(theme.to_ascii(text))

    def flush(self) -> None:
        self._target().flush()

    def isatty(self) -> bool:
        return _stream_is_tty(self._target(), os.environ)

    def fileno(self) -> int:
        return self._target().fileno()


def _make_console(*, stderr: bool) -> Console:
    """Construct a Console that applies recon's color precedence."""
    environ = os.environ
    stream = sys.stderr if stderr else sys.stdout
    is_tty = _stream_is_tty(stream, environ)
    decision = resolve_color(_color_override, environ, is_tty)
    file = cast(IO[str], _AsciiStream(stderr=stderr)) if theme.ascii_active() else None
    if not decision.enabled:
        return Console(stderr=stderr, file=file, force_terminal=is_tty, no_color=True, color_system=None)
    # An explicit --color still colors a dumb terminal, where Rich's own
    # detection would return no color system.
    color_system = "standard" if _is_dumb(environ) else "auto"
    return Console(stderr=stderr, file=file, force_terminal=True, no_color=False, color_system=color_system)


def _reset_consoles() -> None:
    global _console, _err_console  # noqa: PLW0603
    _console = None
    _err_console = None


def set_color_override(value: bool | None) -> None:
    """Force (True) / disable (False) / auto (None) color, rebuilding consoles."""
    global _color_override  # noqa: PLW0603
    _color_override = value
    _reset_consoles()


def set_ascii_override(value: bool) -> None:
    """Record ``--ascii``. prepare_output() applies it."""
    global _ascii_override  # noqa: PLW0603
    _ascii_override = value


def prepare_output() -> bool:
    """Resolve the glyph set before anything renders. Returns ASCII state.

    The CLI calls this once per invocation, before a renderer builds text, so
    glyphs chosen at render time and the console's output filter agree.
    Consoles are rebuilt only when the state changes, which keeps a console a
    test injected with set_console() in place.
    """
    stream = sys.stdout
    active = resolve_ascii(
        _ascii_override,
        os.environ,
        getattr(stream, "encoding", None),
        _stream_is_tty(stream, os.environ),
    )
    if active != theme.ascii_active():
        theme.set_ascii_active(active)
        _reset_consoles()
    return active


def _reconfigure_utf8() -> None:
    """Re-encode stdout/stderr as UTF-8 so a cp1252 pipe never crashes.

    In ASCII mode the console filter emits ASCII only, so this only matters
    for Unicode output written to a pipe or file.
    """
    try:
        for stream in (sys.stdout, sys.stderr):
            stream_any: Any = cast(Any, stream)
            if hasattr(stream_any, "reconfigure"):
                stream_any.reconfigure(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.debug("stdout UTF-8 reconfigure failed: %s", exc)


def get_console() -> Console:
    """Return the active stdout console, creating it if needed."""
    global _console  # noqa: PLW0603
    if _console is None:
        _reconfigure_utf8()
        _console = _make_console(stderr=False)
    return _console


def get_err_console() -> Console:
    """Return the active stderr console, creating it if needed.

    Diagnostics (errors, warnings, progress spinners) go here so they never
    contaminate the stdout data stream that a pipe or agent consumes.
    """
    global _err_console  # noqa: PLW0603
    if _err_console is None:
        get_console()  # ensure the UTF-8 reconfigure has run
        _err_console = _make_console(stderr=True)
    return _err_console


def set_console(console: Console) -> None:
    """Replace the active console (for testing)."""
    global _console  # noqa: PLW0603
    _console = console


def set_err_console(console: Console) -> None:
    """Replace the active stderr console (for testing)."""
    global _err_console  # noqa: PLW0603
    _err_console = console
