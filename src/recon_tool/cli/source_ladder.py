"""Draw the source ladder on stderr while a single-domain lookup collects.

Motion rules (``docs/design-language.md``):

- Animation runs only on an interactive stderr. It is off under
  ``--no-color``, ``NO_COLOR``, ``TERM=dumb``, ``CI``, ``RECON_NO_ANIMATION``,
  ``--debug`` (line logging would cut through the frames), a legacy Windows
  console, and whenever stderr is not a terminal. Machine output (``--json``,
  ``--md``) never reaches this module.
- Each frame is written inside synchronized output (DEC mode 2026), which a
  terminal without support ignores, so a frame never shows half drawn.
- At most 12 frames per second, drawn by one asyncio task that sleeps between
  frames. Progress events only update state; they never draw. When
  collection ends the task is awaited, so nothing keeps running.
- The rows collapse into one source-health line, which is also the whole
  output when animation is off.

Diagnostics never print through the live region: library warnings are
captured during collection (``collection_warnings``) and printed after the
ladder has collapsed.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from typing import Any, TypeVar

from rich.console import Console
from rich.text import Text

from recon_tool import collection_progress
from recon_tool.cli.collection_warnings import debug_logging_active
from recon_tool.formatter import terminal, theme
from recon_tool.formatter.source_ladder import LadderState
from recon_tool.models import SourceResult

__all__ = [
    "MAX_FPS",
    "SYNC_BEGIN",
    "SYNC_END",
    "LiveLadder",
    "animation_disabled_reason",
    "print_health_line",
    "run_with_source_ladder",
]

_I = TypeVar("_I")

MAX_FPS = 12
FRAME_INTERVAL = 1.0 / MAX_FPS
SYNC_BEGIN = "\x1b[?2026h"
SYNC_END = "\x1b[?2026l"
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"
_CLEAR_BELOW = "\x1b[J"
HEADER = "Collecting and correlating public evidence..."


def _flag_set(environ: Mapping[str, str], name: str) -> bool:
    return environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def animation_disabled_reason(
    environ: Mapping[str, str],
    *,
    stderr_tty: bool,
    color_flag: bool | None,
    debug: bool = False,
    legacy_windows: bool = False,
) -> str | None:
    """Return why the ladder must stay static, or None when it may animate."""
    checks = (
        (color_flag is False, "--no-color"),
        (environ.get("NO_COLOR", "") != "", "NO_COLOR"),
        (environ.get("TERM", "").strip().lower() == "dumb", "TERM=dumb"),
        (_flag_set(environ, "CI"), "CI"),
        (_flag_set(environ, "RECON_NO_ANIMATION"), "RECON_NO_ANIMATION"),
        (not stderr_tty, "stderr is not a terminal"),
        (debug, "--debug"),
        (legacy_windows, "legacy Windows console"),
    )
    return next((reason for condition, reason in checks if condition), None)


def _console_disabled_reason(console: Console) -> str | None:
    return animation_disabled_reason(
        os.environ,
        stderr_tty=terminal.stream_is_tty(sys.stderr) and console.is_terminal,
        color_flag=terminal.color_override(),
        debug=debug_logging_active(),
        legacy_windows=console.legacy_windows,
    )


class LiveLadder:
    """Frame loop for the animated ladder. ``clock`` and ``sleep`` are seams.

    The loop draws a frame, then waits for whichever comes first: the frame
    interval or ``stop()``. Waiting is a real sleep, so a settled or idle
    ladder costs no CPU, and the rate can never exceed ``MAX_FPS``.
    """

    def __init__(
        self,
        state: LadderState,
        console: Console,
        *,
        interval: float = FRAME_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._state = state
        self._console = console
        self._interval = max(interval, FRAME_INTERVAL)
        self._clock = clock
        self._sleep = sleep
        self._drawn_lines = 0
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.frames = 0
        self.frame_times: list[float] = []

    @property
    def task(self) -> asyncio.Task[None] | None:
        return self._task

    def _write(self, text: str) -> None:
        if theme.ascii_active():
            text = theme.to_ascii(text)
        stream = self._console.file
        stream.write(text)
        stream.flush()

    def _frame_text(self) -> tuple[str, int]:
        """Render the header and rows, one terminal line each, never wrapped."""
        width = max(20, self._console.width - 1)
        lines = [Text(HEADER, style=theme.MUTED), *self._state.rows(self.frames)]
        with self._console.capture() as capture:
            for line in lines:
                line.truncate(width, overflow="ellipsis")
                self._console.print(line, no_wrap=True, overflow="ellipsis", crop=True, highlight=False)
        return capture.get(), len(lines)

    def _cursor_home(self) -> str:
        return f"\x1b[{self._drawn_lines}F" if self._drawn_lines else "\r"

    def draw(self) -> None:
        """Draw one frame inside synchronized output."""
        body, line_count = self._frame_text()
        self._write(SYNC_BEGIN + self._cursor_home() + _CLEAR_BELOW + body + SYNC_END)
        self._drawn_lines = line_count
        self.frames += 1
        self.frame_times.append(self._clock())

    def clear(self) -> None:
        """Erase the live region and restore the cursor."""
        self._write(SYNC_BEGIN + self._cursor_home() + _CLEAR_BELOW + SYNC_END + _SHOW_CURSOR)
        self._drawn_lines = 0

    async def _run(self) -> None:
        while not self._stopping.is_set():
            self.draw()
            if self._state.settled:
                await self._stopping.wait()
                break
            stop_wait = asyncio.ensure_future(self._stopping.wait())
            tick = asyncio.ensure_future(self._sleep(self._interval))
            try:
                await asyncio.wait({stop_wait, tick}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for pending in (stop_wait, tick):
                    if not pending.done():
                        pending.cancel()
                await asyncio.gather(stop_wait, tick, return_exceptions=True)

    def start(self) -> None:
        self._write(_HIDE_CURSOR)
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        """Stop the frame task, wait for it, and erase the region."""
        self._stopping.set()
        if self._task is not None:
            try:
                await self._task
            finally:
                self.clear()


def print_health_line(state: LadderState, console: Console) -> None:
    """Print the one-line source-health summary on the stderr console."""
    line = state.health_line()
    if line is not None:
        console.print(Text(line), highlight=False, soft_wrap=True)


async def run_with_source_ladder(
    console: Console,
    coro: Coroutine[Any, Any, tuple[_I, list[SourceResult]]],
    *,
    skip_ct: bool,
    active_probes: bool,
) -> tuple[_I, list[SourceResult]]:
    """Await ``resolve_tenant`` under the ladder, then print the health line.

    The live rows (when animation is allowed) are erased before the line is
    printed, so stderr ends with the line alone. A failed collection still
    prints the line when any unit settled; an interrupt prints nothing more.
    """
    state = LadderState.planned(skip_ct=skip_ct, active_probes=active_probes)
    live = LiveLadder(state, console) if _console_disabled_reason(console) is None else None
    with collection_progress.progress_listener(state.apply):
        if live is not None:
            live.start()
        try:
            value = await coro
        except Exception:
            state.abandon()
            await _settle(live)
            print_health_line(state, console)
            raise
        except BaseException:
            await _settle(live)
            raise
    state.finalize(value[1])
    await _settle(live)
    print_health_line(state, console)
    return value


async def _settle(live: LiveLadder | None) -> None:
    if live is not None:
        await live.stop()
