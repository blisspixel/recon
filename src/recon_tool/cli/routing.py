"""Argument normalization for the root ``recon`` group.

Pure helpers used by the root group before Click parses anything:

- ``--color`` / ``--no-color`` and ``--ascii`` are root options, but users
  place them after the domain like every lookup flag. Trailing occurrences move
  in front of the command so they behave exactly like the leading form.
- The other root-only options (``--debug``, ``-V``/``--version``) still have to
  lead; a trailing one gets an error that names the working form.
- A near-miss subcommand typo followed by more arguments gets a suggestion
  instead of a confusing "unexpected extra argument" error.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

COLOR_FLAGS = frozenset({"--color", "--no-color"})
# Root output options accepted anywhere on the command line.
HOISTED_ROOT_FLAGS = COLOR_FLAGS | frozenset({"--ascii"})
ROOT_ONLY_FLAGS = frozenset({"--debug", "-V", "--version"})
_MAX_SUGGESTION_DISTANCE = 2


def _is_positional(arg: str) -> bool:
    return arg == "-" or not arg.startswith("-")


def _command_index(args: Sequence[str]) -> int | None:
    """Return the index of the first positional (domain or command) arg."""
    for index, arg in enumerate(args):
        if arg == "--":
            return None
        if _is_positional(arg):
            return index
    return None


def hoist_trailing_color_flags(args: Sequence[str]) -> list[str]:
    """Move ``--color``/``--no-color``/``--ascii`` after the command in front of it.

    Relative order is preserved, so when both forms appear the last one on the
    command line wins, as with any repeated Click flag. Tokens after a ``--``
    separator are left alone.
    """
    start = _command_index(args)
    if start is None:
        return list(args)
    moved: list[str] = []
    kept: list[str] = []
    tail = args[start:]
    for offset, arg in enumerate(tail):
        if arg == "--":
            kept.extend(tail[offset:])
            break
        (moved if arg in HOISTED_ROOT_FLAGS else kept).append(arg)
    return [*args[:start], *moved, *kept]


def misplaced_root_option(args: Sequence[str]) -> str | None:
    """Return the first root-only option that appears after the command."""
    start = _command_index(args)
    if start is None:
        return None
    for arg in args[start + 1 :]:
        if arg == "--":
            return None
        if arg in ROOT_ONLY_FLAGS:
            return arg
    return None


def misplaced_root_option_message(option: str) -> str:
    """Explain that ``option`` is global and show the working placement."""
    if option in {"-V", "--version"}:
        return f"{option} is a global option. Run it on its own: recon {option}"
    return (
        f"{option} is a global option. Place it before the domain or command, for example: recon {option} example.com"
    )


def _edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, start=1):
        current = [row]
        for column, right_char in enumerate(right, start=1):
            current.append(
                min(
                    previous[column] + 1,
                    current[column - 1] + 1,
                    previous[column - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def near_miss_command(token: str, commands: Iterable[str]) -> str | None:
    """Return the closest command within edit distance 2 of ``token``, if any."""
    lowered = token.lower()
    scored = sorted((_edit_distance(lowered, name), name) for name in commands)
    if scored and scored[0][0] <= _MAX_SUGGESTION_DISTANCE:
        return scored[0][1]
    return None
