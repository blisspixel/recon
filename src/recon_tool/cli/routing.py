"""Argument normalization for the root ``recon`` group.

Pure helpers used by the root group before Click parses anything:

- ``--color`` / ``--no-color`` and ``--ascii`` are root options, but users
  place them after the domain like every lookup flag. Trailing occurrences move
  in front of the command so they behave exactly like the leading form.
- The other root-only options (``--debug``, ``-V``/``--version``) still have to
  lead; a trailing one gets an error that names the working form.
- Values consumed by a command's options stay data even when they spell a
  global flag or the ``--`` separator.
- A near-miss subcommand typo followed by more arguments gets a suggestion
  instead of a confusing "unexpected extra argument" error.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence

from typer.core import TyperCommand, TyperGroup, TyperOption

COLOR_FLAGS = frozenset({"--color", "--no-color"})
# Root output options accepted anywhere on the command line.
HOISTED_ROOT_FLAGS = COLOR_FLAGS | frozenset({"--ascii"})
ROOT_ONLY_FLAGS = frozenset({"--debug", "-V", "--version"})
_MAX_SUGGESTION_DISTANCE = 2


def _is_positional(arg: str) -> bool:
    return arg == "-" or not arg.startswith("-")


def _following_option_values(arg: str, arities: Mapping[str, int]) -> int:
    """Count following values, allowing equals syntax and short clusters."""
    name, equals, _value = arg.partition("=")
    if name in arities:
        return max(0, arities[name] - bool(equals))
    if arg.startswith("--"):
        return 0
    for offset, character in enumerate(arg[1:], start=2):
        arity = arities.get(f"-{character}")
        if arity is None:
            return 0
        if arity:
            return max(0, arity - (offset < len(arg)))
    return 0


def _option_arities(command: TyperCommand | TyperGroup | None) -> dict[str, int]:
    if command is None:
        return {}
    return {
        name: 0 if param.is_flag or param.count else param.nargs
        for param in command.params
        if isinstance(param, TyperOption)
        for name in (*param.opts, *param.secondary_opts)
    }


def option_value_indices(args: Sequence[str], root: TyperGroup) -> frozenset[int]:
    """Locate values from the registered command tree without invoking callbacks.

    A value can itself spell a root flag or ``--``. Follow each command's own
    options because short aliases have different arities on different commands.
    """
    command: TyperCommand | TyperGroup | None = root
    arities = _option_arities(command)
    protected: set[int] = set()
    remaining = 0
    for index, arg in enumerate(args):
        if remaining:
            protected.add(index)
            remaining -= 1
            continue
        if arg == "--":
            break
        if arg.startswith("-") and arg != "-":
            remaining = _following_option_values(arg, arities)
            continue
        if isinstance(command, TyperGroup):
            child = command.commands.get(arg)
            if child is None and command is root:
                child = root.commands.get("lookup")
            command = child if isinstance(child, (TyperCommand, TyperGroup)) else None
            arities = _option_arities(command)
    return frozenset(protected)


def _command_index(args: Sequence[str], protected_indices: Collection[int]) -> int | None:
    """Return the index of the first positional (domain or command) arg."""
    for index, arg in enumerate(args):
        if index in protected_indices:
            continue
        if arg == "--":
            return None
        if _is_positional(arg):
            return index
    return None


def hoist_trailing_color_flags(args: Sequence[str], *, protected_indices: Collection[int] = ()) -> list[str]:
    """Move ``--color``/``--no-color``/``--ascii`` after the command in front of it.

    Relative order is preserved, so when both forms appear the last one on the
    command line wins, as with any repeated Click flag. Tokens after a ``--``
    separator are left alone.
    """
    start = _command_index(args, protected_indices)
    if start is None:
        return list(args)
    moved: list[str] = []
    kept: list[str] = []
    tail = args[start:]
    for offset, arg in enumerate(tail):
        if start + offset in protected_indices:
            kept.append(arg)
            continue
        if arg == "--":
            kept.extend(tail[offset:])
            break
        (moved if arg in HOISTED_ROOT_FLAGS else kept).append(arg)
    return [*args[:start], *moved, *kept]


def misplaced_root_option(args: Sequence[str], *, protected_indices: Collection[int] = ()) -> str | None:
    """Return the first root-only option that appears after the command."""
    start = _command_index(args, protected_indices)
    if start is None:
        return None
    for index, arg in enumerate(args[start + 1 :], start=start + 1):
        if index in protected_indices:
            continue
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
