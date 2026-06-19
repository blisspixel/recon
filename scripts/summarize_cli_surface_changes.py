#!/usr/bin/env python3
"""Summarize CLI command and flag changes between surface inventories."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = ROOT / "docs" / "surface-inventory.json"


@dataclass(frozen=True, order=True)
class FlagToken:
    command: str
    token: str


@dataclass(frozen=True)
class CliSurfaceDiff:
    added_commands: tuple[str, ...]
    removed_commands: tuple[str, ...]
    added_flags: tuple[FlagToken, ...]
    removed_flags: tuple[FlagToken, ...]

    @property
    def has_changes(self) -> bool:
        return any((self.added_commands, self.removed_commands, self.added_flags, self.removed_flags))

    def as_json(self) -> dict[str, object]:
        return {
            "added_commands": list(self.added_commands),
            "removed_commands": list(self.removed_commands),
            "added_flags": [{"command": item.command, "token": item.token} for item in self.added_flags],
            "removed_flags": [{"command": item.command, "token": item.token} for item in self.removed_flags],
        }


def _load_inventory_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_inventory_from_git(ref: str, inventory_path: str, runner: Any = subprocess.run) -> str:
    result = runner(
        ["git", "show", f"{ref}:{inventory_path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git show failed"
        raise ValueError(f"could not read {inventory_path} from {ref}: {detail}")
    return str(result.stdout)


def load_inventory_from_text(text: str) -> Mapping[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, Mapping):
        raise ValueError("surface inventory must be a JSON object")
    return payload


def load_inventory(path: Path) -> Mapping[str, Any]:
    return load_inventory_from_text(_load_inventory_text(path))


def _cli_commands(inventory: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    cli = inventory.get("cli", {})
    if not isinstance(cli, Mapping):
        return {}
    raw_commands = cli.get("commands", [])
    if not isinstance(raw_commands, Sequence) or isinstance(raw_commands, str | bytes | bytearray):
        return {}

    commands: dict[str, Mapping[str, Any]] = {}
    for raw_command in raw_commands:
        if not isinstance(raw_command, Mapping):
            continue
        usage = raw_command.get("usage")
        if isinstance(usage, str) and usage:
            commands[usage] = raw_command
    return commands


def _flag_tokens(commands: Mapping[str, Mapping[str, Any]]) -> set[FlagToken]:
    flags: set[FlagToken] = set()
    for usage, command in commands.items():
        parameters = command.get("parameters", [])
        if not isinstance(parameters, Sequence) or isinstance(parameters, str | bytes | bytearray):
            continue
        for parameter in parameters:
            if not isinstance(parameter, Mapping):
                continue
            tokens = parameter.get("tokens", [])
            if not isinstance(tokens, Sequence) or isinstance(tokens, str | bytes | bytearray):
                continue
            for token in tokens:
                if isinstance(token, str) and token.startswith("-"):
                    flags.add(FlagToken(command=usage, token=token))
    return flags


def diff_cli_surfaces(old_inventory: Mapping[str, Any], new_inventory: Mapping[str, Any]) -> CliSurfaceDiff:
    old_commands = _cli_commands(old_inventory)
    new_commands = _cli_commands(new_inventory)
    old_flags = _flag_tokens(old_commands)
    new_flags = _flag_tokens(new_commands)
    return CliSurfaceDiff(
        added_commands=tuple(sorted(set(new_commands) - set(old_commands))),
        removed_commands=tuple(sorted(set(old_commands) - set(new_commands))),
        added_flags=tuple(sorted(new_flags - old_flags)),
        removed_flags=tuple(sorted(old_flags - new_flags)),
    )


def _code_list(values: Sequence[str], limit: int = 5) -> str:
    shown = list(values[:limit])
    rendered = ", ".join(f"`{value}`" for value in shown)
    extra = len(values) - len(shown)
    if extra > 0:
        rendered = f"{rendered}, plus {extra} more" if rendered else f"{extra} more"
    return rendered


def _flag_list(values: Sequence[FlagToken], limit: int = 5) -> str:
    shown = list(values[:limit])
    rendered = ", ".join(f"`{item.token}` on `{item.command}`" for item in shown)
    extra = len(values) - len(shown)
    if extra > 0:
        rendered = f"{rendered}, plus {extra} more" if rendered else f"{extra} more"
    return rendered


def summarize_cli_surface_changes(diff: CliSurfaceDiff) -> str:
    if not diff.has_changes:
        return "Tool surface changes: no CLI command or flag changes."

    parts: list[str] = []
    if diff.added_commands:
        parts.append(f"added commands {_code_list(diff.added_commands)}")
    if diff.removed_commands:
        parts.append(f"removed commands {_code_list(diff.removed_commands)}")
    if diff.added_flags:
        parts.append(f"added flags {_flag_list(diff.added_flags)}")
    if diff.removed_flags:
        parts.append(f"removed flags {_flag_list(diff.removed_flags)}")
    return "Tool surface changes: " + "; ".join(parts) + "."


def _resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize CLI surface changes between generated inventories.")
    parser.add_argument(
        "old_inventory",
        nargs="?",
        type=Path,
        help="Previous docs/surface-inventory.json path. Omit when using --old-ref.",
    )
    parser.add_argument(
        "new_inventory",
        nargs="?",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="Current docs/surface-inventory.json path.",
    )
    parser.add_argument(
        "--old-ref",
        help="Read the old inventory from this git ref, for example v2.2.8.",
    )
    parser.add_argument(
        "--inventory-path",
        default="docs/surface-inventory.json",
        help="Repository path to read from --old-ref.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the structured diff as JSON.")
    args = parser.parse_args(argv)

    new_inventory_path = args.new_inventory
    if args.old_ref and args.old_inventory is not None:
        if args.new_inventory != DEFAULT_INVENTORY:
            print("error: when using --old-ref, pass at most one inventory path", file=sys.stderr)
            return 2
        new_inventory_path = args.old_inventory

    if args.old_ref:
        old_inventory = load_inventory_from_text(_load_inventory_from_git(args.old_ref, args.inventory_path))
    elif args.old_inventory is not None:
        old_inventory = load_inventory(_resolve_path(args.old_inventory))
    else:
        print("error: provide old_inventory or --old-ref", file=sys.stderr)
        return 2

    new_inventory = load_inventory(_resolve_path(new_inventory_path))
    diff = diff_cli_surfaces(old_inventory, new_inventory)
    if args.json:
        print(json.dumps(diff.as_json(), indent=2, sort_keys=True))
    else:
        print(summarize_cli_surface_changes(diff))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
