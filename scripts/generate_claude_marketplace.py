#!/usr/bin/env python3
"""Generate the repository Claude Code marketplace from the plugin manifest."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_PATH = Path(".claude-plugin") / "marketplace.json"
PLUGIN_MANIFEST = Path("agents/claude-code/.claude-plugin/plugin.json")

MARKETPLACE_NAME = "pueo-labs-recon"
OWNER_NAME = "pueo-labs"
PLUGIN_NAME = "recon"
PLUGIN_SOURCE = "./agents/claude-code"
DESCRIPTION = "Public-metadata domain intelligence: recon MCP server plus usage and triage skills."


class GenerationError(ValueError):
    """Raised when the plugin manifest and project version cannot be published together."""


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _project_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = _as_object_dict(payload.get("project"))
    if project is None:
        raise GenerationError("pyproject.toml is missing [project]")
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise GenerationError("pyproject.toml project.version is missing")
    return version


def _plugin_identity(root: Path) -> tuple[str, str]:
    manifest = _as_object_dict(_read_json(root / PLUGIN_MANIFEST))
    if manifest is None:
        raise GenerationError(f"{PLUGIN_MANIFEST.as_posix()} must be an object")
    name = manifest.get("name")
    version = manifest.get("version")
    if not isinstance(name, str) or name != PLUGIN_NAME:
        raise GenerationError(f"{PLUGIN_MANIFEST.as_posix()} name must be {PLUGIN_NAME!r}, found {name!r}")
    if not isinstance(version, str) or not version.strip():
        raise GenerationError(f"{PLUGIN_MANIFEST.as_posix()} version is missing")
    project_version = _project_version(root)
    if version != project_version:
        raise GenerationError(f"plugin version {version!r} does not match pyproject version {project_version!r}")
    return name, version


def marketplace_document(name: str, version: str) -> dict[str, object]:
    """Return the marketplace object for one plugin identity."""
    return {
        "name": MARKETPLACE_NAME,
        "description": DESCRIPTION,
        "owner": {"name": OWNER_NAME},
        "plugins": [
            {
                "name": name,
                "source": PLUGIN_SOURCE,
                "description": DESCRIPTION,
                "version": version,
            }
        ],
    }


def rendered_bytes(root: Path) -> bytes:
    """Return the canonical marketplace JSON for this checkout."""
    name, version = _plugin_identity(root)
    text = json.dumps(marketplace_document(name, version), indent=2, ensure_ascii=False) + "\n"
    return text.encode()


def _plugin_entry(market: object) -> dict[str, object] | str:
    document = _as_object_dict(market)
    if document is None:
        return "marketplace.json must be an object"
    if document.get("name") != MARKETPLACE_NAME:
        return f"marketplace name must be {MARKETPLACE_NAME!r}"
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        return "marketplace.json must list exactly the recon plugin"
    entries = cast(list[object], plugins)
    if len(entries) != 1:
        return "marketplace.json must list exactly the recon plugin"
    entry = _as_object_dict(entries[0])
    if entry is None:
        return "marketplace.json must list exactly the recon plugin"
    return entry


def agreement_problems(root: Path) -> list[str]:
    """Return name, version, and source disagreements. Empty means they match."""
    try:
        plugin_name, plugin_version = _plugin_identity(root)
        market = _read_json(root / MARKETPLACE_PATH)
    except (OSError, json.JSONDecodeError, GenerationError, tomllib.TOMLDecodeError) as exc:
        return [str(exc)]
    entry = _plugin_entry(market)
    if isinstance(entry, str):
        return [entry]
    problems: list[str] = []
    if entry.get("name") != plugin_name:
        problems.append(f"marketplace plugin name {entry.get('name')!r} does not match {plugin_name!r}")
    if entry.get("version") != plugin_version:
        problems.append(f"marketplace plugin version {entry.get('version')!r} does not match {plugin_version!r}")
    if entry.get("source") != PLUGIN_SOURCE:
        problems.append(f"marketplace plugin source must be {PLUGIN_SOURCE!r}")
    return problems


def check(root: Path) -> list[str]:
    """Return drift messages. A clean result means the committed file matches the generator."""
    problems = agreement_problems(root)
    if problems:
        return problems
    path = root / MARKETPLACE_PATH
    expected = rendered_bytes(root)
    if path.read_bytes() != expected:
        return [f"stale {MARKETPLACE_PATH.as_posix()}"]
    return []


def write(root: Path) -> None:
    """Write the marketplace file. Refuse when the plugin identity does not match the project."""
    path = root / MARKETPLACE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(rendered_bytes(root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the committed marketplace is stale.")
    args = parser.parse_args(argv)
    if args.check:
        problems = check(ROOT)
        if problems:
            print("FAIL: " + "; ".join(problems), file=sys.stderr)
            return 1
        print(f"PASS: {MARKETPLACE_PATH.as_posix()} matches the Claude Code plugin.")
        return 0
    try:
        write(ROOT)
    except GenerationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {MARKETPLACE_PATH.as_posix()}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
