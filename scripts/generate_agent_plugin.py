#!/usr/bin/env python3
"""Generate the schema-pinned Agent Plugins candidate deterministically."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "agents" / "agent-plugin"
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
SOURCE_SKILLS = {
    "recon": ROOT / "agents" / "claude-code" / "skills" / "recon" / "SKILL.md",
    "recon-fingerprint-triage": (ROOT / "agents" / "claude-code" / "skills" / "recon-fingerprint-triage" / "SKILL.md"),
}

_TRIAGE_NATIVE_BOUNDARY = """This is a Claude Code-native skill. Its `argument-hint` field and surrounding
plugin layout are client-specific. It does not claim portable Agent Skills or
Agent Plugins conformance. Portable packaging remains a separate v2.15
decision."""
_TRIAGE_PORTABLE_BOUNDARY = """This is the portable Agent Skills form used by the schema-pinned v2.15
candidate. It omits client-only frontmatter and does not depend on experimental
`allowed-tools` behavior. Package compatibility remains unclaimed until the
frozen representative-client evaluation is complete."""
_TRIAGE_NATIVE_HARD_RULE = "- Do not claim this Claude Code-native skill is a portable Agent Plugins\n  package."
_TRIAGE_PORTABLE_HARD_RULE = (
    "- Do not turn offline schema validation into an unqualified Agent Plugins\n"
    "  compatibility or future-draft conformance claim."
)


class GenerationError(ValueError):
    """Raised when a native source cannot be transformed without ambiguity."""


def _project_version() -> str:
    payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = payload.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise GenerationError("pyproject.toml project.version is missing")
    return version


def _split_skill(path: Path) -> tuple[dict[str, object], str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise GenerationError(f"{path} is missing opening YAML frontmatter")
    try:
        frontmatter_text, body = text[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise GenerationError(f"{path} is missing closing YAML frontmatter") from exc
    metadata = yaml.safe_load(frontmatter_text)
    if not isinstance(metadata, dict) or not all(isinstance(key, str) for key in metadata):
        raise GenerationError(f"{path} frontmatter must be an object with string keys")
    return metadata, body


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    if text.count(old) != 1:
        raise GenerationError(f"{label} source marker must occur exactly once")
    return text.replace(old, new)


def _portable_skill(skill_id: str, source: Path, version: str) -> bytes:
    native, body = _split_skill(source)
    name = native.get("name")
    description = native.get("description")
    if name != skill_id or not isinstance(description, str) or not description.strip():
        raise GenerationError(f"{source} name or description has drifted")

    if skill_id == "recon":
        native_link = "[`docs/recon-schema.json`](../../../../docs/recon-schema.json)"
        release_link = (
            f"[`docs/recon-schema.json`](https://github.com/blisspixel/recon/blob/v{version}/docs/recon-schema.json)"
        )
        body = _replace_once(body, native_link, release_link, label="recon schema link")
    elif skill_id == "recon-fingerprint-triage":
        body = _replace_once(
            body,
            _TRIAGE_NATIVE_BOUNDARY,
            _TRIAGE_PORTABLE_BOUNDARY,
            label="triage packaging boundary",
        )
        body = _replace_once(
            body,
            _TRIAGE_NATIVE_HARD_RULE,
            _TRIAGE_PORTABLE_HARD_RULE,
            label="triage hard boundary",
        )
    else:  # pragma: no cover - SOURCE_SKILLS is a closed internal table
        raise GenerationError(f"unsupported skill id: {skill_id}")

    portable = {
        "name": name,
        "description": description,
        "license": "Apache-2.0",
        "compatibility": (
            f"Requires recon-tool {version} or a compatible v2 release and Python 3.11+. "
            "Live lookups require public network access; MCP launch requires recon on PATH."
        ),
        "metadata": {"author": "blisspixel", "version": version},
    }
    frontmatter = yaml.safe_dump(
        portable,
        allow_unicode=True,
        sort_keys=False,
        width=4096,
    ).strip()
    return f"---\n{frontmatter}\n---\n\n{body.lstrip()}".encode()


def _readme(version: str) -> bytes:
    declaration_url = (
        f"https://github.com/blisspixel/recon/blob/v{version}/docs/agent-portability-evaluation-declaration.md"
    )
    text = f"""\
    # recon Agent Plugins candidate

    Schema-pinned portable packaging candidate for recon-tool {version}. It
    contains the complete MCP surface and the two existing recon skills in the
    fixed [Agent Plugins v1.0.0](https://agent-plugins.org/specification)
    locations.

    This directory has passed offline validation against the vendored canonical
    Agent Plugins v1.0.0 schemas. The specification remains a Working Draft.
    Offline validation is not an unqualified compatibility or conformance claim;
    promotion remains blocked on the frozen Visual Studio Code, Cursor, and Kiro
    [representative-client evaluation]({declaration_url}).

    Prerequisites:

    - Python 3.11 or newer;
    - `recon-tool` installed so the client can resolve the `recon` executable;
    - client-controlled approval for any networked lookup.

    Validate from a recon source checkout:

    ```bash
    uv run python scripts/generate_agent_plugin.py --check
    uv run python scripts/check_agent_plugin.py
    ```

    Agent Plugins controls packaging only. It does not change MCP wire behavior,
    permissions, stable recon JSON, observation capsules, or the separately
    deferred Open Knowledge Format v0.2 projection. Native client scaffolds under
    `agents/` remain supported and unchanged during evaluation.
    """
    return textwrap.dedent(text).encode()


def rendered_files() -> dict[Path, bytes]:
    """Return every generated candidate file and its expected bytes."""

    version = _project_version()
    plugin = {
        "$schema": PLUGIN_SCHEMA,
        "name": "recon",
        "version": version,
        "description": "Public-metadata domain intelligence through the recon MCP server and portable skills.",
        "author": {"name": "blisspixel", "url": "https://github.com/blisspixel"},
        "homepage": "https://github.com/blisspixel/recon",
        "repository": "https://github.com/blisspixel/recon",
        "license": "Apache-2.0",
        "keywords": ["recon", "dns", "domain-intelligence", "mcp", "agent-skills"],
    }
    mcp = {
        "$schema": MCP_SCHEMA,
        "mcpServers": {"recon": {"type": "stdio", "command": "recon", "args": ["mcp"]}},
    }
    rendered = {
        PLUGIN_ROOT / "plugin.json": (json.dumps(plugin, indent=2, ensure_ascii=False) + "\n").encode(),
        PLUGIN_ROOT / "mcp.json": (json.dumps(mcp, indent=2, ensure_ascii=False) + "\n").encode(),
        PLUGIN_ROOT / "README.md": _readme(version),
        PLUGIN_ROOT / "LICENSE": (ROOT / "LICENSE").read_bytes(),
    }
    for skill_id, source in SOURCE_SKILLS.items():
        rendered[PLUGIN_ROOT / "skills" / skill_id / "SKILL.md"] = _portable_skill(skill_id, source, version)
    return rendered


def _write(rendered: dict[Path, bytes]) -> None:
    for path, content in rendered.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _check(rendered: dict[Path, bytes]) -> list[str]:
    problems: list[str] = []
    for path, expected in rendered.items():
        if not path.is_file():
            problems.append(f"missing {path.relative_to(ROOT)}")
        elif path.read_bytes() != expected:
            problems.append(f"stale {path.relative_to(ROOT)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if committed candidate files are stale.")
    args = parser.parse_args(argv)
    try:
        rendered = rendered_files()
    except (OSError, UnicodeError, GenerationError, tomllib.TOMLDecodeError, yaml.YAMLError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    if args.check:
        problems = _check(rendered)
        if problems:
            print("FAIL: " + "; ".join(problems), file=sys.stderr)
            return 1
        print(f"PASS: {len(rendered)} Agent Plugins candidate files are current.")
        return 0
    _write(rendered)
    print(f"Generated {len(rendered)} Agent Plugins candidate files under {PLUGIN_ROOT.relative_to(ROOT)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
