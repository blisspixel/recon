#!/usr/bin/env python3
"""Generate the schema-pinned Agent Plugins candidate deterministically."""

from __future__ import annotations

import argparse
import json
import re
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
Agent Plugins conformance. The generated portable candidate under
`agents/agent-plugin/` is separately schema-validated; compatibility remains
unclaimed until its frozen representative-client evaluation is complete."""
_TRIAGE_PORTABLE_BOUNDARY = """This is the portable Agent Skills form used by the schema-pinned
candidate. It omits client-only frontmatter and does not depend on experimental
`allowed-tools` behavior. Package compatibility remains unclaimed until the
frozen representative-client evaluation is complete."""
_TRIAGE_NATIVE_HARD_RULE = "- Do not claim this Claude Code-native skill is a portable Agent Plugins\n  package."
_TRIAGE_PORTABLE_HARD_RULE = (
    "- Do not turn offline schema validation into an unqualified Agent Plugins\n  compatibility or conformance claim."
)


class GenerationError(ValueError):
    """Raised when a native source cannot be transformed without ambiguity."""


def _release_link(path: str, version: str) -> str:
    return f"[`{path}`](https://github.com/blisspixel/recon/blob/v{version}/{path})"


def _portable_output_modes(body: str) -> str:
    body = _replace_once(
        body,
        "When MCP is connected, call `lookup_tenant(domain)` and reformat to a panel-equivalent summary. "
        "Otherwise shell out (after validating `<domain>` per the rule above):",
        "When MCP is connected, call `lookup_tenant(domain)` and reformat to a panel-equivalent summary. "
        'End with "Ask for full details or evidence." Then stop. '
        "Otherwise shell out (after validating `<domain>` per the rule above):",
        label="recon default MCP follow-up",
    )
    return _replace_once(
        body,
        'Trigger this mode when the user explicitly says "full", "max details", "give me everything", '
        "or when downstream automation needs structured data. Do **not** use shell redirection; "
        "capture stdout and write the file with your own file-write tool:",
        """Trigger this mode when the user explicitly says "full", "max details", "give me everything",
or when downstream automation needs structured data.

With connected MCP, call `lookup_tenant(domain, format="json")` using the actual
tool name exposed by the client. No Bash command is needed. On success, save the
returned JSON text only if the client exposes both a file-write tool and a
writable user workspace. Use the user's chosen output location, and report a
filename only after the write succeeds. The three-line headline below also
applies to a successfully saved MCP result.

If file writing or a writable workspace is unavailable, give a brief hedged
summary and state that artifact delivery is unavailable in this client. Do not
claim a file was saved, attempt an unavailable shell or file tool, or dump raw
JSON unless the user explicitly requests inline JSON. If the lookup itself
fails, report that failure instead of claiming full JSON was collected. Then
stop; the CLI-only recipe below does not apply to the connected MCP branch.

For the CLI fallback only, do **not** use shell redirection; capture stdout and
write the file with your own file-write tool:""",
        label="recon structured MCP delivery",
    )


def _portable_recon_body(body: str, version: str) -> str:
    body = _portable_output_modes(body)
    native_link = "[`docs/recon-schema.json`](../../../../docs/recon-schema.json)"
    body = _replace_once(body, native_link, "`docs/recon-schema.json`", label="recon schema link")
    body = body.replace("`docs/recon-schema.json`", _release_link("docs/recon-schema.json", version))
    body = _replace_once(
        body,
        "Confirm recon is installed before the first call in a session:",
        """First inspect the available tools for the connected recon server. Client tool
namespaces vary; identify recon by its server identity and the exposed tool
names and descriptions, not a required prefix. Already-connected MCP tools are
sufficient: use them without requiring a shell or running `recon --version`.
Do not register a second server or install another runtime to use that connection.

Only for the CLI fallback, confirm recon is installed before the first command:
if no shell is available, report that limitation instead of attempting a tool
that the client does not expose.
""".rstrip(),
        label="recon availability check",
    )
    old_discovery = (
        "Before choosing CLI vs MCP, look at your own available-tools list. "
        "If you see `recon:*` tools (e.g. `mcp__recon__lookup_tenant`, `mcp__recon__analyze_posture`), "
        "the MCP server is connected - prefer those. If you do not, fall back to the CLI. "
        "Do not call an MCP tool speculatively to test connectivity."
    )
    body = _replace_once(
        body,
        old_discovery,
        """Use the tool names actually exposed by the client for recon's `lookup_tenant`,
`analyze_posture`, and other capabilities. Examples such as
`mcp__recon__lookup_tenant` are not a portable naming requirement. Prefer the
connected MCP server; otherwise use the CLI when a shell is available. Do not
call a lookup speculatively to test connectivity.

The portable MCP process stores recon configuration, caches, and limiter state
under the client-managed `PLUGIN_DATA/recon` directory. It does not implicitly
share the CLI's user configuration. Keep user-requested reports in the user's
chosen workspace, not the installed plugin directory; ask for an output location
if the client has not provided a writable workspace.""",
        label="recon tool discovery",
    )
    return _replace_once(
        body,
        "Read your own tool list for `mcp__recon__*`;",
        "Inspect the client's actual recon tool names and server identity;",
        label="recon discovery gotcha",
    )


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
        body = _portable_recon_body(body, version)
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
        # Only released references are linked. The unreleased maintainer
        # workflow remains an explicitly checkout-relative path in the skill.
        body = re.sub(
            r"`(docs/(?:fingerprints|catalog-strategy)\.md)`",
            lambda match: _release_link(match[1], version),
            body,
        )
    else:  # pragma: no cover - SOURCE_SKILLS is a closed internal table
        raise GenerationError(f"unsupported skill id: {skill_id}")

    portable = {
        "name": name,
        "description": description,
        "license": "Apache-2.0",
        "compatibility": (
            f"Requires recon-tool {version} or a compatible v2 release and Python 3.11+. "
            "Use connected MCP tools or a shell with recon on PATH. Live lookups require public network access. "
            + (
                "Catalog patching and tests require a separate recon source checkout."
                if skill_id == "recon-fingerprint-triage"
                else ""
            )
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
    Agent Plugins v1.0.0 schemas. Version 1.0.0 is Published.
    Offline validation is not an unqualified compatibility or conformance claim;
    promotion remains blocked on the frozen Visual Studio Code, Cursor, and Kiro
    [representative-client evaluation]({declaration_url}).

    Prerequisites:

    - Python 3.11 or newer;
    - `recon-tool` installed so the client can resolve the `recon` executable;
    - client-controlled approval for any networked lookup.

    ## Load the directory

    Obtain this directory from a recon source checkout; it is not installed by
    the PyPI wheel or shipped as a separate release asset. Choose the directory
    containing `plugin.json` in a client that supports Agent Plugins v1.0.0.
    You may copy the complete directory elsewhere before loading it. Do not
    choose the repository root, `skills/`, or a client-native scaffold.

    Clients discover the two immediate `skills/*/SKILL.md` files and the root
    `mcp.json`. Both Agent Skills and MCP stdio support are needed for the full
    experience. A skills-only client can use the CLI fallback if it exposes a
    shell. Installation UI and approvals remain client-specific.

    The client must find the installed `recon` executable through its executable
    search path. GUI applications may not inherit a terminal's PATH. Configure
    the client's launch environment or use the documented native MCP installer
    as a separate fallback; do not put an absolute path or shell command into
    this portable `command` field. The launch is `recon` with the separate
    argument `mcp`, from the plugin root. No source checkout is needed to launch.

    ## State and skill prerequisites

    `mcp.json` sets `RECON_CONFIG_DIR` to `${{PLUGIN_DATA}}/recon`. The client
    supplies and expands `PLUGIN_DATA`; recon's configuration, caches, and
    limiter state stay there across plugin updates. The package directory need
    not be writable. This is separate from ordinary CLI/native-client config:
    existing custom fingerprints and profiles are not automatically imported.

    Already-connected MCP tools do not require a shell or a CLI version probe.
    Tool prefixes and skill invocation UI are client-defined. The triage skill
    can review supplied observations and the installed catalog, but editing
    built-in fingerprints and running repository tests requires a separate,
    explicitly selected recon source checkout. Versioned documentation links
    are references, not bundled scripts or permission to clone a repository.

    ## Verify locally

    First check the client's discovered skills and server status. MCP discovery,
    catalog resources, and `get_fingerprints` are local checks; no target lookup
    is needed to verify loading. `recon mcp doctor` checks the local runtime's
    handshake, but does not establish that a particular client loaded this
    package successfully. No paid or live-model client validation is implied.

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
        "mcpServers": {
            "recon": {
                "type": "stdio",
                "command": "recon",
                "args": ["mcp"],
                "env": {"RECON_CONFIG_DIR": "${PLUGIN_DATA}/recon"},
            }
        },
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
