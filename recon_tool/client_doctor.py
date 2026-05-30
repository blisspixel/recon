"""Client-side MCP config check.

`recon doctor --mcp` and `recon mcp doctor` both validate the *server*:
the first confirms the module imports and FastMCP enumerates tools, the
second spawns the server and walks a live JSON-RPC handshake. Neither
reads the *client's* config file, so a healthy server that the client
never registered still looks like a clean bill of health right up until
the tools fail to appear.

This module fills that gap. `recon doctor --client=<name>` reads the
config file the named client actually loads, reports whether an
`mcpServers.recon` stanza is present and well-formed, and (for Claude
Code) explains why a plugin-scoped install would not show up here. It
answers "did the install register with the client" rather than "is the
server itself healthy".

Pure-data, like `mcp_install`: no client SDKs, no network calls, no
spawning. We read the same config paths the installer writes and parse
them with the same BOM-tolerant reader.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Literal

from recon_tool.mcp_install import Client, Scope, resolve_config_path, servers_key

CheckStatus = Literal["ok", "warn", "fail", "info"]


@dataclass(frozen=True)
class ClientCheck:
    """One line in the client-doctor report."""

    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class ClientDoctorReport:
    """Aggregate result of reading one client's MCP config.

    ``notes`` carries teaching text the renderer prints after the
    checks: the plugin-scope caveat, the ``/mcp`` pointer, and the
    restart-means-full-quit reminder. ``ok`` is false only when a
    ``fail`` check is present; ``warn`` (e.g. the PATH gotcha) does not
    fail the report because the stanza may still load fine in a client
    that inherits a different PATH.
    """

    client: str
    checks: tuple[ClientCheck, ...]
    notes: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not any(c.status == "fail" for c in self.checks)


def _read_config(path: Path) -> tuple[Literal["missing", "invalid", "ok"], dict[str, object] | None, str]:
    """Read and parse a client config file.

    Returns ``(state, data, detail)``. ``state`` is ``missing`` when the
    file does not exist, ``invalid`` when it exists but does not parse as
    a JSON object, and ``ok`` otherwise. The BOM-tolerant read mirrors
    ``mcp_install._read_existing`` so a config written by a Windows tool
    that prepends a UTF-8 BOM is not misreported as malformed.
    """
    if not path.exists():
        return "missing", None, "not found"
    if path.is_dir():
        return "invalid", None, "is a directory, not a config file"
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return "invalid", None, f"cannot read: {exc}"
    if not raw.strip():
        return "missing", None, "empty file"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return "invalid", None, f"not valid JSON ({exc.msg} at line {exc.lineno})"
    if not isinstance(data, dict):
        return "invalid", None, f"top-level JSON is {type(data).__name__}, not an object"
    return "ok", {str(k): v for k, v in data.items()}, "parsed"


def _locate_recon(config: dict[str, object], client: Client, cwd: Path) -> tuple[dict[str, object] | None, str]:
    """Find the recon stanza in a parsed config, returning ``(block, where)``.

    Checks the client's canonical top-level key first: ``servers`` for
    VS Code, ``mcpServers`` for everyone else (what ``recon mcp install``
    writes, and the user-scope shape Claude Code uses). For VS Code it
    also falls back to a legacy ``mcpServers`` block, which an older
    installer may have left and which VS Code itself does not read, so
    the operator can be told to move it. For Claude Code it also looks
    under the project-nested ``projects[<cwd>].mcpServers.recon`` shape
    that ``claude mcp add`` writes for local scope, falling back to any
    project entry so a stanza registered under a different working
    directory is still surfaced.
    """
    key = servers_key(client)
    servers = config.get(key)
    if isinstance(servers, dict):
        recon = servers.get("recon")
        if isinstance(recon, dict):
            return {str(k): v for k, v in recon.items()}, f"{key}.recon"

    if client == "vscode":
        legacy = config.get("mcpServers")
        if isinstance(legacy, dict):
            recon = legacy.get("recon")
            if isinstance(recon, dict):
                return {str(k): v for k, v in recon.items()}, "mcpServers.recon"

    if client == "claude-code":
        projects = config.get("projects")
        if isinstance(projects, dict):
            key = str(cwd)
            ordered = [key] + [k for k in projects if k != key]
            for pkey in ordered:
                entry = projects.get(pkey)
                if not isinstance(entry, dict):
                    continue
                ps = entry.get("mcpServers")
                if isinstance(ps, dict):
                    recon = ps.get("recon")
                    if isinstance(recon, dict):
                        return {str(k): v for k, v in recon.items()}, f"projects[{pkey}].mcpServers.recon"

    return None, ""


def _candidate_paths(client: Client, platform_name: str | None) -> list[tuple[Scope, Path]]:
    """Resolve every config path the client supports (user and/or workspace)."""
    paths: list[tuple[Scope, Path]] = []
    for scope in ("user", "workspace"):
        try:
            path = resolve_config_path(client, scope, platform_name=platform_name)  # type: ignore[arg-type]
        except ValueError:
            continue
        paths.append((scope, path))  # type: ignore[arg-type]
    return paths


def _command_checks(block: dict[str, object]) -> list[ClientCheck]:
    """Sanity-check the launch command/args/autoApprove of a found stanza."""
    checks: list[ClientCheck] = []

    command = block.get("command")
    if not isinstance(command, str) or not command:
        checks.append(ClientCheck("command", "fail", "missing or empty: the client cannot launch the server"))
    elif command == "recon":
        if shutil.which("recon"):
            checks.append(ClientCheck("command", "ok", "recon (on PATH)"))
        else:
            checks.append(
                ClientCheck(
                    "command",
                    "warn",
                    "bare 'recon' but recon is not on this machine's PATH. GUI clients often do not "
                    "inherit your shell PATH; use an absolute path or the python -m recon_tool.server form.",
                )
            )
    else:
        # An absolute path is the common installed form: `recon mcp install`
        # persists `shutil.which("recon")`, which on most machines is an
        # absolute path ending in `recon` / `recon.exe`. Recognize that and
        # the python / uvx launcher forms by basename, so a config synced
        # from another machine (where the path does not resolve locally) is
        # not mislabelled "unrecognized".
        #
        # Use PureWindowsPath for the basename: a config synced from a
        # Windows box carries a backslash path, and bare `Path` on POSIX
        # does not treat `\` as a separator, so `Path(r"C:\...\recon.exe").name`
        # returns the whole string and the recon basename is missed.
        # PureWindowsPath accepts both `/` and `\`, so it extracts the
        # right basename for either separator style on either OS.
        basename = PureWindowsPath(command).name.lower()
        known_launcher = basename.startswith(("recon", "python", "uvx", "uv"))
        if Path(command).exists() or known_launcher:
            checks.append(ClientCheck("command", "ok", command))
        else:
            checks.append(
                ClientCheck("command", "warn", f"unrecognized command '{command}'; verify it launches recon mcp")
            )

    args = block.get("args")
    if isinstance(args, list) and args:
        checks.append(ClientCheck("args", "ok", json.dumps(args)))
    else:
        checks.append(ClientCheck("args", "warn", 'missing or empty; expected something like ["mcp"]'))

    if "autoApprove" not in block:
        checks.append(ClientCheck("autoApprove", "info", "no autoApprove key (manual approval is the default)"))
    else:
        auto = block.get("autoApprove")
        if isinstance(auto, list) and auto:
            checks.append(ClientCheck("autoApprove", "info", f"auto-approves {len(auto)} tool(s): {json.dumps(auto)}"))
        else:
            checks.append(ClientCheck("autoApprove", "info", "empty; every tool call needs manual approval"))

    return checks


_CLAUDE_CODE_NOTES: tuple[str, ...] = (
    "Plugin installs are not covered here: the Claude Code plugin keeps its MCP config inside the "
    "plugin, not in ~/.claude.json. If you installed the recon plugin, an empty result above is expected.",
    "In Claude Code, run /mcp to see connected servers and any startup error. If recon is absent there, "
    "the config was not picked up or the server crashed on spawn.",
    "Local stdio tools appear as mcp__recon__*, not mcp__claude_ai_*. Searching for the claude.ai naming "
    "pattern will not find them.",
    "Restart means a full application quit (Alt+F4 / Cmd+Q) and relaunch, not a new chat. A new "
    "conversation in the same process does not re-spawn MCP servers.",
)

_GENERIC_NOTES: tuple[str, ...] = (
    "Open the client's MCP panel to see connected servers and startup errors.",
    "Restart means a full application quit and relaunch, not a new tab or chat. A new window in the "
    "same process does not re-spawn MCP servers.",
)

_VSCODE_NOTES: tuple[str, ...] = (
    "VS Code reads MCP servers from a top-level `servers` key in .vscode/mcp.json, not `mcpServers`. "
    "If the stanza above was found under `mcpServers.recon`, VS Code will not load it; move it under "
    "`servers`. Reinstall with a current recon (`recon mcp install --client=vscode`) to write the right key.",
    "Run 'MCP: List Servers' from the Command Palette to see connected servers and startup errors.",
    "Reload the VS Code window (Developer: Reload Window) or quit and relaunch after changing the config; "
    "a new editor tab does not re-spawn MCP servers.",
)


def check_client(
    client: Client,
    *,
    platform_name: str | None = None,
    cwd: Path | None = None,
) -> ClientDoctorReport:
    """Read ``client``'s MCP config and report whether recon is registered.

    Walks each config path the client supports, parses it, and looks for
    the recon stanza. The first stanza found wins and its launch command
    is sanity-checked. When no stanza is found anywhere, every checked
    path is listed so the operator knows which files were inspected.
    """
    work_cwd = cwd if cwd is not None else Path.cwd()
    key = servers_key(client)
    checks: list[ClientCheck] = []
    candidates = _candidate_paths(client, platform_name)

    located: tuple[dict[str, object], str] | None = None
    for scope, path in candidates:
        state, data, detail = _read_config(path)
        if state == "missing":
            checks.append(ClientCheck("config file", "info", f"{scope}: {path} ({detail})"))
            continue
        if state == "invalid" or data is None:
            checks.append(ClientCheck("config file", "fail", f"{scope}: {path} ({detail})"))
            continue
        block, where = _locate_recon(data, client, work_cwd)
        if block is None:
            checks.append(ClientCheck("config file", "info", f"{scope}: {path} (parsed, no {key}.recon)"))
        elif located is None:
            checks.append(ClientCheck("config file", "ok", f"{scope}: {path} (recon at {where})"))
            located = (block, where)
        else:
            # recon is in this file too, but an earlier candidate already
            # supplied the stanza we sanity-check. Say so rather than
            # mislabelling this file as having no recon entry.
            checks.append(
                ClientCheck("config file", "info", f"{scope}: {path} (also has recon at {where}; first wins)")
            )

    if located is not None:
        block, where = located
        checks.append(ClientCheck("recon stanza", "ok", f"present at {where}"))
        checks.extend(_command_checks(block))
    else:
        if candidates:
            paths_blurb = ", ".join(f"{scope}:{path}" for scope, path in candidates)
            checks.append(
                ClientCheck(
                    "recon stanza",
                    "fail",
                    f"no {key}.recon found in: {paths_blurb}. Run `recon mcp install --client={client}` "
                    f"to write it, or check whether you installed via a plugin instead.",
                )
            )
        else:
            checks.append(ClientCheck("recon stanza", "fail", f"no known config path for client '{client}'"))

    if client == "claude-code":
        notes = _CLAUDE_CODE_NOTES
    elif client == "vscode":
        notes = _VSCODE_NOTES
    else:
        notes = _GENERIC_NOTES
    return ClientDoctorReport(client=client, checks=tuple(checks), notes=notes)
