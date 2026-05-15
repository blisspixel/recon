"""MCP client config installer.

`recon mcp install --client=<name>` writes (or merges) the recon stanza
into the right MCP config file for popular AI clients. The intent is to
remove the "copy-paste this JSON into the right place" friction that
otherwise blocks first-time MCP users.

Design notes:

- Pure-data path table — no client SDKs, no network calls, no shelling
  out. We just know where each client expects its `mcp.json`-shaped
  file and write a stable canonical block.
- Idempotent merge — if the user's config already has `mcpServers`,
  we add `recon` next to whatever else is there. If `recon` is
  already registered, we refuse without `--force` so we never silently
  overwrite a hand-tuned launch command (e.g. someone using `uvx` or
  an absolute path).
- Refuses to clobber unparseable JSON. If the config file exists but
  isn't valid JSON, we error out and tell the user to fix it by hand.
  Better than corrupting their other client config.
- Per-OS user paths only where the client has a documented user-level
  config. Workspace-scoped clients (VS Code) only support
  `--scope workspace`.
- The block we write matches the canonical example in README.md:
  `{"command": "recon", "args": ["mcp"], "autoApprove": []}`. If
  `recon` isn't on PATH at install time we fall back to
  `{"command": "<sys.executable>", "args": ["-m", "recon_tool.server"]}`
  so GUI clients (Claude Desktop, Windsurf) that don't inherit the
  shell PATH still work.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Scope = Literal["user", "workspace"]
Client = Literal["claude-desktop", "claude-code", "cursor", "vscode", "windsurf", "kiro"]

# Keep this in lockstep with the Client literal above. Used by typer for
# enum validation and by the CLI help text.
SUPPORTED_CLIENTS: tuple[Client, ...] = (
    "claude-desktop",
    "claude-code",
    "cursor",
    "vscode",
    "windsurf",
    "kiro",
)


@dataclass(frozen=True)
class _ClientSpec:
    """Per-client config-path metadata.

    ``user_paths`` maps an OS family ("windows" / "darwin" / "linux") to
    the user-scope config file. ``workspace_path`` is relative to the
    operator's current working directory. Either may be None when the
    client doesn't support that scope; one of them must be set.
    """

    user_paths: dict[str, Path] | None
    workspace_path: Path | None
    description: str


def _user_home() -> Path:
    """Resolve the user's home directory or raise ``InstallError``.

    ``Path.home()`` raises ``RuntimeError`` when neither ``HOME`` nor
    ``USERPROFILE`` is set — which happens in some Docker images,
    CI sandboxes, and embedded launch contexts. Without this guard
    the install command would crash with a Python traceback; with
    it the operator gets a one-line "where do you want this?" hint.
    """
    try:
        return Path.home()
    except RuntimeError as exc:
        raise InstallError(
            "cannot resolve user home directory (HOME / USERPROFILE "
            "not set). Pass --config-path explicitly to point at the "
            "client's config file."
        ) from exc


def _appdata_dir() -> Path:
    """Windows %APPDATA% with a same-shaped fallback on non-Windows.

    The fallback lets the path table render predictably in tests and
    in cross-platform docs even when the active OS isn't Windows.
    """
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata)
    return _user_home() / "AppData" / "Roaming"


def _client_specs() -> dict[Client, _ClientSpec]:
    """Source-of-truth path table.

    Computed at call time (not at import time) so monkeypatching
    ``Path.home`` / ``$APPDATA`` in tests actually takes effect.
    """
    home = _user_home()
    appdata = _appdata_dir()
    return {
        "claude-desktop": _ClientSpec(
            user_paths={
                "windows": appdata / "Claude" / "claude_desktop_config.json",
                "darwin": home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
                "linux": home / ".config" / "Claude" / "claude_desktop_config.json",
            },
            workspace_path=None,
            description="Claude Desktop (Anthropic's desktop app)",
        ),
        "claude-code": _ClientSpec(
            user_paths={
                "windows": home / ".claude.json",
                "darwin": home / ".claude.json",
                "linux": home / ".claude.json",
            },
            workspace_path=Path(".mcp.json"),
            description="Claude Code (CLI / IDE plugin)",
        ),
        "cursor": _ClientSpec(
            user_paths={
                "windows": home / ".cursor" / "mcp.json",
                "darwin": home / ".cursor" / "mcp.json",
                "linux": home / ".cursor" / "mcp.json",
            },
            workspace_path=Path(".cursor") / "mcp.json",
            description="Cursor",
        ),
        "vscode": _ClientSpec(
            user_paths=None,
            workspace_path=Path(".vscode") / "mcp.json",
            description="VS Code (with GitHub Copilot or compatible extension)",
        ),
        "windsurf": _ClientSpec(
            user_paths={
                "windows": home / ".codeium" / "windsurf" / "mcp_config.json",
                "darwin": home / ".codeium" / "windsurf" / "mcp_config.json",
                "linux": home / ".codeium" / "windsurf" / "mcp_config.json",
            },
            workspace_path=None,
            description="Windsurf (Codeium)",
        ),
        "kiro": _ClientSpec(
            user_paths={
                "windows": home / ".kiro" / "settings" / "mcp.json",
                "darwin": home / ".kiro" / "settings" / "mcp.json",
                "linux": home / ".kiro" / "settings" / "mcp.json",
            },
            workspace_path=Path(".kiro") / "settings" / "mcp.json",
            description="Kiro",
        ),
    }


def _os_family(platform_name: str | None = None) -> str:
    """Bucket sys.platform into windows / darwin / linux.

    Anything that isn't Windows or macOS gets the linux table — the
    MCP clients that ship for BSDs / WSL all follow Linux conventions.
    """
    name = (platform_name if platform_name is not None else sys.platform).lower()
    if name.startswith("win"):
        return "windows"
    if name == "darwin":
        return "darwin"
    return "linux"


def resolve_config_path(
    client: Client,
    scope: Scope,
    *,
    platform_name: str | None = None,
) -> Path:
    """Return the absolute config path for the given (client, scope).

    Raises ``ValueError`` if the client doesn't support the requested
    scope (e.g. VS Code has no user-scope path).
    """
    spec = _client_specs()[client]
    if scope == "workspace":
        if spec.workspace_path is None:
            raise ValueError(f"{client} does not support workspace-scoped config — use --scope=user instead.")
        return Path.cwd() / spec.workspace_path
    # scope == "user"
    if spec.user_paths is None:
        raise ValueError(f"{client} does not support user-scoped config — use --scope=workspace instead.")
    family = _os_family(platform_name)
    return spec.user_paths[family]


def default_scope(client: Client) -> Scope:
    """Pick a sensible default scope when the user didn't specify one.

    Workspace-scoped clients (VS Code) default to workspace; everything
    else defaults to user, since most operators want recon available
    across all their projects.
    """
    spec = _client_specs()[client]
    if spec.user_paths is None:
        return "workspace"
    return "user"


# Cwd-strip launcher used by the fallback persisted MCP block when
# ``recon`` is not on PATH. Python adds ``""`` (cwd) to ``sys.path[0]``
# on ``-c`` invocations; we filter it out BEFORE any ``recon_tool``
# import so a malicious workspace containing ``recon_tool/server.py``
# cannot shadow the installed package. Works on every supported Python
# version, including Python 3.10 where ``PYTHONSAFEPATH`` is a no-op.
_FALLBACK_LAUNCH_CODE = (
    "import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; from recon_tool.server import main; main()"
)


def build_recon_block() -> dict[str, object]:
    """Return the MCP server stanza we register under `mcpServers.recon`.

    Falls back from ``recon`` to the running interpreter when ``recon``
    isn't on PATH. The fallback uses ``python -c "<safe-launcher>"``
    rather than ``python -m recon_tool.server`` so cwd-shadow attacks
    are blocked on every supported Python version, including Python
    3.10 where ``PYTHONSAFEPATH`` is a no-op.

    Supply-chain hardening (v1.9.9): the launcher code runs
    ``del sys.path[0]`` before importing ``recon_tool``, removing the
    cwd-equivalent entry Python adds to ``sys.path``. This is the
    cross-version protection the previous ``-m`` + ``PYTHONSAFEPATH=1``
    fallback could not provide on Python 3.10. The PYTHONSAFEPATH env
    entry stays in place as belt-and-suspenders for Python 3.11+.

    Operators on any version may still install ``recon`` to PATH and
    let this function return the preferred ``{"command": "recon",
    "args": ["mcp"]}`` form, which is shorter and equivalently safe.
    ``warn_if_fallback`` surfaces a stderr advisory when the fallback
    form is written.
    """
    recon_on_path = shutil.which("recon")
    if recon_on_path:
        return {
            "command": recon_on_path,
            "args": ["mcp"],
            "autoApprove": [],
        }
    return {
        "command": sys.executable,
        # v1.9.9: ``-c`` with explicit sys.path[0] removal closes the
        # cwd-shadow attack on every supported Python. The previous
        # ``-m`` form left Python 3.10 reliant on the runtime guard,
        # which fires AFTER Python imports the (potentially malicious)
        # module — too late to protect against an attacker who put a
        # payload at module top-level. The ``-c`` launcher runs the
        # path-strip BEFORE any recon_tool import, so a shadow
        # ``recon_tool/server.py`` in cwd cannot be selected.
        "args": ["-c", _FALLBACK_LAUNCH_CODE],
        "env": {"PYTHONSAFEPATH": "1"},
        "autoApprove": [],
    }


def warn_if_fallback() -> str | None:
    """Return a stderr-formatted warning when the fallback launch form
    would be persisted, or ``None`` when ``recon`` is on PATH.

    The warning is informational. v1.9.9 changed the persisted
    fallback to use ``python -c "<sys.path-stripping launcher>"``
    instead of ``python -m recon_tool.server``, so the cwd-shadow
    attack is blocked on every supported Python version (including
    Python 3.10 where ``PYTHONSAFEPATH`` is a no-op). Installing
    ``recon`` to PATH still produces a shorter and arguably
    more readable persisted command; the warning recommends it
    on cosmetic grounds, not safety grounds.
    """
    if shutil.which("recon") is not None:
        return None
    return (
        "info: `recon` is not on PATH; persisting the fallback launch "
        f'form (`{sys.executable} -c "<sys.path-stripping launcher>"`). '
        "The launcher removes the cwd entry from sys.path before any "
        "recon_tool import, so the cwd-shadow attack is blocked on every "
        "supported Python (including Python 3.10). For a shorter "
        "persisted command, install recon to PATH "
        "(`pip install --user recon-tool` or `pipx install recon-tool`) "
        "and rerun this install command."
    )


@dataclass(frozen=True)
class InstallPlan:
    """What `install()` is about to do, made inspectable for --dry-run."""

    path: Path
    action: Literal["create", "merge", "replace"]
    existing_block: dict[str, object] | None
    new_block: dict[str, object]
    parent_dirs_to_create: list[Path]


@dataclass(frozen=True)
class InstallResult:
    """What `install()` actually did. Symmetric with InstallPlan."""

    path: Path
    action: Literal["create", "merge", "replace", "noop-dry-run"]
    final_block: dict[str, object]


class InstallError(RuntimeError):
    """Raised when an install would clobber unparseable JSON or an
    existing recon block without --force."""


def _read_existing(path: Path) -> dict[str, object]:
    """Read the existing config or return an empty dict.

    Refuses to proceed (raises InstallError) when the file exists but
    doesn't parse — overwriting unparseable JSON is exactly the kind
    of unhelpful action this command should not take.

    Reads with ``utf-8-sig`` so a UTF-8 BOM (which Windows tools like
    Notepad and some PowerShell redirects sometimes prepend) is
    silently consumed instead of confusing ``json.loads`` into a
    "Unexpected character" error.
    """
    if not path.exists():
        return {}
    if path.is_dir():
        # Common reflex error: passing `~/.cursor/mcp.json` typed with
        # a trailing slash, or pointing `--config-path` at the parent
        # directory. Surface it as a clear "this is a directory" error
        # instead of letting `read_text` produce IsADirectoryError /
        # PermissionError noise that doesn't tell the operator what
        # they actually got wrong.
        raise InstallError(
            f"{path} is a directory, not a config file. Point --config-path at the actual `mcp.json`-shaped file."
        )
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InstallError(f"cannot read {path}: {exc}") from exc
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InstallError(
            f"{path} exists but is not valid JSON ({exc.msg} at line "
            f"{exc.lineno}). Refusing to overwrite. Fix the file or "
            f"delete it and rerun."
        ) from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path} contains {type(data).__name__}, not an object. Refusing to rewrite.")
    return data


_CANONICAL_KEYS: frozenset[str] = frozenset({"command", "args"})


def _merge_recon_block(
    existing: dict[str, object] | None,
    canonical: dict[str, object],
) -> dict[str, object]:
    """Compute the recon block we'd actually write.

    Only ``command`` and ``args`` are authoritative on the install side
    — those are the things ``--force`` is meant to refresh (e.g. when
    the operator moved their python install and `recon` now lives at a
    new path). Everything else the user added (custom ``env``,
    ``disabled``, non-empty ``autoApprove`` lists, hand-written notes
    on bespoke keys) is preserved.

    ``autoApprove`` is in the second category, not the first — if the
    user has hand-curated which tools auto-approve, we keep their
    list. Only when no ``autoApprove`` is present do we seed the
    empty default.
    """
    if existing is None:
        return dict(canonical)
    merged: dict[str, object] = dict(existing)
    for key in _CANONICAL_KEYS:
        merged[key] = canonical[key]
    if "autoApprove" not in merged:
        merged["autoApprove"] = canonical["autoApprove"]
    return merged


def plan_install(
    client: Client,
    scope: Scope,
    *,
    config_path_override: Path | None = None,
    force: bool = False,
    platform_name: str | None = None,
) -> InstallPlan:
    """Compute what an install would do without touching the filesystem.

    Used internally by `install(dry_run=True)` and by the CLI to pre-
    render the plan before asking the user for confirmation.
    """
    path = (
        config_path_override
        if config_path_override is not None
        else resolve_config_path(client, scope, platform_name=platform_name)
    )
    existing = _read_existing(path)
    canonical_block = build_recon_block()
    mcp_servers = existing.get("mcpServers")
    if mcp_servers is not None and not isinstance(mcp_servers, dict):
        raise InstallError(
            f"{path} has an `mcpServers` field that is "
            f"{type(mcp_servers).__name__}, not an object. Refusing to "
            f"rewrite."
        )

    parent_dirs: list[Path] = []
    if not path.parent.exists():
        # Walk up to find the first existing ancestor; everything below
        # it will need to be created. Reported in the plan so dry-run
        # can show the user what new directories will appear.
        parent = path.parent
        while parent != parent.parent and not parent.exists():
            parent_dirs.append(parent)
            parent = parent.parent
        parent_dirs.reverse()

    if not path.exists():
        return InstallPlan(
            path=path,
            action="create",
            existing_block=None,
            new_block=_merge_recon_block(None, canonical_block),
            parent_dirs_to_create=parent_dirs,
        )

    existing_recon: dict[str, object] | None = None
    if isinstance(mcp_servers, dict):
        existing_recon_raw = mcp_servers.get("recon")
        if isinstance(existing_recon_raw, dict):
            # str keys only — JSON guarantees this but we narrow for type-checkers.
            existing_recon = {str(k): v for k, v in existing_recon_raw.items()}

    target_block = _merge_recon_block(existing_recon, canonical_block)

    if existing_recon is not None:
        if existing_recon == target_block:
            # No-op merge — the existing block already has the canonical
            # `command` / `args`, and either an `autoApprove` we won't
            # touch or no other deltas. Idempotent rerun: skip the write.
            return InstallPlan(
                path=path,
                action="merge",
                existing_block=existing_recon,
                new_block=target_block,
                parent_dirs_to_create=[],
            )
        if not force:
            # Tell the operator exactly which canonical fields would
            # change, so they can decide whether they actually want
            # those refreshed.
            diffs = sorted(key for key in _CANONICAL_KEYS if existing_recon.get(key) != target_block.get(key))
            diff_blurb = ", ".join(diffs) if diffs else "fields"
            raise InstallError(
                f"{path} already has an `mcpServers.recon` entry whose "
                f"{diff_blurb} would change. Pass --force to overwrite "
                f"those canonical fields (your other fields — env, "
                f"autoApprove, etc. — are preserved), or edit the file "
                f"by hand."
            )
        return InstallPlan(
            path=path,
            action="replace",
            existing_block=existing_recon,
            new_block=target_block,
            parent_dirs_to_create=[],
        )

    return InstallPlan(
        path=path,
        action="merge",
        existing_block=None,
        new_block=target_block,
        parent_dirs_to_create=[],
    )


def install(
    client: Client,
    scope: Scope,
    *,
    config_path_override: Path | None = None,
    force: bool = False,
    dry_run: bool = False,
    platform_name: str | None = None,
) -> InstallResult:
    """Write the recon stanza into the client's MCP config file.

    Always reads → mutates → writes the entire file rather than
    streaming, so we never end up with a partially-written JSON
    document on disk if we crash mid-operation.
    """
    plan = plan_install(
        client,
        scope,
        config_path_override=config_path_override,
        force=force,
        platform_name=platform_name,
    )
    if dry_run:
        return InstallResult(
            path=plan.path,
            action="noop-dry-run",
            final_block=plan.new_block,
        )

    # Idempotency: if the existing recon block already matches what we'd
    # write byte-for-byte, don't touch the file at all. Avoids bumping
    # the mtime on every install run, which would otherwise trip
    # file-watch reload loops in clients like Cursor and VS Code.
    if plan.action == "merge" and plan.existing_block == plan.new_block:
        return InstallResult(
            path=plan.path,
            action="merge",
            final_block=plan.new_block,
        )

    plan.path.parent.mkdir(parents=True, exist_ok=True)

    existing = _read_existing(plan.path)
    mcp_servers_raw = existing.get("mcpServers")
    if isinstance(mcp_servers_raw, dict):
        mcp_servers: dict[str, object] = {str(k): v for k, v in mcp_servers_raw.items()}
    else:
        mcp_servers = {}
    mcp_servers["recon"] = plan.new_block
    existing["mcpServers"] = mcp_servers

    # ensure_ascii=False preserves non-ASCII characters (e.g. accented
    # comments or unicode field values the user may have in their
    # existing config) instead of munging them into \uXXXX escapes.
    rendered = json.dumps(existing, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    _atomic_write_text(plan.path, rendered)

    return InstallResult(
        path=plan.path,
        action=plan.action,
        final_block=plan.new_block,
    )


def _atomic_write_text(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically.

    Writes to a sibling tempfile in the same directory (so the rename
    crosses no filesystem boundary), fsyncs, then ``os.replace``s the
    target. On POSIX and on Windows (10+) ``os.replace`` is atomic for
    same-volume renames, so a partial write — disk full, antivirus
    mid-scan, network drive drop, OS crash — leaves either the old
    config intact or the new config fully on disk. Never a half-
    written truncation.

    ``newline="\\n"`` forces LF line endings even on Windows, matching
    JSON's on-the-wire format and keeping the file diff-stable in Git.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            # Some filesystems (NFS, some Windows network shares) don't
            # support fsync. The atomicity guarantee from os.replace still
            # holds for the rename itself; we just lose the durability
            # guarantee. Acceptable tradeoff — the alternative is refusing
            # to write at all on unusual filesystems.
            with contextlib.suppress(OSError):
                os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # On any failure between mkstemp and replace, sweep the
        # partial tempfile so we don't leave debris next to the real
        # config every time something goes wrong.
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
