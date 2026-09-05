"""Offline, manifest-driven portable launch checks, not real-client validation."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import AnyUrl

from recon_tool.mcp_client.sdk_compat import SDK_FAMILY, model_wire_dict
from scripts.check_agent_plugin import DEFAULT_PLUGIN_ROOT, DEFAULT_PROJECT, _project_version


def _expand_placeholders(value: str, roots: dict[str, str]) -> str:
    """Expand only original tokens, not placeholder text introduced by paths."""
    return re.sub(r"\$\{(PLUGIN_ROOT|PLUGIN_DATA)\}", lambda match: roots[match[1]], value)


def _parameters(plugin_root: Path, data_root: Path) -> StdioServerParameters:
    """Emulate the spec's default cwd, executable search, and env expansion."""
    server = json.loads((plugin_root / "mcp.json").read_text(encoding="utf-8"))["mcpServers"]["recon"]
    command = str(server["command"])
    # Select this test environment's installed entry point, not a global recon.
    executable_dir = str(Path(sys.executable).parent)
    resolved_command = shutil.which(command, path=executable_dir)
    assert resolved_command, "test environment must install the recon entry point"
    env = {
        "PATH": executable_dir + os.pathsep + os.environ.get("PATH", ""),
        "PLUGIN_ROOT": str(plugin_root),
        "PLUGIN_DATA": str(data_root),
        # No useful home directory is required. These override the MCP SDK's
        # inherited default fields without changing the parent environment.
        "HOME": "",
        "USERPROFILE": "",
        "HOMEDRIVE": "",
        "HOMEPATH": "",
    }
    roots = {"PLUGIN_ROOT": str(plugin_root), "PLUGIN_DATA": str(data_root)}
    for key, value in server["env"].items():
        env[key] = _expand_placeholders(value, roots)
    # The client resolves the bare manifest token before launching. Windows
    # process creation need not use the child's configured PATH for resolution.
    return StdioServerParameters(command=resolved_command, args=server["args"], env=env, cwd=str(plugin_root))


def test_emulated_client_passes_resolved_executable_to_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = str(tmp_path / "client executables" / "recon.exe")
    searches: list[tuple[str, str | None]] = []

    def resolve(command: str, *, path: str | None = None) -> str:
        searches.append((command, path))
        return resolved

    monkeypatch.setattr(shutil, "which", resolve)
    params = _parameters(DEFAULT_PLUGIN_ROOT, tmp_path / "client data")

    assert searches == [("recon", str(Path(sys.executable).parent))]
    assert params.command == resolved
    assert params.args == ["mcp"]


def _assert_runtime_version(discovery: dict[str, Any], expected: str) -> None:
    server_info = discovery.get("_meta", {}).get("io.modelcontextprotocol/serverInfo", {})
    assert server_info.get("version") == expected, "launched server must report this project's recon version"


@pytest.mark.parametrize("actual", ["2.18.3", "", None])
def test_discovery_rejects_wrong_or_missing_runtime_version(actual: str | None) -> None:
    discovery = {"_meta": {"io.modelcontextprotocol/serverInfo": {"version": actual}}}

    with pytest.raises(AssertionError, match="this project's recon version"):
        _assert_runtime_version(discovery, "2.18.4")


def test_emulated_expansion_is_single_pass_and_preserves_unknown_tokens(tmp_path: Path) -> None:
    plugin_root = str(tmp_path / "literal ${PLUGIN_DATA}" / "plugin")
    data_root = str(tmp_path / "literal ${PLUGIN_ROOT}" / "data")
    roots = {"PLUGIN_ROOT": plugin_root, "PLUGIN_DATA": data_root}

    assert _expand_placeholders("${PLUGIN_ROOT} ${PLUGIN_DATA} ${UNKNOWN}", roots) == (
        f"{plugin_root} {data_root} ${{UNKNOWN}}"
    )


async def _discover_catalog(params: StdioServerParameters) -> set[str]:
    # A parallel Windows CI worker can take materially longer to import the
    # installed runtime. Bound the whole lifecycle without a fragile 2s budget.
    async with asyncio.timeout(60), stdio_client(params) as (reader, writer), ClientSession(reader, writer) as session:
        compatible_session: Any = session
        discover = getattr(compatible_session, "discover", None)
        if callable(discover):
            discovery = model_wire_dict(await discover())
            _assert_runtime_version(discovery, _project_version(DEFAULT_PROJECT))
        else:
            # Legacy FastMCP does not advertise recon's own version. The modern
            # server/discover identity above does, and must match the project.
            await compatible_session.initialize()
        tools = model_wire_dict(await session.list_tools())["tools"]
        assert len(tools) == 23
        assert {"lookup_tenant", "get_fingerprints", "build_review_bundle"} <= {tool["name"] for tool in tools}
        uri: Any = AnyUrl("recon://fingerprints") if SDK_FAMILY == "v1" else "recon://fingerprints"
        resource = model_wire_dict(await session.read_resource(uri))
        catalog = json.loads(resource["contents"][0]["text"])
        return {entry["slug"] for entry in catalog["fingerprints"]}


@pytest.mark.asyncio
async def test_relocated_plugin_launch_preserves_client_data_without_source_checkout(tmp_path: Path) -> None:
    data_root = tmp_path / "client data"
    config_root = data_root / "recon"
    config_root.mkdir(parents=True)
    custom = config_root / "fingerprints.yaml"
    custom.write_text(
        "fingerprints:\n"
        "  - name: Synthetic Plugin Marker\n"
        "    slug: synthetic-plugin-marker\n"
        "    category: Security & Compliance\n"
        "    confidence: low\n"
        "    detections:\n"
        "      - type: txt\n"
        "        pattern: '^synthetic-plugin-marker='\n",
        encoding="utf-8",
    )
    marker_bytes = custom.read_bytes()
    for installation in ("first install", "updated install"):
        plugin_root = tmp_path / installation
        shutil.copytree(DEFAULT_PLUGIN_ROOT, plugin_root)
        before = {path.relative_to(plugin_root): path.read_bytes() for path in plugin_root.rglob("*") if path.is_file()}
        assert not (plugin_root / "pyproject.toml").exists()
        assert "synthetic-plugin-marker" in await _discover_catalog(_parameters(plugin_root, data_root))
        after = {path.relative_to(plugin_root): path.read_bytes() for path in plugin_root.rglob("*") if path.is_file()}
        assert after == before, "stdio launch must not mutate the installed package"
        assert custom.read_bytes() == marker_bytes
