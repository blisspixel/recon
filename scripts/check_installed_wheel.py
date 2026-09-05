"""Install one built wheel, then probe its local contracts outside the checkout.

Requires uv for installation, which may download runtime dependencies. All
subsequent CLI and MCP probes are offline, with an external-socket audit guard.
Portable manifest expansion and relocation are emulated, not real-client tests.
This standalone file and mcp.json are the only source inputs required.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_MARKER = "synthetic-wheel-marker"
_MARKER_PATTERN = "synthetic-wheel.vendor.invalid"
_DENIAL_LOG = "RECON_WHEEL_SMOKE_DENIAL_LOG"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def deny_network(event: str, args: tuple[Any, ...]) -> None:
    """Guard Python socket calls, allowing loopback for Windows asyncio pipes.

    This is a regression tripwire, not an operating-system sandbox. Record
    blocked attempts so code that catches an exception cannot hide a failure.
    """
    if event == "recon.wheel_smoke.guard":
        raise RuntimeError("wheel smoke guard active")
    if event in {"socket.connect", "socket.sendto", "socket.sendmsg"}:
        address = args[-1]
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            return
    elif event not in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo"}:
        return
    with Path(os.environ[_DENIAL_LOG]).open("a", encoding="utf-8") as log:
        log.write(event + "\n")
    raise RuntimeError(f"offline wheel smoke blocked {event}")


def _run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 180) -> str:
    result = subprocess.run(  # noqa: S603 - argv is constructed locally, never passed to a shell.
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    _require(
        result.returncode == 0,
        f"{Path(command[0]).name} failed ({result.returncode}):\n{result.stderr}\n{result.stdout}",
    )
    return result.stdout.strip()


def _wheel_path(path: Path, version: str) -> Path:
    wheels = list(path.glob("*.whl")) if path.is_dir() else [path]
    _require(len(wheels) == 1, "expected exactly one wheel")
    wheel = wheels[0].resolve()
    _require(wheel.is_file(), "wheel does not exist")
    _require(wheel.name == f"recon_tool-{version}-py3-none-any.whl", "wheel name does not match expected version")
    return wheel


def _manifest(path: Path) -> dict[str, Any]:
    server = json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["recon"]
    _require(server["type"] == "stdio", "portable manifest must use stdio")
    _require(server["command"] == "recon" and server["args"] == ["mcp"], "unexpected portable launch command")
    _require(server["env"] == {"RECON_CONFIG_DIR": "${PLUGIN_DATA}/recon"}, "unexpected portable data contract")
    return server


def _executable(directory: Path) -> str:
    # Windows CreateProcess can otherwise select a global recon even when the
    # child's PATH points to this venv. Resolve before handing the command to MCP.
    executable = shutil.which("recon", path=str(directory))
    _require(executable is not None, "installed recon entry point is missing")
    resolved = Path(str(executable)).resolve()
    _require(resolved.is_relative_to(directory.resolve()), "recon entry point is outside the fresh environment")
    return str(resolved)


def _assert_install(package_root: Path, environment: Path, actual_version: str, expected_version: str) -> None:
    _require(Path(sys.prefix).resolve() == environment.resolve(), "probe interpreter is outside the fresh environment")
    _require(
        package_root.resolve().is_relative_to(environment.resolve()), "recon import is outside the fresh environment"
    )
    _require(actual_version == expected_version, "installed distribution version does not match the artifact")
    _require(
        not (package_root / "data" / "fingerprints").exists(), "wheel unexpectedly contains source fingerprint YAML"
    )
    _require(
        (package_root / "data" / "fingerprints.generated.json").is_file(), "packaged fingerprint catalog is missing"
    )


def _parameters(plugin_root: Path, data_root: Path) -> Any:
    from mcp.client.stdio import StdioServerParameters

    server = _manifest(plugin_root / "mcp.json")
    executable_dir = Path(sys.executable).parent
    roots = {"PLUGIN_ROOT": str(plugin_root), "PLUGIN_DATA": str(data_root)}
    env = {
        "PATH": str(executable_dir) + os.pathsep + os.environ.get("PATH", ""),
        "HOME": "",
        "USERPROFILE": "",
        "HOMEDRIVE": "",
        "HOMEPATH": "",
        "PYTHONNOUSERSITE": "1",
        "RECON_MCP_FORCE_STDIO": "1",
        _DENIAL_LOG: os.environ[_DENIAL_LOG],
        **roots,
    }
    env.update(
        {
            key: re.sub(r"\$\{(PLUGIN_ROOT|PLUGIN_DATA)\}", lambda m: roots[m[1]], value)
            for key, value in server["env"].items()
        }
    )
    return StdioServerParameters(
        command=_executable(executable_dir), args=server["args"], env=env, cwd=str(plugin_root)
    )


def _assert_server_version(discovery: dict[str, Any], version: str) -> None:
    actual = discovery.get("_meta", {}).get("io.modelcontextprotocol/serverInfo", {}).get("version")
    _require(actual == version, "stdio server version does not match the installed wheel")


def _check_resource(uri: str, result: dict[str, Any], inventory: dict[str, Any]) -> None:
    # Reuse the installed doctor's URI, MIME, JSON-object, catalog envelope,
    # and schema checks. Add built-in anchors so a custom overlay cannot mask a
    # missing packaged catalog. These are smoke anchors, not full catalog parity.
    from recon_tool.mcp_client.doctor import _validate_resource_read  # pyright: ignore[reportPrivateUsage]

    _validate_resource_read(uri, result)
    value = json.loads(result["contents"][0]["text"])
    anchors = {
        "recon://fingerprints": ("fingerprints", "slug", {_MARKER, "aws-cloudfront"}),
        "recon://signals": ("signals", "name", {"AI-platform indicators observed"}),
        "recon://profiles": ("profiles", "name", {"saas-b2b", "public-sector"}),
    }
    if uri in anchors:
        key, field, required = anchors[uri]
        _require(
            required <= {entry[field] for entry in value[key]}, f"packaged or client catalog anchor missing: {uri}"
        )
    elif uri == "recon://schema":
        required = {"queried_domain", "provider", "record_type"}
        _require(
            required <= set(value["required"]) and required <= set(value["properties"]), "lookup schema fields missing"
        )
    elif uri == "recon://surface-inventory":
        _require(value == inventory, "served inventory differs from packaged inventory")


async def _stdio_probe(plugin_root: Path, data_root: Path, version: str, inventory: dict[str, Any]) -> None:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async with (
        asyncio.timeout(60),
        stdio_client(_parameters(plugin_root, data_root)) as (reader, writer),
        ClientSession(reader, writer) as session,
    ):
        _assert_server_version((await session.discover()).model_dump(by_alias=True), version)
        tools = (await session.list_tools()).tools
        expected_tools = {entry["name"] for entry in inventory["mcp"]["tools"]}
        _require(
            len(tools) == len(expected_tools) and {t.name for t in tools} == expected_tools, "tool inventory differs"
        )
        _require(len(expected_tools) == 23, "expected 23 packaged tools")
        _require(
            {"lookup_tenant", "get_fingerprints", "build_review_bundle"} <= expected_tools, "required tools missing"
        )
        resources = (await session.list_resources()).resources
        expected_uris = {entry["uri"] for entry in inventory["mcp"]["resources"]}
        _require(
            len(resources) == len(expected_uris) and {str(r.uri) for r in resources} == expected_uris,
            "resource inventory differs",
        )
        _require(len(expected_uris) == 6, "expected six packaged resources")
        _require(all(r.mime_type == "application/json" for r in resources), "listed resource MIME type differs")
        for uri in sorted(expected_uris):
            result = (await session.read_resource(uri)).model_dump(by_alias=True)
            _check_resource(uri, result, inventory)
        catalog_page = await session.call_tool("get_fingerprints", {"limit": 1, "offset": 0})
        _require(not catalog_page.is_error and bool(catalog_page.content), "local catalog tool failed")
        structured = catalog_page.structured_content
        _require(
            isinstance(structured, dict) and len(structured.get("result", [])) == 1, "catalog tool ignored limit=1"
        )


async def _probe(root: Path, manifest: Path, version: str) -> dict[str, Any]:
    try:
        sys.audit("recon.wheel_smoke.guard")
    except RuntimeError as exc:
        _require(str(exc) == "wheel smoke guard active", "unexpected audit guard failure")
    else:
        raise RuntimeError("offline socket guard was not loaded")
    # Import only after isolation and the sitecustomize socket guard are active.
    from importlib.metadata import version as distribution_version

    import recon_tool
    from recon_tool.discovery import find_candidates, load_runtime_patterns
    from recon_tool.surface_inventory import packaged_surface_inventory_text

    package_root = Path(recon_tool.__file__).resolve().parent
    _assert_install(package_root, root / "venv", distribution_version("recon-tool"), version)
    data_root = root / "client data"
    config = data_root / "recon"
    config.mkdir(parents=True)
    os.environ["RECON_CONFIG_DIR"] = str(config)
    custom = config / "fingerprints.yaml"
    custom.write_text(
        f"fingerprints:\n  - name: Synthetic Wheel Marker\n    slug: {_MARKER}\n"
        "    category: Security & Compliance\n    confidence: low\n    detections:\n"
        f"      - type: cname_target\n        pattern: '{_MARKER_PATTERN}'\n",
        encoding="utf-8",
    )
    custom_bytes = custom.read_bytes()
    patterns = load_runtime_patterns()
    _require({"cloudfront.net", _MARKER_PATTERN} <= patterns, "packaged or custom discovery pattern missing")
    observations = [("alpha.invalid", [{"subdomain": "portal", "chain": ["tenant.cloudfront.net"]}])]
    candidates = find_candidates(observations, existing_patterns=patterns, min_count=1, drop_intra_org=False)
    _require(candidates == [], "packaged discovery failed to filter a known synthetic candidate")
    cli = _executable(Path(sys.executable).parent)
    for command in ([cli, "--version"], [sys.executable, "-I", "-m", "recon_tool", "--version"]):
        _require(_run(command, cwd=root, env=dict(os.environ), timeout=60) == f"recon {version}", "CLI version differs")
    inventory = json.loads(packaged_surface_inventory_text())
    for label in ("first install", "updated install"):
        plugin_root = root / label
        plugin_root.mkdir()
        destination = plugin_root / "mcp.json"
        shutil.copyfile(manifest, destination)
        before = destination.read_bytes()
        await _stdio_probe(plugin_root, data_root, version, inventory)
        _require(destination.read_bytes() == before, "stdio launch changed its manifest")
        _require(list(plugin_root.iterdir()) == [destination], "stdio launch wrote to the emulated install directory")
        _require(custom.read_bytes() == custom_bytes, "stdio launch changed client configuration")
    _require(not Path(os.environ[_DENIAL_LOG]).exists(), "a probe attempted external socket activity")
    return {
        "result": "pass",
        "version": version,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "package_root": str(package_root),
        "source_yaml_absent": True,
        "tool_count": len(inventory["mcp"]["tools"]),
        "resource_count": len(inventory["mcp"]["resources"]),
        "manifest_launches": 2,
        "client_data_retained": True,
        "external_socket_attempts": 0,
    }


def _install_and_probe(wheel: Path, manifest: Path, version: str, *, offline: bool) -> None:
    uv = shutil.which("uv")
    _require(uv is not None, "uv is required to install the wheel in a fresh environment")
    with tempfile.TemporaryDirectory(prefix="recon-wheel-smoke-") as directory:
        root = Path(directory).resolve()
        environment = root / "venv"
        env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        env.update({"UV_LINK_MODE": "copy", "PYTHONNOUSERSITE": "1", _DENIAL_LOG: str(root / "network-denials.txt")})
        _run([str(uv), "venv", "--no-config", "--python", sys.executable, str(environment)], cwd=root, env=env)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _run(
            [
                str(uv),
                "pip",
                "install",
                "--no-config",
                "--python",
                str(python),
                *(["--offline"] if offline else []),
                str(wheel),
            ],
            cwd=root,
            env=env,
        )
        purelib = Path(
            _run([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], cwd=root, env=env)
        )
        _require(purelib.resolve().is_relative_to(environment), "site-packages is outside the fresh environment")
        shutil.copyfile(__file__, purelib / "recon_wheel_probe.py")
        (purelib / "sitecustomize.py").write_text(
            "import sys\nfrom recon_wheel_probe import deny_network\nsys.addaudithook(deny_network)\n",
            encoding="utf-8",
        )
        probe = root / "check_installed_wheel.py"
        shutil.copyfile(__file__, probe)
        copied_manifest = root / "mcp.json"
        shutil.copyfile(manifest, copied_manifest)
        print(
            _run(
                [
                    str(python),
                    "-I",
                    str(probe),
                    "--probe-root",
                    str(root),
                    "--manifest",
                    str(copied_manifest),
                    "--version",
                    version,
                ],
                cwd=root,
                env=env,
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--wheel", type=Path, help="wheel file, or directory containing exactly one wheel")
    mode.add_argument("--probe-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--version", required=True, help="expected project or release-tag version")
    parser.add_argument("--offline", action="store_true", help="also forbid package-index access during installation")
    args = parser.parse_args()
    manifest = args.manifest.resolve()
    _manifest(manifest)
    if args.probe_root:
        print(json.dumps(asyncio.run(_probe(args.probe_root.resolve(), manifest, args.version)), sort_keys=True))
    else:
        _install_and_probe(_wheel_path(args.wheel, args.version), manifest, args.version, offline=args.offline)


if __name__ == "__main__":
    main()
