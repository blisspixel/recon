"""Fast regression tests for the installed-artifact probe, without installation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import check_installed_wheel as smoke

_MANIFEST = Path(__file__).resolve().parents[1] / "agents/agent-plugin/mcp.json"


def test_wheel_selection_requires_one_artifact_with_expected_version(tmp_path: Path) -> None:
    wheel = tmp_path / "recon_tool-1.2.3-py3-none-any.whl"
    with pytest.raises(RuntimeError, match="exactly one wheel"):
        smoke._wheel_path(tmp_path, "1.2.3")
    wheel.touch()
    assert smoke._wheel_path(tmp_path, "1.2.3") == wheel.resolve()
    assert smoke._wheel_path(wheel, "1.2.3") == wheel.resolve()
    with pytest.raises(RuntimeError, match="expected version"):
        smoke._wheel_path(wheel, "1.2.4")
    with pytest.raises(RuntimeError, match="does not exist"):
        smoke._wheel_path(tmp_path / "missing.whl", "1.2.3")
    (tmp_path / "extra.whl").touch()
    with pytest.raises(RuntimeError, match="exactly one wheel"):
        smoke._wheel_path(tmp_path, "1.2.3")


@pytest.mark.parametrize(("field", "value"), [("type", "http"), ("command", "other"), ("args", []), ("env", {})])
def test_unexpected_manifest_contract_is_rejected(tmp_path: Path, field: str, value: Any) -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    manifest["mcpServers"]["recon"][field] = value
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"manifest|portable"):
        smoke._manifest(path)


@pytest.mark.parametrize("result", [None, "outside", "inside"])
def test_entry_point_resolution_never_falls_back_to_global(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: str | None
) -> None:
    executable_dir = tmp_path / "venv" / "Scripts"
    expected = executable_dir / "recon.exe"
    resolved = {None: None, "outside": str(tmp_path / "global" / "recon.exe"), "inside": str(expected)}[result]
    searches = []

    def which(command: str, *, path: str) -> str | None:
        searches.append((command, path))
        return resolved

    monkeypatch.setattr(smoke.shutil, "which", which)
    if result == "inside":
        assert smoke._executable(executable_dir) == str(expected.resolve())
    else:
        with pytest.raises(RuntimeError, match=r"missing|outside"):
            smoke._executable(executable_dir)
    assert searches == [("recon", str(executable_dir))]


@pytest.mark.parametrize("defect", [None, "interpreter", "import", "version", "source_yaml", "catalog"])
def test_install_origin_version_and_generated_data_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str | None
) -> None:
    environment = tmp_path / "venv"
    package = environment / "lib" / "recon_tool"
    (package / "data").mkdir(parents=True)
    (package / "data" / "fingerprints.generated.json").touch()
    monkeypatch.setattr(sys, "prefix", str(tmp_path if defect == "interpreter" else environment))
    if defect == "source_yaml":
        (package / "data" / "fingerprints").mkdir()
    elif defect == "catalog":
        (package / "data" / "fingerprints.generated.json").unlink()
    args = (
        tmp_path if defect == "import" else package,
        environment,
        "wrong" if defect == "version" else "1.2.3",
        "1.2.3",
    )
    if defect:
        with pytest.raises(RuntimeError):
            smoke._assert_install(*args)
    else:
        smoke._assert_install(*args)


@pytest.mark.parametrize("actual", ["1.2.2", "", None])
def test_wrong_or_missing_server_version_fails(actual: str | None) -> None:
    discovery = {"_meta": {"io.modelcontextprotocol/serverInfo": {"version": actual}}}
    with pytest.raises(RuntimeError, match="server version"):
        smoke._assert_server_version(discovery, "1.2.3")
    smoke._assert_server_version({"_meta": {"io.modelcontextprotocol/serverInfo": {"version": "1.2.3"}}}, "1.2.3")


@pytest.mark.parametrize(
    "event",
    [
        "socket.connect",
        "socket.sendto",
        "socket.sendmsg",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
    ],
)
def test_socket_guard_records_even_caught_external_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    log = tmp_path / "denied.txt"
    monkeypatch.setenv(smoke._DENIAL_LOG, str(log))
    with pytest.raises(RuntimeError, match="offline wheel smoke blocked"):
        smoke.deny_network(event, (None, ("192.0.2.1", 443)))
    assert log.read_text(encoding="utf-8") == event + "\n"


def test_socket_guard_allows_asyncio_loopback_but_not_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(smoke._DENIAL_LOG, raising=False)
    for host in ("127.0.0.1", "::1"):
        smoke.deny_network("socket.connect", (None, (host, 1234)))
    smoke.deny_network("open", ("some file",))
    with pytest.raises(RuntimeError, match="wheel smoke guard active"):
        smoke.deny_network("recon.wheel_smoke.guard", ())


def test_subprocess_failures_include_diagnostics_and_have_a_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 2, stdout="out", stderr="err")

    monkeypatch.setattr(smoke.subprocess, "run", run)
    with pytest.raises(RuntimeError, match=r"failed \(2\):\nerr\nout"):
        smoke._run([sys.executable, "--version"], cwd=tmp_path, env={})
    assert calls[0][1]["timeout"] == 180
    assert calls[0][1]["check"] is False
    assert "shell" not in calls[0][1]


def test_manifest_launch_uses_absolute_venv_executable_and_shared_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = tmp_path / "literal ${PLUGIN_DATA}"
    plugin.mkdir()
    (plugin / "mcp.json").write_bytes(_MANIFEST.read_bytes())
    data = tmp_path / "literal ${PLUGIN_ROOT}"
    monkeypatch.setenv(smoke._DENIAL_LOG, str(tmp_path / "denied.txt"))

    def executable(directory: Path) -> str:
        assert directory == Path(sys.executable).parent
        return "absolute-venv-recon"

    monkeypatch.setattr(smoke, "_executable", executable)
    params = smoke._parameters(plugin, data)
    assert params.command == "absolute-venv-recon"
    assert params.args == ["mcp"]
    assert params.cwd == str(plugin)
    assert params.env is not None
    assert params.env["RECON_CONFIG_DIR"] == str(data) + "/recon"
    assert params.env["USERPROFILE"] == ""
    assert params.env[smoke._DENIAL_LOG] == str(tmp_path / "denied.txt")


@pytest.mark.parametrize("offline", [False, True])
def test_bootstrap_installs_only_wheel_and_probes_outside_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offline: bool
) -> None:
    wheel = tmp_path / "recon_tool-1.2.3-py3-none-any.whl"
    wheel.touch()
    calls: list[list[str]] = []

    def which(command: str) -> str:
        assert command == "uv"
        return "uv"

    monkeypatch.setattr(smoke.shutil, "which", which)
    monkeypatch.setenv("PYTHONPATH", "source-contamination")
    monkeypatch.setenv("PYTHONHOME", "source-contamination")

    def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 180) -> str:
        calls.append(command)
        assert cwd.is_relative_to(Path(smoke.tempfile.gettempdir()).resolve())
        assert not (cwd / "pyproject.toml").exists()
        assert "PYTHONPATH" not in env
        assert "PYTHONHOME" not in env
        assert env["UV_LINK_MODE"] == "copy"
        purelib = cwd / "venv" / "lib"
        purelib.mkdir(parents=True, exist_ok=True)
        if "-c" in command:
            return str(purelib)
        if "--probe-root" in command:
            assert command[1] == "-I"
            assert (purelib / "sitecustomize.py").is_file()
            assert (purelib / "recon_wheel_probe.py").is_file()
            assert (cwd / "mcp.json").read_bytes() == _MANIFEST.read_bytes()
        return "pass"

    monkeypatch.setattr(smoke, "_run", run)
    smoke._install_and_probe(wheel, _MANIFEST, "1.2.3", offline=offline)
    assert calls[0][1:3] == ["venv", "--no-config"]
    assert calls[1][1:4] == ["pip", "install", "--no-config"]
    assert calls[1][-1] == str(wheel)
    assert ("--offline" in calls[1]) == offline
    assert len(calls) == 4


def _resource_fixtures() -> tuple[dict[str, Any], dict[str, Any]]:
    from recon_tool.surface_inventory import packaged_surface_inventory_text

    inventory = json.loads(packaged_surface_inventory_text())
    data = Path(__file__).resolve().parents[1] / "src/recon_tool/data"
    payloads = {
        "recon://surface-inventory": inventory,
        "recon://schema": json.loads((data / "recon-schema.json").read_text(encoding="utf-8")),
        "recon://review-bundle-schema": json.loads((data / "review-bundle-schema.json").read_text(encoding="utf-8")),
        "recon://fingerprints": {
            "count": 2,
            "fingerprints": [
                {"slug": slug, "detection_count": 1, "detection_types": ["cname_target"]}
                for slug in (smoke._MARKER, "aws-cloudfront")
            ],
        },
        "recon://signals": {"count": 1, "signals": [{"name": "AI-platform indicators observed"}]},
        "recon://profiles": {"count": 2, "profiles": [{"name": "saas-b2b"}, {"name": "public-sector"}]},
    }
    return inventory, payloads


def _resource_wire(uri: str, value: Any) -> dict[str, Any]:
    return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(value)}]}


def _wire_model(value: dict[str, Any]) -> Any:
    def model_dump(*, by_alias: bool) -> dict[str, Any]:
        assert by_alias is True
        return value

    return SimpleNamespace(model_dump=model_dump)


@pytest.mark.parametrize("catalog", ["fingerprints", "signals", "profiles"])
@pytest.mark.parametrize("defect", ["empty", "wrong_count", "missing_anchor"])
def test_catalog_wrappers_cannot_hide_missing_packaged_data(catalog: str, defect: str) -> None:
    inventory, payloads = _resource_fixtures()
    uri = "recon://" + catalog
    value = payloads[uri]
    if defect == "empty":
        value = {"count": 0, catalog: []}
    elif defect == "wrong_count":
        value["count"] += 1
    else:
        field = "slug" if catalog == "fingerprints" else "name"
        for entry in value[catalog]:
            entry[field] = "unrelated-custom-entry"
    with pytest.raises((ValueError, RuntimeError), match=r"envelope|anchor"):
        smoke._check_resource(uri, _resource_wire(uri, value), inventory)


@pytest.mark.parametrize("defect", ["uri", "mime", "nonobject", "schema_fields"])
def test_resource_contract_rejects_wrong_identity_or_payload(defect: str) -> None:
    inventory, payloads = _resource_fixtures()
    uri = "recon://schema"
    value = payloads[uri]
    if defect == "schema_fields":
        value["required"] = []
        value["properties"] = {}
    result = _resource_wire(uri, [] if defect == "nonobject" else value)
    if defect == "uri":
        result["contents"][0]["uri"] = "recon://signals"
    elif defect == "mime":
        result["contents"][0]["mimeType"] = "text/plain"
    with pytest.raises((ValueError, TypeError, RuntimeError)):
        smoke._check_resource(uri, result, inventory)


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", [None, "version", "tools", "resources", "marker", "tool_error", "tool_empty"])
async def test_stdio_probe_limits_calls_to_local_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str | None
) -> None:
    import mcp
    import mcp.client.stdio

    inventory, payloads = _resource_fixtures()
    tools = [entry["name"] for entry in inventory["mcp"]["tools"]]
    uris = [entry["uri"] for entry in inventory["mcp"]["resources"]]
    calls = []

    class Session:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

        async def discover(self) -> Any:
            version = "wrong" if defect == "version" else "1.2.3"
            return _wire_model({"_meta": {"io.modelcontextprotocol/serverInfo": {"version": version}}})

        async def list_tools(self) -> Any:
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in tools[1 if defect == "tools" else 0 :]])

        async def list_resources(self) -> Any:
            return SimpleNamespace(
                resources=[
                    SimpleNamespace(uri=u, mime_type="application/json")
                    for u in uris[1 if defect == "resources" else 0 :]
                ]
            )

        async def read_resource(self, uri: str) -> Any:
            value = payloads[uri]
            if uri == "recon://fingerprints" and defect == "marker":
                value["fingerprints"][0]["slug"] = "wrong"
            calls.append(uri)
            return _wire_model(_resource_wire(uri, value))

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
            calls.append((name, arguments))
            return SimpleNamespace(
                is_error=defect == "tool_error",
                content=["one fingerprint"],
                structured_content={"result": [] if defect == "tool_empty" else [{"slug": "marker"}]},
            )

    class Transport(Session):
        async def __aenter__(self) -> Any:
            return None, None

    def parameters(plugin_root: Path, data_root: Path) -> None:
        assert plugin_root == tmp_path
        assert data_root == tmp_path

    def transport(params: object) -> Transport:
        assert params is None
        return Transport()

    def session(reader: object, writer: object) -> Session:
        assert reader is None
        assert writer is None
        return Session()

    monkeypatch.setattr(smoke, "_parameters", parameters)
    monkeypatch.setattr(mcp.client.stdio, "stdio_client", transport)
    monkeypatch.setattr(mcp, "ClientSession", session)
    if defect:
        with pytest.raises(RuntimeError):
            await smoke._stdio_probe(tmp_path, tmp_path, "1.2.3", inventory)
    else:
        await smoke._stdio_probe(tmp_path, tmp_path, "1.2.3", inventory)
        assert calls == [*sorted(uris), ("get_fingerprints", {"limit": 1, "offset": 0})]
