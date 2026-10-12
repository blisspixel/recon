"""Exercise the setup owners with private files and synthetic host IPC."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PLUGIN_ID = "org.recon.omarchy"
SCRIPTS = Path(__file__).resolve().parents[1] / "integrations" / "omarchy"
FAKE_HOST = """#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
root = Path(os.environ['RECON_OMARCHY_TEST_ROOT'])
args = sys.argv[1:]
with (root/'calls.jsonl').open('a') as stream:
    stream.write(json.dumps({'args':args,'files_exist':(root/'plugin').exists()})+'\\n')
if os.environ.get('RECON_OMARCHY_TEST_FAIL') == args[1]:
    sys.exit(1)
if os.environ.get('RECON_OMARCHY_TEST_HANG') == args[1]:
    time.sleep(60)
config = json.loads((root/'config.json').read_text())
if args[1] == 'listShellConfig':
    print(json.dumps(config))
elif args[1] == 'rescanPlugins':
    (root/'rescanned').touch()
elif args[1] == 'listPlugins' and not (root/'plugin').exists():
    count = int((root/'removal-scans').read_text()) if (root/'removal-scans').exists() else 0
    (root/'removal-scans').write_text(str(count+1))
    mode = os.environ.get('RECON_OMARCHY_REMOVAL_INVENTORY')
    if mode == 'refused':
        sys.exit(7)
    if mode == 'stubborn':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if mode in ('hung', 'stubborn'):
        time.sleep(60)
    if mode == 'malformed-json':
        print('{broken')
    elif mode == 'malformed-shape':
        print(json.dumps({'plugins':[]}))
    elif mode == 'malformed-entry':
        print(json.dumps([{'name':'missing id'}]))
    elif mode == 'empty-reply':
        pass
    elif mode == 'multiple-json':
        print('[]')
        print('[]')
    else:
        entries = [{'id':'synthetic.other', 'kinds':['panel']}]
        if count == 0 or mode == 'stale':
            entries.append({'id':'org.recon.omarchy', 'kinds':['panel']})
        print(json.dumps(entries))
elif args[1] == 'listPlugins':
    count = int((root/'scans').read_text()) if (root/'scans').exists() else 0
    (root/'scans').write_text(str(count+1))
    stale = count == 0 or os.environ.get('RECON_OMARCHY_STALE_REGISTRY') == '1'
    print(json.dumps([{'id':'org.recon.omarchy', 'kinds':['panel','bar-widget'] if stale else ['panel']}]))
elif args[1] == 'enablePlugin':
    assert args[2:] == ['org.recon.omarchy', '{}']
    if not any(x['id'] == args[2] for x in config['plugins']):
        config['plugins'].append({'id':args[2]})
    (root/'config.json').write_text(json.dumps(config))
    print('ok')
elif args[1] == 'setPluginEnabled':
    assert args[2:] == ['org.recon.omarchy', 'false']
    config['plugins'] = [x for x in config['plugins'] if x['id'] != args[2]]
    for entries in config['bar']['layout'].values():
        entries[:] = [x for x in entries if x['id'] != args[2]]
    (root/'config.json').write_text(json.dumps(config))
    print('ok')
else:
    raise AssertionError(args)
"""


@pytest.fixture
def host(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    if sys.platform != "linux":
        pytest.skip("The Omarchy lifecycle runtime is Linux-only")
    if shutil.which("bash") is None or shutil.which("jq", path=os.defpath) is None:
        pytest.skip("The Omarchy Bash and jq setup runtime is not installed on the fixture PATH")
    timeout = shutil.which("timeout", path=os.defpath)
    if timeout is None:
        pytest.skip("The Omarchy lifecycle runtime requires GNU coreutils timeout on the fixture PATH")
    version = subprocess.run(  # noqa: S603 - admitted local utility, version only, no shell.
        [timeout, "--version"], capture_output=True, text=True, timeout=5, check=False
    )
    if version.returncode != 0 or "GNU coreutils" not in version.stdout:
        pytest.skip("The Omarchy lifecycle runtime requires GNU coreutils timeout")
    binaries = tmp_path / "bin with spaces"
    binaries.mkdir()
    # Use the exact test interpreter without changing any installed environment.
    (binaries / "python3").symlink_to(sys.executable)
    manager = binaries / "omarchy-shell"
    manager.write_text(FAKE_HOST, encoding="utf-8")
    manager.chmod(0o755)
    implementation = binaries / "shim-implementation"
    implementation.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    implementation.chmod(0o755)
    (binaries / "recon").symlink_to(implementation)
    restart = binaries / "omarchy-restart-shell"
    restart.write_text("#!/bin/sh\nexit 98\n", encoding="utf-8")
    restart.chmod(0o755)
    config: dict[str, Any] = {
        "version": 1,
        "plugins": [{"id": "synthetic.other", "private": "DO_NOT_LOG_HOST_FIELD"}],
        "bar": {"layout": {"left": [{"id": "omarchy.workspaces"}], "center": [], "right": []}},
        "unknown": {"preserve": True},
    }
    (tmp_path / "config.json").write_text(json.dumps(config), encoding="utf-8")
    env = os.environ.copy()
    env.update(PATH=str(binaries) + os.pathsep + os.defpath, RECON_OMARCHY_TEST_ROOT=str(tmp_path))
    return tmp_path, env


def invoke(host: tuple[Path, dict[str, str]], action: str) -> subprocess.CompletedProcess[str]:
    root, env = host
    bash = shutil.which("bash")
    assert bash is not None
    return subprocess.run(  # noqa: S603 - actual owner script, private destination, fixed function name.
        [
            bash,
            "-c",
            'source "$1"; ' + action + '_plugin "$2"',
            "--",
            str(SCRIPTS / (action + ".sh")),
            str(root / "plugin"),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def config(host: tuple[Path, dict[str, str]]) -> dict[str, Any]:
    return json.loads((host[0] / "config.json").read_text(encoding="utf-8"))


def calls(host: tuple[Path, dict[str, str]]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (host[0] / "calls.jsonl").read_text(encoding="utf-8").splitlines()]


def test_install_enables_panel_without_bar_or_restart_and_keeps_lexical_shim(host: tuple[Path, dict[str, str]]) -> None:
    before = config(host)
    result = invoke(host, "install")
    assert result.returncode == 0, result.stdout + result.stderr
    after = config(host)
    assert after["bar"] == before["bar"]
    assert after["unknown"] == before["unknown"]
    assert after["plugins"] == [*before["plugins"], {"id": PLUGIN_ID}]
    manifest = json.loads((host[0] / "plugin/manifest.json").read_text(encoding="utf-8"))
    assert manifest["kinds"] == ["panel"]
    assert manifest["entryPoints"] == {"panel": "Panel.qml"}
    assert manifest["defaultLauncher"] == str(host[0] / "bin with spaces/recon")
    assert "DO_NOT_LOG_HOST_FIELD" not in result.stdout + result.stderr
    assert [call["args"][1] for call in calls(host)] == [
        "listShellConfig",
        "rescanPlugins",
        "listPlugins",
        "listPlugins",
        "enablePlugin",
        "listShellConfig",
    ]


def test_reinstall_preserves_explicit_invalid_and_unknown_own_settings(host: tuple[Path, dict[str, str]]) -> None:
    before = config(host)
    before["plugins"].append({"id": PLUGIN_ID, "reconCommand": None, "timeoutSec": 15, "unknown": {"nested": True}})
    (host[0] / "config.json").write_text(json.dumps(before), encoding="utf-8")
    result = invoke(host, "install")
    assert result.returncode == 0, result.stdout + result.stderr
    assert config(host) == before


def test_stale_bar_widget_registry_never_enables_a_bar_entry(host: tuple[Path, dict[str, str]]) -> None:
    before = config(host)
    host[1]["RECON_OMARCHY_STALE_REGISTRY"] = "1"
    result = invoke(host, "install")
    assert result.returncode != 0
    assert config(host) == before
    assert not any(call["args"][1] == "enablePlugin" for call in calls(host))
    assert "did not discover" in result.stderr


@pytest.mark.parametrize("placement", ["bar", "duplicates"])
def test_legacy_and_duplicate_placements_refuse_before_any_mutation(
    host: tuple[Path, dict[str, str]], placement: str
) -> None:
    before = config(host)
    own = {"id": PLUGIN_ID, "reconCommand": "/synthetic/old", "private": "OWN_SETTINGS"}
    before["bar"]["layout"]["right"].append(own)
    if placement == "duplicates":
        before["plugins"].append(own)
    (host[0] / "config.json").write_text(json.dumps(before), encoding="utf-8")
    (host[0] / "plugin").mkdir()
    (host[0] / "plugin/preserve.txt").write_text("old plugin", encoding="utf-8")
    result = invoke(host, "install")
    assert result.returncode != 0
    assert config(host) == before
    assert (host[0] / "plugin/preserve.txt").read_text(encoding="utf-8") == "old plugin"
    assert not (host[0] / "plugin/manifest.json").exists()
    assert [call["args"] for call in calls(host)] == [["shell", "listShellConfig"]]
    if placement == "bar":
        assert "disabling deletes its settings" in result.stderr


def test_unavailable_host_does_not_copy_or_claim_enabled(host: tuple[Path, dict[str, str]]) -> None:
    host[1]["RECON_OMARCHY_TEST_FAIL"] = "listShellConfig"
    result = invoke(host, "install")
    assert result.returncode != 0
    assert not (host[0] / "plugin").exists()
    assert "unavailable" in result.stderr
    assert "panel enabled" not in result.stdout


def test_uninstall_disables_before_deleting_and_preserves_other_entries(host: tuple[Path, dict[str, str]]) -> None:
    assert invoke(host, "install").returncode == 0
    result = invoke(host, "uninstall")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (host[0] / "plugin").exists()
    assert all(entry["id"] != PLUGIN_ID for entry in config(host)["plugins"])
    assert config(host)["plugins"][0]["private"] == "DO_NOT_LOG_HOST_FIELD"
    disable = next(call for call in calls(host) if call["args"][1] == "setPluginEnabled")
    assert disable["files_exist"] is True
    assert calls(host)[-3:] == [
        {"args": ["shell", "rescanPlugins"], "files_exist": False},
        {"args": ["shell", "listPlugins"], "files_exist": False},
        {"args": ["shell", "listPlugins"], "files_exist": False},
    ]
    assert (host[0] / "removal-scans").read_text(encoding="utf-8") == "2"
    assert "disabled and removed" in result.stdout


def test_failed_disable_preserves_installed_files_and_settings(host: tuple[Path, dict[str, str]]) -> None:
    assert invoke(host, "install").returncode == 0
    before = config(host)
    host[1]["RECON_OMARCHY_TEST_FAIL"] = "setPluginEnabled"
    result = invoke(host, "uninstall")
    assert result.returncode != 0
    assert (host[0] / "plugin/manifest.json").is_file()
    assert config(host) == before


@pytest.mark.parametrize("action", ["install", "uninstall"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("plugins", "missing"),
        ("plugins", None),
        ("plugins", {}),
        ("plugins", [None]),
        ("bar", "missing"),
        ("bar", None),
        ("bar", []),
        ("layout", "missing"),
        ("layout", None),
        ("layout", []),
        ("left", "missing"),
        ("left", None),
        ("left", {}),
        ("left", [123]),
    ],
)
def test_invalid_configuration_refuses_before_mutation(
    host: tuple[Path, dict[str, str]], action: str, field: str, value: Any
) -> None:
    before = config(host)
    container = (
        before if field in ("plugins", "bar") else before["bar"] if field == "layout" else before["bar"]["layout"]
    )
    if value == "missing":
        container.pop(field)
    else:
        container[field] = value
    (host[0] / "config.json").write_text(json.dumps(before), encoding="utf-8")
    destination = host[0] / "plugin"
    destination.mkdir()
    (destination / "preserve.txt").write_text("existing plugin", encoding="utf-8")
    result = invoke(host, action)
    assert result.returncode != 0
    assert "invalid configuration" in result.stderr
    assert config(host) == before
    assert (destination / "preserve.txt").read_text(encoding="utf-8") == "existing plugin"
    assert [call["args"] for call in calls(host)] == [["shell", "listShellConfig"]]


def test_supported_string_bar_widgets_are_preserved_and_own_legacy_string_refuses(
    host: tuple[Path, dict[str, str]],
) -> None:
    before = config(host)
    before["bar"]["layout"]["left"] = ["omarchy.workspaces"]
    (host[0] / "config.json").write_text(json.dumps(before), encoding="utf-8")
    assert invoke(host, "install").returncode == 0
    assert config(host)["bar"] == before["bar"]
    after = config(host)
    after["plugins"] = [entry for entry in after["plugins"] if entry["id"] != PLUGIN_ID]
    after["bar"]["layout"]["right"].append(PLUGIN_ID)
    (host[0] / "config.json").write_text(json.dumps(after), encoding="utf-8")
    manifest = (host[0] / "plugin/manifest.json").read_bytes()
    result = invoke(host, "install")
    assert result.returncode != 0
    assert "legacy bar placement" in result.stderr
    assert config(host) == after
    assert (host[0] / "plugin/manifest.json").read_bytes() == manifest


@pytest.mark.parametrize(
    ("action", "method"),
    [
        ("install", "listShellConfig"),
        ("install", "rescanPlugins"),
        ("install", "listPlugins"),
        ("install", "enablePlugin"),
        ("uninstall", "listShellConfig"),
        ("uninstall", "setPluginEnabled"),
        ("uninstall", "rescanPlugins"),
    ],
)
def test_each_setup_ipc_attempt_is_bounded(host: tuple[Path, dict[str, str]], action: str, method: str) -> None:
    if action == "uninstall":
        assert invoke(host, "install").returncode == 0
    host[1]["RECON_OMARCHY_TEST_HANG"] = method
    result = invoke(host, action)
    assert result.returncode != 0
    assert f"Omarchy IPC {method} failed or timed out" in result.stderr
    assert "Check the running shell" in result.stderr
    assert "panel enabled" not in result.stdout
    assert "disabled and removed" not in result.stdout


@pytest.mark.parametrize(
    ("mode", "diagnosis", "attempts"),
    [
        ("stale", "still lists Recon", 20),
        ("malformed-json", "invalid plugin inventory", 1),
        ("malformed-shape", "invalid plugin inventory", 1),
        ("malformed-entry", "invalid plugin inventory", 1),
        ("empty-reply", "invalid plugin inventory", 1),
        ("multiple-json", "invalid plugin inventory", 1),
        ("refused", "could not read plugin inventory", 1),
        ("hung", "could not read plugin inventory", 1),
        ("stubborn", "could not read plugin inventory", 1),
    ],
)
def test_uninstall_does_not_claim_inventory_absence_on_failed_verification(
    host: tuple[Path, dict[str, str]], mode: str, diagnosis: str, attempts: int
) -> None:
    assert invoke(host, "install").returncode == 0
    before = config(host)
    before_calls = len(calls(host))
    host[1]["RECON_OMARCHY_REMOVAL_INVENTORY"] = mode
    result = invoke(host, "uninstall")
    assert result.returncode != 0
    assert diagnosis in result.stderr
    assert "Rerun uninstall.sh" in result.stderr
    assert "disabled and removed" not in result.stdout
    assert not (host[0] / "plugin").exists()
    expected = {**before, "plugins": [entry for entry in before["plugins"] if entry["id"] != PLUGIN_ID]}
    assert config(host) == expected
    assert int((host[0] / "removal-scans").read_text(encoding="utf-8")) == attempts
    removal_calls = calls(host)[before_calls:]
    assert [call["args"][1] for call in removal_calls[:4]] == [
        "listShellConfig",
        "setPluginEnabled",
        "listShellConfig",
        "rescanPlugins",
    ]
    assert all(call["args"] == ["shell", "listPlugins"] for call in removal_calls[4:])
