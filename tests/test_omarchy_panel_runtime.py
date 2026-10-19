"""Run the real Quickshell process and panel owners without a user desktop."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from recon_tool.formatter.delta import format_delta_json
from recon_tool.formatter.serialize import format_tenant_json
from recon_tool.models import DeltaReport, TenantInfo

REPO = Path(__file__).resolve().parents[1]
FAKE_COMMAND = """#!/usr/bin/env python3
import json, os, signal, socket, sys, time
from pathlib import Path

def exchange(message):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10 if message['kind'] == 'config' else 3)
        connection.connect(os.environ['RECON_QML_SOCKET'])
        connection.sendall((json.dumps(message)+'\\n').encode())
        reply = b''
        while b'\\n' not in reply:
            part = connection.recv(65536)
            if not part:
                raise RuntimeError('private test socket closed without a reply')
            reply += part
        return reply.decode()

args = sys.argv[1:]
name = os.path.basename(sys.argv[0])
if name == 'omarchy-shell':
    assert args == ['shell', 'listShellConfig']
    sys.stdout.write(exchange({'kind':'config'}))
elif name == 'omarchy-launch-terminal':
    exchange({'kind':'terminal','args':args})
else:
    domain = args[1] if args[0] == 'delta' else args[0]
    reports = json.loads((Path(os.environ['RECON_QML_ROOT'])/'reports.json').read_text())
    raw = reports[domain]['delta' if args[0] == 'delta' else 'lookup']
    def delayed_exit(signum, frame):
        time.sleep(0.2)
        sys.stdout.write(raw)
        sys.exit(0)
    signal.signal(signal.SIGTERM, delayed_exit)
    exchange({'kind':'cli','args':args})
    if domain == 'nobaseline.invalid' and args[0] == 'delta':
        sys.exit(3)
    if domain == 'stubborn.invalid':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if domain in ('cancel.invalid', 'timeout.invalid', 'stubborn.invalid'):
        while True:
            time.sleep(0.02)
    if domain == 'malformed.invalid':
        print('{broken')
    elif domain == 'empty.invalid':
        pass
    elif domain == 'failure.invalid':
        print('synthetic command failure', file=sys.stderr)
        sys.exit(7)
    elif domain == 'domainonly.invalid':
        print(json.dumps({'domain':domain, 'services':[]}))
    elif domain == 'baddelta.invalid':
        print(json.dumps({'record_type':'delta', 'has_changes':'false'}))
    else:
        sys.stdout.write(raw)
"""

FAKE_STYLE = """pragma Singleton
import QtQuick
QtObject { readonly property QtObject font: QtObject { property string family: "Sans Serif" } }
"""

FAKE_COLOR = """pragma Singleton
import QtQuick
import Quickshell
QtObject {
    id: root
    readonly property string currentThemePath: Quickshell.env("RECON_QML_ROOT") + "/state/omarchy/current/theme"
    property color background: "#181825"
    property color foreground: "#cdd6f4"
    property color accent: "#89b4fa"
    property color muted: "#6c7086"
    property color urgent: "#f38ba8"
    readonly property QtObject popups: QtObject { property color background: root.background }
}
"""

DARK_THEME = """mode = "dark"
background = "#181825"
foreground = "#cdd6f4"
accent = "#89b4fa"
red = "#f7768e"
yellow = "#e0af68"
green = "#9ece6a"
"""


@pytest.fixture
def private_runtime() -> Iterator[Path]:
    # Unix sockets have short path limits; keep only this owned runtime shallow.
    with tempfile.TemporaryDirectory(prefix="rq-", dir=os.environ.get("RECON_QUALIFICATION_FIXTURES")) as directory:
        yield Path(directory)


def test_real_quickshell_panel_process_and_theme_contracts(tmp_path: Path, private_runtime: Path) -> None:
    executable = shutil.which("quickshell")
    if executable is None:
        pytest.skip("The optional Quickshell desktop runtime is not installed")
    root = tmp_path / "isolated-shell"
    root.mkdir()
    reports: dict[str, dict[str, str]] = {}
    for label in (
        "success",
        "nobaseline",
        "next",
        "visual",
        "cancel",
        "timeout",
        "stubborn",
        "malformed",
        "empty",
        "failure",
        "domainonly",
        "canonicaldelta",
        "baddelta",
    ):
        domain = label + ".invalid"
        info = TenantInfo(
            tenant_id=None, display_name="Synthetic Example", default_domain=domain, queried_domain=domain
        )
        delta = DeltaReport(
            domain=domain,
            added_services=(),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
        )
        reports[domain] = {"lookup": format_tenant_json(info) + "\n", "delta": format_delta_json(delta) + "\n"}
    canonical = json.loads(reports["success.invalid"]["lookup"])
    assert canonical["queried_domain"] == "success.invalid"
    assert "domain" not in canonical
    (root / "reports.json").write_text(json.dumps(reports), encoding="utf-8")
    commons = root / "Commons"
    commons.mkdir()
    (commons / "qmldir").write_text(
        "module qs.Commons\nsingleton Color 1.0 Color.qml\nsingleton Style 1.0 Style.qml\n", encoding="utf-8"
    )
    (commons / "Color.qml").write_text(FAKE_COLOR, encoding="utf-8")
    (commons / "Style.qml").write_text(FAKE_STYLE, encoding="utf-8")
    theme = root / "state" / "omarchy" / "current" / "theme"
    theme.mkdir(parents=True)
    (theme / "colors.toml").write_text(DARK_THEME, encoding="utf-8")
    (theme.parent / "theme.name").write_text("synthetic-dark\n", encoding="utf-8")
    binary = root / "bin"
    binary.mkdir()
    (binary / "python3").symlink_to(sys.executable)
    for name in ("recon", "omarchy-shell", "omarchy-launch-terminal"):
        script = binary / name
        script.write_text(FAKE_COMMAND, encoding="utf-8")
        script.chmod(0o755)
    shutil.copytree(REPO / "integrations/omarchy", root / "Recon")
    template = (REPO / "tests/qml/omarchy_panel_harness.qml").read_text(encoding="utf-8")
    (root / "shell.qml").write_text(template, encoding="utf-8")
    runtime = private_runtime
    env = os.environ.copy()
    env.update(
        PATH=str(binary) + os.pathsep + os.defpath,
        QT_QPA_PLATFORM="offscreen",
        QT_QUICK_BACKEND="software",
        QML_DISABLE_DISK_CACHE="1",
        XDG_RUNTIME_DIR=str(runtime),
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_DATA_HOME=str(root / "data"),
        XDG_CACHE_HOME=str(root / "cache"),
        XDG_STATE_HOME=str(root / "state"),
        RECON_QML_SOCKET=str(runtime / "host.sock"),
        RECON_QML_ROOT=str(root),
        RECON_QML_EXPECTED_LOOKUP=reports["success.invalid"]["lookup"],
    )
    result = subprocess.run(  # noqa: S603 - installed runtime, own config, synthetic processes only.
        [executable, "--no-duplicate", "--no-color", "--path", str(root / "shell.qml")],
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "RECON_QML_FAILED" not in output, output
    marker = next(
        (line.partition("RECON_QML_PASSED ")[2] for line in output.splitlines() if "RECON_QML_PASSED " in line), ""
    )
    assert marker, output
    passed = json.loads(marker)
    assert passed == [
        "absent-only seed",
        "passive opening and payload",
        "fresh settings merge",
        "unchanged settings",
        "explicit invalid value",
        "settings repair",
        "explicit empty value",
        "empty value repair",
        "invalid form",
        "invalid bounds and mode",
        "refused settings write",
        "missing settings executable",
        "settings timeout",
        "malformed payload",
        "malformed config",
        "duplicate config",
        "legacy string placement",
        "canonical lookup argv",
        "copy and paste",
        "terminal argv",
        "no baseline",
        "explicit baseline",
        "canonical delta",
        "invented lookup schema",
        "invalid delta schema",
        "malformed result",
        "empty result",
        "nonzero result",
        "cancel start",
        "late cancelled exit",
        "timeout start",
        "late timeout exit",
        "next run",
        "missing executable",
        "forced termination start",
        "forced termination exit",
        "close running panel",
        "closed panel exit",
        "visual lookup",
        "dark render",
        "light render",
        "theme name recolor",
    ]
    for name in ("dark.png", "light.png"):
        assert (root / name).stat().st_size > 1000
