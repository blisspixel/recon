"""Omarchy panel status colors: distinct success, warning and error roles (issue #231)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
OMARCHY_DIR = REPO_ROOT / "integrations" / "omarchy"
PANEL = (OMARCHY_DIR / "Panel.qml").read_text(encoding="utf-8")
VIEW = (OMARCHY_DIR / "ReconView.qml").read_text(encoding="utf-8")
PALETTE = (OMARCHY_DIR / "ThemePalette.js").read_text(encoding="utf-8")


STATUS_ROLES = ("success", "warning", "error", "info")


def _native_role(name: str) -> str:
    block = PANEL.split("readonly property var nativeColors: ({", 1)[1].split("})", 1)[0]
    match = re.search(rf"\b{name}:\s*([^,\n]+)", block)
    assert match is not None, name
    return match.group(1).strip()


def test_status_roles_are_distinct_and_not_accent_or_urgent() -> None:
    roles = {name: _native_role(name) for name in STATUS_ROLES}
    assert len(set(roles.values())) == 4, roles
    for expression in roles.values():
        assert expression not in ("Commons.Color.accent", "Commons.Color.urgent"), roles
    fills = {name: _native_role(name + "Fill") for name in STATUS_ROLES}
    assert len(set(fills.values())) == 4, fills
    for expression in fills.values():
        assert "Commons.Color.accent" not in expression, fills
        assert "Commons.Color.urgent" not in expression, fills
    # Accent stays the focus and selection role.
    assert _native_role("accent") == "Commons.Color.accent"


def test_confidence_badge_matches_cli_roles() -> None:
    # High is success, Medium info, Low warning; the badge keeps its word.
    badge = VIEW.split("// Confidence badge", 1)[1].split("// Provider & Tenant Row", 1)[0]
    assert badge.count('c === "medium" ? root.colors.info :') == 2
    assert 'c === "medium" ? root.colors.infoFill : root.colors.warningFill' in badge
    assert badge.count("root.colors.info : root.colors.warning") == 2
    assert 'c.slice(1) + " Confidence"' in badge


def test_preview_fallback_has_light_and_dark_sets() -> None:
    # The standalone view no longer embeds one fixed dark hex palette.
    assert not re.search(r"#[0-9A-Fa-f]{6}", VIEW)
    assert "property bool lightTheme" in VIEW
    assert "ThemePalette.fallback.light" in VIEW
    assert "ThemePalette.fallback.dark" in VIEW
    assert "lightTheme: root.lightTheme" in PANEL


def test_theme_colors_are_read_without_a_shell_and_follow_theme_changes() -> None:
    # Read through Quickshell FileView, from the host's own theme path, with no process.
    assert 'path: root.themePath + "/colors.toml"' in PANEL
    assert "Commons.Color.currentThemePath" in PANEL
    assert not re.search(r"command\s*=.*theme", PANEL, re.IGNORECASE)
    assert "omarchy-theme" not in PANEL
    # Reread at open and when the host palette or the theme name changes while open.
    assert "themeColorsFile.reload();" in PANEL.split("function open(", 1)[1].split("function close(", 1)[0]
    assert "target: Commons.Color" in PANEL
    assert "enabled: root.opened" in PANEL
    assert "watchChanges: root.opened" in PANEL
    assert "onLoadFailed: root.themeKeys = ({})" in PANEL


def test_installer_copies_every_local_import() -> None:
    install = (OMARCHY_DIR / "install.sh").read_text(encoding="utf-8")
    copied = re.search(r"\{([^}]*)\}", install.split('cp -- "${SCRIPT_DIR}"/', 1)[1])
    assert copied is not None
    names = set(copied.group(1).split(","))
    for source in OMARCHY_DIR.glob("*.qml"):
        for local in re.findall(r'^import "([^"]+)"', source.read_text(encoding="utf-8"), re.MULTILINE):
            assert local in names, (source.name, local)


NODE_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(process.argv[process.argv.length - 1], "utf8").replace(/^\.pragma library\s*$/m, "");
const palette = {};
vm.runInNewContext(source + "\nthis.out = {parse, isLight, statusRoles, fill, fallback};", palette);
const cases = JSON.parse(fs.readFileSync(0, "utf8"));
const results = cases.map(function(c) {
    const keys = palette.out.parse(c.raw);
    const light = palette.out.isLight(keys, c.background);
    return {keys: keys, light: light, roles: palette.out.statusRoles(keys, light, c.urgent)};
});
process.stdout.write(JSON.stringify({results: results, fallback: palette.out.fallback}));
"""

CANONICAL_DARK = """mode = "dark"
accent = "#7aa2f7"
background = "#1a1b26"
foreground = "#a9b1d6"
red = "#f7768e"
yellow = "#e0af68"
green = "#9ece6a"
blue = "#7aa2f7"
bright_green = "#b9f27c"
"""
CANONICAL_LIGHT = """mode = 'light'
background = "#eff1f5"
red = "#D20F39"   # inline comment
yellow = "#df8e1d"
green = "#40a02b"
blue = "#1e66f5"
"""
LEGACY = """background = "#fdf6e3"
color1 = "#dc322f"
color2 = "#859900"
color3 = "#b58900"
color4 = "#268bd2"
"""


def _run_palette(cases: list[dict[str, str]]) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed to evaluate the QML JavaScript library")
    result = subprocess.run(  # noqa: S603 - fixed local script and repository file, no shell.
        [node, "-e", NODE_HARNESS, str(OMARCHY_DIR / "ThemePalette.js")],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_palette_reads_theme_green_yellow_red_and_mode() -> None:
    output = _run_palette(
        [
            {"raw": CANONICAL_DARK, "background": "#1a1b26", "urgent": "#f7768e"},
            {"raw": CANONICAL_LIGHT, "background": "#eff1f5", "urgent": "#d20f39"},
            {"raw": LEGACY, "background": "#fdf6e3", "urgent": "#dc322f"},
        ]
    )
    dark, light, legacy = output["results"]
    assert dark["keys"] == {
        "mode": "dark",
        "red": "#f7768e",
        "yellow": "#e0af68",
        "green": "#9ece6a",
        "blue": "#7aa2f7",
    }
    assert dark["light"] is False
    assert (dark["roles"]["success"], dark["roles"]["warning"], dark["roles"]["error"]) == (
        "#9ece6a",
        "#e0af68",
        "#f7768e",
    )
    assert dark["roles"]["source"] == "theme"
    assert dark["roles"]["warningFill"] == "#1fe0af68"
    assert dark["roles"]["info"] == "#7aa2f7"
    assert dark["roles"]["infoFill"] == "#1f7aa2f7"
    assert light["roles"]["info"] == "#1e66f5"
    assert light["light"] is True
    assert light["roles"]["error"] == "#d20f39"
    # Legacy ANSI keys work and the light flag falls back to background luminance.
    assert legacy["light"] is True
    assert (legacy["roles"]["success"], legacy["roles"]["warning"], legacy["roles"]["error"]) == (
        "#859900",
        "#b58900",
        "#dc322f",
    )
    assert legacy["roles"]["info"] == "#268bd2"
    for item in output["results"]:
        roles = item["roles"]
        assert roles["source"] == "theme"
        assert len({roles[name] for name in STATUS_ROLES}) == 4


def test_palette_falls_back_without_collapsing_roles() -> None:
    output = _run_palette(
        [
            {"raw": "", "background": "#101315", "urgent": "#a55555"},
            {"raw": "", "background": "#f3f3f3", "urgent": "#a01929"},
            {"raw": 'green = "#aaaaaa"\nyellow = "#aaaaaa"\nred = "#bbbbbb"\n', "background": "#000000", "urgent": ""},
            {"raw": 'green = "not-a-color"\nmode = "sepia"\nred = "#12345"\n', "background": "#000000", "urgent": ""},
            {
                "raw": 'green = "#00aa00"\nyellow = "#aaaa00"\nred = "#aa0000"\nblue = "#aaaa00"\n',
                "background": "#000000",
                "urgent": "",
            },
            {"raw": 'green = "#00aa00"\nyellow = "#aaaa00"\nred = "#aa0000"\n', "background": "#000000", "urgent": ""},
        ]
    )
    fallback = output["fallback"]
    empty_dark, empty_light, colliding, invalid, info_collides, info_missing = output["results"]
    assert empty_dark["light"] is False
    assert empty_light["light"] is True
    assert empty_dark["roles"]["source"] == "fallback"
    # Error keeps the host's own urgent role; success and warning use the fixed set.
    assert empty_dark["roles"]["error"] == "#a55555"
    assert empty_dark["roles"]["success"] == fallback["dark"]["success"]
    assert empty_light["roles"]["warning"] == fallback["light"]["warning"]
    assert colliding["roles"]["source"] == "fallback"
    assert invalid["keys"] == {}
    # Info that repeats another role, or is absent, sends the theme to the fallback set.
    assert info_collides["roles"]["source"] == "fallback"
    assert info_missing["roles"]["source"] == "fallback"
    assert info_missing["roles"]["info"] == fallback["dark"]["info"]
    for item in output["results"]:
        roles = item["roles"]
        assert len({roles[name] for name in STATUS_ROLES}) == 4
    for mode in ("light", "dark"):
        roles = fallback[mode]
        assert len({roles[name] for name in (*STATUS_ROLES, "accent")}) == 5
        assert len({roles[name + "Fill"] for name in STATUS_ROLES}) == 4
