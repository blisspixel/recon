# Recon Omarchy panel

An on-demand, keyboard-first public-metadata inspector. The plugin reuses Recon's
structured CLI output and adds no service, watcher or automatic network query.
Plugin version 2.0.0 changes the host integration from a bar widget to a panel;
it does not change the Recon package version or CLI contract.

## Install and open

Install `recon-tool` with the supported [installer](../../docs/getting-started.md)
or an existing isolated tool manager. Confirm `recon --version` works before:

```bash
cd integrations/omarchy
bash install.sh
omarchy-shell shell toggle org.recon.omarchy '{}'
```

The setup scripts require the running Omarchy shell and its existing `jq` and
coreutils `timeout` utilities. Every setup IPC attempt has a one-second limit
plus a one-second force-termination grace. Invalid version1 configuration shapes
are refused before setup mutation, including missing or non-array plugin and
bar-layout sections; supported string bar-widget entries remain supported.
It copies the plugin to `~/.config/omarchy/plugins/org.recon.omarchy`, rescans the
registry, waits for registration and enables one inline `plugins[]` entry. It
neither adds a bar slot nor restarts the shell. Failure to verify enablement is
reported as failure. Duplicate Recon entries are refused before modification.
Registration waits for the own ID with exactly panel-only kinds, rather than
accepting a stale bar-widget registry entry. The current public inventory does
not expose version or launcher metadata, so it cannot prove freshness of an
already panel-only registry entry. Installed manifest bytes are updated; a
settings read failure remains visible and disables dispatch.

The installed manifest records the absolute lexical path of the external
`recon` launcher found on PATH, preserving tool-manager shim identity. On first
open only, the panel seeds an **absent** `reconCommand` through its own host
facade. An existing value, including empty, null or invalid values, is never
replaced automatically. Reinstalling does not reset existing inline settings.

Use the host's public `toggle` or `summon` command, which can load an unopened
panel. No plugin-owned IPC target needs to be running beforehand:

```bash
omarchy-shell shell summon org.recon.omarchy '{"domain":"alpha.invalid","mode":"delta"}'
```

Opening, prefilled payloads, pasting, copying and saving settings never run a
lookup. Press Enter or Inspect to query. A malformed payload produces an error
and cannot dispatch a command.

## Settings and execution

Choose **Settings** in the panel. Settings belong to the one enabled inline
Omarchy entry, not a second plugin configuration file:

| Setting | Contract |
| --- | --- |
| `reconCommand` | Absolute executable launcher path; preserve the shim path rather than its symlink target |
| `timeoutSec` | Integer from 10 to 120 seconds; absent defaults to 30 |
| `defaultMode` | `lookup` or `delta`; absent defaults to `lookup` |

Invalid explicit settings and failed settings reads disable dispatch. The form
allows repair; missing or non-executable launchers produce a visible startup
error. Each Save reads the fresh own entry, merges only edited fields, writes
through the own-plugin facade, then verifies those values through another read.
Unknown own-entry keys and fresh changes to untouched fields are preserved.
The host replaces an entry as a unit; this is not a compare-and-swap transaction
or a guarantee against a simultaneous write between that read and write. Full
host configuration is neither logged nor retained by the panel.

Lookup uses `[absoluteLauncher, domain, "--json"]`; comparison uses
`[absoluteLauncher, "delta", domain, "--json"]`. Arguments are passed directly,
with no shell interpolation. Only one child runs at a time. Cancellation and
timeout retain their diagnosis through a delayed exit, send SIGTERM, then
SIGKILL after one second if necessary. Reading settings has a separate
five-second timeout. Closing the panel cancels its owned query.

A missing baseline (delta exit 3) offers **Record baseline**. That explicit action
runs one ordinary lookup; opening the panel or comparing does not silently
collect a baseline. Incomplete comparisons retain their partial badge, degraded
sources, suppressed fields and comparable changes. Observations are not a
security verdict.

**Copy JSON** copies the completed structured result as plain text through Qt.
It launches no process and does not query. **Open in terminal** is a separate,
explicit new lookup using `recon <domain> --explain`, not a display of the cached
JSON. It invokes the host terminal helper with separate arguments:
`[omarchy-launch-terminal, "--hold", absoluteLauncher, domain, "--explain"]`.
Terminal support for `--hold` is best effort.

The UI follows the host's live native palette and font, including light and
dark themes. There is no automatic watching or scheduled refresh. Optional
watching remains a separate follow-up, not an installed background feature.

## Colors

Status colors match the CLI roles: success is the active theme's green,
warning its yellow and error its red. The theme accent stays the focus and
selection color. Every status chip and banner also carries its word (for
example "Degraded sources", "Changes Observed", "Partial comparison"), so the
panel still reads correctly when a theme's colors are close or identical.

The host `Color` singleton exposes only `foreground`, `background`, `accent`,
`urgent` and `muted`, with no green, yellow or light/dark flag. The panel
therefore reads the active theme's own `colors.toml` from the host's
`Color.currentThemePath` (normally `~/.local/state/omarchy/current/theme`)
through Quickshell `FileView`. It reads only `green`, `yellow`, `red`, the
legacy `color2`, `color3`, `color1` and `mode`, accepts six-digit hex values
only, and never runs a shell or helper for this. The light/dark flag is the
theme's `mode` key, or the luminance of the host background when `mode` is
absent.

The file is read when the panel opens and again when the theme changes while it
is open: either the host's live palette roles change, or
`~/.local/state/omarchy/current/theme.name` is rewritten. Omarchy replaces the
whole theme directory on a switch, so the panel watches that name file rather
than `colors.toml` itself. The watch exists only while the panel is open. A
missing or unreadable file, a missing role, or two roles with the same color
fall back to a fixed light or dark set picked by the light/dark flag, with
error kept on the host's `urgent` role. The same light and dark sets serve
standalone previews of `ReconView.qml`:

```bash
python scripts/preview_omarchy_ui.py --light --output /tmp/recon-light.png
```

The preview script needs PySide6, which is not a recon dependency.

## Optional keybinding and menu entry

These examples are manual opt-ins. The installer does not edit user bindings or
menus. Current Omarchy uses Lua bindings; add a free shortcut to
`~/.config/omarchy/bindings.lua`:

```lua
o.bind("SUPER + ALT + R", "Recon", "omarchy-shell shell toggle org.recon.omarchy '{}'")
```

An optional native menu entry in
`~/.config/omarchy/extensions/omarchy-menu.jsonc` can use:

```json
{
  "recon": {
    "label": "Recon",
    "description": "On-demand public-metadata lookup",
    "action": "omarchy-shell shell summon org.recon.omarchy '{}'"
  }
}
```

Merge this entry into the existing object, preserving other entries. Check for
shortcut and menu ID conflicts before choosing either example.

| Shortcut | Action |
| --- | --- |
| Enter | Inspect the entered domain |
| Escape | Cancel the active lookup or dismiss the panel |
| Ctrl+D | Toggle baseline comparison |
| Ctrl+L | Clear the domain input and visible results |
| Tab / Shift+Tab | Navigate controls |

## Legacy bar migration

Version 1.0.0 used a bar placement. The host can still load an enabled panel
from that entry, but its public IPC has no supported operation to move the
entry to `plugins[]` while preserving settings and removing the bar placement.
The installer therefore refuses a legacy bar entry **before any file, settings
or enablement mutation**. It does not rewrite the whole host configuration.

Export and inspect **only the Recon entry** before explicitly disabling it:

```bash
omarchy-shell shell listShellConfig | jq '[.plugins[]?, .bar.layout.left[]?, .bar.layout.center[]?, .bar.layout.right[]?] | map(select((if type == "string" then . else .id end) == "org.recon.omarchy"))' > recon-plugin-settings.json
```

Confirm the export contains the intended entry. Keep it privately if its custom
settings are sensitive. Disabling **deletes the old inline entry and its
settings**; it is not a lossless migration:

```bash
omarchy-shell shell setPluginEnabled org.recon.omarchy false
bash install.sh
```

Open Settings and re-enter the supported values from the export. Other custom
keys remain in the export and are not automatically restored. If duplicate
entries exist, resolve their ownership in Omarchy before reinstalling. An
assisted migration is outside this plugin's current contract.

## Remove

```bash
cd integrations/omarchy
bash uninstall.sh
```

Uninstall disables and verifies removal of the own host entry before deleting
plugin files, without restarting the shell, then waits for the own ID to leave
the public inventory after rescanning. Verification polls at most 20 times,
0.1 seconds apart, with each IPC client limited to one second plus a one-second
force-termination grace using Omarchy's coreutils `timeout`. Stale inventory,
malformed replies and refused or timed-out IPC report failure rather than
claiming verified removal; rerun uninstall once the shell is ready. A failed
disable preserves files. Disabling removes inline settings, so export them first
if needed. Remove any manually added keybinding or menu entry yourself.

## Qualification and limits

The panel lifecycle, manifest and facade contract were reviewed against Omarchy
commit [`9480d1b6`](https://github.com/omacom/omarchy/tree/9480d1b6a98156314dbabe6bfef08f39f8b9cd07).
The theme color source (`shell/Commons/Color.qml`, `bin/omarchy-theme-set` and
`docs/theming.md`) was reviewed against Omarchy commit
[`81fd2d23`](https://github.com/omacom/omarchy/tree/81fd2d23ca6e3462183a4dc8360de3113fa8d80c).
The host's panel loader supplies the manifest and own-plugin facade; generic
bar-widget settings are not injected into panels. Settings reads use the fixed
public `omarchy-shell shell listShellConfig` call and immediately project the
own entry in memory. Writes use that own facade, with no second live authority.

```bash
uv run pytest tests/test_omarchy_integration.py tests/test_omarchy_lifecycle.py tests/test_omarchy_panel_runtime.py tests/test_omarchy_theme_colors.py
```

With the optional installed Qt Quick Test and Quickshell runtimes, these tests
execute actual QML rendering, process startup/termination, clipboard operations
and Bash lifecycle scripts with synthetic CLI/IPC peers and private XDG roots.
Successful lookup and delta fixtures come from the actual Python formatters and
synthetic models, with raw JSON byte-copy controls and malformed-schema refusals.
They exercise no real desktop, user configuration or external domain. Missing
optional desktop runtimes are reported as skips. Light/dark rendering checks
supply native palette roles in an isolated shell; they do not establish live
compatibility with every Omarchy release or terminal.

Primary contracts: [Quickshell Process](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/Process/),
[Qt plain-text copying](https://doc.qt.io/qt-6/qml-qtquick-textedit.html#copy-method),
and [terminal argv and hold support](https://github.com/Vladimir-csp/xdg-terminal-exec#syntax).
