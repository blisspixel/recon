# Recon Omarchy Integration

A polished, keyboard-first Omarchy desktop shell plugin for Recon.

This plugin integrates Recon directly into Omarchy's Quickshell environment,
allowing developers and security operators to inspect public-metadata domain
intelligence and baseline drift without leaving their keyboard workflow.

## Features

- **Keyboard-First Interface**: Focus the domain input automatically, press
  `Enter` to inspect, `Ctrl+D` to toggle baseline comparison, and `Esc` to
  cancel or dismiss.
- **Direct Process Execution**: Invokes `recon` directly with structured argument
  arrays (`["recon", domain, "--json"]` or `["recon", "delta", domain, "--json"]`).
  Never invokes an intermediate shell or shell interpolation.
- **Safe Input & Clipboard Handling**: Pasting text into the domain input box
  never triggers an automatic network request. Execution requires an explicit
  operator action.
- **Client-Side Domain Validation**: Validates and normalizes input against
  canonical domain rules before spawning any process, immediately rejecting
  spaces, shell meta-characters, and malformed strings.
- **Fail-Closed Bounded Execution**: Enforces a 30-second timeout guard. If
  remote nameservers or network links hang, the query halts safely.
- **Baseline Drift Detection**: Seamlessly toggles delta comparison against
  cached baseline snapshots, highlighting added and removed services.
- **Hedged Observation Semantics**: Surfaces provider, tenant indicators,
  services, and CT subdomains with explicit uncertainty and hedge notices.
  Observations are not a security verdict.
- **Independent & Removable**: Lives cleanly in user configuration space with zero
  system daemon dependencies.

## Installation

Ensure `recon` is installed and available on your PATH:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

Run the installation script:

```bash
cd integrations/omarchy
./install.sh
```

Or copy manually into Omarchy's third-party plugin directory:

```bash
mkdir -p ~/.config/omarchy/plugins/org.recon.omarchy
cp manifest.json Widget.qml ReconView.qml README.md ~/.config/omarchy/plugins/org.recon.omarchy/
```

Restart the Omarchy shell to activate the bar widget:

```bash
omarchy-restart-shell
```

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Enter` | Run inspection for entered domain |
| `Escape` | Cancel active lookup (if running) or dismiss panel |
| `Ctrl+D` | Toggle baseline delta comparison mode |
| `Ctrl+L` | Clear domain input and current results |
| `Tab` / `Shift+Tab` | Navigate interactive controls |

## Removal

To remove the plugin cleanly:

```bash
cd integrations/omarchy
./uninstall.sh
```

Or delete the plugin folder directly:

```bash
rm -rf ~/.config/omarchy/plugins/org.recon.omarchy
omarchy-restart-shell
```
