# Linux and Omarchy Environment Guide

This guide details running recon on Linux environments with a specific focus
on Omarchy and Arch Linux developer workstations.

## Overview

recon is a pure-Python package compatible with Python 3.11 through 3.14. It
requires no compiled extensions, native C dependencies, or root capabilities.
On Linux systems, recon runs as an unprivileged CLI and local stdio MCP server.

Omarchy is an agentic Linux distribution built on Arch Linux, featuring the
Hyprland compositor, the Quickshell desktop shell, and pre-wired lazy-loaded
coding agent launchers. recon integrates cleanly with Omarchy's architecture.

## Installation under PEP 668

Arch Linux and Omarchy mark system Python packages as externally managed
following PEP 668. Direct `pip install` against system Python will be refused.
Use an isolated tool manager:

### Recommended: uv tool

```bash
uv tool install recon-tool
```

`uv` installs recon into an isolated tool environment and symlinks the `recon`
binary into `~/.local/bin/`.

### Alternative: pipx

```bash
pipx install recon-tool
```

### Ephemeral execution: uvx

To run recon without persistent installation:

```bash
uvx --from recon-tool recon example.com
```

Verify the installation:

```bash
recon --version
recon doctor
```

## Omarchy Agent Integration

Omarchy ships with first-class support for AI coding agents. Launchers such as
`claude` (Claude Code), `codex` (OpenAI Codex), `agy` (Google Antigravity),
`copilot` (GitHub Copilot CLI), and `grok` (Grok Build) are provided as
lazy-loaded stubs managed by `mise` in `~/.local/bin/`.

### Claude Code MCP Configuration

To register recon as a Model Context Protocol (MCP) server for Claude Code:

```bash
recon mcp install --client=claude-code
```

This writes the interpreter-bound recon stanza into Claude Code's user
configuration file.

### Support for CLAUDE_CONFIG_DIR and Account Switching

Omarchy supports multi-account agent profiles and autoswitching between
subscriptions. As documented in Omarchy's agent manual, an explicit
`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, or `GROK_HOME` environment variable takes
precedence over the default profile directory.

When `CLAUDE_CONFIG_DIR` is set in the environment:

1. `recon mcp install --client=claude-code` resolves the configuration target to
   `$CLAUDE_CONFIG_DIR/.claude.json` instead of `~/.claude.json`.
2. `recon doctor --client=claude-code` inspects the active `$CLAUDE_CONFIG_DIR/.claude.json`
   file and reports its status.
3. When `CLAUDE_CONFIG_DIR` is unset, the installer and doctor default to `~/.claude.json`.

This ensures that switched accounts and isolated workspaces retain access to the
recon MCP server without manual JSON editing.

### Interpreter-Bound Launcher Security

When `recon mcp install` generates a server configuration block, it does not
persist a bare `recon` command that depends on shell PATH or active mise stubs.
Instead, it binds the stanza to the executing Python interpreter with:

```json
{
  "command": "/path/to/python",
  "args": ["-c", "import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; from recon_tool.server import main; main()"],
  "env": {
    "PYTHONSAFEPATH": "1"
  }
}
```

This design provides two protections on Omarchy:

1. **Path Independence**: The MCP server launches reliably even when GUI
   terminals or background subshells do not inherit the operator's shell PATH.
2. **Workspace Isolation**: Python's working directory is stripped from
   `sys.path` prior to loading `recon_tool`, preventing an untrusted workspace
   from shadowing server modules.

### Verifying MCP Connectivity

After installing the MCP configuration, verify the setup:

```bash
# 1. Verify static registry and installed dependencies
recon doctor --mcp

# 2. Test live stdio JSON-RPC handshake
recon mcp doctor

# 3. Inspect client-specific configuration
recon doctor --client=claude-code
```

## Terminal Rendering in Hyprland

Omarchy defaults to modern terminal emulators such as Alacritty and Foot running
under Hyprland. recon's output formats are designed for high-fidelity terminal
rendering:

- **Compact Briefing Panels**: The default `recon <domain>` panel uses UTF-8
  box-drawing characters and ANSI color styling. It wraps cleanly without
  truncation in standard terminal dimensions.
- **No Paging Interference**: Commands run with predictable exit codes and do
  not spawn interactive pagers that could block agent pipelines.
- **Structured Output**: Passing `--json` emits machine-readable JSON for
  scripting or agent digestion.

## Network Privileges and DNS Resolution

recon performs public metadata reconnaissance without privileged network access:

- **No Root or Capabilities Required**: recon does not perform raw packet
  crafting or port scanning. No `sudo`, `CAP_NET_RAW`, or `CAP_NET_ADMIN`
  capabilities are needed.
- **DNS Queries**: recon performs standard UDP and TCP port 53 DNS queries using
  the system resolver. On Omarchy, this functions transparently with both
  `systemd-resolved` and standard `/etc/resolv.conf` setups.
- **Outbound HTTPS**: Certificate transparency log lookups (via `crt.sh`) and
  MTA-STS policy queries use unprivileged outbound HTTPS requests on port 443.
- **No Credentials Required**: Default operation requires no API keys, accounts,
  or tokens.

## Omarchy Quickshell Desktop Plugin

recon ships an asynchronous desktop plugin for Omarchy located in
[`integrations/omarchy/`](../integrations/omarchy/):

- **Keyboard-driven workflow**: Enter an apex domain, press `Enter` to run
  bounded inspection, and press `Ctrl+D` to toggle baseline delta comparison.
- **Direct process invocation**: Passes structured argument arrays directly
  (`["recon", domain, "--json"]`) without shell interpolation.
- **Safe clipboard handling**: Pasting text never triggers an automatic network request.
- **Bounded execution**: Enforces a 30-second timeout guard.
- **Independent installation and removal**:
  ```bash
  cd integrations/omarchy
  ./install.sh     # Installs to ~/.config/omarchy/plugins/org.recon.omarchy/
  ./uninstall.sh   # Cleans up the plugin directory
  ```
- **Preview**: An offscreen rendered UI preview is available at
  [`docs/assets/omarchy-recon-preview.png`](assets/omarchy-recon-preview.png).
