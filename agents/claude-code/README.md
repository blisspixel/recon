# recon — Claude Code plugin

This directory packages recon as a [Claude Code plugin](https://docs.claude.com/en/docs/claude-code/plugins): one install wires up the MCP server and ships a skill that teaches Claude *when* and *how* to use recon.

## What's inside

```
agents/claude-code/
├── .claude-plugin/plugin.json   # plugin manifest
├── .mcp.json                    # MCP server registration (recon mcp)
├── skills/recon/SKILL.md        # skill — recon's voice, workflow patterns, hedging rules
└── README.md                    # this file
```

## Install

The plugin wires up Claude Code (skill + MCP launch config). It does **not** install the recon Python package — that step is still the user's responsibility, just like any other MCP server.

### 1. Install the recon CLI

Pick whichever fits your environment:

| Form | Command | When to use |
|---|---|---|
| **pip (default)** | `pip install recon-tool` | Most users. `recon` ends up on PATH; lowest startup latency. |
| **uv tool** | `uv tool install recon-tool` | uv users who want isolated tool installs. |
| **uvx (zero pre-install)** | (configured per `.mcp.json`, see below) | One-shot use; uv fetches recon-tool on first MCP launch and caches it. Adds a few seconds of cold-start latency the first time. |

Then verify:

```bash
recon doctor --mcp
```

### 2. Install the Claude Code plugin

**Local development / testing.** Point Claude Code at this directory directly:

```bash
claude --plugin-dir ./agents/claude-code
```

The plugin loads for that session without going through a marketplace.

**Marketplace install.** Once recon is published to a Claude Code plugin marketplace, users install by name:

```
/plugin install recon@<marketplace-name>
```

A marketplace is itself just a repo containing a `.claude-plugin/marketplace.json` index that points at one or more plugins. The official marketplace is at [claude.com/plugins](https://claude.com/plugins); you can also publish your own. See the [plugin marketplaces docs](https://code.claude.com/docs/en/plugin-marketplaces.md) for the current schema and submission flow — both are still evolving.

### 3. Try it

In a Claude Code session:

```
Run a recon lookup on contoso.com and summarize what's observable.
```

The skill auto-loads when you mention a domain alongside recon-shaped intent. The MCP server starts on demand.

## Choosing the MCP launch command

The shipped `.mcp.json` uses `command: "recon"`, which works for anyone who pip-installed `recon-tool` globally. If `recon` is not on the launcher's PATH (rare for Claude Code, more common for sandboxed environments), pick one of these alternatives by editing your local copy of `.mcp.json`:

```jsonc
// (a) Python module form — works when recon_tool is installed in the python on PATH.
{
  "mcpServers": {
    "recon": {
      "command": "python",
      "args": ["-m", "recon_tool.server"]
    }
  }
}

// (b) uvx form — no pre-install needed; uv fetches recon-tool from PyPI.
//     Note the --from flag: the package is recon-tool, the script is recon.
{
  "mcpServers": {
    "recon": {
      "command": "uvx",
      "args": ["--from", "recon-tool", "recon", "mcp"]
    }
  }
}
```

Use the absolute path to your Python or `uvx` binary if neither is on PATH for the launcher.

## Approval policy

Plugin-bundled MCP servers are auto-approved by Claude Code when the plugin is enabled — there is no `autoApprove` field in the plugin `.mcp.json` schema. recon's MCP tools are read-only by design, but the user can still review or disable individual tool calls through Claude Code's normal MCP approval UI. Users who want stricter manual approval should add recon as a user-level MCP server in their own Claude Code config rather than relying on the plugin form.

## What this plugin does *not* do

- It does not change recon's behavior. The MCP server exposed by this plugin is the same `recon mcp` documented in [`docs/mcp.md`](../../docs/mcp.md).
- It does not add new network surface. The skill is instructions only.
- It does not bundle credentials, API keys, or paid data. recon never has, and never will.

For the full MCP tool reference, per-client config locations beyond Claude Code, and advanced agentic workflows, see [`docs/mcp.md`](../../docs/mcp.md). For other AI clients (Cursor, Windsurf, Kiro, VS Code, …), see the sibling folders under [`../`](../).
