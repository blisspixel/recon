# recon — Windsurf install

Two pieces wire recon into [Windsurf](https://codeium.com/windsurf): the MCP server (so Windsurf can call recon) and the agent guidance (so Windsurf knows *when* to use it). Windsurf does not auto-load skill files — guidance lives in `.windsurfrules`.

## What's inside

```
agents/windsurf/
├── mcp_config.json   # MCP server registration
└── README.md         # this file
```

## 1. Install the recon CLI

```bash
pip install recon-tool
recon doctor --mcp
```

Other forms (`uv tool install`, `uvx`) work too — see [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

Drop [`mcp_config.json`](mcp_config.json) at:

| Platform | Path |
|---|---|
| macOS / Linux | `~/.codeium/windsurf/mcp_config.json` |
| Windows | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` |

**macOS PATH gotcha.** Windsurf is a GUI Electron app and does not inherit your shell's PATH. If `command: "recon"` fails to launch the server, replace it with the absolute path (`which recon` in your shell) or the Python module form (`{ "command": "/usr/local/bin/python3", "args": ["-m", "recon_tool.server"] }`).

## 3. Wire the agent guidance

Windsurf reads [`.windsurfrules`](https://docs.codeium.com/windsurf/memories) at the project root — plain markdown, merged with global rules, no skill auto-loading.

The canonical recon guidance lives in [`AGENTS.md`](../../AGENTS.md). Two ways to use it:

```markdown
# .windsurfrules — option A (reference)
See @AGENTS.md for recon usage guidance.

# .windsurfrules — option B (inline)
# Paste the body of AGENTS.md directly.
```

## Verifying the install

In Windsurf, ask:

> Run a recon lookup on contoso.com and summarize what's observable.

Windsurf should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
