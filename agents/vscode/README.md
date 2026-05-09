# recon — VS Code (with GitHub Copilot) install

Two pieces wire recon into [VS Code](https://code.visualstudio.com/) when paired with GitHub Copilot: the MCP server (so Copilot can call recon) and the agent guidance (so Copilot knows *when* to use it). Copilot reads `.github/copilot-instructions.md` — that loads always, not on-demand.

## What's inside

```
agents/vscode/
├── mcp.json   # MCP server registration
└── README.md  # this file
```

## 1. Install the recon CLI

```bash
pip install recon-tool
recon doctor --mcp
```

Other forms (`uv tool install`, `uvx`) work too — see [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

**One-shot install (recommended):**

```bash
recon mcp install --client=vscode             # writes .vscode/mcp.json in cwd
recon mcp install --client=vscode --dry-run   # preview without writing
```

VS Code's MCP config is workspace-scoped only — there is no user-level config. Run the install from your project root.

**Manual install:** drop [`mcp.json`](mcp.json) at:

| Scope | Path |
|---|---|
| Workspace | `.vscode/mcp.json` |

**macOS PATH gotcha.** VS Code is a GUI Electron app and does not inherit your shell's PATH. If `command: "recon"` fails to launch the server, replace it with the absolute path (`which recon` in your shell) or the Python module form (`{ "command": "/usr/local/bin/python3", "args": ["-m", "recon_tool.server"] }`). The install command auto-detects this case and falls back to the Python module form when `recon` isn't on PATH at install time.

## 3. Wire the agent guidance

GitHub Copilot reads [`.github/copilot-instructions.md`](https://docs.github.com/en/copilot/customizing-copilot/about-customizing-github-copilot-chat-responses#about-repository-custom-instructions-for-github-copilot-chat) at the repo root. The canonical recon guidance lives in [`AGENTS.md`](../../AGENTS.md). Two ways to use it:

```markdown
<!-- .github/copilot-instructions.md — option A (reference) -->
See [`AGENTS.md`](../AGENTS.md) for recon usage guidance.

<!-- option B (inline) -->
<!-- Paste the body of AGENTS.md directly. -->
```

Copilot loads instructions for every chat turn — keep the file focused.

## Verifying the install

In VS Code Copilot Chat, ask:

> Run a recon lookup on contoso.com and summarize what's observable.

Copilot should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
