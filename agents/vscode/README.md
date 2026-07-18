# recon - VS Code (with GitHub Copilot) install

Two pieces wire recon into [VS Code](https://code.visualstudio.com/) when paired with GitHub Copilot: the MCP server (so Copilot can call recon) and the agent guidance (so Copilot knows *when* to use it). Copilot reads `.github/copilot-instructions.md` - that loads always, not on-demand.

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

Other forms (`uv tool install`, `uvx`) work too - see [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

**One-shot install (recommended):**

```bash
recon mcp install --client=vscode             # writes .vscode/mcp.json in cwd
recon mcp install --client=vscode --dry-run   # preview without writing
```

The installer defaults to workspace scope and writes `.vscode/mcp.json` from
your project root. VS Code also supports a user-profile `mcp.json`; open it with
**MCP: Open User Configuration** and use `--config-path` if you want recon's
merge-safe installer to update that profile file.

**Manual install:** drop [`mcp.json`](mcp.json) at:

| Scope | Path |
|---|---|
| Workspace | `.vscode/mcp.json` |
| User profile | Open with **MCP: Open User Configuration** |

VS Code's current stdio schema requires `"type": "stdio"`. It does not define
an `autoApprove` property; tool confirmations follow VS Code's trust and
permission settings.

**macOS PATH gotcha.** VS Code is a GUI Electron app and does not inherit your shell's PATH. If the shipped manual config's `command: "recon"` fails, rerun `recon mcp install --client=vscode --force` from the Python environment where recon is installed. The installer always writes that interpreter's absolute path and a sys.path-stripping launcher, so it does not depend on VS Code's PATH. Prefer it over hand-writing `python -m recon_tool.server` in a workspace config.

## 3. Wire the agent guidance

GitHub Copilot reads [`.github/copilot-instructions.md`](https://docs.github.com/en/copilot/customizing-copilot/about-customizing-github-copilot-chat-responses#about-repository-custom-instructions-for-github-copilot-chat) at the repo root. The canonical recon guidance lives in [`AGENTS.md`](../../AGENTS.md). Two ways to use it:

```markdown
<!-- .github/copilot-instructions.md - option A (reference) -->
See [`AGENTS.md`](../AGENTS.md) for recon usage guidance.

<!-- option B (inline) -->
<!-- Paste the body of AGENTS.md directly. -->
```

Copilot loads instructions for every chat turn - keep the file focused.

## Verifying the install

In VS Code Copilot Chat, ask:

> Run a recon lookup on alpha.invalid and summarize what's observable.

Copilot should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
