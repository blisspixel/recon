# Agent integrations

Per-agent install scaffolds for AI clients. Each subfolder is self-contained — pick the one that matches your agent and follow that folder's README.

## Folders

| Agent | Folder | Pieces shipped |
|---|---|---|
| **Claude Code** | [`claude-code/`](claude-code/) | Full plugin: MCP registration + skill + plugin manifest. One install wires everything up. |
| **Kiro** | [`kiro/`](kiro/) | MCP config + instructions for using the canonical SKILL.md as a Kiro skill. |
| **Cursor** | [`cursor/`](cursor/) | MCP config + `.cursor/rules/recon.md` template based on `AGENTS.md`. |
| **Windsurf** | [`windsurf/`](windsurf/) | MCP config + `.windsurfrules` reference template. |
| **VS Code + Copilot** | [`vscode/`](vscode/) | MCP config + `.github/copilot-instructions.md` template. |

For Claude Desktop and other clients without a folder here, see [`docs/mcp.md`](../docs/mcp.md) — the same MCP shape works everywhere; only the config path and PATH-inheritance behaviour differ.

## How the pieces fit together

Every supported agent has the same two things to wire:

1. **The MCP server** — so the AI can call recon. JSON snippet, dropped at the client's MCP config path.
2. **The agent guidance** — so the AI knows *when* to reach for recon and *how* to talk about its output. Different clients support this differently:

| Client | Guidance format | Loads when |
|---|---|---|
| Claude Code | `SKILL.md` (frontmatter + body) | Description matches user intent |
| Kiro | `SKILL.md` *or* steering files | Description matches *or* always (steering) |
| Cursor | `.cursor/rules/*.md` (frontmatter) | Description matches *or* `alwaysApply: true` |
| Windsurf | `.windsurfrules` (plain markdown) | Always |
| VS Code + Copilot | `.github/copilot-instructions.md` | Always |

The guidance content itself is the same in every case. We maintain it in two mirrored files:

- [`agents/claude-code/skills/recon/SKILL.md`](claude-code/skills/recon/SKILL.md) — the body, with skill-format frontmatter for Claude Code and Kiro auto-loading.
- [`AGENTS.md`](../AGENTS.md) at the repo root — the same body, no frontmatter, for tools that don't have a skill format. Auto-detected by Kiro and other agents.md-aware clients.

If you contribute changes to one, mirror them into the other.

## macOS PATH gotcha (most GUI clients)

Cursor, Windsurf, VS Code, and Claude Desktop are GUI Electron apps. On macOS they do not inherit your shell's PATH, so `command: "recon"` will fail to launch the MCP server even when `recon` works fine in your terminal.

Two fixes — both apply equally to every shipped `mcp.json`:

1. **Use the absolute path to recon.** Run `which recon` in your shell and substitute the full path:
   ```json
   { "command": "/Users/you/.local/bin/recon", "args": ["mcp"] }
   ```
2. **Use the Python module form.** Works for any Python that has `recon-tool` installed:
   ```json
   { "command": "/usr/local/bin/python3", "args": ["-m", "recon_tool.server"] }
   ```

Run `recon doctor --mcp` in your shell to confirm recon is reachable; it prints copy-pasteable JSON snippets for several supported clients.

Kiro is also a desktop app but its MCP loader has been more forgiving in practice. If `command: "recon"` fails on Kiro, fall back to the same fixes.

## Verifying any install

Once configured, ask the client:

> Run a recon lookup on contoso.com and summarize what's observable.

If the client reports the recon MCP server is connected and tools enumerate, you're done. If not, check:

- Is `recon-tool` installed in the same Python environment the client launches?
- Does `recon doctor --mcp` succeed in your shell?
- Are you hitting the macOS GUI PATH issue above?

For deeper troubleshooting, the full MCP reference lives in [`docs/mcp.md`](../docs/mcp.md).
