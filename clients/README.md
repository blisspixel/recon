# Per-client install snippets

Copy-pasteable MCP config fragments and agent guidance for AI clients other than Claude Code. Claude Code users should install the full plugin under [`../claude-code/`](../claude-code/) — it bundles the MCP server registration *and* the skill in one install.

All clients here use the same `mcpServers` JSON shape; only the file location and a few optional fields differ. Every snippet assumes `pip install recon-tool` is already done and `recon` is on PATH.

## Two pieces, every client

There are two things to wire up per client:

1. **The MCP server** — so the AI can call recon. JSON snippet, dropped at the client's MCP config path.
2. **The agent guidance** — so the AI knows *when* to reach for recon and *how* to talk about its output. Different clients support this differently; see the table below.

## MCP config

| Client | Drop snippet at | Snippet |
|---|---|---|
| Kiro (workspace) | `.kiro/settings/mcp.json` | [`kiro/mcp.json`](kiro/mcp.json) |
| Kiro (global) | `~/.kiro/settings/mcp.json` | [`kiro/mcp.json`](kiro/mcp.json) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` (Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`) | [`windsurf/mcp_config.json`](windsurf/mcp_config.json) |
| Cursor (project) | `.cursor/mcp.json` | same as Windsurf snippet |
| Cursor (global) | `~/.cursor/mcp.json` | same as Windsurf snippet |
| VS Code + Copilot | `.vscode/mcp.json` | same as Windsurf snippet |

For Claude Desktop, see [`docs/mcp.md`](../docs/mcp.md) — it has its own config path and the strongest PATH-inheritance gotcha.

## Agent guidance

| Client | What it supports | What to do |
|---|---|---|
| **Kiro** (recommended path) | Kiro Skills follow the open [agentskills.io](https://agentskills.io) standard — the same `SKILL.md` format Claude Code uses. | Copy [`../claude-code/skills/recon/SKILL.md`](../claude-code/skills/recon/SKILL.md) to `~/.kiro/skills/recon/SKILL.md` (global) or `.kiro/skills/recon/SKILL.md` (workspace). Kiro auto-loads it on-demand based on the description. |
| **Kiro** (alternative) | Steering files at `~/.kiro/steering/` or `.kiro/steering/`. AGENTS.md is auto-detected at workspace root. | Drop [`../AGENTS.md`](../AGENTS.md) at the user's workspace root. It loads always, not on-demand — fine for projects where recon is the main tool, heavier than needed for general-purpose workspaces. |
| **Windsurf** | `.windsurfrules` at project root, plain markdown, merged with global rules. No skill auto-loading. | Reference AGENTS.md from `.windsurfrules`: `See @AGENTS.md for recon usage guidance.` Or paste the AGENTS.md content directly into `.windsurfrules`. |
| **Cursor** | `.cursor/rules/*.md` with frontmatter (`description`, `globs`, `alwaysApply`). | Drop AGENTS.md content into `.cursor/rules/recon.md` with `description: ...` matching the skill description. |
| **VS Code + Copilot** | `.github/copilot-instructions.md` (always-loaded). | Reference AGENTS.md from there, or include its content. |

The canonical guidance content lives in two places that mirror each other:

- [`../claude-code/skills/recon/SKILL.md`](../claude-code/skills/recon/SKILL.md) — same body, plus skill frontmatter for Claude Code and Kiro skill auto-loading.
- [`../AGENTS.md`](../AGENTS.md) — same body, no frontmatter, for tools that don't have a skill format.

If you contribute changes to one, mirror them into the other.

## macOS PATH gotcha

Windsurf, Cursor, VS Code, and Claude Desktop are GUI Electron apps. On macOS they do not inherit your shell's PATH, so `command: "recon"` will fail to launch the MCP server even when `recon` works fine in your terminal. Two fixes:

1. **Use the absolute path to recon** — run `which recon` in your shell and substitute the full path:
   ```json
   { "command": "/Users/you/.local/bin/recon", "args": ["mcp"] }
   ```
2. **Use the Python module form** — works for any Python that has `recon-tool` installed:
   ```json
   { "command": "/usr/local/bin/python3", "args": ["-m", "recon_tool.server"] }
   ```

Run `recon doctor --mcp` in your shell to confirm recon is reachable; it prints a copy-pasteable JSON snippet for several supported clients.

Kiro is also a desktop app but its MCP loader has been more forgiving in practice. If `command: "recon"` fails on Kiro, fall back to the same fixes.

## Verifying the install

Once configured, ask the AI client something like:

> Run a recon lookup on contoso.com and summarize what's observable.

If the client reports the recon MCP server is connected and tools enumerate, you're done. If not, check:

- Is `recon-tool` installed in the same Python environment the client launches?
- Does `recon doctor --mcp` succeed in your shell?
- Are you hitting the macOS GUI PATH issue above?
