# Agent integrations

Source-checkout scaffolds for AI clients. PyPI installs the recon CLI and MCP
runtime, not this repository directory. For a released MCP setup, start with
`recon mcp install --client=<name>`. Use these folders only when you have a
source checkout and want the accompanying guidance or development artifacts;
the client folders reuse the canonical guidance in
the repository-root [`AGENTS.md`](../AGENTS.md) rather than carrying stale
copies.

## Quickest path: `recon mcp install`

For the MCP-server half of the setup, the canonical move is:

```bash
recon mcp install --client=claude-desktop
# supported: claude-desktop, claude-code, cursor, vscode, windsurf, kiro
recon mcp install --client=cursor --dry-run            # preview the plan
recon mcp install --client=kiro --scope=workspace      # project-local instead of user-global
```

The install is idempotent and merge-safe: sibling MCP servers and
client-supported extra fields survive a `--force` rerun. Unsupported legacy
approval fields are removed for Claude Code and VS Code, whose current schemas
delegate approval to client permission settings. Writes are atomic, so a
failure mid-write never leaves a truncated config.

That handles **piece 1** of the setup (the MCP server). Per-client folders below still cover **piece 2** (the agent guidance - when and how the client should reach for recon) and per-client gotchas.

## Folders

| Agent | Folder | Repository content |
|---|---|---|
| **Agent Plugins candidate** | [`agent-plugin/`](agent-plugin/) | Complete current 23-tool portable packaging candidate, generated from the native skills and validated offline against the byte-pinned Published v1.0.0 schemas. The frozen v2.15 evaluation contract remains a historical 22-tool frame, and representative-client compatibility remains unclaimed. |
| **Claude Code** | [`claude-code/`](claude-code/) | Source-checkout-only client plugin: MCP registration + skill + manifest. It is not a PyPI or GitHub Release asset. |
| **Kiro** | [`kiro/`](kiro/) | MCP config + instructions for using the canonical SKILL.md as a Kiro skill. |
| **Cursor** | [`cursor/`](cursor/) | MCP config + instructions for creating `.cursor/rules/recon.md` from `AGENTS.md`. |
| **Windsurf** | [`windsurf/`](windsurf/) | MCP config + instructions for creating a `.windsurfrules` reference. |
| **VS Code + Copilot** | [`vscode/`](vscode/) | MCP config + instructions for creating `.github/copilot-instructions.md`. |

The client-named folders are native scaffolds. The Claude Code directory follows
Claude Code's `.claude-plugin/plugin.json` and `.mcp.json` conventions; it is
not the root `plugin.json` plus `mcp.json` package defined by the portable
[Agent Plugins v1.0.0 specification](https://agent-plugins.org/specification).
The separate `agent-plugin/` candidate uses that root layout and omits
client-only or experimental skill fields. It passes offline pinned-schema
validation. That result is not a compatibility claim. The package remains an
evaluation artifact until the frozen VS Code,
Cursor, and Kiro install-through-failure frame passes. Use the native install
paths until that decision is published.

For Claude Desktop and other clients without a folder here, `recon mcp install --client=claude-desktop` covers the MCP wiring; see [`docs/mcp.md`](../docs/mcp.md) for full reference.

## How the pieces fit together

Every supported agent has the same two things to wire:

1. **The MCP server** - so the AI can call recon. JSON snippet, dropped at the client's MCP config path.
2. **The agent guidance** - so the AI knows *when* to reach for recon and *how* to talk about its output. Different clients support this differently:

| Client | Guidance format | Loads when |
|---|---|---|
| Claude Code | `SKILL.md` (frontmatter + body) | Description matches user intent |
| Kiro | `SKILL.md` *or* steering files | Description matches *or* always (steering) |
| Cursor | `.cursor/rules/*.md` (frontmatter) | Description matches *or* `alwaysApply: true` |
| Windsurf | `.windsurfrules` (plain markdown) | Always |
| VS Code + Copilot | `.github/copilot-instructions.md` | Always |

The behavioral contract is shared across clients. It is maintained in two
format-specific files:

- [`agents/claude-code/skills/recon/SKILL.md`](claude-code/skills/recon/SKILL.md) - skill-format guidance for Claude Code and Kiro auto-loading, with CLI-specific gotchas.
- [`AGENTS.md`](../AGENTS.md) at the repo root - portable guidance for tools that do not use the skill format. Auto-detected by Kiro and other agents.md-aware clients.

The prose need not be byte-for-byte identical, but collection boundaries,
failure behavior, MCP invocation contracts, and output interpretation must stay
semantically aligned.

## macOS PATH gotcha (most GUI clients)

Cursor, Windsurf, VS Code, and Claude Desktop are GUI Electron apps. On macOS they do not inherit your shell's PATH, so `command: "recon"` will fail to launch the MCP server even when `recon` works fine in your terminal.

Two fixes - both apply equally to every shipped `mcp.json`:

1. **Use the absolute path to recon.** Run `which recon` in your shell and substitute the full path:
   ```json
   { "command": "/Users/you/.local/bin/recon", "args": ["mcp"] }
   ```
2. **Rerun the installer from the right Python.** `recon mcp install
   --client=<name> --force` always writes that interpreter's absolute path and
   a sys.path-stripping launcher. Prefer it over hand-writing
   `python -m recon_tool.server` in workspace configs.

Run `recon doctor --mcp` in your shell to confirm recon is reachable; it prints copy-pasteable JSON snippets for several supported clients. For a live JSON-RPC handshake check (does the server actually respond?), run `recon mcp doctor`.

Kiro is also a desktop app but its MCP loader has been more forgiving in practice. If `command: "recon"` fails on Kiro, fall back to the same fixes.

## Verifying any install

Once configured, ask the client:

> Run a recon lookup on alpha.invalid and summarize what's observable.

If the client reports the recon MCP server is connected and tools enumerate, you're done. If not, check:

- Is `recon-tool` installed in the same Python environment the client launches?
- Does `recon doctor --mcp` succeed in your shell? (Static-shape check.)
- Does `recon mcp doctor` succeed? (Live JSON-RPC handshake - catches subprocess-level failures the static check can't see.)
- Are you hitting the macOS GUI PATH issue above?

For deeper troubleshooting, the full MCP reference lives in [`docs/mcp.md`](../docs/mcp.md).
