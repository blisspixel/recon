# recon — Kiro install

Two pieces wire recon into [Kiro](https://kiro.dev/): the MCP server (so Kiro can call recon) and the agent guidance (so Kiro knows *when* to use it). Kiro auto-loads agent skills using the [agentskills.io](https://agentskills.io) standard — the same `SKILL.md` format Claude Code uses — so the same skill body works in both places.

## What's inside

```
agents/kiro/
├── mcp.json    # MCP server registration
└── README.md   # this file
```

## 1. Install the recon CLI

```bash
pip install recon-tool
recon doctor --mcp
```

Other forms (`uv tool install`, `uvx`) work too — see [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

Drop [`mcp.json`](mcp.json) at one of these paths:

| Scope | Path |
|---|---|
| Workspace | `.kiro/settings/mcp.json` |
| Global | `~/.kiro/settings/mcp.json` |

The shipped config sets `command: "recon"`. If `recon` is not on Kiro's launcher PATH (rare on Kiro, more common in sandboxed setups), edit the file to use the absolute binary path or the Python module form — both alternatives are documented in [`../claude-code/README.md`](../claude-code/README.md#choosing-the-mcp-launch-command).

## 3. Wire the agent guidance

**Recommended path — Kiro Skills.** Kiro auto-loads `SKILL.md` files based on the description frontmatter. Copy the canonical skill body in:

```bash
# Workspace scope
mkdir -p .kiro/skills/recon
cp ../claude-code/skills/recon/SKILL.md .kiro/skills/recon/SKILL.md

# Or global scope
mkdir -p ~/.kiro/skills/recon
cp ../claude-code/skills/recon/SKILL.md ~/.kiro/skills/recon/SKILL.md
```

Skills load on-demand when the description matches the user's intent — lower context overhead than steering files.

**Alternative — steering files.** If you'd rather load guidance always (not on-demand), drop [`AGENTS.md`](../../AGENTS.md) at your workspace root. Kiro auto-detects it. This is heavier than skills for general-purpose workspaces but fine when recon is the main tool.

## Verifying the install

In Kiro, ask:

> Run a recon lookup on contoso.com and summarize what's observable.

Kiro should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
