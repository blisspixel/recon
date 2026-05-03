# recon — Cursor install

Two pieces wire recon into [Cursor](https://cursor.com/): the MCP server (so Cursor can call recon) and the agent guidance (so Cursor knows *when* to use it). Cursor reads `.cursor/rules/*.md` files with frontmatter — those drive when the rule applies.

## What's inside

```
agents/cursor/
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

Drop [`mcp.json`](mcp.json) at one of these paths:

| Scope | Path |
|---|---|
| Project | `.cursor/mcp.json` |
| Global | `~/.cursor/mcp.json` |

**macOS PATH gotcha.** Cursor is a GUI Electron app and does not inherit your shell's PATH. If `command: "recon"` fails to launch the server, replace it with the absolute path (`which recon` in your shell) or the Python module form (`{ "command": "/usr/local/bin/python3", "args": ["-m", "recon_tool.server"] }`).

## 3. Wire the agent guidance

Cursor reads [`.cursor/rules/*.md`](https://docs.cursor.com/context/rules) at the project root. The canonical recon guidance lives in [`AGENTS.md`](../../AGENTS.md) — drop its content into a rule file with the appropriate frontmatter:

```markdown
---
description: Passive domain intelligence — Microsoft 365 / Google Workspace tenant identification, email security configuration (DMARC, DKIM, SPF, MTA-STS, BIMI), SaaS fingerprinting from DNS, certificate-transparency findings, related-domain discovery. Use when a domain name appears alongside phrases like "what does <company> use", "tenant", "DMARC", "email security posture", "SaaS stack", "fingerprint", "passive recon", or "vendor diligence".
globs:
alwaysApply: false
---

<!-- Paste the body of AGENTS.md below this line. -->
```

Save as `.cursor/rules/recon.md`. Cursor surfaces it on-demand when the description matches the user's intent — lighter than `alwaysApply: true`.

## Verifying the install

In Cursor, ask:

> Run a recon lookup on contoso.com and summarize what's observable.

Cursor should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
