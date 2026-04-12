# MCP Server (AI Agent Integration)

recon runs as an MCP server so any MCP-compatible AI tool can call it directly — no API keys, no glue code.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, Kiro, or any other [MCP client](https://modelcontextprotocol.io/).

## Setup

1. Install recon:

```bash
pip install recon-tool                    # from PyPI
```

2. Add this to your AI client's MCP config:

```json
{
  "mcpServers": {
    "recon": {
      "command": "recon",
      "args": ["mcp"],
      "autoApprove": ["lookup_tenant", "analyze_posture", "assess_exposure", "find_hardening_gaps"]
    }
  }
}
```

> Alternative: use `"command": "python", "args": ["-m", "recon_tool.server"]` if `recon` isn't on your PATH.

3. Ask your AI tool something like: "Run a recon lookup on northwindtraders.com and summarize the security posture."

## Available Tools

| Tool | What it does | Parameters |
|------|-------------|------------|
| `lookup_tenant` | Full domain intelligence — tenant details, email score, SaaS fingerprints, signals | `domain`, `format`: `text` / `json` / `markdown` |
| `analyze_posture` | Neutral posture observations across email, identity, infrastructure | `domain` |
| `assess_exposure` | Security posture score (0–100) with email, identity, infrastructure sections | `domain` |
| `find_hardening_gaps` | Categorized hardening gaps with severity and "Consider" recommendations | `domain` |
| `compare_postures` | Side-by-side posture comparison of two domains | `domain_a`, `domain_b` |
| `chain_lookup` | Recursive domain discovery via CNAME/CT breadcrumbs | `domain`, `depth` (1–3) |
| `reload_data` | Reload fingerprints, signals, and posture rules from disk | none |

All tools are read-only and idempotent. The defensive tools (`assess_exposure`, `find_hardening_gaps`, `compare_postures`) operate on existing pipeline data with zero additional network calls. The server includes a bounded TTL cache (120s) and per-domain rate limiting.

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in your project |
| Kiro | `.kiro/settings/mcp.json` in your project or `~/.kiro/settings/mcp.json` globally |
