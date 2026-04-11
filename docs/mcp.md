# MCP Server (AI Agent Integration)

recon runs as an MCP server so any MCP-compatible AI tool can call it directly — no API keys, no glue code.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, Kiro, or any other [MCP client](https://modelcontextprotocol.io/).

## Setup

1. Install recon:

```bash
pip install recon-tool                    # from PyPI (when published)
pip install -e .                          # or from source
```

2. Add this to your AI client's MCP config:

```json
{
  "mcpServers": {
    "recon": {
      "command": "python",
      "args": ["-m", "recon_tool.server"],
      "autoApprove": ["lookup_tenant"]
    }
  }
}
```

> On macOS/Linux, use `"python3"` instead of `"python"` if that's your default.

3. Ask your AI tool something like: "Run a recon lookup on northwindtraders.com and summarize the security posture."

## Available Tools

| Tool | What it does | Parameters |
|------|-------------|------------|
| `lookup_tenant` | Full domain intelligence — tenant details, email score, SaaS fingerprints, signals | `domain` (required), `format`: `text` / `json` / `markdown` |
| `reload_data` | Reload fingerprints and signals after editing `~/.recon/*.yaml` | none |
| `domain_report` | Prompt template for clients that support slash commands | `domain` |

The server includes a bounded TTL cache (120s) and per-domain rate limiting to prevent hammering upstream endpoints when an agent calls `lookup_tenant` repeatedly. All tools are read-only and idempotent.

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in your project |
| Kiro | `.kiro/settings/mcp.json` in your project or `~/.kiro/settings/mcp.json` globally |
