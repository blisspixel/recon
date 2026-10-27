# recon - Codex install

Two pieces wire recon into [Codex](https://learn.chatgpt.com/codex/extend/mcp.md): the MCP server (so Codex can call recon) and the agent guidance (so Codex knows *when* to use it). The ChatGPT desktop app, the Codex CLI, and the IDE extension share one config file.

## What's inside

```
agents/codex/
└── README.md   # this file
```

Codex reads TOML, so this folder does not ship an `mcp.json`.

## 1. Install the recon CLI

```bash
pip install recon-tool
recon doctor --mcp
```

Other forms (`uv tool install`, `uvx`) work too. See [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

**One-shot install (recommended):**

```bash
recon mcp install --client=codex                  # writes ~/.codex/config.toml
recon mcp install --client=codex --scope=workspace  # writes .codex/config.toml in cwd
recon mcp install --client=codex --dry-run        # preview the TOML table
```

The install always writes the active interpreter's absolute path and a
sys.path-stripping launcher, so it does not depend on Codex's PATH. It appends
`[mcp_servers.recon]`, or leaves the file unchanged when that table's command
and args already match. Sibling tables and comments outside the recon span stay
byte for byte. `--force` replaces only that span, including child tables such
as `[mcp_servers.recon.env]`. Custom keys and comments inside the replaced span
do not survive. The install does not write `tool_timeout_sec` or
`default_tools_approval_mode`.

`tool_timeout_sec` defaults to 60 seconds. `chain_lookup` can take longer, so
set `tool_timeout_sec` above 60 on `[mcp_servers.recon]` if those lookups time
out. `default_tools_approval_mode = "writes"` prompts only for tools that are
not marked read-only.

| Scope | Path |
|---|---|
| User | `~/.codex/config.toml` |
| Trusted project | `.codex/config.toml` |

Codex loads `.codex/config.toml` only for a project it already trusts. This
scaffold does not decide that trust.

## 3. Wire the agent guidance

Codex reads a repository [`AGENTS.md`](../../AGENTS.md) when it loads project
instructions. That file is the canonical guidance. This folder does not install
a second copy.

## Verifying the install

```bash
recon doctor --client=codex
```

In Codex, ask:

> Run a recon lookup on alpha.invalid and summarize what's observable.

Codex should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
