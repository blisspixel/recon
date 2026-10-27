# recon - Gemini CLI install

Two pieces wire recon into [Gemini CLI](https://github.com/google-gemini/gemini-cli): the MCP server (so Gemini CLI can call recon) and the agent guidance (so it knows *when* to use it).

## What's inside

```
agents/gemini/
└── README.md   # this file
```

This folder does not ship a `settings.json`. Copying a hand-written `command: "recon"` block is the PATH failure the installer avoids.

## 1. Install the recon CLI

```bash
pip install recon-tool
recon doctor --mcp
```

Other forms (`uv tool install`, `uvx`) work too. See [`docs/mcp.md`](../../docs/mcp.md#cli-install-options).

## 2. Wire the MCP server

**One-shot install (recommended):**

```bash
recon mcp install --client=gemini                  # writes ~/.gemini/settings.json
recon mcp install --client=gemini --scope=workspace  # writes .gemini/settings.json in cwd
recon mcp install --client=gemini --dry-run        # preview
```

The install always writes the active interpreter's absolute path and a
sys.path-stripping launcher, so it does not depend on Gemini CLI's PATH. It
merges `mcpServers.recon` next to sibling servers. `--force` refreshes the
canonical launcher fields and preserves client-supported custom fields.
`autoApprove` is omitted because the Gemini server schema rejects unknown
keys. The install does not write `timeout`.

Gemini CLI's per-server `timeout` is milliseconds. The documented default is
600000. `gemini mcp add` defaults to project scope. `recon mcp install`
defaults to the user file when that path exists, and `--scope=workspace`
selects the project file.

| Scope | Path |
|---|---|
| User | `~/.gemini/settings.json` |
| Project | `.gemini/settings.json` |

## 3. Wire the agent guidance

Gemini CLI context files are named `GEMINI.md`. This folder does not install
one, and it does not claim that Gemini CLI auto-loads `AGENTS.md`. The
canonical instructions remain the repository-root [`AGENTS.md`](../../AGENTS.md).
Use them when you write a `GEMINI.md` for a workspace that should reach for recon.

## Verifying the install

```bash
recon doctor --client=gemini
```

In Gemini CLI, ask:

> Run a recon lookup on alpha.invalid and summarize what's observable.

Gemini CLI should report the `recon` MCP server connected and tools enumerated. If not, check [`docs/mcp.md`](../../docs/mcp.md#troubleshooting).
