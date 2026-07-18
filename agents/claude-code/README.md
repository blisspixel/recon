# recon - Claude Code plugin

This directory packages recon as a [Claude Code plugin](https://docs.claude.com/en/docs/claude-code/plugins): one install wires up the MCP server and ships a skill that teaches Claude *when* and *how* to use recon.

## What's inside

```
agents/claude-code/
├── .claude-plugin/plugin.json   # plugin manifest
├── .mcp.json                    # MCP server registration (recon mcp)
├── skills/recon/SKILL.md        # skill - recon's voice, workflow patterns, hedging rules
└── README.md                    # this file
```

## Skill vs MCP server: what each adds

The two pieces do different jobs, which is worth spelling out if your setup already ships a `/recon` skill and you are wondering what the MCP server buys you:

- **The skill** teaches Claude when to reach for recon and how to read its hedged output. Driving the CLI, it covers the one-shot analyses: the lookup, the model-bound public-evidence index (`recon <domain> --exposure --json`), the hardening observations (`recon <domain> --gaps --json`), and model-relative Bayesian diagnostics (`--fusion`, `--explain-dag`). For most presales and vendor-diligence work, that is the whole job, with zero setup.
- **The MCP server** adds what a one-shot CLI call does not do well: stateful and iterative agentic workflows. `simulate_hardening` what-if loops where Claude proposes a fix, recomputes the model-bound index, and proposes another; cache-only ephemeral-fingerprint replay over retained apex/root TXT, SPF, MX, NS, and CNAME observations; live two-domain `compare_postures`; and `test_hypothesis`. Owner-qualified ephemeral rules require a fresh lookup through recon's normal documented network boundary. If you have a working skill and the MCP install succeeds but you are not sure what changed, this is the difference.

The earlier framing of "the MCP server adds `assess_exposure` / `find_hardening_gaps` / the posterior tools" was too strong: those one-shot analyses are reachable from the CLI too (`--exposure`, `--gaps`, `--fusion`), so a skill can drive them. The honest distinction is one-shot (either path) versus stateful/iterative (MCP).

## Install

The plugin wires up Claude Code (skill + MCP launch config). It does **not** install the recon Python package - that step is still the user's responsibility, just like any other MCP server.

### 1. Install the recon CLI

Pick whichever fits your environment:

| Form | Command | When to use |
|---|---|---|
| **pip (default)** | `pip install recon-tool` | Most users. `recon` ends up on PATH; lowest startup latency. |
| **uv tool** | `uv tool install recon-tool` | uv users who want isolated tool installs. |
| **uvx (zero pre-install)** | (configured per `.mcp.json`, see below) | One-shot use; uv fetches recon-tool on first MCP launch and caches it. Adds a few seconds of cold-start latency the first time. |

Then verify:

```bash
recon doctor --mcp
```

### 2a. (Alternative) Wire MCP without the plugin

If you want recon's MCP server registered in Claude Code without using the plugin form, run:

```bash
recon mcp install --client=claude-code               # user-level: ~/.claude.json
recon mcp install --client=claude-code --scope=workspace  # project-local: .mcp.json
recon mcp install --client=claude-code --dry-run     # preview without writing
```

The install merges into existing `mcpServers` without touching siblings;
`--force` refreshes the canonical launcher while preserving client-supported
custom fields. Claude Code does not define `autoApprove` in this configuration,
so the installer removes that legacy field and leaves permissions to Claude
Code's permission rules.

The plugin path below (2b) is still the recommended setup because it bundles the recon **skill** alongside the MCP server.

### 2b. Install the Claude Code plugin

**Local development / testing.** Point Claude Code at this directory directly:

```bash
claude --plugin-dir ./agents/claude-code
```

The plugin loads for that session without going through a marketplace.

**Marketplace install.** Once recon is published to a Claude Code plugin marketplace, users install by name:

```
/plugin install recon@<marketplace-name>
```

A marketplace is itself just a repo containing a `.claude-plugin/marketplace.json` index that points at one or more plugins. The official marketplace is at [claude.com/plugins](https://claude.com/plugins); you can also publish your own. See the [plugin marketplaces docs](https://code.claude.com/docs/en/plugin-marketplaces.md) for the current schema and submission flow - both are still evolving.

### 3. Try it

After install, run `recon mcp doctor` for a live JSON-RPC handshake check - spawns the server and confirms a real MCP client can talk to it.


In a Claude Code session:

```
Run a recon lookup on alpha.invalid and summarize what's observable.
```

The skill auto-loads when you mention a domain alongside recon-shaped intent. The MCP server starts on demand.

If the tools do not appear after install, the cause is almost always that Claude Code did not re-read the config, not a broken config. Run `recon doctor --client=claude-code` to confirm the stanza is present, run `/mcp` inside Claude Code to see connected servers and any startup error, and if recon is still missing, fully quit and relaunch the app (a new chat in the same process does not re-spawn MCP servers). Local stdio tools appear as `mcp__recon__*`, not `mcp__claude_ai_*`. The full checklist is in [`docs/mcp.md`](../../docs/mcp.md#when-doctor-passes-but-the-tools-dont-load).

## Choosing the MCP launch command

The shipped file uses the wrapped `{ "mcpServers": { "recon": { ... } } }` form. That is the correct schema for a plugin-bundled `.mcp.json`, the same shape a project-root `.mcp.json` and `~/.claude.json` use ([Claude Code MCP docs](https://code.claude.com/docs/en/mcp)). If you have seen flat, unwrapped entries elsewhere, those are most likely the client's enabled-servers list rather than a plugin config.

The shipped `.mcp.json` uses `command: "recon"`, which works for anyone who pip-installed `recon-tool` globally. If `recon` is not on the launcher's PATH (rare for Claude Code, more common for sandboxed environments), prefer one of these paths:

1. Rerun `recon mcp install --client=claude-code --force` from the Python environment where recon is installed. The installer always writes that interpreter's absolute path and a sys.path-stripping launcher, so the generated registration does not depend on PATH.
2. Edit your local copy of `.mcp.json` to use the absolute path to the installed `recon` script.

```jsonc
{
  "mcpServers": {
    "recon": {
      "command": "/absolute/path/to/recon",
      "args": ["mcp"]
    }
  }
}

// uvx form, no pre-install needed; uv fetches recon-tool from PyPI.
//     Note the --from flag: the package is recon-tool, the script is recon.
{
  "mcpServers": {
    "recon": {
      "command": "uvx",
      "args": ["--from", "recon-tool", "recon", "mcp"]
    }
  }
}
```

Use the absolute path to your `recon` or `uvx` binary if neither is on PATH for the launcher. Avoid hand-writing `python -m recon_tool.server` in plugin or workspace configs unless the working directory is trusted; Python imports through cwd before recon can run its server-side guard, so the installer uses a `-c` launcher that strips cwd-equivalent entries from `sys.path` first.

## Approval policy

Enabling the plugin starts its bundled MCP server automatically; it does not
auto-approve every tool call. Plugin and user-configured MCP tools follow Claude
Code's permission rules, and the plugin `.mcp.json` schema has no `autoApprove`
field. recon marks four local session and catalog mutations with
`readOnlyHint: false`:
`inject_ephemeral_fingerprint`, `clear_ephemeral_fingerprints`, `reload_data`,
and `reevaluate_domain`. The last replaces one cached merged result after
applying the current session catalog without making a network request. It can
replay only retained apex/root TXT, SPF, MX, NS, and CNAME observations;
owner-qualified rule types return a tool error and need the documented fresh-
lookup workflow. All other MCP tools are annotated read-only. These annotations
are hints, not permission grants. Configure allow or deny rules with Claude
Code's documented permission system. Installing both the plugin and a user-
level server leaves two registrations, so it is cleaner to pick one path unless
duplication is intentional.

## What this plugin does *not* do

- It does not change recon's behavior. The MCP server exposed by this plugin is the same `recon mcp` documented in [`docs/mcp.md`](../../docs/mcp.md).
- It does not add new network surface. The skill is instructions only.
- It does not bundle credentials, API keys, or paid data. recon never has, and never will.

For the full MCP tool reference, per-client config locations beyond Claude Code, and advanced agentic workflows, see [`docs/mcp.md`](../../docs/mcp.md). For other AI clients (Cursor, Windsurf, Kiro, VS Code, …), see the sibling folders under [`../`](../).
