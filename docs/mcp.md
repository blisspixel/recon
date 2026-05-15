# MCP Server (AI Agent Integration)

recon runs as a local stdio MCP server so MCP-compatible AI tools can call it
directly — no API keys, no glue code. The default `pip install recon-tool`
includes the MCP server.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, or any other
[MCP client](https://modelcontextprotocol.io/).

> [!WARNING]
> `recon mcp` runs with the privileges of the calling user or editor process.
> Treat connected AI agents as untrusted input: prompt injection, tool
> poisoning, and parameter tampering are possible. Start with manual approvals,
> keep `autoApprove` empty by default, and prefer an isolated workspace or
> container for production agent use.

## Setup

1. Install recon:

```bash
pip install recon-tool
```

2. Wire the MCP server into your client. Two ways:

   **a. One-shot install (recommended).** Let recon write the right config block at the right per-OS path:

   ```bash
   recon mcp install --client=claude-desktop
   # supported: claude-desktop, claude-code, cursor, vscode, windsurf, kiro
   recon mcp install --client=cursor --dry-run        # preview without writing
   recon mcp install --client=cursor --scope=workspace  # project-local instead of user-global
   ```

   The command merges the recon stanza into your existing config without touching sibling MCP servers. Existing `autoApprove` lists, custom `env` vars, `disabled` flags, and any other fields you've added to your recon block survive a `--force` rerun — only `command` and `args` are authoritative on the install side. Writes are atomic (sibling tempfile + `os.replace`), so a partial-write failure leaves the original config intact.

   **b. Manual install.** If you'd rather edit by hand, drop this into the right config file (table below):

   ```json
   {
     "mcpServers": {
       "recon": {
         "command": "recon",
         "args": ["mcp"],
         "autoApprove": []
       }
     }
   }
   ```

   > Alternative: use `"command": "python", "args": ["-m", "recon_tool.server"]`
   > if `recon` is not on your PATH.

3. Ask your AI tool something like: "Run a recon lookup on
northwindtraders.com and summarize the security posture."

Example multi-step prompt for deeper analysis:

> "Look up contoso.com with explain=true. Then run assess_exposure and
> find_hardening_gaps. Finally, simulate_hardening with DMARC reject and
> MTA-STS enforce applied, and tell me the new posture score."

## Startup warning

`recon mcp` prints a warning banner to `stderr` before the stdio transport
starts so JSON-RPC framing stays clean on `stdout`. The entrypoint warns about
the server's local privilege level and the need for manual approvals:

```text
================================================================================
recon MCP Server vX.Y.Z

WARNING: This server runs with the privileges of the calling user.
Treat connected AI agents as untrusted input.
Start with manual approvals; only enable auto-approval for tools you
deliberately trust.
================================================================================
```

recon intentionally does not add a separate "safe mode" or "full auto" CLI
flag here. Approval policy belongs in the MCP client config, and the safest
default is an empty `autoApprove` list.

### Running `recon mcp` directly in a terminal

If you launch `recon mcp` (or `python -m recon_tool.server`) by hand in a shell, recon detects that stdin is a TTY and prints a "this is not a REPL" panel before exiting cleanly. The MCP server is meant to be spawned by an MCP client over stdio JSON-RPC; running it interactively used to surface a Pydantic JSON-parse traceback the first time you pressed Enter, which scared people off. The panel replaces that.

If you genuinely need to drive the JSON-RPC loop by hand (e.g. piping crafted requests for debugging), set `RECON_MCP_FORCE_STDIO=1` (case-insensitive — `1`, `true`, `yes`, `on` all enable the bypass) before launching.

## Available Tools

| Tool | Network calls? | What it does | Parameters |
|------|----------------|-------------|------------|
| `lookup_tenant` | Cache first; may resolve | Full domain intelligence — tenant details, email score, SaaS fingerprints, signals. When `explain=true`, the response includes a JSON-serialisable `explanation_dag` with `evidence → slug → rule → signal → insight` provenance alongside the flat explanations list. | `domain`, `format`: `text` / `json` / `markdown`, `explain`: bool |
| `analyze_posture` | Cache first; may resolve | Neutral posture observations across email, identity, infrastructure. Accepts an optional `profile` argument — one of `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`, or a custom name from `~/.recon/profiles/`. | `domain`, `explain`: bool, `profile`: str (optional) |
| `cluster_verification_tokens` | Cache first; may resolve each domain | Cluster a list of domains by shared TXT site-verification tokens. Reveals hedged "possible relationship" signals — operator-scoped credential reuse. | `domains`: array of domain strings |
| `assess_exposure` | Cache first; may resolve | Security posture score (0–100) with email, identity, infrastructure sections, using only the passive observables already collected (see [correlation.md](correlation.md) for the inference model). | `domain` |
| `find_hardening_gaps` | Cache first; may resolve | Categorized hardening gaps with severity and "Consider" recommendations, using only the passive observables already collected (see [correlation.md](correlation.md) for the inference model). | `domain` |
| `compare_postures` | Cache first; may resolve both domains | Side-by-side posture comparison of two domains | `domain_a`, `domain_b` |
| `chain_lookup` | Yes | Recursive domain discovery via CNAME/CT breadcrumbs | `domain`, `depth` (1–3) |
| `discover_fingerprint_candidates` | Yes | Mine a domain for new-fingerprint candidates. Resolves with unclassified-CNAME-chain capture, applies intra-org and already-covered filters, returns a ranked candidate list. Pair with the `/recon-fingerprint-triage` skill to turn candidates into YAML stanzas. | `domain`, `skip_ct`: bool, `keep_intra_org`: bool, `min_count`: int |
| `reload_data` | No | Reload fingerprints, signals, and posture rules from disk | none |
| `get_fingerprints` | No | List all loaded fingerprints with slugs, categories, detection types | `category` (optional filter) |
| `get_signals` | No | List all loaded signals with rules, layers, conditions | `category`, `layer` (optional filters) |
| `explain_signal` | No unless `domain` is provided | Query a signal's trigger conditions and current state for a domain | `signal_name`, `domain` (optional) |
| `test_hypothesis` | Cache first; may resolve | Test a theory against signals and evidence — returns likelihood + evidence | `domain`, `hypothesis` |
| `simulate_hardening` | Cache first; may resolve | What-if: re-compute exposure score with hypothetical fixes applied, using only the passive observables already collected (see [correlation.md](correlation.md) for the inference model). | `domain`, `fixes` (array) |
| `inject_ephemeral_fingerprint` | No | Inject a temporary fingerprint for the current session | `name`, `slug`, `category`, `confidence`, `detections` (array) |
| `reevaluate_domain` | No | Re-evaluate cached domain data against current fingerprints (including ephemeral) | `domain` |
| `list_ephemeral_fingerprints` | No | List all currently loaded ephemeral fingerprints | none |
| `clear_ephemeral_fingerprints` | No | Remove all ephemeral fingerprints from the session | none |
| `get_infrastructure_clusters` *(v1.8+)* | Cache first; may resolve | Surfaces the CT co-occurrence community-detection report already computed during lookup — algorithm, modularity score, cluster list. Read-only exposure of computed state. | `domain` |
| `export_graph` *(v1.8+)* | Cache first; may resolve | Companion to `get_infrastructure_clusters`. Returns the underlying graph as nodes + weighted edges + cluster_assignment for downstream Mermaid / GraphViz / CSV rendering. | `domain` |

The lookup and analysis tools are read-only. The ephemeral fingerprint tools
mutate only in-memory session state for the current server process; they do not
write to disk and do not trigger new network calls on their own. Tools marked
with `explain` support structured provenance output. Catalog tools
(`get_fingerprints`, `get_signals`, and MCP resources) do not call the network.
Domain-analysis tools are cache-first and may resolve the domain when no fresh
cache entry exists. The server includes a bounded TTL cache (120s) and
per-domain rate limiting.

## Catalog Resources

recon exposes three MCP resources so agents can browse "what can this tool detect?" without spending a tool invocation on introspection:

| URI | Content |
|---|---|
| `recon://fingerprints` | Full SaaS fingerprint catalog (slug, name, category, confidence, match_mode, detection_count, ...) |
| `recon://signals` | Derived intelligence signals with candidate slugs, min_matches, contradicts/requires relationships, and positive-when-absent inversions |
| `recon://profiles` | Built-in posture profile lenses (category boosts, signal boosts, focus categories) |

Each resource returns deterministic JSON sourced from the already-loaded YAML catalogs. No network calls. Changes to custom `~/.recon/fingerprints/` or `~/.recon/signals.yaml` require calling `reload_data` to take effect.

## Staleness Timestamps

Every `TenantInfo` result carries two ISO-8601 UTC fields:

- `resolved_at` — when the live resolution produced this result. Always set.
- `cached_at` — when the on-disk cache entry was written. Set only when the result was served from `~/.recon/cache/`.

Agents can compare the two to decide whether to re-resolve. On a fresh lookup, `cached_at` is `null`. On a cache hit, `resolved_at` is preserved from the original resolution so it reflects *when the data was produced*, not just when the cache entry was last written.

## Ephemeral Fingerprints

Ephemeral fingerprints let AI agents inject temporary detection patterns at runtime. They live in memory only, are scoped to the current server session, and are validated through the same regex/ReDoS checks as built-in fingerprints.

To keep long-running MCP sessions available under prompt injection or abusive
tool calls, ephemeral storage is quota-bounded: at most 100 ephemeral
fingerprints, at most 20 detections on a single injected fingerprint, and at
most 500 total ephemeral detections per process. Oversized injections return a
JSON error; use `clear_ephemeral_fingerprints` or restart the server to reset
the session quota.

### Workflow

1. Look up a domain with `lookup_tenant` (caches DNS data).
2. Inject an ephemeral fingerprint with `inject_ephemeral_fingerprint`.
3. Re-evaluate the domain with `reevaluate_domain` — zero network calls, uses cached data.
4. List active ephemeral fingerprints with `list_ephemeral_fingerprints`.
5. Clear all ephemeral fingerprints with `clear_ephemeral_fingerprints` when done.

### Example: Detecting a custom SaaS service

```
Agent: "Inject an ephemeral fingerprint for Fabrikam's internal platform."

→ inject_ephemeral_fingerprint(
    name="Fabrikam Platform",
    slug="fabrikam-platform",
    category="Internal",
    confidence="medium",
    detections=[{"type": "txt", "pattern": "fabrikam-platform-verify="}]
  )

← {"status": "ok", "name": "Fabrikam Platform", "slug": "fabrikam-platform", "detections_accepted": 1}

Agent: "Now re-evaluate contoso.com to see if they use Fabrikam Platform."

→ reevaluate_domain(domain="contoso.com")

← Updated TenantInfo JSON (includes Fabrikam Platform if TXT record matches)
```

### Example: Listing and clearing

```
→ list_ephemeral_fingerprints()
← [{"name": "Fabrikam Platform", "slug": "fabrikam-platform", "category": "Internal", "confidence": "medium", "detection_count": 1}]

→ clear_ephemeral_fingerprints()
← {"status": "ok", "removed": 1}
```

Ephemeral fingerprints are deliberately local-only and session-scoped. They
support the same feedback-driven prior tuning workflow described in the
Bayesian layer (v1.9.0; stable v2.0+, see
[roadmap.md](roadmap.md#v190--probabilistic-fusion-shipped)) without
ever writing to disk or sharing data — the priors stay in memory for
the current server process and are gone when it exits.

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Code | Use the bundled plugin at [`agents/claude-code/`](../agents/claude-code/) — wires up MCP and ships a skill in one install |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in your project |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Kiro (workspace) | `.kiro/settings/mcp.json` |
| Kiro (global) | `~/.kiro/settings/mcp.json` |

Per-agent install scaffolds (config snippets + guidance templates) live under [`agents/`](../agents/) — one folder per client.

### PATH gotcha for GUI clients

GUI MCP clients (Claude Desktop, Windsurf, Cursor, VS Code) typically don't inherit your shell's PATH. If a client can't find `recon`, replace `"command": "recon"` with the absolute path (run `which recon` / `where recon` to find it), or use the Python module form:

```json
{
  "mcpServers": {
    "recon": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "recon_tool.server"]
    }
  }
}
```

### Verify your setup

Two complementary checks:

- **`recon doctor --mcp`** — *static* diagnostic. Confirms the MCP dependencies are installed, the server module loads, FastMCP introspection finds all tools, and `recon` is on your PATH. Also prints a copy-pasteable JSON snippet for every supported client.
- **`recon mcp doctor`** — *live* end-to-end check. Spawns the recon MCP server through the running interpreter, opens a real `stdio_client` + `ClientSession`, runs an `initialize` + `tools/list` handshake the way a client would, and asserts the canonical anchor tools (`lookup_tenant`, `analyze_posture`, `assess_exposure`, `find_hardening_gaps`, `chain_lookup`) are registered. If the spawned server crashes during `initialize`, the trailing twelve lines of its stderr are spliced into the failure detail so you see the actual ImportError / traceback instead of an opaque `BrokenPipeError`. 30-second handshake timeout.

The static check (`recon doctor --mcp`) is the right starting point. If it passes but a client still can't talk to the server, run `recon mcp doctor` to confirm the JSON-RPC loop itself is healthy.
