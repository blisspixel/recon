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

2. Add this to your AI client's MCP config:

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

## Available Tools

| Tool | Network calls? | What it does | Parameters |
|------|----------------|-------------|------------|
| `lookup_tenant` | Cache first; may resolve | Full domain intelligence — tenant details, email score, SaaS fingerprints, signals. When `explain=true`, the response includes a JSON-serialisable `explanation_dag` with `evidence → slug → rule → signal → insight` provenance alongside the flat explanations list. | `domain`, `format`: `text` / `json` / `markdown`, `explain`: bool |
| `analyze_posture` | Cache first; may resolve | Neutral posture observations across email, identity, infrastructure. Accepts an optional `profile` argument — one of `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`, or a custom name from `~/.recon/profiles/`. | `domain`, `explain`: bool, `profile`: str (optional) |
| `cluster_verification_tokens` | Cache first; may resolve each domain | Cluster a list of domains by shared TXT site-verification tokens. Reveals hedged "possible relationship" signals — operator-scoped credential reuse. | `domains`: array of domain strings |
| `assess_exposure` | Cache first; may resolve | Security posture score (0–100) with email, identity, infrastructure sections | `domain` |
| `find_hardening_gaps` | Cache first; may resolve | Categorized hardening gaps with severity and "Consider" recommendations | `domain` |
| `compare_postures` | Cache first; may resolve both domains | Side-by-side posture comparison of two domains | `domain_a`, `domain_b` |
| `chain_lookup` | Yes | Recursive domain discovery via CNAME/CT breadcrumbs | `domain`, `depth` (1–3) |
| `reload_data` | No | Reload fingerprints, signals, and posture rules from disk | none |
| `get_fingerprints` | No | List all loaded fingerprints with slugs, categories, detection types | `category` (optional filter) |
| `get_signals` | No | List all loaded signals with rules, layers, conditions | `category`, `layer` (optional filters) |
| `explain_signal` | No unless `domain` is provided | Query a signal's trigger conditions and current state for a domain | `signal_name`, `domain` (optional) |
| `test_hypothesis` | Cache first; may resolve | Test a theory against signals and evidence — returns likelihood + evidence | `domain`, `hypothesis` |
| `simulate_hardening` | Cache first; may resolve | What-if: re-compute exposure score with hypothetical fixes applied | `domain`, `fixes` (array) |
| `inject_ephemeral_fingerprint` | No | Inject a temporary fingerprint for the current session | `name`, `slug`, `category`, `confidence`, `detections` (array) |
| `reevaluate_domain` | No | Re-evaluate cached domain data against current fingerprints (including ephemeral) | `domain` |
| `list_ephemeral_fingerprints` | No | List all currently loaded ephemeral fingerprints | none |
| `clear_ephemeral_fingerprints` | No | Remove all ephemeral fingerprints from the session | none |

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

## Where to Put the Config

| Client | Config file location |
|--------|---------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally |
| VS Code + Copilot | `.vscode/mcp.json` in your project |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

### PATH gotcha for GUI clients

GUI MCP clients (Claude Desktop, Windsurf) typically don't inherit your shell's PATH. If a client can't find `recon`, replace `"command": "recon"` with the absolute path (run `which recon` / `where recon` to find it), or use the Python module form:

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

Run `recon doctor --mcp` to confirm the MCP dependencies are installed, the server loads, all tools enumerate, and `recon` is on your PATH. The output includes a copy-pasteable JSON snippet for every supported client.
