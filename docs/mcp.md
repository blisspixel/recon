# MCP Server (AI Agent Integration)

recon runs as an MCP server so any MCP-compatible AI tool can call it directly — no API keys, no glue code.

Works with Claude Desktop, Cursor, VS Code + Copilot, ChatGPT, or any other [MCP client](https://modelcontextprotocol.io/).

## Setup

1. Install recon with MCP support:

```bash
pip install recon-tool[mcp]               # from PyPI, with MCP server
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

Example multi-step prompt for deeper analysis:

> "Look up contoso.com with explain=true. Then run assess_exposure and find_hardening_gaps. Finally, simulate_hardening with DMARC reject and MTA-STS enforce applied, and tell me the new posture score."

## Available Tools

| Tool | What it does | Parameters |
|------|-------------|------------|
| `lookup_tenant` | Full domain intelligence — tenant details, email score, SaaS fingerprints, signals. When `explain=true`, the response includes a JSON-serialisable `explanation_dag` with `evidence → slug → rule → signal → insight` provenance alongside the flat explanations list. | `domain`, `format`: `text` / `json` / `markdown`, `explain`: bool |
| `analyze_posture` | Neutral posture observations across email, identity, infrastructure. Accepts an optional `profile` argument (v0.9.3) — one of `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`, or a custom name from `~/.recon/profiles/`. | `domain`, `explain`: bool, `profile`: str (optional) |
| `cluster_verification_tokens` | Cluster a list of domains by shared TXT site-verification tokens (v0.9.3). Reveals hedged "possible relationship" signals — operator-scoped credential reuse — without any additional network calls beyond the per-domain cache warm-up. | `domains`: array of domain strings |
| `assess_exposure` | Security posture score (0–100) with email, identity, infrastructure sections | `domain` |
| `find_hardening_gaps` | Categorized hardening gaps with severity and "Consider" recommendations | `domain` |
| `compare_postures` | Side-by-side posture comparison of two domains | `domain_a`, `domain_b` |
| `chain_lookup` | Recursive domain discovery via CNAME/CT breadcrumbs | `domain`, `depth` (1–3) |
| `reload_data` | Reload fingerprints, signals, and posture rules from disk | none |
| `get_fingerprints` | List all loaded fingerprints with slugs, categories, detection types | `category` (optional filter) |
| `get_signals` | List all loaded signals with rules, layers, conditions | `category`, `layer` (optional filters) |
| `explain_signal` | Query a signal's trigger conditions and current state for a domain | `signal_name`, `domain` (optional) |
| `test_hypothesis` | Test a theory against signals and evidence — returns likelihood + evidence | `domain`, `hypothesis` |
| `simulate_hardening` | What-if: re-compute exposure score with hypothetical fixes applied | `domain`, `fixes` (array) |
| `inject_ephemeral_fingerprint` | Inject a temporary fingerprint for the current session | `name`, `slug`, `category`, `confidence`, `detections` (array) |
| `reevaluate_domain` | Re-evaluate cached domain data against current fingerprints (including ephemeral) | `domain` |
| `list_ephemeral_fingerprints` | List all currently loaded ephemeral fingerprints | none |
| `clear_ephemeral_fingerprints` | Remove all ephemeral fingerprints from the session | none |

All tools are read-only and idempotent. Tools marked with `explain` parameter support structured provenance output. The agentic tools (`test_hypothesis`, `simulate_hardening`, `get_fingerprints`, `get_signals`, `explain_signal`) operate on cached pipeline data with zero additional network calls. The ephemeral fingerprint tools (`inject_ephemeral_fingerprint`, `reevaluate_domain`, `list_ephemeral_fingerprints`, `clear_ephemeral_fingerprints`) let AI agents inject temporary detection patterns and re-evaluate cached data without new network calls. The server includes a bounded TTL cache (120s) and per-domain rate limiting.

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
