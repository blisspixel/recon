# Roadmap

Stay passive. Stay zero-creds. Stay focused on signal intelligence. Be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

## What's shipped

| Version | Highlights |
|---------|-----------|
| v0.1.0 | Core pipeline: OIDC + UserRealm + DNS sources, 155 fingerprints, Rich CLI, MCP server |
| v0.2.0 | Certificate intelligence, 4-layer signal engine (26 signals), posture analysis, delta mode, chain resolution |
| v0.3.0 | Google Workspace parity (identity routing, CNAME modules, BIMI/VMC, MTA-STS/TLS-RPT), evidence traceability, dual confidence model, per-detection scoring, fingerprint metadata enrichment. 187 fingerprints, 29 signals, 22 posture rules |
| v0.4.0 | Hedged inference language, removed sys.argv hack, `recon mcp` subcommand, disk cache (`--no-cache`, `--cache-ttl`), `--html` output, `--csv` batch output, `doctor --fix` scaffolding. 597 tests |

## What's next

Priorities are ordered by impact. Items near the top are more likely to ship soon.

### Make the intelligence trustworthy

The tool's biggest risk is sounding more certain than the evidence warrants. These items make uncertainty visible and inference auditable.

- ~~**Tighten inference language**~~ ✓ Done (v0.4.0)

- **Validation corpus** — a curated set of 20–30 well-known domains with expected outputs (services, signals, confidence levels). Run as a regression suite to measure fingerprint accuracy, surface false positives, and document known failure modes. Publish the results so users can calibrate how much to trust the output. The tool already has 604 unit tests; this adds *quality-of-inference* tests.

- **Per-insight provenance in default output** — the evidence chain is already available in `--verbose` and `--json`, but the default panel should hint at provenance. When the tool says "Email security 4/5 strong," users should be able to see which records contributed without switching to verbose mode. The data is there; it's a formatting question.

### Make it resilient

- **crt.sh fallback** — crt.sh is slow, frequently down, and rate-limited. Everyone who works with CT logs knows this. Add CertSpotter or Cloudflare CT as a secondary source so certificate intelligence and related domain discovery don't depend on a single fragile endpoint. The `crtsh_degraded` flag already signals when crt.sh fails; a fallback would eliminate the gap entirely.

- ~~**Lightweight local cache**~~ ✓ Done (v0.4.0 — `--no-cache`, `--cache-ttl`)

- ~~**Authoritative DNS option**~~ — deferred. The current resolver uses system DNS which works well for most users.

- **Cost-ordered error recovery** — classify errors by recovery cost and try cheapest first. DNS timeout → retry with fallback resolver (cheap). crt.sh timeout → skip (free, bonus source). Microsoft 429 → backoff (medium). Instead of treating all errors the same, make the retry strategy aware of what each failure actually costs.

- **Batch cascade bail-out** — in batch mode, if a class of failure repeats across domains (e.g., DNS resolver down, Microsoft 503s), detect the pattern and bail early instead of timing out on each domain individually.

### Better output

- ~~**`--html` output**~~ ✓ Done (v0.4.0)

- ~~**`--csv` output for batch mode**~~ ✓ Done (v0.4.0)

- **Graph export from `--chain`** — `.dot` for Graphviz, CSV for Maltego, or JSONL for Neo4j. The ChainReport data is already structured for this; it just needs new formatters. Visualizing recursive domain relationships in a terminal gets messy past depth 1.

- **Real-world example output in README** — show actual (non-fictional) output for a well-known domain so people can calibrate signal density and usefulness before installing. The fictional Northwind example is clean, but real output is what lets people decide if the tool is worth trying.

### Deepen the intelligence

- **Expanded org-size heuristics** — better bucketing (SMB / mid-market / enterprise) from SPF complexity, domain count, service mix, and certificate issuance patterns.

- **`compare_tenants(domain_a, domain_b)` MCP tool** — structured diff between two domains' intelligence. Useful for competitive analysis, M&A due diligence, or comparing a company's posture against industry peers.

### Agent ecosystem

The MCP server already works well. These items make recon a better citizen in multi-agent workflows:

- **Structured output contracts** — stable, versioned JSON schema for `--json` output. Treat it like an API contract with semver guarantees so agents don't break when new fields are added.

- **llms.txt** — publish at the docs site or PyPI page so AI crawlers discover the tool without parsing HTML.

- **A2A Agent Card** — `/.well-known/agent.json` for Google's [Agent-to-Agent protocol](https://github.com/google/A2A). An orchestrator agent discovers recon, delegates a lookup, passes the result downstream.

- **Batch-friendly streaming** — emit results as they complete (JSONL / newline-delimited JSON) so agents and pipelines can process incrementally instead of waiting for the entire batch.

- **OpenClaw / NemoClaw compatibility** — OpenClaw is the fastest-growing open-source agent platform (NVIDIA's NemoClaw builds on it for enterprise). As local-first AI agents become the norm, ensure recon's MCP server works cleanly as a tool provider in the OpenClaw ecosystem. This mostly means staying MCP-compliant and keeping the tool interface simple — recon does intelligence, the agent handles actions.

### Distribution

- **PyPI publish** — `pip install recon-tool` instead of clone + editable install.
- **Docker image** — for pipelines, CI/CD, and air-gapped environments.
- **Community fingerprint contribution flow** — automated validation on PR, optional `recon update-fingerprints` to pull latest.

### CLI cleanup

- ~~**Kill the `sys.argv` hack**~~ ✓ Done (v0.4.0 — replaced with custom TyperGroup)

- ~~**`recon mcp` subcommand**~~ ✓ Done (v0.4.0)

- ~~**`recon doctor --fix`**~~ ✓ Done (v0.4.0)

## Not planned

These come up but don't fit the tool's identity:

- **Plugin / module system** (SpiderFoot-style) — recon is a focused pipeline, not a framework. If you need broad OSINT, use SpiderFoot or Amass.
- **Active scanning** (brute-force, zone transfers, port scanning, web scraping) — this would destroy the "passive and legally safe" property that makes the tool usable without authorization.
- **Paid API integrations** (Shodan, BuiltWith, Clearbit, etc.) — the zero-creds constraint is a feature, not a limitation. Pipe `--json` into whatever paid tool you already have.
- **Web dashboard / `recon serve`** — this is a CLI tool and MCP server. The `--html` export covers the "share a pretty report" use case without running a web server.
- **Local database / history store** — save your `--json` output to files. Your filesystem is the database. The `--compare` flag handles diffing.
- **AI-generated pitch text** — the tool surfaces signal intelligence, not prose. Feed `--json` to an LLM via the MCP server if you want narrative output.
- **Interactive REPL mode** — use the MCP server inside an AI tool for live exploration. That's what it's for.
