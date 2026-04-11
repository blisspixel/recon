# Roadmap

The guiding principle: stay passive, stay zero-creds, stay focused on signal intelligence, and be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

## Done

- ✓ Certificate metadata extraction — issuer diversity, issuance velocity, cert age from crt.sh (v0.1.0)
- ✓ Metadata-aware signal matching — 4-layer YAML signal engine with cross-reference conditions (v0.2.0)
- ✓ Neutral posture analysis — `--posture` and `analyze_posture` MCP tool (v0.2.0)
- ✓ Delta / change detection — `--compare previous.json` (v0.2.0)
- ✓ Recursive domain chaining — `--chain --depth N` and `chain_lookup` MCP tool (v0.2.0)
- ✓ Google Workspace parity — identity routing, CNAME module probing, BIMI/VMC identity, site-verification tokens, MTA-STS/TLS-RPT, enhanced CSE (v0.3.0)
- ✓ Evidence traceability — per-detection EvidenceRecord with source type, raw value, rule name (v0.3.0)
- ✓ Dual confidence model — evidence_confidence + inference_confidence, backward-compatible (v0.3.0)
- ✓ Per-detection corroboration scoring — high/medium/low based on independent record type diversity (v0.3.0)
- ✓ Fingerprint metadata enrichment — provider_group/display_group replace keyword heuristics (v0.3.0)
- ✓ Richer MCP toolset — `analyze_posture`, `chain_lookup`, outcome-oriented tools (v0.2.0)

## Trustworthiness & calibration

The tool's biggest risk is sounding more authoritative than the evidence warrants. These items make uncertainty visible and inference auditable.

- Tighten inference language — use "suggests," "likely," "observed indicators" instead of declarative claims in insights and signals. The posture analysis already uses neutral framing; extend that tone to all derived output. Quick pass through `insights.py` and `signals.yaml`.
- Validation corpus — a curated set of 20-30 known domains with expected outputs (services, signals, confidence). Run as a regression suite to measure fingerprint accuracy and surface false positives. Publish known failure modes and ambiguous cases.
- Per-insight provenance in default output — the evidence chain is available in `--verbose` and `--json`, but the default panel should hint at provenance (e.g., "Email security 4/5 strong" → show which records contributed). The data is already there; it's a formatting question.

## Reliability & resilience

- crt.sh fallback — crt.sh is slow, frequently down, and rate-limited. Add CertSpotter or Cloudflare CT as a secondary source so certificate intelligence and related domain discovery don't depend on a single fragile endpoint. The `crtsh_degraded` flag already signals when crt.sh fails; a fallback would eliminate the gap.
- Lightweight local cache (`~/.recon/cache/`) — the MCP server caches in-memory (120s TTL), but the CLI is stateless. A disk-backed cache with configurable TTL (default 24h) would avoid re-hitting endpoints on repeated lookups. JSON files on disk, no dependencies. CLI flags: `--no-cache` to bypass, `--cache-ttl` to override.
- Authoritative DNS option — add `--resolver` flag to query specific nameservers (e.g., `--resolver 8.8.8.8`) or authoritative nameservers directly, bypassing local caching resolvers. Useful for fresh data and avoiding cache poisoning.
- Cost-ordered error recovery — classify errors by recovery cost and try cheapest first. DNS timeout → retry with fallback resolver (cheap). crt.sh timeout → skip (free, bonus source). Microsoft 429 → backoff (medium).
- Consecutive-error tracking in the MCP server — if `lookup_tenant` fails 3 times in a row for the same error class, surface a specific diagnostic instead of repeating the same generic error.
- Batch cascade bail-out — if a class of failure repeats across domains in batch mode (e.g., DNS resolver down, Microsoft 503s), detect the pattern and bail early instead of timing out on each domain individually.

## Better output

- `--html` output — self-contained single-file report for sharing in email or proposals.
- `--csv` output for batch mode — MSPs and sales engineers live in spreadsheets.
- Graph export from `--chain` — `.dot` for Graphviz, CSV for Maltego, or JSONL for Neo4j/BloodHound. The ChainReport data is already structured; it just needs new formatters. Visualizing recursive domain relationships in a terminal gets messy past depth 1.
- Real-world example output in README — show actual (non-fictional) output for a well-known domain so people can calibrate signal density and usefulness before installing.
- `recon doctor --fix` — auto-scaffold `~/.recon/fingerprints.yaml` and `signals.yaml` templates with inline comments.

## Deepen the intelligence

- Expanded org-size and maturity heuristics — better bucketing (SMB / mid-market / enterprise) from SPF complexity, domain count, service mix, and certificate issuance patterns.
- `compare_tenants(domain_a, domain_b)` MCP tool — structured diff between two domains' intelligence. Useful for competitive analysis or M&A due diligence.

## Agent-friendly by default

- llms.txt — publish at the docs site / PyPI page so AI crawlers discover the tool without parsing HTML.
- Structured output contracts — stable, versioned JSON schema for `--json` output. Treat it like an API contract with semver guarantees so agents don't break when new fields are added.
- A2A Agent Card — `/.well-known/agent.json` for Google's [Agent-to-Agent protocol](https://github.com/google/A2A). An orchestrator agent discovers recon, delegates a lookup, passes the result to a proposal-writing or CRM-update agent.
- Batch-friendly streaming — emit results as they complete (JSONL / newline-delimited JSON) so agents and pipelines can process incrementally.

## Scale and distribution

- PyPI publish — `pip install recon-tool` instead of clone + editable install.
- Docker image — for pipelines, CI/CD, and air-gapped environments.
- Community fingerprint contribution flow — automated validation on PR, optional `recon update-fingerprints` to pull latest.

## CLI cleanup

- Kill the `sys.argv` preprocessing hack — `_preprocess_args()` mutates `sys.argv` to inject `lookup` as the default subcommand. It works but it's fragile and surprising for anyone importing the module. Replace with a proper Typer default command or callback-based approach.
- `recon mcp` subcommand — start the MCP server from the CLI instead of requiring `python -m recon_tool.server`. Makes it discoverable and consistent with the other subcommands.

## Not planned

These come up but don't fit the tool's identity:

- Plugin / module system (SpiderFoot-style) — recon is a focused pipeline, not a framework. If you need broad OSINT, use SpiderFoot or Amass.
- Active scanning (brute-force, zone transfers, port scanning, web scraping) — this would destroy the "passive and legally safe" property.
- Paid API integrations (Shodan, BuiltWith, Clearbit, etc.) — the zero-creds constraint is a feature, not a limitation. Pipe `--json` into whatever paid tool you already have.
- Web dashboard / `recon serve` — this is a CLI tool and MCP server. The `--html` export covers the "share a pretty report" use case.
- Local database / history store — save your `--json` output to files. Your filesystem is the database.
- AI-generated pitch text — the tool surfaces signal intelligence, not prose. Feed `--json` to an LLM via the MCP server.
- Interactive REPL mode — use the MCP server inside an AI tool for live exploration.
