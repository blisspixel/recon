# Roadmap

The guiding principle: stay passive, stay zero-creds, stay focused on signal intelligence, and be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

## Deepen the intelligence

- Google Workspace parity — M365 gets tenant ID, company name, auth type, and region from public endpoints. Google Workspace currently only gets MX/SPF detection. Google has public discovery endpoints that could surface org name, directory info, and workspace configuration without credentials. This is the biggest coverage gap.
- Expanded org-size and maturity heuristics — better bucketing (SMB / mid-market / enterprise) from SPF complexity, domain count, and service mix
- Smarter CNAME/DKIM following — deeper passive subdomain discovery from public records without active scanning
- Migration and risk signal refinement — detect patterns like recent Google → M365 shifts, legacy auth exposure, or security posture gaps that suggest conversation starters

## Better output

- `--html` output — self-contained single-file report for sharing in email or proposals
- `--csv` output for batch mode — MSPs and sales engineers live in spreadsheets
- Delta / change reports — compare current scan to a previous `--json` export and surface what changed
- `recon doctor --fix` — auto-scaffold `~/.recon/fingerprints.yaml` and `signals.yaml` templates with inline comments

## Reliability & resilience

- Lightweight local cache (`~/.recon/cache/`) — the MCP server already caches results in-memory (120s TTL), but the CLI is stateless. A disk-backed cache with configurable TTL (default 24h) would avoid re-hitting endpoints on repeated lookups. Useful for humans running the same domain twice and for agents that call recon multiple times in a workflow. No external dependencies — just JSON files on disk.
- Cost-ordered error recovery — classify errors by recovery cost and try cheapest first. DNS timeout → retry with fallback resolver (cheap). crt.sh timeout → skip (free, bonus source). Microsoft 429 → backoff (medium). Instead of treating all errors the same, make the retry strategy aware of what each failure actually costs.
- Consecutive-error tracking in the MCP server — if `lookup_tenant` fails 3 times in a row for the same error class, surface a more specific diagnostic message instead of repeating the same generic error. Helps agents and users understand whether the problem is transient or structural.
- Batch cascade bail-out — in batch mode, if a class of failure repeats across domains (e.g., a DNS resolver is down, or Microsoft endpoints are returning 503s), detect the pattern and bail early on remaining domains that would hit the same failure. Prevents large batch runs from wasting minutes timing out on each domain individually when the underlying issue is systemic.

## Agent-friendly by default

The MCP server already works and follows good practices (outcome-oriented tools, caching, rate limiting, structured logging). The next step is making recon a first-class citizen across the AI agent ecosystem:

- llms.txt — when recon has a docs site or PyPI page, publish an `llms.txt` at the root so AI crawlers and agents can discover what the tool does without parsing HTML.
- Structured output contracts — stable, versioned JSON schema for `--json` output so agents can rely on the shape without breaking when new fields are added. Treat `--json` like an API contract with semver guarantees.
- Richer MCP toolset — `compare_tenants(domain_a, domain_b)` that returns a structured diff, `suggest_security_wins(domain)` that highlights the lowest-hanging email security improvements. Keep tools outcome-oriented (one call, one useful answer) per [MCP best practices](https://www.philschmid.de/mcp-best-practices).
- A2A Agent Card — publish a `/.well-known/agent.json` so recon can participate in multi-agent workflows via Google's [Agent-to-Agent protocol](https://github.com/google/A2A). An orchestrator agent could discover recon, delegate a domain lookup, and pass the structured result to a proposal-writing agent or CRM-update agent. recon stays focused on intelligence; downstream agents handle actions.
- Batch-friendly streaming — for large domain lists, emit results as they complete (JSONL / newline-delimited JSON) so agents and pipelines can process incrementally instead of waiting for the entire batch.
- OpenClaw / open agent compatibility — as self-hosted AI agent platforms (OpenClaw, etc.) mature, ensure recon's MCP server works cleanly as a tool provider in those ecosystems. This mostly means staying standards-compliant and keeping the tool interface simple.

## Scale and distribution

- PyPI publish — `pip install recon-tool` instead of clone + editable install
- Docker image — for pipelines, CI/CD, and air-gapped environments
- Community fingerprint contribution flow — automated validation on PR, optional `recon update-fingerprints` to pull latest

## Not planned

These come up but don't fit the tool's identity:

- Plugin / module system (SpiderFoot-style) — recon is a focused pipeline, not a framework. If you need broad OSINT, use SpiderFoot or Amass. If you need focused domain intelligence, use recon.
- Active scanning (brute-force, zone transfers, port scanning, web scraping) — this would destroy the "passive and legally safe" property.
- Paid API integrations (Shodan, BuiltWith, Clearbit, etc.) — the zero-creds constraint is a feature, not a limitation. Pipe the `--json` output into whatever paid tool you already have.
- Web dashboard / `recon serve` — this is a CLI tool and MCP server. The `--html` export covers the "share a pretty report" use case.
- Local database / history store — save your `--json` output to files. Your filesystem is the database.
- AI-generated pitch text — the tool surfaces signal intelligence, not prose. Feed `--json` to an LLM via the MCP server.
- Interactive REPL mode — use the MCP server inside an AI tool for live exploration.
