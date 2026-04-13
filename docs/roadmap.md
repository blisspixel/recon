# Roadmap

Stay passive. Stay zero-creds. Stay focused on signal intelligence. Be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

The priority order is: machine trust (stable, evidence-backed, deterministic) → explainability (why a signal fired, what weakens confidence) → composability (MCP quality, JSON quality, batch workflows) → accuracy (validation corpus, precision/recall). Features come last. Trust comes first.

## What's shipped

| Version | Highlights |
|---------|-----------|
| v0.1.0 | Core pipeline: OIDC + UserRealm + DNS sources, 155 fingerprints, Rich CLI, MCP server |
| v0.2.0 | Certificate intelligence, 4-layer signal engine (26 signals), posture analysis, delta mode, chain resolution |
| v0.3.0 | Google Workspace parity, evidence traceability, dual confidence model, per-detection scoring, fingerprint metadata. 187 fingerprints, 29 signals |
| v0.4.0 | Hedged inference language, CLI cleanup (sys.argv fix, `recon mcp`, `doctor --fix`), disk cache, CSV batch output |
| v0.5.1 | Defensive security tools (`assess_exposure`, `find_hardening_gaps`, `compare_postures`), CLI flags (`--exposure`, `--gaps`), 660 tests, 83% coverage. HTML removed |
| v0.6.0 | CertIntelProvider protocol, CertSpotter fallback, generalized `degraded_sources`, validation corpus, 723 tests, 84% coverage |

## Now

These build on each other in order:

1. **Explainable intelligence (`--explain` flag)** — for every insight and signal, show the matched evidence, which rules fired, and why confidence landed where it did. Include "what would weaken this signal" context. The data is already in evidence records and detection scores — this is a formatting + MCP feature, not new infrastructure.

2. **Enhanced YAML correlation engine** — upgrade the signal and fingerprint YAML schema with `contradicts` (negation), `match_mode: all` (AND logic for fingerprint detections), detection `weight` (not all evidence is equal), and signal-to-signal references (meta-signals that fire when other signals are active). Small loader changes, massive correlation power.

3. **MCP introspection tools** — `get_fingerprints`, `get_signals`, `explain_signal(name)` so agents can understand why a signal triggered and what would change the conclusion. Depends on `--explain` logic existing.

4. **Conflict-aware merge output** — enrich `--json` output to expose candidate values when sources disagree, with per-candidate confidence. Natural extension of `--explain`.

## Soon

Ordered by dependency and impact:

1. **Custom profile templates** — YAML files in `~/.recon/profiles/` that combine signals + posture rules into named archetypes (e.g., `--profile fintech`, `--profile startup`). Natural extension of the existing YAML extensibility for vertical-specific use cases. Community-contributable.

2. **Cloud strategy inference from CA fingerprints** — correlate dominant CA families with infrastructure CNAMEs to surface a "Primary Cloud Bias" observation. Pure analysis on existing data. Depends on validation corpus to catch false positives.

3. **Delegation graph topology in chain mode** — summarize the shape of SPF include chains, CNAME delegation trees, and shared site-verification tokens. Depends on validation corpus.

4. **Docker image** — for CI/CD pipelines and air-gapped environments. No dependencies.

5. **Agent workflow documentation** — document common patterns for MCP users. No dependencies, but more useful after MCP introspection tools exist.

## Intentionally not doing

These are deliberate design decisions, not missing features:

- **HTML output / web reports** — markdown renders everywhere that matters: GitHub, VS Code, Obsidian, Notion, AI agents. HTML is bloat for a focused CLI tool. Use `--md` and pipe it wherever you want.
- **Web dashboard / `recon serve`** — this is a CLI tool and MCP server, not a web app.
- **Pydantic models** — frozen dataclasses are simpler, have zero dependencies, and work perfectly. Pydantic adds complexity for no real benefit here.
- **STIX2 / Maltego / graph exports** — the `--json` output can be piped into whatever format converter you need. Same principle as HTML — don't add output formats the tool doesn't need.
- **Plugin / module system** — recon is a focused pipeline, not a framework. If you need broad OSINT, use SpiderFoot or Amass.
- **Active scanning** (port scanning, brute-force, zone transfers, web scraping) — this would destroy the "passive and legally safe" property.
- **Paid API integrations** (Shodan, BuiltWith, Clearbit) — the zero-creds constraint is a feature. Pipe `--json` into whatever paid tool you already have.
- **Local database / history store** — save `--json` to files. Your filesystem is the database. `--compare` handles diffing.
- **AI-generated pitch text** — the tool surfaces signal intelligence, not prose. Feed `--json` to an LLM via the MCP server.
- **Interactive REPL** — use the MCP server inside an AI tool. That's what it's for.
- **Structured JSON schema contract** — the tool is still evolving. Locking down a schema now slows iteration. Snapshot tests are a lighter alternative when stability matters.
- **Formal observation/predicate layer** — the current EvidenceRecord + TenantInfo model is sufficient. A full subject/predicate/value graph is a research project, not a CLI tool improvement.
- **SBOM / signed releases** — enterprise packaging theater. Premature for the current project stage.
- **llms.txt / A2A Agent Card** — premature until the tool has a web presence beyond PyPI.
- **Batch streaming (JSONL)** — the current batch mode works fine.
- **Timeline narrative generation** — the delta mode surfaces raw, factual changes; any higher-level narrative synthesis is left to the user or AI agent via MCP.
- **Subdomain takeover warnings or exploitation guidance** — crosses into offensive security territory. The tool only surfaces observable configuration facts in neutral, defensive language (see `find_hardening_gaps` and `assess_exposure`). It never suggests or enables takeover techniques.
- **Prometheus metrics / structured logging overhaul** — the existing JSON logging in the MCP server is sufficient. This is a CLI tool, not a web service.
- **Per-tool MCP auth** — the MCP protocol handles auth at the transport level. Adding our own is redundant.
