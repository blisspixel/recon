# Roadmap

Guiding constraints: stay passive, stay zero-creds, no paid API keys, no database. Priority order: correctness and trust → explainability → composability (MCP, JSON, batch) → accuracy (validation, precision/recall) → new features.

## What's shipped

| Version | Highlights |
|---------|-----------|
| v0.1.0 | Core pipeline: OIDC + UserRealm + DNS sources, 155 fingerprints, Rich CLI, MCP server |
| v0.2.0 | Certificate intelligence, 4-layer signal engine (26 signals), posture analysis, delta mode, chain resolution |
| v0.3.0 | Google Workspace parity, evidence traceability, dual confidence model, per-detection scoring, fingerprint metadata. 187 fingerprints, 29 signals |
| v0.4.0 | Hedged inference language, CLI cleanup (sys.argv fix, `recon mcp`, `doctor --fix`), disk cache, CSV batch output |
| v0.5.1 | Defensive security tools (`assess_exposure`, `find_hardening_gaps`, `compare_postures`), CLI flags (`--exposure`, `--gaps`), 660 tests, 83% coverage. HTML removed |
| v0.6.0 | CertIntelProvider protocol, CertSpotter fallback, generalized `degraded_sources`, validation corpus, 723 tests, 84% coverage |
| v0.7.0 | `--explain` flag, enhanced YAML (`contradicts`, `match_mode: all`, detection `weight`, meta-signals), 5 new MCP tools (`get_fingerprints`, `get_signals`, `explain_signal`, `test_hypothesis`, `simulate_hardening`), conflict-aware merge, ~190 fingerprints, 34 signals, 896 tests |

## Now

Shipped. See "Soon" for what's next.

## Soon

Ordered by dependency and impact:

1. **Custom profile templates + interpretive lenses** — YAML files in `~/.recon/profiles/` that combine signals + posture rules into named archetypes (e.g., `--profile fintech`, `--profile startup`). Lenses reweight signals for different perspectives (defensive security, vendor due diligence, IT architecture review). Community-contributable. Depends on the enhanced YAML engine (v0.7.0).

2. **Negative-space analysis** — detect the absence of expected signals as intelligence. "M365 tenant detected but no DKIM selectors" or "Enterprise security stack but no MDM" are louder than what's present. Extends the `contradicts` engine from v0.7.0 into a dedicated absence-detection layer.

3. **Organizational archetype signatures** — build a "tech DNA" fingerprint from signal density and type mix. A startup with aggressive SaaS + high cert churn looks different from a regulated enterprise with compliance gateways + conservative DNS. Pure YAML rules, no new data sources.

4. **Dynamic agent-driven weight tuning** — let MCP agents temporarily override fingerprint/signal weights for a single call, enabling real-time "what if I weight this higher?" reasoning loops. The static weights from v0.7.0 become the foundation.

5. **Cloud strategy inference from CA fingerprints** — correlate dominant CA families with infrastructure CNAMEs to surface a "Primary Cloud Bias" observation. Pure analysis on existing data.

6. **Delegation graph topology in chain mode** — summarize the shape of SPF include chains, CNAME delegation trees, and shared site-verification tokens as a JSON graph structure.

7. **Temporal signal sequencing** — use CT log issuance timestamps to detect clustering and velocity patterns (e.g., "8 new agent.* subdomains in 14 days"). Extends the existing `issuance_velocity` metadata into richer temporal awareness.

8. **Docker image** — for CI/CD pipelines and air-gapped environments. No dependencies.

9. **Agent workflow documentation** — document common patterns for MCP users: reasoning loops, hypothesis testing, supply-chain intel workflows.

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
