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
| v0.8.0 | Fingerprint coverage expansion: 12 new fingerprints (agentic AI, supply chain, edge/CDN, SPF flattening), 5 enriched fingerprints, 1 pattern fix, 7 new signals, 4 updated signals, 4 new posture rules, ~206 fingerprints, 41 signals, 958 tests |

## Now

Shipped. See "Soon" for what's next.

## Soon

Ordered by dependency and impact:

1. **Negative-space analysis / expected counterparts** — detect the absence of expected signals as intelligence. Formalize as YAML `expected_counterparts`: if `microsoft365` is present, expect `intune`, `defender`. "M365 tenant detected but no DKIM selectors" or "Enterprise security stack but no MDM" are louder than what's present. Extends the `contradicts` engine from v0.7.0 into a dedicated absence-detection layer. The expanded fingerprint set from v0.8.0 makes this more useful — more slugs means more meaningful absences.

2. **Ephemeral fingerprints via MCP** — new `inject_ephemeral_fingerprint` MCP tool that lets AI agents add temporary detection patterns at runtime. The agent isn't scanning anything new — it's re-evaluating cached data against an additional pattern. Ephemeral rules live in memory only (not persisted to disk), are scoped to the current session, and are validated through the same regex/ReDoS checks as built-in fingerprints. This lets agents leverage their training data to detect obscure SaaS CNAMEs that aren't in the YAML yet, without requiring manual edits.

3. **CT subdomain lexical taxonomy** — build a lexical parser for CT-discovered subdomain prefixes/suffixes (`prd-`, `stg-`, `dev-`, `eu-west-`, `us-east-`). Emit signals like "Mature DevOps Pipeline" (dev/stg/prd splits detected) and "Geo-Distributed Infrastructure" (region prefixes detected). Pure analysis on existing CT data, no new network calls.

4. **Site-verification token clustering in batch mode** — when running `recon batch` against multiple domains, map shared `google-site-verification` tokens across domains to surface subsidiary/parent relationships. Proves organizational ownership when two domains share the same Search Console instance.

5. **Identity federation branding extraction** — extract custom branding asset URLs from Microsoft OIDC tenant discovery responses (already fetched). Logo file names and CDN paths can reveal parent companies, holding companies, or recent acquisitions.

6. **Custom profile templates + interpretive lenses** — YAML files in `~/.recon/profiles/` that combine signals + posture rules into named archetypes (e.g., `--profile fintech`, `--profile startup`). Lenses reweight signals for different perspectives (defensive security, vendor due diligence, IT architecture review). Community-contributable.

7. **Organizational archetype signatures** — build a "tech DNA" fingerprint from signal density and type mix. A startup with aggressive SaaS + high cert churn looks different from a regulated enterprise with compliance gateways + conservative DNS. Pure YAML rules, no new data sources.

8. **Dynamic agent-driven weight tuning** — let MCP agents temporarily override fingerprint/signal weights for a single call, enabling real-time "what if I weight this higher?" reasoning loops. The static weights from v0.7.0 become the foundation.

9. **Cloud strategy inference from CA fingerprints** — correlate dominant CA families with infrastructure CNAMEs to surface a "Primary Cloud Bias" observation. Pure analysis on existing data.

10. **Delegation graph topology in chain mode** — summarize the shape of SPF include chains, CNAME delegation trees, and shared site-verification tokens as a JSON graph structure.

11. **Temporal signal sequencing** — use CT log issuance timestamps to detect clustering and velocity patterns (e.g., "8 new agent.* subdomains in 14 days"). Extends the existing `issuance_velocity` metadata into richer temporal awareness.

12. **DMARC RUA/RUF vendor extraction** — pipe the raw `_dmarc` TXT record content through the fingerprint matcher to detect DMARC report routing vendors (Valimail, dmarcian, Agari, Proofpoint EFD) from `rua=mailto:...@vendor.com` patterns. Requires a small code change to feed DMARC TXT through the detection pipeline. High signal value — tells you exactly what email governance tool they pay for.

13. **DMARC phased rollout detection** — extract the `pct=` tag from DMARC records into metadata. A domain with `p=quarantine; pct=25` is actively rolling out enforcement. Requires code change to parse `pct` into a new metadata field. Enables a "DMARC Phased Rollout" posture observation.

14. **Passive ASN/BGP mapping** — resolve apex A/AAAA records (standard DNS query) and map IPs to a locally bundled ASN database (MaxMind GeoLite2 or similar). Detects true hosting infrastructure without HTTP requests. Adds ~5MB dependency and requires periodic database updates.

15. **Docker image** — for CI/CD pipelines and air-gapped environments. No dependencies.

16. **Agent workflow documentation** — document common patterns for MCP users: reasoning loops, hypothesis testing, supply-chain intel workflows.

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
- **HTTP endpoint probing** (`.well-known/` paths, OIDC discovery on arbitrary domains, d3p manifests) — this crosses from passive DNS observation into active HTTP probing of target infrastructure. recon queries DNS and known identity providers (Microsoft, Google), not arbitrary URLs on target domains.
- **TLS handshake inspection** (cipher suite fingerprinting, PQC key exchange detection) — requires active connection to target servers. Fundamentally different from reading public DNS records.
- **Generic subdomain name pattern matching** (e.g., matching `n8n.*` or `automation.*` as service indicators) — too noisy, too many false positives. Verification TXT records and CNAME delegations to known provider infrastructure are far more reliable signals.
