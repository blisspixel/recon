# Roadmap

Stay passive. Stay zero-creds. Stay focused on signal intelligence. Be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

## What's shipped

| Version | Highlights |
|---------|-----------|
| v0.1.0 | Core pipeline: OIDC + UserRealm + DNS sources, 155 fingerprints, Rich CLI, MCP server |
| v0.2.0 | Certificate intelligence, 4-layer signal engine (26 signals), posture analysis, delta mode, chain resolution |
| v0.3.0 | Google Workspace parity, evidence traceability, dual confidence model, per-detection scoring, fingerprint metadata. 187 fingerprints, 29 signals |
| v0.4.0 | Hedged inference language, CLI cleanup (sys.argv fix, `recon mcp`, `doctor --fix`), disk cache, CSV batch output |
| v0.5.1 | Defensive security tools (`assess_exposure`, `find_hardening_gaps`, `compare_postures`), CLI flags (`--exposure`, `--gaps`), 660 tests, 83% coverage. HTML removed |

## Now

- **crt.sh fallback** — crt.sh is the single point of failure for certificate intelligence and related domain discovery. It's slow, frequently down, and rate-limited. Add CertSpotter as a secondary CT source (free, no API key, reliable). The `crtsh_degraded` flag already signals when crt.sh fails; a fallback eliminates the gap.

- **Validation corpus** — a set of 20–30 known domains with expected outputs (services, signals, confidence) run as automated regression tests. Produces a markdown accuracy report that both humans and agents can consume. This is the "how often is this right?" story — the tool has 660 unit tests for code correctness, but no tests for inference quality.

## Soon

- **Docker image** — for CI/CD pipelines and air-gapped environments where installing Python isn't practical. `docker run recon-tool pepsi.com` as a one-liner.

- **Real-world example output** — show actual output for a domain the project controls or a willing non-profit, with the fictional Northwind example kept as the primary. Real output lets people calibrate signal density before installing.

## Intentionally not doing

These are deliberate design decisions, not missing features:

- **HTML output / web reports** — markdown renders everywhere that matters: GitHub, VS Code, Obsidian, Notion, AI agents. HTML is bloat for a focused CLI tool. Use `--md` and pipe it wherever you want.
- **Web dashboard / `recon serve`** — this is a CLI tool and MCP server, not a web app. The `--md` export is the shareable report format.
- **Plugin / module system** — recon is a focused pipeline, not a framework. If you need broad OSINT, use SpiderFoot or Amass.
- **Active scanning** (port scanning, brute-force, zone transfers, web scraping) — this would destroy the "passive and legally safe" property.
- **Paid API integrations** (Shodan, BuiltWith, Clearbit) — the zero-creds constraint is a feature. Pipe `--json` into whatever paid tool you already have.
- **Local database / history store** — save `--json` to files. Your filesystem is the database. `--compare` handles diffing.
- **AI-generated pitch text** — the tool surfaces signal intelligence, not prose. Feed `--json` to an LLM via the MCP server.
- **Interactive REPL** — use the MCP server inside an AI tool. That's what it's for.
- **Structured JSON schema contract** — the tool is still evolving. Locking down a schema now slows iteration. The JSON output is stable in practice but not formally versioned yet.
- **Graph visualization exports** — the `--chain --json` output is already structured. A 10-line script converts it to `.dot` or Maltego CSV. Not worth adding to the tool.
- **llms.txt / A2A Agent Card** — needs a docs site first. Premature until the tool has a web presence beyond PyPI.
- **Batch streaming (JSONL)** — the current batch mode works. Streaming is an optimization for a problem nobody has reported.
- **OpenClaw / NemoClaw compatibility** — already compatible via MCP. Nothing to build.
