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

- **Validation corpus** — a set of 20–30 known domains with expected outputs (services, signals, confidence) run as automated regression tests. Produces a markdown accuracy report (`docs/accuracy.md`) that both humans and agents can consume. This is the "how often is this right?" story — the tool has 660 unit tests for code correctness, but no tests for inference quality.

- **Degraded sources in output** — expand the existing `crtsh_degraded` boolean into a `degraded_sources` list so users and agents always know which data sources were unavailable and how that affects result quality.

## Soon

- **Docker image** — for CI/CD pipelines and air-gapped environments. `docker run recon-tool contoso.com` as a one-liner.

- **MCP introspection tools** — `get_fingerprints`, `get_signals`, `explain_signal(name)` so agents can understand why a signal triggered and what fingerprints are available. Makes the tool self-documenting for AI workflows.

- **Agent workflow documentation** — document common patterns like "Run recon on all vendors from a CSV and rank by exposure score" so MCP users have a starting point.

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
- **Structured JSON schema contract** — the tool is still evolving. Locking down a schema now slows iteration.
- **llms.txt / A2A Agent Card** — premature until the tool has a web presence beyond PyPI.
- **Batch streaming (JSONL)** — the current batch mode works fine.
- **Prometheus metrics / structured logging overhaul** — the existing JSON logging in the MCP server is sufficient. This is a CLI tool, not a web service.
- **Per-tool MCP auth** — the MCP protocol handles auth at the transport level. Adding our own is redundant.
