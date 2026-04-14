# recon

Passive domain intelligence CLI and MCP server. Queries public DNS records and unauthenticated Microsoft/Google endpoints — no credentials or API keys.

## What it does

`recon <domain>` returns: company name, email provider, tenant ID, auth type, email security score (0-5), 208 SaaS service fingerprints, security stack detection, signal intelligence (AI adoption, GTM maturity, org size hints), and related domains (via CNAME breadcrumbs + certificate transparency + common subdomain probing).

## Commands

```bash
recon northwindtraders.com              # default panel output
recon northwindtraders.com --json       # structured JSON
recon northwindtraders.com --md         # markdown report
recon northwindtraders.com --full       # everything
recon batch domains.txt --json          # batch mode
recon doctor                            # connectivity check
```

## Project structure

- `recon_tool/` — source code
  - `cli.py` — Typer CLI, entry point is `run()`
  - `resolver.py` — orchestrates concurrent source queries
  - `sources/` — OIDC, UserRealm, DNS lookup sources (DNS includes crt.sh cert transparency)
  - `fingerprints.py` + `data/fingerprints.yaml` — SaaS detection (data-driven, no code changes needed)
  - `signals.py` + `data/signals.yaml` — signal intelligence engine
  - `insights.py` — derived intelligence from fingerprint matches
  - `merger.py` — result merging, confidence scoring
  - `formatter.py` — Rich terminal output, JSON, markdown
  - `server.py` — MCP server (FastMCP, stdio transport)
  - `http.py` — SSRF-safe HTTP client with retry/backoff
  - `validator.py` — domain input validation
  - `models.py` — frozen dataclasses (TenantInfo, SourceResult)
- `tests/` — 1147 tests, pytest + hypothesis
- `data/fingerprints.yaml` — 208 SaaS fingerprints
- `data/signals.yaml` — 4-layer signal definitions (44 signals, two-pass evaluation + absence detection)

## Development

```bash
pip install -e ".[dev]"
pytest tests/                    # run tests
ruff check recon_tool/           # lint
pyright recon_tool/              # type check
```

## Key patterns

- All source queries run concurrently via `asyncio.gather`
- Fingerprints and signals are YAML-driven — edit data files, not code
- Models are frozen dataclasses (immutable)
- HTTP transport has SSRF protection and retry with exponential backoff
- MCP server has TTL cache (120s) and per-domain rate limiting
- Custom fingerprints go in `~/.recon/fingerprints.yaml` (additive only)
- Custom signals go in `~/.recon/signals.yaml` (additive only)

## Testing

- Integration tests are skipped by default (`-m 'not integration'`)
- Run `pytest -m integration` for network tests
- All examples in README use fictional companies (Northwind Traders, Contoso, Fabrikam)
