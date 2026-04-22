# recon

Passive domain intelligence CLI and MCP server. Queries public DNS records and unauthenticated Microsoft/Google endpoints — no credentials or API keys.

## What it does

`recon <domain>` returns: company name, email provider, tenant ID, auth type, email security score (0-5), 227 SaaS service fingerprints, security stack detection, signal intelligence (AI adoption, GTM maturity, org size hints, hedged hardening observations), categorized services (Email / Identity / Cloud / Security / AI / Collaboration / Other), lexical taxonomy observations from CT-discovered subdomains, sovereignty hints (GCC / GCC High / China 21Vianet / B2C) from OIDC metadata, and related domains (via CNAME breadcrumbs + certificate transparency + common subdomain probing).

## Commands

```bash
recon northwindtraders.com              # default panel output
recon northwindtraders.com --json       # structured JSON
recon northwindtraders.com --md         # markdown report
recon northwindtraders.com --full       # everything
recon northwindtraders.com --explain    # full reasoning + evidence DAG
recon northwindtraders.com --profile fintech   # apply a posture lens
recon batch domains.txt --json          # batch mode (cross-domain token clustering)
recon doctor                            # connectivity check
recon mcp                               # start MCP server (stdio)
recon cache show                        # list all cached CT data
recon cache show contoso.com            # inspect cache for a domain
recon cache clear contoso.com           # clear cache for a domain
recon cache clear --all                 # clear all CT cache
recon fingerprints list                 # list all built-in fingerprints
recon fingerprints search <query>       # search by slug / name / pattern
recon fingerprints show <slug>          # inspect one fingerprint
recon fingerprints check                # validate the catalog + dupe-check + specificity
recon fingerprints new <slug>           # scaffold a new entry with all three gates
recon fingerprints test <slug>          # run one fingerprint against the public corpus
recon signals list                      # list all signals
recon signals search <query>            # search signals
recon signals show "<name>"             # inspect one signal
```

## Project structure

- `recon_tool/` — source code
  - `cli.py` — Typer CLI, entry point is `run()`
  - `resolver.py` — orchestrates concurrent source queries
  - `sources/` — OIDC, UserRealm, DNS lookup sources (DNS includes crt.sh cert transparency)
  - `fingerprints.py` + `data/fingerprints/` — SaaS detection (data-driven, one YAML per category, no code changes needed)
  - `signals.py` + `data/signals.yaml` — signal intelligence engine
  - `absence.py` — negative-space evaluation + positive-when-absent hardening observations
  - `lexical.py` — CT subdomain lexical taxonomy (env / region / tenancy prefixes)
  - `clustering.py` — shared verification token clustering (batch-scope)
  - `profiles.py` + `data/profiles/` — posture profile lenses
  - `insights.py` — derived intelligence from fingerprint matches
  - `merger.py` — result merging, confidence scoring
  - `explanation.py` — explanation records + JSON-serializable provenance DAG
  - `formatter.py` — Rich terminal output (v0.9.3 redesigned panel), JSON, markdown
  - `ct_cache.py` — per-domain CT subdomain cache (`~/.recon/ct-cache/`, 7-day TTL)
  - `server.py` — MCP server (FastMCP, stdio transport), included in the default `pip install recon-tool`
  - `http.py` — SSRF-safe HTTP client with retry/backoff
  - `retry.py` — transient-failure retry decorator for sources
  - `validator.py` — domain input validation
  - `models.py` — frozen dataclasses (TenantInfo, SourceResult, Signal, …)
- `tests/` — 1585 tests, pytest + hypothesis
- `data/fingerprints/` — 227 SaaS fingerprints across 8 per-category YAML files
- `data/profiles/` — 6 built-in posture profiles (fintech, healthcare, saas-b2b, high-value-target, public-sector, higher-ed)
- `data/signals.yaml` — 4-layer signal definitions (42 signals, two-pass + absence + positive-when-absent evaluation)

## Development

```bash
uv sync --extra dev              # or: pip install -e ".[dev]"
pre-commit install               # activate pre-commit hooks
pytest tests/                    # run tests (coverage must stay >=80%)
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
