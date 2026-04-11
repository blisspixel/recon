# recon

One command. One domain. Everything you need to know.

```bash
recon example.com
```

```
╭──────────────────────────── Example Corp ─────────────────────────────╮
│   Company:    Example Corp                                            │
│   Domain:     example.onmicrosoft.com                                 │
│   Provider:   Microsoft 365                                           │
│   Tenant ID:  a1b2c3d4-e5f6-7890-abcd-ef1234567890                   │
│   Region:     NA                                                      │
│   Auth:       Federated                                               │
│   Confidence: ●●● High (3 sources)                                    │
│   Services:   Anthropic (Claude), Atlassian (Jira/Confluence),        │
│ DKIM (Exchange Online), DocuSign, Exchange Autodiscover, Figma,       │
│ Intune / MDM, KnowBe4, Microsoft 365, Microsoft Teams, Miro,         │
│ Salesforce, Slack, Zendesk                                            │
│                                                                       │
│   Federated identity via Okta                                         │
│   Email security 4/5 strong (DMARC reject, DKIM, SPF strict, BIMI)   │
│   Email gateway: Proofpoint in front of Exchange                      │
│   Likely M365 E3/E5 (Intune + federated auth)                        │
│   Security stack: KnowBe4 (security training), Okta (identity)       │
│   Mac management (Jamf)                                               │
│   AI Adoption: anthropic                                              │
│   Modern Collaboration: slack, miro, atlassian, figma                 │
│                                                                       │
│   Related:    examplecorp.onmicrosoft.com                             │
╰───────────────────────────────────────────────────────────────────────╯
```

Give it any domain. It queries public endpoints and DNS records — no credentials, no API keys — and returns a clean picture of who they are, what they run, how secure their email is, and what signals matter.

Works for Microsoft 365, Google Workspace, or any provider. Built for architects, MSPs, and partners who need to understand a company before a call, a proposal, or a funding request. Also works as an MCP server for AI tools.

## Install

Requires Python 3.10+.

```bash
pip install -e .
```

Run `recon doctor` after install to verify connectivity to all data sources. It checks:

- OIDC discovery endpoint (login.microsoftonline.com)
- GetUserRealm endpoint
- Autodiscover SOAP endpoint
- DNS resolution (TXT records)
- MCP server module loading
- Fingerprint database loading (built-in + custom from `~/.recon/`)

If any check fails, lookups will still work but may return incomplete results for that source.

## Usage

```bash
recon acme.com                                # clean default
recon acme.com --services                     # M365 vs tech stack split
recon acme.com --full                         # everything at once
recon acme.com --md > report.md               # markdown report
recon acme.com --json                         # structured JSON
recon https://www.acme.com/                   # URLs work too (scheme + www stripped)
recon batch domains.txt --json                # batch mode (default 5 concurrent)
recon batch domains.txt --json -c 10          # batch with 10 concurrent lookups
recon doctor                                  # connectivity check
```

> The shorthand `recon acme.com` is equivalent to `recon lookup acme.com`.
> This is handled by `run()` in `cli.py` — if you import and call `app()` directly
> as a library, use the explicit `lookup` subcommand.

## Input Handling

The tool normalizes whatever you paste in:

- `acme.com` → `acme.com`
- `https://www.acme.com/about` → `acme.com`
- `HTTP://ACME.COM` → `acme.com`
- `  acme.com  ` → `acme.com`

Schemes, `www.` prefixes, paths, trailing slashes, and whitespace are all stripped automatically.

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| (default) | | Services, insights, and signal intelligence |
| `--services` | `-s` | M365 services vs tech stack breakdown |
| `--domains` | `-d` | All domains found in the tenant |
| `--full` | `-f` | Everything (verbose + services + domains) |
| `--json` | | Structured JSON with all fields |
| `--md` | | Full markdown report |
| `--verbose` | `-v` | Per-source resolution status |
| `--sources` | | Detailed source breakdown table |
| `--timeout` | `-t` | Max seconds for resolution (default: 60) |
| `--debug` | | Enable debug logging |

Batch-specific:

| Flag | Short | Description |
|------|-------|-------------|
| `--concurrency` | `-c` | Max concurrent lookups, 1-20 (default: 5) |

> **Rate limiting:** Each domain hits 3+ external endpoints. With `-c 20`, that's
> 60+ concurrent requests to Microsoft endpoints. The HTTP transport retries on
> 429/503 with exponential backoff, and a small inter-domain delay prevents
> burst-flooding. Keep concurrency low for large batch files.
>
> **Output ordering:** Batch results are printed in input-file order after all
> domains complete. A single slow domain (up to 60s timeout) delays the entire
> batch output.

## What You Get

| Signal | Source |
|--------|--------|
| Company name | Microsoft GetUserRealm |
| Email provider | MX records (Microsoft, Google, Zoho, etc.) |
| Tenant ID | OIDC discovery (Microsoft only) |
| Auth type (Federated / Managed) | GetUserRealm NameSpaceType |
| Identity provider | DNS TXT (Okta, Duo detected → refines auth insight) |
| Email security score (0-5) | DMARC + DKIM + SPF strict + MTA-STS + BIMI |
| 140+ SaaS services | TXT, SPF, MX, CNAME, NS, CAA, subdomain TXT |
| Email gateway detection | Proofpoint, Mimecast, Barracuda, Trend Micro, Symantec, Trellix |
| SASE / ZTNA detection | Zscaler, Netskope, Palo Alto |
| Security tooling | CrowdStrike, SentinelOne, KnowBe4, Wiz, 1Password, etc. |
| Certificate authorities | CAA records (Let's Encrypt, DigiCert, AWS ACM, etc.) |
| License tier hints | Intune + auth type signals E3/E5 |
| Infrastructure and CDN | NS records, CNAME records |
| Signal intelligence | AI adoption, GTM maturity, digital transformation |
| Related domains | Auto-discovered from CNAME breadcrumbs (autodiscover, DKIM) |
| Migration signals | Google + Microsoft coexistence |
| Org size estimate | SPF complexity, tenant domain count |

All from public sources. Zero authentication.

### Related Domain Auto-Enrichment

When a domain's autodiscover CNAME or DKIM delegation points to a different domain (e.g., `autodiscover.brand.com` → `autodiscover.internal.com`), the tool automatically runs DNS fingerprinting on the related domain and merges the results. This means looking up a public-facing brand domain automatically picks up services configured on the organization's internal IT domain.

### Email Security Score Details

The score counts five specific protections (1 point each):

| Points | Requires |
|--------|----------|
| 1 | DMARC policy is `reject` or `quarantine` (not `none`) |
| 1 | DKIM selectors found (Exchange or Google selectors) |
| 1 | SPF with `-all` (hard fail, not `~all` softfail) |
| 1 | MTA-STS record present |
| 1 | BIMI record present |

A domain with DMARC `none` + DKIM + SPF `~all` scores 1/5 (only DKIM counts).

## Fingerprint Database

Fingerprints are loaded from `data/fingerprints.yaml` and validated on startup (schema, regex safety, required fields). Add new services by editing the YAML — no code changes needed.

Custom fingerprints: drop a `fingerprints.yaml` in `~/.recon/` to add your own. Custom patterns are validated the same way — invalid regex or missing fields are skipped with a warning. Custom fingerprints are **additive only** — you cannot override or disable built-in fingerprints from the custom file.

Set `RECON_CONFIG_DIR` to override the custom fingerprint directory (default: `~/.recon/`).

Detection types supported in YAML:

| Type | What it queries | Matching |
|------|----------------|----------|
| `txt` | TXT records at zone apex | Regex |
| `spf` | SPF include directives | Substring |
| `mx` | MX record hostnames | Substring |
| `ns` | NS record hostnames | Substring |
| `cname` | CNAME targets (www, root) | Substring |
| `subdomain_txt` | TXT at a specific subdomain | `subdomain:regex` format |
| `caa` | CAA record values | Substring |

Categories: AI & Generative, Productivity & Collaboration, CRM & Marketing, Security & Compliance, Support & Helpdesk, Email & Communication, DevTools & Infrastructure, Data & Analytics, HR & Operations, Payments & Finance, Sales Intelligence, Social & Advertising, Infrastructure, Misc.

## Signal Intelligence

Derived automatically from fingerprint matches. Defined in `data/signals.yaml`. Signals are organized in three layers:

**Layer 1 — Single-category detection:**

| Signal | Triggers when |
|--------|--------------|
| AI Adoption | OpenAI, Anthropic, Mistral, or Perplexity detected |
| High GTM Maturity | 2+ sales/marketing tools |
| Enterprise Security Stack | 2+ security tools |
| Modern Collaboration | 3+ collaboration tools |
| Dev & Engineering Heavy | 2+ dev tools |
| Data & Analytics Investment | 2+ data tools |
| Multi-Cloud | 2+ cloud providers detected |

**Layer 2 — Cross-category composites** (correlate signals across domains):

| Signal | Triggers when |
|--------|--------------|
| Digital Transformation | 4+ tools across AI, collaboration, and cloud |
| Sales-Led Growth | 3+ CRM, sales engagement, and marketing automation tools |
| Product-Led Growth | 3+ analytics, engagement, and support tools |
| Enterprise IT Maturity | 4+ identity, endpoint, email security, and MDM tools |
| Heavy Outbound Stack | 2+ email sending services |

**Layer 3 — Consistency checks** (contradictions between signal layers):

| Signal | Triggers when |
|--------|--------------|
| Security Gap — Gateway Without DMARC | Email gateway deployed but DMARC not enforcing |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Input validation error (bad domain, missing file) |
| 3 | No data found (domain resolved but no information) |
| 4 | Internal or network error |

## MCP Server

Works with any MCP client — Claude, Kiro, VS Code Copilot, Cursor, ChatGPT, etc.

```json
{
  "mcpServers": {
    "recon": {
      "command": "python",
      "args": ["-m", "recon_tool.server"],
      "autoApprove": ["lookup_tenant"]
    }
  }
}
```

> On macOS/Linux, use `"python3"` instead of `"python"` if that's your default.

The `lookup_tenant` tool accepts `domain` and optional `format` parameter (`"text"`, `"json"`, or `"markdown"`). Invalid format values are rejected with a clear error. The `reload_data` tool reloads fingerprint and signal definitions from disk without restarting the server — useful after editing `~/.recon/fingerprints.yaml`. Includes a `domain_report` prompt template for clients that support slash commands.

## How It Works

Three sources queried concurrently via `asyncio.gather`, results merged and cross-validated:

1. **OIDC Discovery** — tenant ID, region (Microsoft only)
2. **GetUserRealm + Autodiscover** — company name, auth type, tenant domains (Microsoft only)
3. **DNS Records** — services, tech stack, email security, infrastructure (all domains)

Microsoft-specific sources return empty results when no M365 tenant is detected. DNS fingerprinting runs for every domain.

When related domains are discovered from CNAME breadcrumbs (autodiscover redirects, DKIM delegation to a different domain), the tool automatically runs DNS-only lookups on them and merges the additional services into the result.

## Development

```bash
pip install -e ".[dev]"

pytest tests/                          # run tests (integration tests skipped by default)
pytest tests/ --cov=recon_tool         # with coverage
pytest tests/ -m integration           # integration tests only (requires network)
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## License

MIT
