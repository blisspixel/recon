# recon

Passive domain intelligence from public DNS and Microsoft/Google endpoints.

```bash
recon northwindtraders.com
```

```
╭────────────────────────── Northwind Traders ──────────────────────────╮
│   Company:    Northwind Traders                                       │
│   Domain:     northwindtraders.onmicrosoft.com                        │
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
│   Related:    northwind-internal.com                                  │
╰───────────────────────────────────────────────────────────────────────╯
```

> The example above is fictional. "Northwind Traders" is a [Microsoft sample company name](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges). All tenant IDs, domains, and service lists shown are fabricated for illustration.

Give it a domain. It queries public endpoints and DNS records — no credentials, no API keys — and returns what it can find: tenant details, email security posture, SaaS fingerprints, and derived signals.

Works for Microsoft 365, Google Workspace, or any provider. Useful if you're an architect, MSP, or partner trying to understand a company before a call or proposal. Also runs as an MCP server for AI tools.

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
recon northwindtraders.com                    # clean default
recon northwindtraders.com --services         # M365 vs tech stack split
recon northwindtraders.com --full             # everything at once
recon northwindtraders.com --md > report.md   # markdown report
recon northwindtraders.com --json             # structured JSON
recon https://www.contoso.com/                # URLs work too (scheme + www stripped)
recon batch domains.txt --json                # batch mode (default 5 concurrent)
recon batch domains.txt --json -c 10          # batch with 10 concurrent lookups
recon doctor                                  # connectivity check
```

> The shorthand `recon northwindtraders.com` is equivalent to `recon lookup northwindtraders.com`.
> This is handled by `run()` in `cli.py` — if you import and call `app()` directly
> as a library, use the explicit `lookup` subcommand.

## Input Handling

The tool normalizes whatever you paste in:

- `northwindtraders.com` → `northwindtraders.com`
- `https://www.northwindtraders.com/about` → `northwindtraders.com`
- `HTTP://NORTHWINDTRADERS.COM` → `northwindtraders.com`
- `  northwindtraders.com  ` → `northwindtraders.com`

Schemes, `www.` prefixes, paths, trailing slashes, and whitespace are all stripped automatically.

## Examples

The `examples/` folder contains sample files:

- `sample-output.json` — Example JSON output (fictional data)
- `sample-batch.txt` — Example batch input file

```bash
recon batch examples/sample-batch.txt --json    # try batch mode with sample domains
```

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
| 140+ SaaS services | TXT, SPF, MX, CNAME, NS, CAA, subdomain TXT (only services that leave DNS footprints) |
| Email gateway detection | Proofpoint, Mimecast, Barracuda, Trend Micro, Symantec, Trellix |
| SASE / ZTNA detection | Zscaler, Netskope, Palo Alto |
| Security tooling | CrowdStrike, SentinelOne, KnowBe4, Wiz, 1Password, etc. |
| Certificate authorities | CAA records (Let's Encrypt, DigiCert, AWS ACM, etc.) |
| License tier hints | Intune + auth type signals E3/E5 |
| Infrastructure and CDN | NS records, CNAME records |
| Signal intelligence | AI adoption, GTM maturity, digital transformation (directional, not definitive) |
| Related domains | Auto-discovered from CNAME breadcrumbs (autodiscover, DKIM) |
| Migration signals | Google + Microsoft coexistence |
| Org size estimate | SPF complexity, tenant domain count (rough heuristic) |

All from public sources. Zero authentication. Results vary — some domains are rich with DNS records, others are sparse.

### Related Domain Auto-Enrichment

When a domain's autodiscover CNAME or DKIM delegation points to a different domain (e.g., `autodiscover.northwindtraders.com` → `autodiscover.northwind-internal.com`), the tool automatically runs DNS fingerprinting on the related domain and merges the results. This means looking up a public-facing brand domain automatically picks up services configured on the organization's internal IT domain.

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

## Limitations

This is passive reconnaissance only. It queries public DNS records and unauthenticated Microsoft/Google endpoints. That means:

- It can only see services that leave DNS footprints (domain verification TXT records, SPF includes, MX entries, etc.). Plenty of SaaS tools don't require DNS records and won't show up.
- Email security scoring is based on what's published in DNS. A score of 5/5 doesn't mean email security is perfect — it means the five specific public signals are present.
- Signal intelligence (AI adoption, org size hints, etc.) is inferred from fingerprint matches. It's directional, not definitive. A company with an OpenAI TXT record is probably evaluating or using it, but you don't know how deeply.
- Microsoft-specific data (tenant ID, auth type, company name) only works for M365 tenants. Google Workspace domains get DNS fingerprinting but no tenant metadata.
- Related domain enrichment follows one level of CNAME breadcrumbs. It won't map an entire corporate domain tree.
- The fingerprint database (143 services as of v0.1.0) is good but not exhaustive. It grows with contributions.

Treat the output as a starting point for conversation, not a complete picture.

## Roadmap

Ideas under consideration. The guiding principle: stay passive, stay zero-creds, stay focused on signal intelligence, and be a great tool for both humans and AI agents. If it needs a paid API key or a database, it doesn't belong here.

### Deepen the intelligence

- Custom signals YAML (`~/.recon/signals.yaml`) — same extensibility model as fingerprints, so you can encode your own signal rules without code changes
- Certificate transparency lookups (crt.sh) — additional passive source for subdomain discovery and certificate history, still zero-creds
- Expanded org-size and maturity heuristics — better bucketing (SMB / mid-market / enterprise) from SPF complexity, domain count, and service mix
- Smarter CNAME/DKIM following — deeper passive subdomain discovery from public records without active scanning
- Migration and risk signal refinement — detect patterns like recent Google → M365 shifts, legacy auth exposure, or security posture gaps that suggest conversation starters

### Better output

- `--html` output — self-contained single-file report for sharing in email or proposals
- Delta / change reports — compare current scan to a previous `--json` export and surface what changed
- `recon doctor --fix` — auto-scaffold `~/.recon/fingerprints.yaml` and `signals.yaml` templates with inline comments

### Agent-friendly by default

The MCP server already works and follows good practices (outcome-oriented tools, caching, rate limiting, structured logging). The next step is making recon a first-class citizen across the AI agent ecosystem:

- CLAUDE.md / Kiro steering / agent context files — ship ready-made project context files so AI coding tools (Claude Code, Kiro, Cursor, etc.) immediately understand how to use recon. A `CLAUDE.md` tells Claude Code what the tool does and how to call it. A `.kiro/steering/` file does the same for Kiro. These are just markdown files in the repo — zero cost, high value.
- llms.txt — when recon has a docs site or PyPI page, publish an `llms.txt` at the root so AI crawlers and agents can discover what the tool does without parsing HTML.
- Structured output contracts — stable, versioned JSON schema for `--json` output so agents can rely on the shape without breaking when new fields are added. Treat `--json` like an API contract with semver guarantees.
- Richer MCP toolset — `compare_tenants(domain_a, domain_b)` that returns a structured diff, `suggest_security_wins(domain)` that highlights the lowest-hanging email security improvements. Keep tools outcome-oriented (one call, one useful answer) per [MCP best practices](https://www.philschmid.de/mcp-best-practices).
- A2A Agent Card — publish a `/.well-known/agent.json` so recon can participate in multi-agent workflows via Google's [Agent-to-Agent protocol](https://github.com/google/A2A). An orchestrator agent could discover recon, delegate a domain lookup, and pass the structured result to a proposal-writing agent or CRM-update agent. recon stays focused on intelligence; downstream agents handle actions.
- Batch-friendly streaming — for large domain lists, emit results as they complete (JSONL / newline-delimited JSON) so agents and pipelines can process incrementally instead of waiting for the entire batch.
- OpenClaw / open agent compatibility — as self-hosted AI agent platforms (OpenClaw, etc.) mature, ensure recon's MCP server works cleanly as a tool provider in those ecosystems. This mostly means staying standards-compliant and keeping the tool interface simple.

### Scale and distribution

- PyPI publish — `pip install recon-tool` instead of clone + editable install
- Docker image — for pipelines, CI/CD, and air-gapped environments
- Community fingerprint contribution flow — automated validation on PR, optional `recon update-fingerprints` to pull latest

### Not planned

These come up but don't fit the tool's identity:

- Paid API integrations (Shodan, BuiltWith, Clearbit, etc.) — the zero-creds constraint is a feature, not a limitation. Adding paid sources changes who can use the tool and adds key management complexity. If you need enrichment beyond public DNS, pipe the `--json` output into whatever paid tool you already have.
- Web dashboard / `recon serve` — this is a CLI tool and MCP server. A web UI is a different product with different maintenance costs. The `--html` export covers the "share a pretty report" use case without running a server.
- Local database / history store — adds state management, migration concerns, and disk usage tracking to what's currently a stateless tool. Save your `--json` output to files if you want history. Your filesystem is the database.
- AI-generated pitch text / natural language copilot — the tool's job is to surface signal intelligence, not to write your emails. Feed the `--json` output to an LLM and prompt it yourself. Baking generation into the CLI couples it to a model provider and adds a dependency that will break. This is exactly what the MCP server and A2A support are for — let a downstream agent handle the prose.
- Interactive REPL mode — the CLI flags already cover every query type. For live exploration, use the MCP server inside an AI tool — that's literally what it's for.

## Development

```bash
pip install -e ".[dev]"

pytest tests/                          # run tests (integration tests skipped by default)
pytest tests/ --cov=recon_tool         # with coverage
pytest tests/ -m integration           # integration tests only (requires network)
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## Legal

### Disclaimer

This tool queries publicly available DNS records and unauthenticated HTTP endpoints (Microsoft OIDC discovery, GetUserRealm, Google Workspace). It does not attempt to authenticate, exploit vulnerabilities, bypass access controls, or access any non-public data.

The information returned is the same information available to anyone running `dig`, `nslookup`, or visiting the same public endpoints in a browser. No credentials, API keys, or special access are used or required.

This tool is intended for legitimate purposes such as:

- Pre-sales research and proposal preparation
- IT architecture assessment and planning
- Email security posture review
- Vendor and partner due diligence

You are responsible for ensuring your use of this tool complies with all applicable laws, regulations, and terms of service in your jurisdiction. The authors are not responsible for how this tool is used.

This tool is not designed for, and should not be used for, unauthorized access, competitive intelligence gathering that violates applicable law, harassment, or any purpose that would violate the terms of service of the queried endpoints.

### Accuracy

Output is derived from public DNS records and unauthenticated endpoints. It may be incomplete, outdated, or incorrect. Do not make business decisions based solely on this tool's output without independent verification.

### Fictional Examples

All company names, tenant IDs, and domains used in this README, the `examples/` folder, and test fixtures are fictional. They use [Microsoft's standard sample company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Northwind Traders, Contoso, Fabrikam, etc.) or clearly fabricated identifiers. Any resemblance to real organizations is coincidental.

### Third-Party Services

This tool queries endpoints operated by Microsoft, Google, and public DNS infrastructure. It is not affiliated with, endorsed by, or sponsored by any of these companies. Product names mentioned in fingerprint definitions are trademarks of their respective owners.

## License

MIT — see [LICENSE](LICENSE) for details.
