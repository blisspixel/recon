# recon

Passive infrastructure intelligence for humans and agents. Turns public DNS, identity endpoints, and certificate transparency into structured organizational intelligence — no credentials, no API keys, no interaction with target systems.

```bash
recon contoso.com
```

```
╭──────────────────────────── Contoso Ltd ─────────────────────────────╮
│                                                                      │
│  Company:    Contoso Ltd                                             │
│  Domain:     contoso.onmicrosoft.com                                 │
│  Provider:   Microsoft 365 + Google Workspace                        │
│  Tenant ID:  a1b2c3d4-e5f6-7890-abcd-ef1234567890                    │
│  Region:     NA                                                      │
│  Auth:       Managed                                                 │
│  GWS Auth:   Managed                                                 │
│  Confidence: ●●● High (4 sources)                                    │
│  Services:   AWS CloudFront, AWS Elastic Load Balancer,              │
│              DKIM (Exchange Online), Google (site verified),         │
│              Google Workspace, Imperva (Incapsula), Microsoft 365,   │
│              Okta, Salesforce Marketing Cloud                        │
│                                                                      │
│  Insights:   Cloud-managed identity indicators (Entra ID native)     │
│              Google Workspace: Managed identity (Google-native)      │
│              Email security 2/5 moderate (DMARC reject, DKIM)        │
│              Dual provider: Google + Microsoft coexistence           │
│              Security stack: Okta (identity), Imperva (WAF)          │
│              Enterprise Security Stack: okta, imperva                │
│              Multi-Cloud: aws-cloudfront, aws-elb                    │
│              Dual Email Provider: microsoft365, google-workspace     │
│              Google-Native Identity: google-workspace, google-site,  │
│              google-managed                                          │
│                                                                      │
│  Certs:      280 total, 10 in last 90d, 3 issuers (DigiCert,        │
│              Entrust, Sectigo)                                       │
│                                                                      │
│  Related:    api.contoso.com, cdn.contoso.com, dev.contoso.com,      │
│              shop.contoso.com, staging.contoso.com                   │
│                                                                      │
╰──────────────────────────────────────────────────────────────────────╯
```

> This example is based on the structure and density of a real Fortune 500 lookup, with all identifying details replaced using [Microsoft's standard fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Contoso, Northwind Traders, Fabrikam, etc.). Tenant IDs, domains, and service lists are fabricated. No real company is depicted.

Give it a domain. No credentials, no API keys, no interaction with the target's servers. recon queries public DNS, identity endpoints, and certificate transparency logs — the signals every organization must emit for email, SaaS, and cloud infrastructure to function — and assembles them into a coherent picture of the organization's technology posture.

Each signal alone is unremarkable: a TXT record here, a CNAME delegation there, a certificate issuer pattern in the CT logs. The art is in the correlation. recon reads these scattered, public signals across orthogonal sources (OIDC discovery, GetUserRealm, Google identity routing, DNS fingerprints, certificate transparency) and synthesizes them into structured intelligence — tenant details, email security posture, SaaS fingerprints, derived signals, hardening gaps, and posture scores. The target never knows they were observed.

Works for Microsoft 365, Google Workspace, or any provider. Useful for anyone who needs domain intelligence — architects, MSPs, security professionals, defenders, sales engineers, researchers. Also runs as an [MCP server](docs/mcp.md) for AI agents.

## Why recon?

| | recon | dig / nslookup | whatweb | dnsrecon | cloud_enum | Paid tools |
|---|---|---|---|---|---|---|
| Zero credentials | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| M365 tenant detection | ✓ | ✗ | ✗ | ✗ | partial | varies |
| Google Workspace detection | ✓ | ✗ | ✗ | ✗ | ✗ | varies |
| Email security scoring | ✓ | ✗ | ✗ | ✗ | ✗ | varies |
| SaaS fingerprinting (187) | ✓ | ✗ | partial | ✗ | ✗ | ✓ |
| Signal intelligence | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Certificate intelligence | ✓ | ✗ | ✗ | ✗ | ✗ | varies |
| Posture analysis | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Security posture scoring | ✓ | ✗ | ✗ | ✗ | ✗ | varies |
| Delta / change detection | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Recursive domain chaining | ✓ | ✗ | ✗ | partial | ✗ | varies |
| MCP server for AI agents | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Extensible (custom YAML) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

recon reads the organizational metadata layer — DNS records, identity endpoints, and certificate transparency logs that companies publish to make their email, SaaS, and security infrastructure work. It doesn't scrape websites, probe servers, or analyze page content. It turns infrastructure signals into business intelligence.

## Install

Requires Python 3.10+.

```bash
pip install recon-tool                    # from PyPI
pip install -e .                          # or from source
recon doctor                              # verify connectivity
```

## Usage

```bash
recon northwindtraders.com                # default panel output
recon northwindtraders.com --json         # structured JSON
recon northwindtraders.com --md           # markdown report
recon northwindtraders.com --full         # everything (services + domains + posture)
recon northwindtraders.com --services     # M365 vs GWS vs tech stack split
recon northwindtraders.com --posture      # neutral posture observations
recon northwindtraders.com --compare prev.json  # delta: what changed since last run
recon northwindtraders.com --chain --depth 2    # recursive domain discovery
recon northwindtraders.com --no-cache     # bypass disk cache
recon northwindtraders.com --exposure     # security posture assessment
recon northwindtraders.com --gaps         # hardening gap analysis
recon batch domains.txt --json            # batch mode (default 5 concurrent)
recon batch domains.txt --csv             # batch CSV for spreadsheets
recon batch domains.txt --json -c 10      # batch with 10 concurrent
recon doctor                              # connectivity check
recon doctor --fix                        # scaffold custom config templates
recon mcp                                 # start MCP server (stdio)
```

Input is normalized automatically — URLs, schemes, `www.` prefixes, paths, and whitespace are all stripped.

## What You Get

| Signal | Source |
|--------|--------|
| Company name, tenant ID, auth type | Microsoft OIDC + GetUserRealm |
| Google Workspace auth type, modules, corporate identity | Google login flow + CNAME probing + BIMI VMC |
| Email provider | MX records |
| Email security score (0–5) | DMARC + DKIM + SPF + MTA-STS + BIMI |
| 187 SaaS services | TXT, SPF, MX, CNAME, NS, CAA, SRV, DKIM selectors |
| Email gateway / SASE / security stack | DNS fingerprints |
| Signal intelligence (29 signals) | Metadata-aware YAML rules with cross-reference conditions |
| Certificate intelligence | crt.sh metadata: issuance velocity, issuer diversity, cert age |
| Posture observations | Neutral factual analysis across email, identity, infrastructure |
| Related domains | CNAME breadcrumbs + certificate transparency (crt.sh) |
| Delta / change detection | Compare current vs. previous JSON export |
| Evidence traceability | Per-detection source records with dual confidence scoring |
| Security posture assessment | Exposure scoring, hardening gaps, comparative analysis (MCP + CLI) |

All from public sources. Zero authentication. Results vary by domain.

## MCP Server

recon runs as an MCP server for Claude, Cursor, VS Code, Kiro, ChatGPT, or any MCP client:

```json
{
  "mcpServers": {
    "recon": {
      "command": "recon",
      "args": ["mcp"],
      "autoApprove": ["lookup_tenant", "analyze_posture"]
    }
  }
}
```

Then ask your AI: "Run a recon lookup on northwindtraders.com and analyze the posture."

Available MCP tools: `lookup_tenant`, `analyze_posture`, `assess_exposure`, `find_hardening_gaps`, `compare_postures`, `chain_lookup`, `reload_data`.

See [docs/mcp.md](docs/mcp.md) for setup details, available tools, and config file locations per client.

## Documentation

| Doc | Contents |
|-----|----------|
| [Fingerprints](docs/fingerprints.md) | Detection types, custom fingerprints, email security scoring, related domain enrichment |
| [Signals](docs/signals.md) | 4-layer signal intelligence, 29 signal rules, metadata conditions, custom signals |
| [MCP Server](docs/mcp.md) | AI agent integration setup, tools, config locations |
| [Roadmap](docs/roadmap.md) | What's planned, what's not, and why |
| [Legal](docs/legal.md) | Disclaimer, accuracy, fictional examples, third-party notice |
| [Contributing](CONTRIBUTING.md) | How to add fingerprints, signals, and code |
| [Changelog](CHANGELOG.md) | Version history |

## Development

```bash
pip install -e ".[dev]"
pytest tests/                          # 660 tests
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## License

MIT — see [LICENSE](LICENSE) for details.

This tool queries only public DNS records and unauthenticated endpoints. See [docs/legal.md](docs/legal.md) for full disclaimer.
