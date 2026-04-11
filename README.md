# recon

Passive domain intelligence from public DNS and Microsoft/Google endpoints.

```bash
recon northwindtraders.com
```

```
╭──────────────────────── Northwind Traders ───────────────────────╮
│                                                                  │
│  Company:    Northwind Traders                                   │
│  Domain:     northwindtraders.onmicrosoft.com                    │
│  Provider:   Microsoft 365                                       │
│  Tenant ID:  a1b2c3d4-e5f6-7890-abcd-ef1234567890                │
│  Region:     NA                                                  │
│  Auth:       Federated                                           │
│  Confidence: ●●● High (3 sources)                                │
│  Services:   Anthropic (Claude), Atlassian (Jira/Confluence),    │
│              DocuSign, Exchange Autodiscover, Figma,             │
│              Intune / MDM, KnowBe4, Microsoft 365,               │
│              Microsoft Teams, Miro, Salesforce, Slack, Zendesk   │
│                                                                  │
│  Insights:   Federated identity indicators observed (likely Okta)│
│              Email security 4/5 strong (DMARC reject, DKIM,      │
│              SPF strict)                                         │
│              Email gateway: Proofpoint in front of Exchange      │
│              M365 E3/E5 indicators (Intune + federated auth)     │
│              Security stack: KnowBe4 (training), Okta (identity) │
│              AI Adoption: anthropic                              │
│              Modern Collaboration: slack, miro, atlassian, figma │
│                                                                  │
│  Related:    northwind-internal.com                              │
│                                                                  │
╰──────────────────────────────────────────────────────────────────╯
```

> The example above is fictional. All tenant IDs, domains, and service lists are fabricated for illustration.

Give it a domain. It queries public endpoints and DNS records — no credentials, no API keys — and returns what it can find: tenant details, email security posture, SaaS fingerprints, derived signals, certificate intelligence, and neutral posture observations.

Works for Microsoft 365, Google Workspace, or any provider. Useful for anyone who needs domain intelligence — architects, MSPs, security professionals, red teamers, defenders, sales engineers, researchers. Also runs as an [MCP server](docs/mcp.md) for AI tools.

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
recon northwindtraders.com --html         # self-contained HTML report
recon northwindtraders.com --full         # everything (services + domains + posture)
recon northwindtraders.com --services     # M365 vs GWS vs tech stack split
recon northwindtraders.com --posture      # neutral posture observations
recon northwindtraders.com --compare prev.json  # delta: what changed since last run
recon northwindtraders.com --chain --depth 2    # recursive domain discovery
recon northwindtraders.com --no-cache     # bypass disk cache
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

Available MCP tools: `lookup_tenant`, `analyze_posture`, `chain_lookup`, `reload_data`.

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
pytest tests/                          # 597 tests
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## License

MIT — see [LICENSE](LICENSE) for details.

This tool queries only public DNS records and unauthenticated endpoints. See [docs/legal.md](docs/legal.md) for full disclaimer.
