# recon

Passive domain intelligence from public sources. Queries DNS records, Microsoft/Google identity endpoints, and certificate transparency logs to build a picture of an organization's technology stack — no credentials, no API keys, no active scanning.

> **Defensive use only.** recon is designed for legitimate security posture assessment, IT architecture review, vendor due diligence, and defensive hardening. It performs zero active scanning and zero credentialed access. See [docs/legal.md](docs/legal.md) for the full intended-use policy.

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
│  Certs:      280 total, 10 in last 90d, 3 issuers (DigiCert,         │
│              Entrust, Sectigo)                                       │
│                                                                      │
│  Related:    api.contoso.com, cdn.contoso.com, dev.contoso.com,      │
│              shop.contoso.com, staging.contoso.com                   │
│                                                                      │
╰──────────────────────────────────────────────────────────────────────╯
```

> This example uses [Microsoft's fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Contoso, Northwind Traders, Fabrikam). Tenant IDs, domains, and service lists are fabricated. No real company is depicted.

Give it a domain. recon queries public DNS, identity endpoints, and certificate transparency logs — the signals organizations emit for email, SaaS, and cloud infrastructure to function — and correlates them into structured output.

```bash
recon northwindtraders.com --explain      # see why each signal fired
```

Works for Microsoft 365, Google Workspace, or any provider. Also runs as an [MCP server](docs/mcp.md) for AI agents.

## What it does

recon collects public signals (DNS TXT/MX/CNAME/NS/SRV/CAA records, Microsoft and Google identity endpoints, certificate transparency logs) and matches them against a set of YAML-defined fingerprint and signal rules. Each signal alone is unremarkable — a TXT record, a CNAME delegation, a certificate pattern. The art is in the correlation. The matching is rule-based, not machine learning, but combining scattered records into a coherent view of what an organization is actually running is where the value comes from.

It's an early-stage project maintained by a solo developer. The fingerprint database covers 206 SaaS services and the signal engine has 41 rules across 4 layers. Coverage and accuracy will vary by domain — organizations with rich public DNS get detailed results; those with minimal records or heavy proxying will produce sparse output. Results should be treated as indicators, not ground truth.

## How it compares

recon occupies a specific niche: it fuses DNS, identity endpoints, and CT logs into correlated output. Most existing tools do one of these well but not the combination.

| | recon | dig / nslookup | dnsrecon | Paid tools |
|---|---|---|---|---|
| Zero credentials | ✓ | ✓ | ✓ | varies |
| M365 / GWS tenant detection | ✓ | ✗ | ✗ | varies |
| Email security scoring | ✓ | ✗ | ✗ | varies |
| SaaS fingerprinting | 206 services | ✗ | ✗ | typically more |
| Signal correlation rules | 41 rules | ✗ | ✗ | varies |
| Certificate intelligence | ✓ | ✗ | ✗ | varies |
| MCP server for AI agents | ✓ | ✗ | ✗ | rare |
| Custom YAML extensibility | ✓ | ✗ | ✗ | varies |

Paid tools (BuiltWith, SecurityTrails, etc.) generally have broader coverage, more data sources, and battle-tested accuracy. recon's advantage is that it's free, requires no accounts, and runs locally.

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
recon northwindtraders.com --explain      # show why each signal fired
recon batch domains.txt --json            # batch mode (default 5 concurrent)
recon batch domains.txt --csv             # batch CSV for spreadsheets
recon batch domains.txt --json -c 10      # batch with 10 concurrent
recon doctor                              # connectivity check
recon doctor --fix                        # scaffold custom config templates
recon mcp                                 # start MCP server (stdio)
```

Input is normalized automatically — URLs, schemes, `www.` prefixes, paths, and whitespace are all stripped.

## What you get

| Signal | Source |
|--------|--------|
| Company name, tenant ID, auth type | Microsoft OIDC + GetUserRealm |
| Google Workspace auth type, modules | Google login flow + CNAME probing + BIMI VMC |
| Email provider | MX records |
| Email security score (0–5) | DMARC + DKIM + SPF + MTA-STS + BIMI |
| 206 SaaS services | TXT, SPF, MX, CNAME, NS, CAA, SRV, DKIM selectors |
| Signal intelligence (41 rules) | YAML-based correlation rules with cross-reference conditions |
| Certificate intelligence | crt.sh + CertSpotter: issuance velocity, issuer diversity |
| Posture observations | Neutral factual analysis across email, identity, infrastructure |
| Related domains | CNAME breadcrumbs + certificate transparency |
| Delta / change detection | Compare current vs. previous JSON export |
| Security posture assessment | Exposure scoring, hardening gaps, comparative analysis |

All from public sources. Zero authentication. Results vary by domain — sparse DNS means sparse output.

## MCP Server

recon runs as an MCP server for Claude, Cursor, VS Code, ChatGPT, or any MCP client:

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

For deeper analysis, try: "Look up contoso.com with explain=true, then assess_exposure and find_hardening_gaps. Simulate hardening with DMARC reject and MTA-STS enforce, and tell me the new posture score."

12 MCP tools available: `lookup_tenant`, `analyze_posture`, `assess_exposure`, `find_hardening_gaps`, `compare_postures`, `chain_lookup`, `reload_data`, `get_fingerprints`, `get_signals`, `explain_signal`, `test_hypothesis`, `simulate_hardening`.

All tools are read-only and idempotent. The agentic tools (`test_hypothesis`, `simulate_hardening`, `explain_signal`) operate on cached data with zero additional network calls.

See [docs/mcp.md](docs/mcp.md) for setup details, available tools, and config file locations per client.

## Documentation

| Doc | Contents |
|-----|----------|
| [Fingerprints](docs/fingerprints.md) | Detection types, custom fingerprints, email security scoring |
| [Signals](docs/signals.md) | Signal rules, layers, metadata conditions, custom signals |
| [MCP Server](docs/mcp.md) | AI agent integration setup, tools, config locations |
| [Roadmap](docs/roadmap.md) | What's planned, what's not, and why |
| [Legal](docs/legal.md) | Disclaimer, accuracy, fictional examples |
| [Contributing](CONTRIBUTING.md) | How to add fingerprints, signals, and code |
| [Changelog](CHANGELOG.md) | Version history |

## Limitations

- **Coverage depends on public DNS.** Organizations behind Cloudflare, with minimal DNS records, or that don't publish SaaS verification tokens will return near-empty results. This is a fundamental constraint of passive-only collection — there's no workaround.
- **Fingerprints will go stale.** SaaS providers rebrand, change DNS patterns, and get acquired. 206 fingerprints maintained by a solo developer will fall behind. Community contributions are the only way this scales.
- **Signal rules are heuristic.** The 41 YAML rules produce useful indicators, not definitive assessments. False positives happen. Missed signals happen. Don't make business decisions based solely on this output.
- **No accuracy benchmarks yet.** There's no published precision/recall data. The tool can produce confident-looking output that's wrong. Treat it as a starting point for investigation, not a source of truth.
- **Early-stage project.** This is a solo developer effort. It works, but it hasn't been battle-tested by a community yet. Expect rough edges and breaking changes.

## Development

```bash
pip install -e ".[dev]"
pytest tests/                          # 958 tests
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## License

MIT — see [LICENSE](LICENSE) for details.

This tool queries only public DNS records and unauthenticated endpoints. See [docs/legal.md](docs/legal.md) for full disclaimer.
