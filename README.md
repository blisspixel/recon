# recon

Passive domain intelligence from public sources. Queries DNS records, Microsoft/Google identity endpoints, and certificate transparency logs to build a picture of an organization's technology stack — no credentials, no API keys, no active scanning.

> **Defensive use only.** recon is designed for legitimate security posture assessment, IT architecture review, vendor due diligence, and defensive hardening. It performs zero active scanning and zero credentialed access. See [docs/legal.md](docs/legal.md) for the full intended-use policy.

```bash
recon contoso.com
```

```
Contoso Ltd
contoso.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (primary) via Proofpoint gateway + Google Workspace (secondary)
  Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890 • NA
  Auth         Federated (Entra ID + Google Workspace)
  Confidence   ●●● High (4 sources)

Services
  Email          Microsoft 365, Google Workspace, Proofpoint, DMARC, DKIM,
                 SPF: strict (-all), BIMI
  Identity       Okta, Google Workspace (managed identity)
  Cloud          Cloudflare (CDN), AWS Route 53 (DNS)
  Security       Wiz, CAA: 3 issuers restricted
  Collaboration  Slack, Atlassian (Jira/Confluence)

High-signal related domains
  api.contoso.com, login.contoso.com, portal.contoso.com, sso.contoso.com,
  admin.contoso.com, status.contoso.com, support.contoso.com
  (57 total — 50 more, use --full to see all)

Insights
  Federated identity indicators observed (likely Okta — enterprise SSO)
  Email security 4/5 strong (DMARC reject, DKIM, SPF strict, BIMI)
  Email gateway: Proofpoint in front of Exchange
  Dual provider: Google + Microsoft coexistence
```

> Examples use [Microsoft's fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Contoso, Northwind Traders, Fabrikam). Tenant IDs, services, and domains are fabricated. No real company is depicted.

Works for Microsoft 365, Google Workspace, or any provider. Also runs as an [MCP server](docs/mcp.md) for AI agents.

## Install

Requires Python 3.10+.

```bash
pip install recon-tool                 # from PyPI
pip install -U recon-tool              # upgrade an existing install
recon doctor                           # verify connectivity
```

## Usage

```bash
recon contoso.com                              # default panel
recon contoso.com --explain                    # full reasoning + provenance DAG
recon contoso.com --full                       # everything (services + domains + posture)
recon contoso.com --profile fintech            # apply a posture lens (v0.9.3)
recon contoso.com --json                       # structured JSON for piping
recon batch domains.txt --json                 # batch (cross-domain token clustering)
recon mcp                                      # start MCP server (stdio)
```

Built-in profiles: `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`. Custom profiles live in `~/.recon/profiles/*.yaml`.

See [docs/](docs/) for the full CLI reference, fingerprint and signal documentation, and MCP setup.

## MCP Server

recon runs as an MCP server for Claude, Cursor, VS Code, ChatGPT, or any MCP client. The Model Context Protocol lets AI agents call tools like recon directly from your chat.

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

Then ask your AI: *"Run a recon lookup on contoso.com and tell me what's running."*

See [docs/mcp.md](docs/mcp.md) for the full tool list, advanced agentic workflows, and per-client config locations.

## Limitations

- **Coverage depends on public DNS.** Organizations behind heavy proxies, with minimal DNS records, or that don't publish SaaS verification tokens will return sparse results. This is fundamental to passive-only collection. When sources transiently fail, the CLI tells you which one and why so you can retry or accept the partial answer.
- **Heuristic, not ground truth.** The fingerprint database and signal rules are rule-based and solo-maintained. Confident-looking output can still be wrong. Treat results as indicators for investigation, not as definitive assessments. Don't make business decisions based solely on this output.

## Development

```bash
pip install -e ".[dev]"
pytest tests/                          # 1479 tests, 88% coverage
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
```

## License

MIT — see [LICENSE](LICENSE) for details.

This tool queries only public DNS records and unauthenticated endpoints. See [docs/legal.md](docs/legal.md) for full disclaimer.
