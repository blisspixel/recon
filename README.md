# recon

[![CI](https://github.com/blisspixel/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/recon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![Python](https://img.shields.io/pypi/pyversions/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![License](https://img.shields.io/pypi/l/recon-tool.svg?cacheSeconds=300)](https://github.com/blisspixel/recon/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blisspixel/recon/badge)](https://scorecard.dev/viewer/?uri=github.com/blisspixel/recon)

Point recon at a domain and get its **public** technology and identity
footprint: email security, mail and identity providers, SaaS indicators, and
certificate-transparency findings. No credentials, no API keys, no active
scanning. Ships as a CLI, versioned JSON, and a local MCP server for agent
tools.

A domain is a query coordinate, not proof of one organization or product.
Observations, not verdicts.

> **Defensive use only.** Posture review, vendor diligence, architecture
> review. See
> [docs/legal.md](https://github.com/blisspixel/recon/blob/main/docs/legal.md).

## Quick start

```bash
uv tool install recon-tool   # or: pipx install recon-tool
recon --version
recon doctor                 # optional online connectivity check
recon example.com
```

Python 3.11-3.14 on Windows, macOS, or Linux. Install helpers, update/uninstall,
and supply-chain verification:
[docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md),
[docs/supply-chain.md](https://github.com/blisspixel/recon/blob/main/docs/supply-chain.md).

Default collection is public metadata only. DNS may be visible to resolvers;
the only default target-owned HTTP request is the standards-defined MTA-STS
policy fetch. Opt-in direct probes and the full network boundary:
[docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md).

### Example output

![Synthetic terminal showing recon's default output](https://raw.githubusercontent.com/blisspixel/recon/main/docs/assets/terminal-demo.svg)

This is a deterministic, no-network fixture for Contoso Ltd using IETF reserved `.invalid` namespaces (`contoso.invalid`). No real organization is depicted.

<!-- terminal-demo-transcript:start -->
<details>
<summary>Accessible text transcript</summary>

```text
$ recon contoso.invalid
Contoso Ltd
contoso.invalid
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (MX delivery path) + Proofpoint gateway (MX
               delivery path)
  Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890 • NA
  Tenant domain contoso.onmicrosoft.invalid
  Auth         Federated
  Confidence   ●●● High (4 sources)


Services
  Email          Microsoft 365 (MX delivery path),
                 Proofpoint (MX delivery path), DMARC reject, DKIM,
                 SPF strict, MTA-STS enforce
  Identity       Okta (CNAME endpoint binding)
  Cloud          Cloudflare (CDN/edge), AWS Route 53 (DNS)
  Security       Wiz Security (public TXT account indicator)
  Collaboration  Slack (public TXT account indicator),
                 Atlassian (Jira/Confluence) (CNAME endpoint binding)


High-signal related domains
  login.contoso.invalid, status.contoso.invalid, support.contoso.invalid

Insights
  Federated identity observed; identity-vendor indicators: Okta
  Email security: observed controls: DMARC reject, DKIM, SPF strict, MTA-STS

```

</details>
<!-- terminal-demo-transcript:end -->

## Use with an AI agent (MCP / skill)

Wire recon into Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Kiro,
or any MCP-compatible client:

```bash
recon mcp install --client=claude-desktop
# also: claude-code, cursor, vscode, windsurf, kiro
recon mcp doctor
```

Start with manual tool approvals. Treat agents as untrusted input.
Full setup and tool catalog:
[docs/mcp.md](https://github.com/blisspixel/recon/blob/main/docs/mcp.md).
Per-client scaffolds and skills:
[agents/](https://github.com/blisspixel/recon/tree/main/agents).

Then ask in natural language, for example:

| You say | What the agent should do |
|---|---|
| "Recon contoso.invalid" | Call `lookup_tenant` (or `recon contoso.invalid`) and return the panel-style summary |
| "What does contoso.invalid run for email and identity?" | Same lookup; lead with MX/IdP/tenant facts and confidence |
| "Why do you think that?" | Re-run with explain / provenance (`--explain` or `explain=true`) |
| "Compare contoso.invalid and fabrikam.invalid" | `compare_postures` or two lookups side by side |
| "Any public hardening gaps?" | `find_hardening_gaps` after a lookup - hedged "Consider" notes only |

**Example chat (Contoso demo shape):**

> **You:** Recon contoso.invalid and tell me what you observe.
>
> **Agent:** Public evidence for `contoso.invalid` (fictional demo):
> - **Mail:** Microsoft 365 delivery path plus Proofpoint gateway; DMARC
>   `p=reject`, SPF strict, MTA-STS enforce.
> - **Identity:** Federated; Okta indicator via CNAME.
> - **Tenant:** GUID present, region NA; confidence high from four sources.
> - **Also seen:** Cloudflare edge, AWS Route 53 DNS, Slack/Atlassian/Wiz
>   public indicators.
>
> These are public-record observations, not a security grade or proof of
> active product use. Say if you want evidence detail or a gap review.

Guidance files for skill-style clients live under
[agents/claude-code/skills/recon/](https://github.com/blisspixel/recon/tree/main/agents/claude-code/skills/recon/)
and root
[AGENTS.md](https://github.com/blisspixel/recon/blob/main/AGENTS.md).

## Common commands

```bash
recon example.com                              # default panel
recon example.com --explain                    # evidence trail
recon example.com --json                       # structured record
recon batch domains.txt --json                 # batch JSON array
recon delta example.com                        # diff vs local cache
recon mcp install --client=cursor              # wire MCP into a client
```

More flags and modes:
[docs/cli-surface.md](https://github.com/blisspixel/recon/blob/main/docs/cli-surface.md),
[docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md).

JSON/automation contracts:
[schema](https://github.com/blisspixel/recon/blob/main/docs/schema.md) ·
[stability](https://github.com/blisspixel/recon/blob/main/docs/stability.md) ·
[operational contract](https://github.com/blisspixel/recon/blob/main/docs/operational-contract.md) ·
[automation examples](https://github.com/blisspixel/recon/blob/main/docs/automation-examples.md).

## When to use it

| Need | recon | Not recon |
|---|---|---|
| External stack / email / identity signals | Yes - passive public metadata | Authenticated inventory or CMDB truth |
| Vendor diligence or defensive review | Yes - hedged, evidence-linked | Vuln scanning, exploits, host facts |
| Agent or pipeline automation | Yes - CLI, JSON, MCP | Hosted SaaS, dashboards, firmographics |

Public channel ceiling (sparse SaaS, gateway-hidden mailboxes, CT limits):
[docs/limitations.md](https://github.com/blisspixel/recon/blob/main/docs/limitations.md).

## Docs

| Topic | Link |
|---|---|
| Install and first commands | [docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md) |
| How it works | [docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md) |
| MCP and agents | [docs/mcp.md](https://github.com/blisspixel/recon/blob/main/docs/mcp.md), [agents/](https://github.com/blisspixel/recon/tree/main/agents) |
| Full docs index | [docs/README.md](https://github.com/blisspixel/recon/blob/main/docs/README.md) |
| Roadmap | [ROADMAP.md](https://github.com/blisspixel/recon/blob/main/ROADMAP.md) · [docs/roadmap.md](https://github.com/blisspixel/recon/blob/main/docs/roadmap.md) |
| Changelog | [CHANGELOG.md](https://github.com/blisspixel/recon/blob/main/CHANGELOG.md) |
| Security reporting | [SECURITY.md](https://github.com/blisspixel/recon/blob/main/SECURITY.md) · [docs/security.md](https://github.com/blisspixel/recon/blob/main/docs/security.md) |
| Optional remote MCP draft | [docs/optional-cloud-deployment-plan.md](https://github.com/blisspixel/recon/blob/main/docs/optional-cloud-deployment-plan.md) |

## Development

```bash
uv sync
uv run pre-commit install
uv run python scripts/release_readiness.py --allow-dirty
uv run python scripts/check.py
```

`python scripts/check.py` is the canonical local gate (lint, types, coverage,
artifacts, hygiene). Green locally means green in CI.

Project hygiene: keep examples reserved and synthetic, keep validation artifacts
aggregate-only, and avoid dead code or placeholders. See
[CONTRIBUTING.md](https://github.com/blisspixel/recon/blob/main/CONTRIBUTING.md).

## License

Apache 2.0. Free to use, build on, fork, and share. See
[LICENSE](https://github.com/blisspixel/recon/blob/main/LICENSE) for
the full terms.
