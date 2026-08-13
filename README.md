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

## Quick Start

Install with `uv` or `pipx`:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

Python 3.11 through 3.14, on Windows, macOS, or Linux.

Optional helpers at `scripts/install.ps1` and `scripts/install.sh` drive an
existing `uv` or `pipx` installation. Download a
[release-tag source archive](https://github.com/blisspixel/recon/releases/latest),
review the helper locally, then run it. Each helper installs the exact version
represented by that tag, preserves a sole existing `uv` or `pipx` owner, and
refuses ambiguous or unmanaged installations. Do not pipe mutable branch
content into a shell. To verify published artifacts before installing, follow the
[consumer verification recipe](https://github.com/blisspixel/recon/blob/main/docs/supply-chain.md#consumer-verification-quick-path).

Verify the installed command offline:

```bash
recon --version
```

Then optionally test online connectivity to recon's public data sources:

```bash
recon doctor
```

Before the first lookup, know what leaves your machine. recon makes DNS queries
that recursive and authoritative DNS infrastructure may observe. Its only
default request to a target-owned endpoint is the standards-defined MTA-STS
policy fetch. Google CSE and BIMI certificate probes run only when
`--direct-probes` is explicitly enabled. Readable overview:
[docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md).
Formal correlation model (layers, Bayesian DAG, robustness research):
[docs/correlation.md](https://github.com/blisspixel/recon/blob/main/docs/correlation.md).

```bash
recon example.com
```

### Example output

![Synthetic terminal showing recon's default output](https://raw.githubusercontent.com/blisspixel/recon/main/docs/assets/terminal-demo.svg)

This is a deterministic, no-network fixture for the fictional Example Industries Ltd using reserved `example.com`. No real organization is depicted. Other project fixtures use IETF reserved `.invalid` namespaces.

<!-- terminal-demo-transcript:start -->
<details>
<summary>Accessible text transcript</summary>

```text
$ recon example.com
Example Industries Ltd
example.com
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 + Proofpoint gateway
  Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890 • NA
  Tenant domain example-industries.onmicrosoft.example.com
  Auth         Federated
  Confidence   ●●● High (4 sources)


Services
  Email            Microsoft 365, Proofpoint, DMARC reject, DKIM,
                   SPF strict, MTA-STS enforce
  Identity         Okta
  Cloud            Cloudflare (CDN/edge), AWS Route 53 (DNS)
  Security         Wiz Security
  Data & Analytics Snowflake, Datadog
  Collaboration    Slack, Atlassian (Jira/Confluence), GitHub, Zoom
                   Evidence roles: --explain


High-signal related domains
  login.example.com, status.example.com, support.example.com

Insights
  Federated identity observed; identity-vendor indicators: Okta
  Email security: observed controls: DMARC reject, DKIM, SPF strict, MTA-STS

```

</details>
<!-- terminal-demo-transcript:end -->

Install, update, uninstall, and first-run detail:
[docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md).

## What recon Is Good For

| Need | Use recon for | Use something else when |
|---|---|---|
| Fast external stack context | Passive DNS, identity-endpoint, CT, SaaS, and posture indicators | You need authenticated tenant inventory or asset-management truth |
| Defensive review or vendor diligence | Hedged observations and evidence traces you can verify | You need vulnerability scanning, exploit checks, or host-level facts |
| Automation-friendly output | Stable JSON, batch mode, delta mode, and local MCP tools | You need dashboards, scheduling, or report generation built in |

recon reports observations, not verdicts. Public channel ceiling:
[docs/limitations.md](https://github.com/blisspixel/recon/blob/main/docs/limitations.md).

## Common Commands

```bash
recon example.com                              # default panel
recon example.com --explain                    # evidence trail
recon example.com --plain                      # linear text for screen readers and grep
recon example.com --json                       # structured record
recon batch domains.txt --json                 # batch JSON array
recon delta example.com                        # diff vs local cache
recon capsule capture example.com -o run.json  # caller-owned replay artifact
recon mcp install --client=cursor              # wire MCP into a client
```

More flags:
[docs/cli-surface.md](https://github.com/blisspixel/recon/blob/main/docs/cli-surface.md).
JSON contracts:
[schema](https://github.com/blisspixel/recon/blob/main/docs/schema.md) ·
[stability](https://github.com/blisspixel/recon/blob/main/docs/stability.md) ·
[operational contract](https://github.com/blisspixel/recon/blob/main/docs/operational-contract.md).

Versioned JSON remains recon's structured runtime contract. The
[Open Knowledge Format v0.2](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)
projection is deferred until a named consumer justifies the mapping. recon does
not emit OKF, and any future OKF view would be additive rather than a replacement
for JSON. Caller-owned JSON observation capsules are documented in
[docs/observation-capsules.md](https://github.com/blisspixel/recon/blob/main/docs/observation-capsules.md),
with the decision boundary in
[ADR-0014](https://github.com/blisspixel/recon/blob/main/docs/adr/0014-caller-owned-capsules-and-okf-deferral.md).

`docs/surface-inventory.json`, `docs/cli-surface.md`, and
`recon://surface-inventory` are generated discovery context and drift guards,
not stable runtime API contracts. ADR-0007 records the promotion gate.

## Use with an AI agent (plugin / MCP / skill)

Wire recon into Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Kiro,
or any MCP-compatible client:

```bash
recon mcp install --client=claude-desktop
# also: claude-code, cursor, vscode, windsurf, kiro
recon mcp doctor
```

Start with manual tool approvals. Treat agents as untrusted input.
Full setup:
[docs/mcp.md](https://github.com/blisspixel/recon/blob/main/docs/mcp.md).
Per-client scaffolds and skills:
[agents/](https://github.com/blisspixel/recon/tree/main/agents).

The current scaffolds use each client's native configuration. In particular,
the bundled Claude Code plugin uses Claude Code's client-specific layout; it
does not claim conformance with the portable
[Agent Plugins v1.0.0 working draft](https://agent-plugins.org/specification).
A schema-pinned portable package is tracked in the roadmap. Until it is
validated across representative clients, use the documented client-specific
install path above.

| You say | What the agent should do |
|---|---|
| "Recon example.com" | Call `lookup_tenant` (or `recon example.com`) and return the panel-style summary |
| "What does example.com run for email and identity?" | Same lookup; lead with MX/IdP/tenant facts and confidence |
| "Why do you think that?" | Re-run with explain / provenance (`--explain` or `explain=true`) |
| "Compare example.com and example.net" | `compare_postures` or two lookups side by side |
| "Any public hardening gaps?" | `find_hardening_gaps` after a lookup - hedged "Consider" notes only |

**Example chat (Example Industries demo shape):**

> **You:** Recon example.com and tell me what you observe.
>
> **Agent:** Public evidence for `example.com` (fictional demo):
> - **Mail:** Microsoft 365 delivery path plus Proofpoint gateway; DMARC
>   `p=reject`, SPF strict, MTA-STS enforce.
> - **Identity:** Federated; Okta indicator via CNAME.
> - **Tenant:** GUID present, region NA; confidence high from four sources.
> - **Also seen:** Cloudflare and Route 53 infrastructure, Wiz, Snowflake,
>   Datadog, Slack, Atlassian, GitHub, and Zoom public indicators.
>
> These are public-record observations, not a security grade or proof of
> active product use. Say if you want evidence detail or a gap review.

Guidance:
[agents/claude-code/skills/recon/](https://github.com/blisspixel/recon/tree/main/agents/claude-code/skills/recon/),
[AGENTS.md](https://github.com/blisspixel/recon/blob/main/AGENTS.md).

## Optional Cloud Access

Local execution is the default, and the project does not operate a hosted
service. For teams that want shared remote access, the repository includes a
draft authenticated container and Cloud Run Terraform starting point. It is
intended to be directionally useful, not a validated production deployment.
Operators own deployment, identity, data handling, cost, and operations.

- [Optional cloud plan](https://github.com/blisspixel/recon/blob/main/docs/optional-cloud-deployment-plan.md)
- [Draft deployment framework](https://github.com/blisspixel/recon/tree/main/deploy)

## Docs

| Topic | Link |
|---|---|
| Install and first commands | [docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md) |
| How it works | [docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md) |
| Observation capsules | [docs/observation-capsules.md](https://github.com/blisspixel/recon/blob/main/docs/observation-capsules.md) |
| Correlation model | [docs/correlation.md](https://github.com/blisspixel/recon/blob/main/docs/correlation.md) |
| MCP and agents | [docs/mcp.md](https://github.com/blisspixel/recon/blob/main/docs/mcp.md), [agents/](https://github.com/blisspixel/recon/tree/main/agents) |
| Full docs index | [docs/README.md](https://github.com/blisspixel/recon/blob/main/docs/README.md) |
| Roadmap | [ROADMAP.md](https://github.com/blisspixel/recon/blob/main/ROADMAP.md) · [docs/roadmap.md](https://github.com/blisspixel/recon/blob/main/docs/roadmap.md) · [docs/strategic-gap-audit.md](https://github.com/blisspixel/recon/blob/main/docs/strategic-gap-audit.md) |
| Changelog | [CHANGELOG.md](https://github.com/blisspixel/recon/blob/main/CHANGELOG.md) |
| Security | [SECURITY.md](https://github.com/blisspixel/recon/blob/main/SECURITY.md) · [docs/security.md](https://github.com/blisspixel/recon/blob/main/docs/security.md) |

Research and publication pointers (maintainer track, not the product core):
[docs/submission-freeze-checklist.md](https://github.com/blisspixel/recon/blob/main/docs/submission-freeze-checklist.md),
[validation/2026-06-30-submission-freeze-local-proof.md](https://github.com/blisspixel/recon/blob/main/validation/2026-06-30-submission-freeze-local-proof.md),
[docs/public-label-snapshot-decision.md](https://github.com/blisspixel/recon/blob/main/docs/public-label-snapshot-decision.md)
(public lists as robustness checks rather than population rates), and
[docs/m365-tenancy-decision.md](https://github.com/blisspixel/recon/blob/main/docs/m365-tenancy-decision.md).

## Development

```bash
uv sync
uv run pre-commit install
uv run python scripts/release_readiness.py --allow-dirty
uv run python scripts/check.py
```

`uv run python scripts/check.py` is the canonical local gate: lint, type
checks, coverage-gated tests, generated-artifact and catalog checks, text and
link hygiene, interface and claim checks, and size and complexity ratchets.
Green locally means green in CI.

Project hygiene: keep examples reserved and synthetic, keep validation artifacts
aggregate-only, and avoid dead code or placeholders. See
[CONTRIBUTING.md](https://github.com/blisspixel/recon/blob/main/CONTRIBUTING.md).

## License

Apache 2.0. Free to use, build on, fork, and share. See
[LICENSE](https://github.com/blisspixel/recon/blob/main/LICENSE) for
the full terms.
