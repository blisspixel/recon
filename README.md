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
tools. About ten seconds per domain.

> **Defensive use only.** Posture review, vendor diligence, architecture
> review. See
> [docs/legal.md](https://github.com/blisspixel/recon/blob/main/docs/legal.md).

## Quick Start

Install and check the version offline:

```bash
uv tool install recon-tool    # or: pipx install recon-tool
recon --version               # offline check
```

Python 3.11 through 3.14, on Windows, macOS, or Linux. `recon doctor` tests
online connectivity to recon's public data sources.

Optional install helpers at `scripts/install.ps1` and `scripts/install.sh` drive
an existing `uv` or `pipx` installation. Download a
[release-tag source archive](https://github.com/blisspixel/recon/releases/latest),
review the helper locally, then run it: each installs the exact version
represented by that tag, preserves a sole existing owner, and refuses ambiguous
or unmanaged installations. Do not pipe mutable branch content into a shell. To
verify published artifacts first, follow the
[consumer verification recipe](https://github.com/blisspixel/recon/blob/main/docs/supply-chain.md#consumer-verification-quick-path).

Before the first lookup, know what leaves your machine. recon makes DNS queries
that recursive and authoritative DNS infrastructure may observe. Its only
default request to a target-owned endpoint is the standards-defined MTA-STS
policy fetch; Google CSE and BIMI certificate probes run only when
`--direct-probes` is explicitly enabled. See
[ADR-0011](https://github.com/blisspixel/recon/blob/main/docs/adr/0011-public-metadata-collection-boundary.md).

```bash
recon example.com
```

Every lookup is live. recon ships no offline demo mode, so reserved names such
as `example.com` return a panel of stray public residue from unrelated test
configurations, including a meaningless display name, at High confidence. It
shows you the shape of the output, not a result about any organization. Point
recon at a domain you operate or are authorized to review to see a real
footprint.

A domain is a query coordinate, not proof of one organization or product: recon
reports observations, not verdicts. That is the caution to keep beside every row
the panel shows.

### Illustrated output (synthetic, not a captured run)

![Synthetic terminal showing recon's default output](https://raw.githubusercontent.com/blisspixel/recon/main/docs/assets/terminal-demo.svg)

The panel above is **generated, not captured**:
[`scripts/generate_terminal_demo.py`](https://github.com/blisspixel/recon/blob/main/scripts/generate_terminal_demo.py)
drives recon's real formatter over a deterministic, no-network fixture for the
fictional Example Industries Ltd. It shows the *shape* of a full-signal
result, every row a rich target can fill, and no live lookup of reserved
`example.com` reproduces it. No real organization is depicted. Other project
fixtures use IETF reserved `.invalid` namespaces.

<!-- terminal-demo-transcript:start -->
<details>
<summary>Accessible text transcript</summary>

```text
$ recon example.com    # synthetic fixture, not a captured run
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
How to report a result without overstating it:
[docs/reporting-observations.md](https://github.com/blisspixel/recon/blob/main/docs/reporting-observations.md).

v2.15 and v2.16 closed a five-round presentation-drift class. Independent
testers installed the published package, never read the source, and kept finding
the same issue: a decision applied to one renderer and not the others. The
engine is feature-complete. Those findings and their fixes are in
[CHANGELOG.md](https://github.com/blisspixel/recon/blob/main/CHANGELOG.md) and in
[ADR-0015](https://github.com/blisspixel/recon/blob/main/docs/adr/0015-role-split-vendor-claims-in-the-default-view.md)
through
[ADR-0017](https://github.com/blisspixel/recon/blob/main/docs/adr/0017-one-briefing-in-every-shape.md).

The living work is the fingerprint catalog. Vendors add, rename, and retire the
public patterns recon detects, so a rule with no re-check is a slow source of
false positives and negatives. Most useful contributions are one YAML file, not
code: a current vendor-documentation page (or a disclosure-safe aggregate
basis), a `verified` date, a fictional positive, and a lookalike negative.
[CONTRIBUTING.md](https://github.com/blisspixel/recon/blob/main/CONTRIBUTING.md)
has the schema, the validation command, and what is deliberately out of scope.
The freshness loop and its coverage floor live in
[docs/catalog-strategy.md](https://github.com/blisspixel/recon/blob/main/docs/catalog-strategy.md).

## Common Commands

```bash
recon example.com                              # default panel
recon example.com --explain                    # evidence trail
recon example.com --gaps                       # neutral hardening prompts
recon example.com --plain                      # panel as linear text (screen readers, grep)
recon example.com --plain --full               # every field, linear
recon example.com --json                       # structured record
recon example.com --explain-dag --explain-dag-format mermaid   # evidence DAG
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
A complete-surface portable candidate now lives under
[`agents/agent-plugin/`](https://github.com/blisspixel/recon/tree/main/agents/agent-plugin)
and passes network-free validation against the exact pinned v1.0.0 schemas.
That is not a compatibility or conformance claim. Until the frozen VS Code,
Cursor, and Kiro evaluation passes, use the documented client-specific install
path above.

| You say | What the agent should do |
|---|---|
| "Recon example.com" | Call `lookup_tenant` (or `recon example.com`) and return the panel-style summary |
| "What does example.com run for email and identity?" | Same lookup; lead with MX/IdP/tenant facts and confidence |
| "Why do you think that?" | Re-run with explain / provenance (`--explain` or `explain=true`) |
| "Compare example.com and example.net" | `compare_postures` or two lookups side by side |
| "Any public hardening gaps?" | `find_hardening_gaps` after a lookup - hedged "Consider" notes only |

**Example chat.** This transcript uses the same synthetic Example Industries
fixture as the illustration above, so it shows the shape of a full-signal
answer rather than what a live `example.com` lookup returns:

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
| Glossary of recon's terms | [docs/glossary.md](https://github.com/blisspixel/recon/blob/main/docs/glossary.md) |
| Install and first commands | [docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md) |
| Reporting a result without overstating it | [docs/reporting-observations.md](https://github.com/blisspixel/recon/blob/main/docs/reporting-observations.md) |
| How it works | [docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md) |
| Known weak areas and conservative wording | [docs/weak-areas.md](https://github.com/blisspixel/recon/blob/main/docs/weak-areas.md) |
| Catalog growth and freshness loop | [docs/catalog-strategy.md](https://github.com/blisspixel/recon/blob/main/docs/catalog-strategy.md) |
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
