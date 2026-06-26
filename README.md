# recon

[![CI](https://github.com/blisspixel/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/recon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![Python](https://img.shields.io/pypi/pyversions/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![License](https://img.shields.io/pypi/l/recon-tool.svg?cacheSeconds=300)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blisspixel/recon/badge)](https://scorecard.dev/viewer/?uri=github.com/blisspixel/recon)

Passive domain intelligence from public sources. recon reads public DNS,
certificate transparency, and unauthenticated Microsoft and Google identity
discovery endpoints to report what an organization appears to publish about its
identity stack, email posture, SaaS footprint, and related domains.

It uses no credentials, no API keys, no paid feeds, and no active scanning. It
is a local Python CLI, importable library, JSON producer, and stdio MCP server.
It is not a hosted service, scheduler, vulnerability scanner, company research
tool, or firmographic database.

> **Defensive use only.** Use recon for legitimate posture review, IT
> architecture review, vendor diligence, and defensive hardening. See
> [docs/legal.md](docs/legal.md) for the intended-use policy.

## Quick Start

Install or update with the platform script:

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
```

**macOS or Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.sh | bash
```

Open a new terminal and verify the install:

```bash
recon doctor
```

Run a lookup:

```bash
recon contoso.com
```

Example output shape:

```text
Contoso Ltd
contoso.com

Provider     Microsoft 365 via Proofpoint gateway
Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890
Auth         Federated
Confidence   High (4 sources)

Services
  Email       Microsoft 365, Proofpoint, DMARC, DKIM, SPF strict
  Identity    Okta, Entra ID
  Cloud       Cloudflare, AWS Route 53

Insights
  Federated identity indicators observed
  Email security 4/5: DMARC reject, DKIM, SPF strict, BIMI
  Email gateway: Proofpoint in front of Exchange
```

Examples use [Microsoft's fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges).
Tenant IDs, services, and domains in examples are fabricated. No real company is
depicted.

For detailed install, update, uninstall, and first-run workflows, read
[docs/getting-started.md](docs/getting-started.md).

## What recon Is Good For

| Need | Use recon for | Use something else when |
|---|---|---|
| Fast external stack context | Passive DNS, identity-endpoint, CT, SaaS, and posture indicators | You need authenticated tenant inventory or asset-management truth |
| Defensive review or vendor diligence | Hedged observations and evidence traces you can verify | You need vulnerability scanning, exploit checks, or host-level facts |
| Automation-friendly output | Stable JSON, batch mode, delta mode, and local MCP tools | You need dashboards, scheduling, or report generation built in |

recon reports observations, not verdicts. A missing DMARC record is a missing
record. A Microsoft 365 tenant indicator is an observed indicator. The operator
decides what those facts mean in context.

## Common Commands

```bash
recon contoso.com                              # default panel
recon https://www.contoso.com/path             # normalize URL to apex
recon mail.contoso.com                         # reduce sub-host to apex
recon mail.contoso.com --exact                 # keep that literal host
recon contoso.com --explain                    # reasoning and provenance
recon contoso.com --full                       # services, domains, posture
recon contoso.com --json                       # structured lookup record
recon batch domains.txt --json                 # batch JSON array
recon batch domains.txt --ndjson               # one record per line
recon batch domains.txt --summary              # aggregate-only cohort summary
recon delta contoso.com                        # diff against cached snapshot
recon mcp install --client=cursor              # wire MCP into a client
recon mcp doctor                               # live MCP handshake check
```

Built-in posture profiles: `fintech`, `healthcare`, `saas-b2b`,
`high-value-target`, `public-sector`, and `higher-ed`. Custom profiles live in
`~/.recon/profiles/*.yaml`.

Generated command and flag reference:
[docs/cli-surface.md](docs/cli-surface.md).

## How recon Works

recon reads:

- DNS records: MX, TXT, SPF, DMARC, DKIM, BIMI, CNAME, NS, SRV, and CAA.
- Certificate transparency: SAN names, issuers, issuance timing, and bounded
  related-domain hints.
- Identity discovery: unauthenticated Microsoft and Google endpoints.

By default, the only request the queried domain's own servers see is the
standards-based MTA-STS policy fetch at `mta-sts.<domain>`. Google CSE and BIMI
VMC direct probes are opt-in behind `--direct-probes`.

The engine then maps observables to fingerprint slugs, derived signals, graph
motifs, and optional Bayesian posteriors. Sparse public evidence stays sparse:
the result widens uncertainty or lowers confidence instead of inventing a clean
answer.

Long-form explanation: [docs/how-it-works.md](docs/how-it-works.md).
Formal model: [docs/correlation.md](docs/correlation.md).

## JSON and Automation

`recon <domain> --json` emits a stable single-domain lookup object. Batch and
delta modes emit different shapes, so route by mode or by `record_type`.

```bash
recon contoso.com --json
recon batch domains.txt --json
recon batch domains.txt --ndjson
recon delta contoso.com --json
```

Read these before building an integration:

- [docs/schema.md](docs/schema.md): stable JSON contract.
- [docs/recon-schema.json](docs/recon-schema.json): machine-readable schema.
- [docs/automation-examples.md](docs/automation-examples.md): parser examples.
- [docs/operational-contract.md](docs/operational-contract.md): timeouts,
  bounds, exit codes, cache, and partial-result semantics.

`docs/surface-inventory.json`, `docs/cli-surface.md`, and
`recon://surface-inventory` are generated discovery context and drift guards,
not stable runtime API contracts. ADR-0007 records the promotion gate for any
future stable subset.

## MCP Server

The default install includes a local stdio MCP server for MCP-compatible tools.
Start with manual approvals and an empty `autoApprove` list. Treat connected
agents as untrusted input.

```bash
recon mcp install --client=claude-desktop
recon mcp install --client=cursor --dry-run
recon mcp doctor
```

The installer writes the right per-client config shape and preserves sibling
MCP servers. Full setup, tool list, read-only versus stateful guidance, and
troubleshooting live in [docs/mcp.md](docs/mcp.md). Per-client scaffolds live in
[agents/](agents/).

## Limitations

The public channel has a ceiling:

- Internal-only workloads are invisible.
- SaaS products without DNS verification records may not appear.
- Email gateways can hide the downstream mailbox provider.
- CT logs can be stale, partial, rate-limited, or absent.
- Fingerprints are rule-based indicators, not proof of active use.

Read [docs/limitations.md](docs/limitations.md) before using recon output for a
high-stakes decision. Read [docs/data-handling-policy.md](docs/data-handling-policy.md)
before committing any validation artifact.

## Documentation

- [docs/getting-started.md](docs/getting-started.md): install, update,
  uninstall, and first commands.
- [docs/how-it-works.md](docs/how-it-works.md): readable model overview.
- [docs/README.md](docs/README.md): complete docs index.
- [docs/roadmap.md](docs/roadmap.md): current plan, invariants, and scope
  boundaries.
- [CHANGELOG.md](CHANGELOG.md): shipped changes.

## Development

```bash
uv sync
pre-commit install
uv run python scripts/release_readiness.py --allow-dirty
uv run python scripts/check.py
```

`python scripts/check.py` is the local CI mirror. It runs lint, type checks,
coverage-gated tests, generated-artifact checks, validation hygiene, and
ratchets. Do not push on `--fast` alone.

House rules: no AI attribution, no em-dashes or emojis, no real-company data in
public examples or validation artifacts, no dead code, and no placeholders.
Contributor details: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. Free to use, build on, fork, and share. See [LICENSE](LICENSE) for
the full terms.
