# recon

[![CI](https://github.com/blisspixel/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/recon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![Python](https://img.shields.io/pypi/pyversions/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![License](https://img.shields.io/pypi/l/recon-tool.svg?cacheSeconds=300)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blisspixel/recon/badge)](https://scorecard.dev/viewer/?uri=github.com/blisspixel/recon)

Passive domain intelligence from public sources. recon reads public DNS,
certificate transparency, and unauthenticated Microsoft and Google identity
discovery endpoints to compose typed observations around a domain's public
technology and identity namespace. A domain is the query coordinate, not proof
of one organization, owner, account, or deployed product.

It uses no credentials, no API keys, no paid feeds, and no active scanning. It
is a local Python CLI, importable library, JSON producer, and stdio MCP server.
It is not a hosted service, scheduler, vulnerability scanner, company research
tool, or firmographic database.

> **Defensive use only.** Use recon for legitimate posture review, IT
> architecture review, vendor diligence, and defensive hardening. See
> [docs/legal.md](docs/legal.md) for the intended-use policy.

## Quick Start

Install with `uv` or `pipx`:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

Python 3.11 through 3.14 is supported. The latest Python 3.14 patch is
recommended for new installations and development; older supported versions
retain the same product behavior and output contracts. Current measurements
and version-specific decisions are in [docs/performance.md](docs/performance.md).

If `uv` or `pipx` is already installed, the platform script can install or
update recon:

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex"
```

**macOS or Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/blisspixel/recon/main/scripts/install.sh | bash
```

Open a new terminal and run an offline verification of the installed command:

```bash
recon --version
```

Optionally test online connectivity to recon's public data sources:

```bash
recon doctor
```

Before the first lookup, note that recon makes DNS queries which recursive and
authoritative DNS infrastructure may observe. Its only default request to a
target-owned HTTP endpoint is the standards-defined MTA-STS policy fetch at
`https://mta-sts.<domain>/.well-known/mta-sts.txt`. Google CSE and BIMI direct
probes run only when `--direct-probes` is explicitly enabled.

Run the first lookup:

```bash
recon contoso.com
```

Example output shape:

```text
Contoso Ltd
contoso.com

Provider     Microsoft 365 (MX delivery path) + Proofpoint gateway (MX delivery path)
Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890
Auth         Federated
Confidence   High (4 sources)

Services
  Email       Microsoft 365, Proofpoint, DMARC, DKIM, SPF strict
  Identity    Okta, Entra ID
  Cloud       Cloudflare, AWS Route 53

Insights
  Federated identity observed; identity-vendor indicators: Okta
  Email security: observed controls: DMARC reject, DKIM, SPF strict, BIMI
  MX gateway observed: Proofpoint
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
recon contoso.com --full                       # expanded evidence, domains, posture
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

Default collection includes bounded DNS queries through the configured
recursive resolver, so authoritative DNS infrastructure may observe resulting
resolver traffic. The only default target-owned HTTP or application request is
the standards-based MTA-STS policy fetch at `mta-sts.<domain>`. Google CSE and
BIMI VMC direct probes are opt-in behind `--direct-probes`.

The engine then maps observables to fingerprint slugs, derived signals, typed
topology, provenance paths, per-slug evidence strength, and model-relative
Bayesian diagnostics. Sparse public evidence stays sparse: the result lowers
confidence or remains unresolved instead of inventing a clean answer. A source
failure remains unavailable rather than becoming a negative observation. The
Bayesian uncertainty band is evidence-responsive, not a demonstrated credible
or confidence interval.

The reviewed built-in fingerprint source remains split YAML. Release wheels
load one deterministic generated JSON catalog, while custom and session-scoped
fingerprints still pass through the runtime validator. This keeps contributor
review readable and removes repeated YAML parsing from cold CLI startup without
changing catalog order, matching, or public output.

Long-form explanation: [docs/how-it-works.md](docs/how-it-works.md).
Formal model and robustness research program:
[docs/correlation.md](docs/correlation.md).

## JSON and Automation

`recon <domain> --json` emits a stable single-domain lookup object. Batch and
delta modes emit different shapes, so route by mode or by `record_type`.
`recon batch --summary --json` preserves the separate aggregate-only
`cohort_summary` 2.1 contract. New consumers can select
`--summary-schema 2.2` for raw-evidence-bound DMARC rates, corrected missingness,
and explicit metric kinds. The standalone reducer uses
`--schema-version 2.2` for the corresponding atemporal compatibility view.

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
Start with manual approvals. Approval syntax is client-specific, and some
current client schemas do not define `autoApprove`. Treat connected agents as
untrusted input.

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
- [docs/external-writeup-plan.md](docs/external-writeup-plan.md): active
  maintainer plan for external write-up readiness.
- [docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md):
  final paper and artifact freeze gate before any external submission package.
- [docs/c3-ct-validation-plan.md](docs/c3-ct-validation-plan.md): closed
  certificate-transparency validation plan.
- [CHANGELOG.md](CHANGELOG.md): shipped changes.

## Roadmap Focus

recon has a stable baseline, but product quality work remains. The top three
priorities are:

1. Make every default claim traceable to evidence and remove product-use,
   cloud-type, or security-maturity conclusions that public metadata cannot
   support.
2. Establish an aggregate-safe quality baseline for claim precision,
   abstention, provenance, catalog coverage, degradation, latency, CT value,
   and agent context cost before expanding inference or graph machinery.
3. Keep the exact MCP v1.28.1 and v2.0.0b1 compatibility matrix green, then
   repeat the full gate against the final 2026-07-28 specification and stable
   v2 SDK before changing the production dependency.

The dependency order, acceptance evidence, stop rules, and current code-graph
summary live in [docs/roadmap.md](docs/roadmap.md). The implementation plan is
[docs/engineering-refinement-plan.md](docs/engineering-refinement-plan.md), and
the current step-back review is
[docs/strategic-gap-audit.md](docs/strategic-gap-audit.md). Research publication,
OpenSSF process, outside replication, and archive work remain separate
maintainer tracks so they do not displace product truthfulness or measured
utility.

The most recent completed historical local proof for the separate publication
track is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).
The current paper and artifact package is unfrozen after subsequent product,
documentation, and release changes. Maintainers must rerun the submission gate
before external submission.
Its [public-label decision](docs/public-label-snapshot-decision.md) keeps public
lists as robustness checks rather than population rates, and its
[M365 tenancy decision](docs/m365-tenancy-decision.md) keeps that evidence as
corroboration rather than independent calibration.

## Development

```bash
uv sync
uv run pre-commit install
uv run python scripts/release_readiness.py --allow-dirty
uv run python scripts/check.py
```

`uv run python scripts/check.py` is the canonical local gate. It runs lint, type checks,
coverage-gated tests, generated-artifact checks, validation hygiene, and
ratchets. Its full-suite stage uses at most four file-grouped test workers while
preserving combined branch coverage. Focused `pytest` commands stay serial by
default. Do not push on `--fast` alone.

Project hygiene: keep examples fictional or synthetic, keep validation artifacts
aggregate-only, run `uv run python scripts/check.py`, and
avoid dead code or placeholders.
Contributor details: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. Free to use, build on, fork, and share. See [LICENSE](LICENSE) for
the full terms.
