# recon

[![CI](https://github.com/blisspixel/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/recon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![Python](https://img.shields.io/pypi/pyversions/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![License](https://img.shields.io/pypi/l/recon-tool.svg?cacheSeconds=300)](https://github.com/blisspixel/recon/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blisspixel/recon/badge)](https://scorecard.dev/viewer/?uri=github.com/blisspixel/recon)

Point recon at a domain and get its public technology and identity footprint:
email security posture, mail and identity providers, SaaS indicators, and
certificate-transparency findings. It reads public DNS, certificate
transparency, and unauthenticated Microsoft and Google identity discovery
endpoints, and composes what it finds into typed, evidence-backed observations.

A domain is the query coordinate, not proof of one organization, owner,
account, or deployed product. recon uses no credentials, no API keys, no paid
feeds, and no active scanning. It ships as a local Python package with a CLI,
versioned JSON output, and a stdio MCP server. It is not a scheduler,
vulnerability scanner, company research tool, or firmographic database.

> **Defensive use only.** Use recon for legitimate posture review, IT
> architecture review, vendor diligence, and defensive hardening. See
> [docs/legal.md](https://github.com/blisspixel/recon/blob/main/docs/legal.md) for the intended-use policy.

## Quick Start

Install with `uv` or `pipx`:

```bash
uv tool install recon-tool
# or
pipx install recon-tool
```

Python 3.11 through 3.14, on Windows, macOS, or Linux. Later Python versions
are not yet part of the compatibility claim.

Optional helpers at `scripts/install.ps1` and `scripts/install.sh` drive an
existing `uv` or `pipx` installation. Download a
[release-tag source archive](https://github.com/blisspixel/recon/releases/latest),
review the helper locally, then run it. Each helper installs the exact version
represented by that tag, preserves a sole existing `uv` or `pipx` owner, and
refuses ambiguous or unmanaged installations. Do not pipe mutable branch
content into a shell. To verify the exact GitHub and PyPI artifacts, their
signed evidence, and their byte parity before installing, follow the
[consumer verification recipe](https://github.com/blisspixel/recon/blob/main/docs/supply-chain.md#consumer-verification-quick-path).

Verify the installed command offline:

```bash
recon --version
```

Then optionally test online connectivity to recon's public data sources:

```bash
recon doctor
```

`recon doctor` uses synthetic requests and never queries a user-supplied
target. Its `--fix`, `--mcp`, and `--client` modes are local-only.

Before the first lookup, know what leaves your machine. recon makes DNS queries
that recursive and authoritative DNS infrastructure may observe. Its only
default request to a target-owned endpoint is the standards-defined MTA-STS
policy fetch at `https://mta-sts.<domain>/.well-known/mta-sts.txt`. Google CSE
and BIMI certificate probes run only when `--direct-probes` is explicitly
enabled.

Run the first lookup:

```bash
recon example.com
```

Example output shape:

![Synthetic terminal showing recon's default output](https://raw.githubusercontent.com/blisspixel/recon/main/docs/assets/terminal-demo.svg)

This is the actual default-panel renderer fed by a deterministic, no-network
fixture. It uses IETF reserved `.invalid` namespaces. Tenant IDs, services,
and organization details are fabricated. No real organization is depicted as
the evaluated target.

<!-- terminal-demo-transcript:start -->
<details>
<summary>Accessible text transcript</summary>

```text
$ recon alpha.invalid
Synthetic Alpha Ltd
alpha.invalid
──────────────────────────────────────────────────────────────────────────────
  Provider     Microsoft 365 (MX delivery path) + Proofpoint gateway (MX
               delivery path)
  Tenant       a1b2c3d4-e5f6-7890-abcd-ef1234567890 • NA
  Tenant domain synthetic-alpha.onmicrosoft.invalid
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
  login.alpha.invalid, status.alpha.invalid, support.alpha.invalid

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

recon reports observations, not verdicts. A missing DMARC record is a missing
record. A Microsoft 365 tenant indicator is an observed indicator. The operator
decides what those facts mean in context.

## Common Commands

```bash
recon example.com                              # default panel
recon https://www.example.com/path             # normalize URL to apex
recon mail.example.com                         # reduce sub-host to apex
recon mail.example.com --exact                 # keep that literal host
recon example.com --explain                    # retained evidence and explanation
recon example.com --full                       # expanded evidence, domains, posture
recon example.com --plain                      # linear text for screen readers and grep
recon example.com --json                       # structured lookup record
recon batch domains.txt --json                 # batch JSON array
recon batch domains.txt --ndjson               # one record per line
recon delta example.com                        # diff against cached snapshot
recon cache show                               # bounded payload-free cache overview
recon fingerprints list                        # local catalog of public-record matchers
recon signals list                             # local catalog of derived observations
recon mcp install --client=cursor              # wire MCP into a client
recon mcp doctor                               # live MCP tools/resources check
```

The catalog and cache commands are local and make no network requests. Built-in
posture profiles are `fintech`, `healthcare`, `saas-b2b`, `high-value-target`,
`public-sector`, and `higher-ed`; custom profiles live in
`~/.recon/profiles/*.yaml`.

Bounded cache inspection, catalog search semantics, corpus testing, and the
narrow-terminal layout rules are covered in
[docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md).
The generated command and flag reference is
[docs/cli-surface.md](https://github.com/blisspixel/recon/blob/main/docs/cli-surface.md).

## How recon Works

recon reads:

- DNS records: MX, TXT, SPF, DMARC, DKIM, BIMI, CNAME, NS, SRV, and CAA.
- Certificate transparency: SAN names, issuers, issuance timing, and bounded
  related-domain hints.
- Identity discovery: unauthenticated Microsoft and Google endpoints.

It then maps those observables to fingerprint slugs, derived signals, typed
topology, provenance paths, and per-slug evidence strength. Sparse public
evidence stays sparse: the result lowers confidence or stays unresolved instead
of inventing a clean answer, and a source failure remains unavailable rather
than becoming a negative observation. Reported confidence is model-relative
rather than a calibrated probability.

Long-form explanation:
[docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md).
Formal model and robustness research program:
[docs/correlation.md](https://github.com/blisspixel/recon/blob/main/docs/correlation.md).

## JSON and Automation

```bash
recon example.com --json
recon batch domains.txt --json
recon batch domains.txt --ndjson
recon delta example.com --json
```

Single-domain, batch, and delta modes emit different shapes, so route by mode
or by `record_type`. Batch processing is record-oriented: a valid run keeps exit
code 0 when individual domains fail, so consumers must inspect `record_type`
and `error_kind` per record rather than the process exit status. `--ndjson`
releases completed records as they finish and is the lowest-memory choice for
large inputs.

Read these before building an integration:

- [docs/schema.md](https://github.com/blisspixel/recon/blob/main/docs/schema.md): stable JSON contract.
- [docs/recon-schema.json](https://github.com/blisspixel/recon/blob/main/docs/recon-schema.json): machine-readable schema.
- [docs/stability.md](https://github.com/blisspixel/recon/blob/main/docs/stability.md): what may change, and when.
- [docs/operational-contract.md](https://github.com/blisspixel/recon/blob/main/docs/operational-contract.md): timeouts,
  bounds, exit codes, cache, and partial-result semantics.
- [docs/automation-examples.md](https://github.com/blisspixel/recon/blob/main/docs/automation-examples.md): parser examples.
- [docs/aggregate-state.md](https://github.com/blisspixel/recon/blob/main/docs/aggregate-state.md): cohort summary and
  reducer schema versions.

`docs/surface-inventory.json`, `docs/cli-surface.md`, and
`recon://surface-inventory` are generated discovery context and drift guards,
not stable runtime API contracts. ADR-0007 records the promotion gate for any
future stable subset.

## MCP Server

The default install includes a local stdio MCP server for MCP-compatible tools.
Start with manual approvals, and treat connected agents as untrusted input.
Approval syntax is client-specific, and some current client schemas do not
define `autoApprove`.

```bash
recon mcp install --client=claude-desktop
recon doctor --mcp
recon mcp doctor
recon doctor --client=claude-desktop
```

Those checks cover three different boundaries in order: the static server
registry, live local stdio discovery with canonical tool and JSON resource
reads, and the named client's saved configuration. The installer writes the
correct per-client config shape and preserves sibling MCP servers. Full setup,
tool list, read-only versus stateful guidance, and troubleshooting live in
[docs/mcp.md](https://github.com/blisspixel/recon/blob/main/docs/mcp.md);
per-client scaffolds live in
[agents/](https://github.com/blisspixel/recon/tree/main/agents).

## Optional Cloud Access

Local execution is the default, and the project does not operate a hosted
service. For teams that want shared remote access, the repository includes a
draft authenticated container and Cloud Run Terraform starting point. It is
intended to be directionally useful, not a validated production deployment.
Operators own deployment, identity, data handling, cost, and operations.

- [Optional cloud architecture and platform plan](https://github.com/blisspixel/recon/blob/main/docs/optional-cloud-deployment-plan.md)
- [Draft deployment framework](https://github.com/blisspixel/recon/tree/main/deploy)

## Limitations

The public channel has a ceiling:

- Internal-only workloads are invisible.
- SaaS products without DNS verification records may not appear.
- Email gateways can hide the downstream mailbox provider.
- CT logs can be stale, partial, rate-limited, or absent.
- Fingerprints are rule-based indicators, not proof of active use.

Read [docs/limitations.md](https://github.com/blisspixel/recon/blob/main/docs/limitations.md)
before using recon output for a high-stakes decision, and
[docs/data-handling-policy.md](https://github.com/blisspixel/recon/blob/main/docs/data-handling-policy.md)
before committing any validation artifact.

## Security

Report a vulnerability through the process in
[SECURITY.md](https://github.com/blisspixel/recon/blob/main/SECURITY.md). The
threat model, trust boundaries, and hostile-input handling are described in
[docs/security.md](https://github.com/blisspixel/recon/blob/main/docs/security.md).

## Documentation

- [docs/getting-started.md](https://github.com/blisspixel/recon/blob/main/docs/getting-started.md): install, update,
  uninstall, and first commands.
- [docs/how-it-works.md](https://github.com/blisspixel/recon/blob/main/docs/how-it-works.md): readable model overview.
- [docs/README.md](https://github.com/blisspixel/recon/blob/main/docs/README.md): complete docs index, grouped by
  audience.
- [ROADMAP.md](https://github.com/blisspixel/recon/blob/main/ROADMAP.md): where the project stands and what is next.
- [CHANGELOG.md](https://github.com/blisspixel/recon/blob/main/CHANGELOG.md): shipped changes.

## Roadmap Focus

recon has a stable baseline, but product quality work remains. The top three
priorities are:

1. Make every default claim traceable to evidence, and remove product-use,
   cloud-type, or security-maturity conclusions that public metadata cannot
   support.
2. Keep the exact MCP v1.28.1 and v2.0.0 compatibility matrix green. Changing
   the production dependency remains a separate, deliberate release decision.
3. Establish an aggregate-safe quality baseline for claim precision,
   abstention, provenance, catalog coverage, degradation, latency, CT value,
   and agent context cost before expanding inference or graph machinery.

A fourth, explicitly lower-priority track covers the optional cloud framework.
Broad catalog growth stays blocked behind independent rank, regional,
vendor-seed, and drift rounds; real target names never enter this repository.

Dependency order, acceptance evidence, and stop rules live in
[docs/roadmap.md](https://github.com/blisspixel/recon/blob/main/docs/roadmap.md),
with the current step-back review in
[docs/strategic-gap-audit.md](https://github.com/blisspixel/recon/blob/main/docs/strategic-gap-audit.md).

Research publication, OpenSSF process, outside replication, and archive work
are separate maintainer tracks that do not displace product truthfulness. The
paper and artifact package is unfrozen after subsequent product and release
changes, so maintainers must rerun
[docs/submission-freeze-checklist.md](https://github.com/blisspixel/recon/blob/main/docs/submission-freeze-checklist.md)
before any external submission; the most recent completed local proof is
[validation/2026-06-30-submission-freeze-local-proof.md](https://github.com/blisspixel/recon/blob/main/validation/2026-06-30-submission-freeze-local-proof.md).
Its
[public-label decision](https://github.com/blisspixel/recon/blob/main/docs/public-label-snapshot-decision.md)
keeps public lists as robustness checks rather than population rates, and its
[M365 tenancy decision](https://github.com/blisspixel/recon/blob/main/docs/m365-tenancy-decision.md)
keeps that evidence as corroboration rather than independent calibration.

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
Green locally means green in CI. Do not push on `--fast` alone.

Project hygiene: keep examples reserved and synthetic, keep validation artifacts
aggregate-only, and avoid dead code or placeholders. The gate rejects a retired
target-example vocabulary across public text while preserving provider
definitions and ACME protocol terms. Contributor details:
[CONTRIBUTING.md](https://github.com/blisspixel/recon/blob/main/CONTRIBUTING.md).

## License

Apache 2.0. Free to use, build on, fork, and share. See
[LICENSE](https://github.com/blisspixel/recon/blob/main/LICENSE) for
the full terms.
