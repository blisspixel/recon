# recon

[![CI](https://github.com/blisspixel/recon/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/recon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![Python](https://img.shields.io/pypi/pyversions/recon-tool.svg?cacheSeconds=300)](https://pypi.org/project/recon-tool/)
[![License](https://img.shields.io/pypi/l/recon-tool.svg?cacheSeconds=300)](LICENSE)

Passive domain intelligence from public sources. Queries DNS records, Microsoft/Google identity endpoints, and certificate transparency logs to build a picture of an organization's technology stack: no credentials, no API keys, no active scanning.

Drop in a domain, get an evidence-backed read on its identity stack, email posture, and cloud footprint in seconds, with the uncertainty widened when the public channel is sparse.

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
  (57 total, 50 more, use --full to see all)

Insights
  Federated identity indicators observed (likely Okta, enterprise SSO)
  Email security 4/5: DMARC reject, DKIM, SPF strict, BIMI
  Email gateway: Proofpoint in front of Exchange
  Dual provider: Google + Microsoft coexistence
```

> Examples use [Microsoft's fictional company names](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges) (Contoso, Northwind Traders, Fabrikam). Tenant IDs, services, and domains are fabricated. No real company is depicted.

Works for Microsoft 365, Google Workspace, or any provider. Also runs as an [MCP server](docs/mcp.md) for AI agents; the default `pip install recon-tool` includes MCP support.

**Jump to:** [Install](#install) · [Usage](#usage) · [How it works](#how-recon-works) · [AI agents and MCP](#mcp-server) · [Automation and JSON](#automation-and-json) · [Limitations](#limitations) · [Docs index](docs/README.md)

## Why recon?

| If you need... | Use recon for... | Reach for something heavier when... |
|---|---|---|
| Fast external stack context | Passive DNS, identity-endpoint, CT, SaaS, and posture indicators with no credentials | You need authenticated tenant inventory or asset-management truth |
| Defensive review or vendor diligence | Hedged observations and evidence traces you can verify | You need vulnerability scanning, exploit checks, or host-level facts |
| Automation-friendly output | Stable `--json`, batch mode, delta mode, and local MCP tools | You need dashboards, scheduled monitoring, or report generation |

## recon in practice

recon is a zero-credential first pass for external technology-stack and posture visibility. Run it before a vendor diligence call, a partner integration, an M&A review, or a hardening audit. Output is hedged, traceable, and shaped for downstream automation.

recon does not replace commercial EASM platforms, active scanners, or continuous monitoring. It is the upstream signal that feeds those tools, with full provenance so you can verify any conclusion before you act on it.

recon also does not score or rank organizations, enrich domains with firmographics, or maintain an industry intelligence database. It reports what the public channel reveals, with provenance, and leaves business interpretation to the operator.

## How recon works

recon reads the public channel: DNS records (MX, CNAME, SPF, DMARC,
TXT), certificate-transparency SAN sets, and the unauthenticated
identity-discovery endpoints Microsoft and Google publish for tenant
resolution. No credentials, no scanning, nothing the target can see
beyond a single MTA-STS policy fetch.

It then runs those observables through a small Bayesian network and
reports each high-level claim (M365 tenant, federated identity,
email-policy enforcement, CDN fronting, and so on) as an 80% confidence
interval, not a yes/no verdict. The interval is the load-bearing field:
on hardened or heavily-proxied targets it **widens** rather than
collapsing on a fake-confident point estimate, because absent evidence
is treated as no evidence, not as evidence of absence. The intervals
are evidence-responsive (they track how much the public channel
constrains each claim); they are not yet empirically calibrated against
ground truth, which no passive tool can observe. The structural motifs
recon surfaces (a CDN in front of an identity provider, an email
gateway in front of M365, a secondary Google Workspace alongside
primary M365) are the ones single-source detection often misses.

> **For the formal model:** the adversarial missing-data treatment
> (MNAR, with the absent-evidence rule grounded in m-graphs and Manski
> partial identification), the calibration principles the credible
> interval satisfies, and the failure-mode catalog across five hardening
> postures live in [docs/correlation.md](docs/correlation.md).

The fingerprint catalog is shaped by passive-DNS observation of real
corpora. The built-in catalog ships with the package; operators can
extend it for their own environment by dropping additions into
`~/.recon/fingerprints.yaml` (additive only, cannot override
built-ins). Anything broadly useful can be contributed upstream via
the workflow in [CONTRIBUTING.md](CONTRIBUTING.md). The maintainer
runs the same scan-triage loop against a private corpus before each
release; the catalog grows from observed gaps, not invented entries.

## Install

Requires Python 3.11+.

```bash
pip install recon-tool                 # includes MCP server
pip install -U recon-tool              # upgrade
recon doctor                           # verify connectivity
```

## Usage

```bash
recon contoso.com                              # default panel
recon contoso.com --explain                    # full reasoning + provenance DAG
recon contoso.com --full                       # everything (services + domains + posture)
recon contoso.com --profile fintech            # apply a posture lens
recon contoso.com --confidence-mode strict     # drop hedging on dense-evidence targets (current)
recon contoso.com --json                       # structured JSON for piping
recon batch domains.txt --json                 # batch (cross-domain token clustering)
cat domains.txt | recon batch - --json         # batch reading domains from stdin
recon batch domains.txt --json --include-ecosystem  # add v1.8 ecosystem hypergraph
recon batch domains.txt --summary              # one aggregate-only cohort summary (panel)
recon batch domains.txt --summary --json       # the same, as JSON for downstream tooling
recon contoso.com --chain --depth 2            # follow related-domain breadcrumbs
recon delta contoso.com                        # diff against last cached snapshot
recon mcp                                      # start MCP server (stdio)
```

Built-in profiles: `fintech`, `healthcare`, `saas-b2b`, `high-value-target`, `public-sector`, `higher-ed`. Custom profiles live in `~/.recon/profiles/*.yaml`.

**Shell completion.** recon ships tab-completion for the command tree and flags (via Typer). Install it for your current shell, or print the script to wire it up yourself:

```bash
recon --install-completion                     # add completion to your shell config
recon --show-completion                        # print the completion script (bash/zsh/fish/powershell)
```

After `--install-completion`, start a new shell for it to take effect.

See [docs/README.md](docs/README.md) for the organized documentation index.

## MCP server

recon runs as an MCP server for Claude, Cursor, VS Code, ChatGPT, or any MCP client. The Model Context Protocol lets AI agents call tools like recon directly from your chat.

**One-shot install.** Let recon write the right config block for you:

```bash
recon mcp install --client=claude-desktop   # or claude-code, cursor, vscode, windsurf, kiro
recon mcp doctor                            # spawn the server and verify the JSON-RPC handshake
```

The install command is idempotent and merge-safe: sibling MCP servers, hand-curated `autoApprove` lists, custom `env` vars, and any other keys you've added to the recon block all survive a `--force` rerun. Use `--dry-run` first to preview the plan.

**Manual install.** If you'd rather edit by hand, add this to your client's MCP config:

```json
{
  "mcpServers": {
    "recon": {
      "command": "recon",
      "args": ["mcp"],
      "autoApprove": []
    }
  }
}
```

The default install already includes the MCP server. Keep approvals manual until you've decided which tools, if any, you want to trust automatically. recon's MCP tools are split into read-only and stateful sets (the three ephemeral-fingerprint / reload tools are stateful); see the [autoApprove guidance](docs/mcp.md#read-only-vs-stateful-autoapprove-guidance) for which is which.

Then ask your AI: *"Run a recon lookup on contoso.com and tell me what's running."*

See [docs/mcp.md](docs/mcp.md) for the full tool list, advanced agentic workflows, and per-client config locations.

Installed but the tools don't appear? Run `recon doctor --client=<name>` to confirm the config carries the recon stanza, then see the [troubleshooting checklist](docs/mcp.md#when-doctor-passes-but-the-tools-dont-load). The usual fix is a full application restart, since a new chat does not re-spawn MCP servers.

**Claude Code, Kiro, Windsurf, Cursor, VS Code:** per-agent install scaffolds live under [`agents/`](agents/), one folder per client with its MCP config and guidance template. Claude Code users get a full plugin (MCP + skill in one install) at [`agents/claude-code/`](agents/claude-code/). The skill drives the CLI for the one-shot analyses (lookup, `--exposure` score, `--gaps`, `--fusion` posteriors); the MCP server adds the stateful, iterative workflows (what-if hardening loops, ephemeral fingerprints, live two-domain compare). That folder's README has the breakdown. The portable [`AGENTS.md`](AGENTS.md) at the repo root is auto-detected by Kiro and other agents.md-aware tools.

**Quickest install for AI clients with file-write tools.** Paste this prompt to your AI:

> Fetch `https://raw.githubusercontent.com/blisspixel/recon/main/agents/claude-code/skills/recon/SKILL.md` and save it to my Claude Code skills directory (`~/.claude/skills/recon/SKILL.md`), or to `~/.kiro/skills/recon/SKILL.md` if I'm using Kiro. Then run `pip install recon-tool` and `recon doctor` to verify.

The SKILL.md follows the open [agentskills.io](https://agentskills.io) standard, so the same file works in Claude Code and Kiro.

## Automation and JSON

recon is built for piping, and the output shape depends on the command:
`recon <domain> --json` emits a single result object; `recon batch ... --json`
emits a wrapped array (`--ndjson` gives one object per line); `recon delta`
emits a DeltaReport. Validate any shape against
[`docs/recon-schema.json`](docs/recon-schema.json)
([raw URL](https://raw.githubusercontent.com/blisspixel/recon/main/docs/recon-schema.json));
the v2.0 stability contract and every field live in
[`docs/schema.md`](docs/schema.md), and drift between schema and emitter is
caught by `tests/test_json_schema_file.py`.

The CLI also returns stable exit codes (`0` success, `1` general error,
`2` validation, `3` no data, `4` internal) so a script can branch on the
outcome without parsing output. Full contract:
[`docs/schema.md`](docs/schema.md#exit-codes).

## Limitations

The short version is below; [docs/limitations.md](docs/limitations.md) has the
full inventory, including known noise patterns and a guide to when to reach for
a different tool.

- **Coverage depends on public DNS.** Organizations behind heavy proxies, with minimal DNS records, or that don't publish SaaS verification tokens will return sparse results. This is fundamental to passive-only collection. When sources transiently fail, the CLI tells you which one and why so you can retry or accept the partial answer.
- **Internal workloads are structurally invisible.** Server-side API consumption (an org running internal Google Cloud ML, internal AWS data pipelines, internal Snowflake warehouses without public verification tokens, and so on) leaves no trace in public DNS, CT logs, or unauthenticated identity-discovery endpoints. recon cannot tell you what runs internally; it can only tell you what the org publishes externally. The CLI panel calls this out explicitly: the "Cloud" line surfaces what is observable, and on sparse-but-multi-domain apexes a one-line "Passive-DNS ceiling" footer notes that internal workloads and SaaS without DNS verification do not appear in public DNS records. A "Multi-cloud" indicator collapses sibling slugs (Route 53 + CloudFront = one AWS) when the public footprint touches more than one cloud vendor.
- **Heuristic, not ground truth.** The fingerprint database and signal rules are rule-based and solo-maintained. Confident-looking output can still be wrong. The credible interval is the load-bearing field, not the point estimate: by construction, sparse evidence on hardened targets produces a wide interval rather than a confident-looking point estimate, and the `sparse=true` flag in the JSON output is the operator-facing signal that the layer has hit the passive-observation ceiling. Every detection in the catalog carries a description and a vendor doc URL, so a finding can be re-verified against the vendor's own documentation before action. Treat results as indicators for investigation, not as definitive assessments. Don't make business decisions based solely on this output. See [docs/correlation.md](docs/correlation.md) for the calibration principles the interval satisfies and the failure-mode catalog across hardening postures.

## Development

```bash
uv sync                                # installs the dev group (pip: pip install -e . --group dev, pip 25.1+)
pytest tests/                          # full test suite
ruff check recon_tool/                 # lint
pyright recon_tool/                    # type check
pre-commit install                     # activate pre-commit hooks
```

## License

MIT. See [LICENSE](LICENSE) for details.

This tool queries only public DNS records and unauthenticated endpoints. See [docs/legal.md](docs/legal.md) for full disclaimer.
