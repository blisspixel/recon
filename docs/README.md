# Documentation

Project docs live here. Repository-root files stay at the root only when
tooling expects them there: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, and `LICENSE`.

## Start Here

| Need | Read |
|---|---|
| Product scope and next work | [roadmap.md](roadmap.md) |
| Known passive-collection limits | [limitations.md](limitations.md) |
| Sparse or thin-looking results | [weak-areas.md](weak-areas.md) |
| CLI/API stability guarantees | [stability.md](stability.md) |
| Release checklist and tag flow | [release-process.md](release-process.md) |

## Using recon

| Topic | Read |
|---|---|
| MCP server setup and tool list | [mcp.md](mcp.md) |
| JSON output contract | [schema.md](schema.md) |
| Performance expectations | [performance.md](performance.md) |
| Intended-use and query exposure | [legal.md](legal.md) |
| Engineering threat model | [security.md](security.md) |

## Extending recon

| Topic | Read |
|---|---|
| Fingerprint schema and testing | [fingerprints.md](fingerprints.md) |
| Derived signal rules | [signals.md](signals.md) |
| Contribution workflow | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Local validation workspace | [../validation/README.md](../validation/README.md) |

## What Not To Put Here

Live validation corpora, real-company result JSON, and generated summaries stay
under `validation/` as ignored local artifacts. Do not move them into `docs/`.
