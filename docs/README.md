# Documentation

Project docs live here. Repository-root files stay at the root only when
tooling expects them there: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, and `LICENSE`.

## Start Here

| Need | Read |
|---|---|
| Product scope and next work | [roadmap.md](roadmap.md) |
| Why correlation works the way it does | [correlation.md](correlation.md) |
| Known passive-collection limits | [limitations.md](limitations.md) |
| Sparse or thin-looking results | [weak-areas.md](weak-areas.md) |
| CLI/API stability guarantees | [stability.md](stability.md) |
| Release checklist and tag flow | [release-process.md](release-process.md) |

## Using recon

| Topic | Read |
|---|---|
| MCP server setup and tool list | [mcp.md](mcp.md) |
| JSON output contract | [schema.md](schema.md) |
| Cohort summaries across many domains | [aggregate-state.md](aggregate-state.md) |
| Upgrading from v1.x to v2.0 | [migration-v2.md](migration-v2.md) |
| Performance expectations | [performance.md](performance.md) |
| Intended-use and query exposure | [legal.md](legal.md) |

## Trust and assurance

For anyone evaluating recon as a primitive to build on.

| Topic | Read |
|---|---|
| Engineering threat model | [security.md](security.md) |
| Auditable claim → mechanism → test → residual | [assurance-case.md](assurance-case.md) |
| Runtime contract (timeouts, caps, exit codes, determinism) | [operational-contract.md](operational-contract.md) |
| Release integrity (reproducible, signed, attested builds) | [supply-chain.md](supply-chain.md) |
| Keeping the model honest over time (maintainer loop + drift gate) | [maintainer-validation.md](maintainer-validation.md) |
| Requirements-and-invariants map, machine-checked in CI | [traceability-matrix.md](traceability-matrix.md) |
| What may and may not enter the public repo (data-handling policy) | [data-handling-policy.md](data-handling-policy.md) |
| What each number is backed by (observed / consistency / evidence-responsive / coverage) | [statistical-assurance.md](statistical-assurance.md) |

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
