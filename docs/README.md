# Documentation

Project docs live here. Repository-root files stay at the root only when
tooling or reader expectations make the root location useful: `README.md`,
`ROADMAP.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`CODE_OF_CONDUCT.md`, `LICENSE`, `THIRD-PARTY-NOTICES.md`, `CITATION.cff`, and
`AGENTS.md`.

The docs are organized by reader need:

- Start with orientation when you are new.
- Use how-to guides when you have a task.
- Use reference pages when you need a contract.
- Use explanation pages when you need the model, rationale, or assurance story.

## Start Here

| Need | Read |
|---|---|
| First overview | [../README.md](../README.md) |
| Install, update, uninstall, and first commands | [getting-started.md](getting-started.md) |
| Current plan and project boundaries | [roadmap.md](roadmap.md) |
| Dependency-ordered implementation plan | [engineering-refinement-plan.md](engineering-refinement-plan.md) |
| Time-bound MCP 2026 compatibility plan | [mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md) |
| What recon can and cannot see | [limitations.md](limitations.md) |
| Rules versus agent judgment | [agentic-balance.md](agentic-balance.md) |

## How-To Guides

| Task | Read |
|---|---|
| Wire recon into an MCP client | [mcp.md](mcp.md) |
| Consume JSON safely in scripts | [automation-examples.md](automation-examples.md) |
| Upgrade from v1.x to v2.0 | [migration-v2.md](migration-v2.md) |
| Run maintainer validation safely | [maintainer-validation.md](maintainer-validation.md) |
| Review the closed certificate-transparency validation plan | [c3-ct-validation-plan.md](c3-ct-validation-plan.md) |
| Use the maintainer loop contract | [maintainer-loop-runbook.md](maintainer-loop-runbook.md) |
| Cut and verify a release | [release-process.md](release-process.md) |

## Reference

| Contract | Read |
|---|---|
| JSON output schema | [schema.md](schema.md) |
| Machine-readable JSON Schema | [recon-schema.json](recon-schema.json) |
| Generated CLI command and flag reference | [cli-surface.md](cli-surface.md) |
| Generated CLI, MCP, schema, and maintainer context inventory | [surface-inventory.json](surface-inventory.json) |
| Runtime timeouts, caps, cache, and exit codes | [operational-contract.md](operational-contract.md) |
| Stable surfaces and SemVer policy | [stability.md](stability.md) |
| Fingerprint schema | [fingerprints.md](fingerprints.md) |
| Catalog growth and quality strategy | [catalog-strategy.md](catalog-strategy.md) |
| Signal schema | [signals.md](signals.md) |
| Cohort-summary output | [aggregate-state.md](aggregate-state.md) |
| Internal proof-carrying claim contracts | [claim-contracts.md](claim-contracts.md) |

`cli-surface.md`, `surface-inventory.json`, and
`recon://surface-inventory` are generated discovery context, not stable runtime
contracts. See [ADR-0007](adr/0007-surface-inventory-discovery-context.md).

## Explanation and Assurance

| Topic | Read |
|---|---|
| Plain-language model overview | [how-it-works.md](how-it-works.md) |
| Formal correlation model and robustness research program | [correlation.md](correlation.md) |
| Executable first claim contract and certificate algebra | [claim-contracts.md](claim-contracts.md) |
| Known weak areas and conservative wording | [weak-areas.md](weak-areas.md) |
| Security threat model | [security.md](security.md) |
| Audit-ready claim to mechanism to test map | [assurance-case.md](assurance-case.md) |
| Traceability matrix | [traceability-matrix.md](traceability-matrix.md) |
| Statistical-assurance dossier | [statistical-assurance.md](statistical-assurance.md) |
| Supply-chain and release integrity | [supply-chain.md](supply-chain.md) |
| OpenSSF Scorecard and Best Practices posture | [openssf-posture.md](openssf-posture.md) |
| OpenSSF Best Practices Badge readiness | [openssf-badge-readiness.md](openssf-badge-readiness.md) |
| Data-handling policy | [data-handling-policy.md](data-handling-policy.md) |
| Legal and query-exposure notes | [legal.md](legal.md) |
| Public-metadata collection boundary | [adr/0011-public-metadata-collection-boundary.md](adr/0011-public-metadata-collection-boundary.md) |
| Performance expectations | [performance.md](performance.md) |
| Native acceleration decision | [adr/0010-evidence-gated-native-acceleration.md](adr/0010-evidence-gated-native-acceleration.md) |

## Historical Records

These records preserve completed decisions and audit receipts. They are not the
current roadmap or current security posture.

| Record | Read |
|---|---|
| Completed roadmap history | [roadmap-history.md](roadmap-history.md) |
| Resolved security-audit findings | [security-audit-resolutions.md](security-audit-resolutions.md) |

## Research

| Topic | Read |
|---|---|
| Related work and positioning | [related-work.md](related-work.md) |
| Strategic gap audit | [strategic-gap-audit.md](strategic-gap-audit.md) |
| Artifact review guide | [artifact-review.md](artifact-review.md) |
| Submission freeze checklist | [submission-freeze-checklist.md](submission-freeze-checklist.md) |
| Archive readiness checklist | [archive-readiness.md](archive-readiness.md) |
| Outside public replication runbook | [replication-runbook.md](replication-runbook.md) |
| External write-up readiness plan and gates | [external-writeup-plan.md](external-writeup-plan.md) |
| Paper claim map | [paper-claim-map.md](paper-claim-map.md) |
| Paper figure package | [paper-figures.md](paper-figures.md) |
| Historical public claim audit refresh | [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) |
| Historical submission-freeze local proof | [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md) |
| Public label snapshot and public-list sampling decision | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) |
| M365 tenancy corroboration decision | [m365-tenancy-decision.md](m365-tenancy-decision.md) |
| Paper outline | [paper-outline.md](paper-outline.md) |
| Paper draft | [paper-draft.md](paper-draft.md) |
| Bayesian CPT discipline | [bayesian-cpt-discipline.md](bayesian-cpt-discipline.md) |
| ADR index | [adr/README.md](adr/README.md) |

## Contributing

| Topic | Read |
|---|---|
| Contribution workflow | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Engineering practices | [engineering-practices.md](engineering-practices.md) |
| Local validation workspace | [../validation/README.md](../validation/README.md) |
| Agent integration scaffolds | [../agents/README.md](../agents/README.md) |

## Governance and Release Records

| Record | Read |
|---|---|
| Shipped changes | [../CHANGELOG.md](../CHANGELOG.md) |
| Security policy and reporting | [../SECURITY.md](../SECURITY.md) |
| Community conduct | [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) |
| Apache 2.0 license | [../LICENSE](../LICENSE) |
| Third-party notices | [../THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) |
| Citation metadata | [../CITATION.cff](../CITATION.cff) |
| Portable agent guidance | [../AGENTS.md](../AGENTS.md) |

## What Not To Put Here

Live validation corpora, real-company result JSON, and generated private-run
summaries stay under gitignored validation workspaces. Do not move them into
`docs/`.
