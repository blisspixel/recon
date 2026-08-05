# Documentation

Project docs live here. Repository-root files stay at the root only when
tooling or reader expectations make the root location useful: `README.md`,
`ROADMAP.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`CODE_OF_CONDUCT.md`, `LICENSE`, `THIRD-PARTY-NOTICES.md`, `CITATION.cff`, and
`AGENTS.md`.

The docs are grouped by who you are. The first three sections cover using and
building against recon. The rest are maintainer working documents: accurate and
public, but not written for a first-time reader.

## Using recon

| Need | Read |
|---|---|
| First overview | [../README.md](../README.md) |
| Install, update, uninstall, and first commands | [getting-started.md](getting-started.md) |
| Plain-language model overview | [how-it-works.md](how-it-works.md) |
| What recon can and cannot see | [limitations.md](limitations.md) |
| Known weak areas and conservative wording | [weak-areas.md](weak-areas.md) |
| Wire recon into an MCP client | [mcp.md](mcp.md) |
| Rules versus agent judgment when driving recon from an agent | [agentic-balance.md](agentic-balance.md) |
| Generated CLI command and flag reference | [cli-surface.md](cli-surface.md) |
| Expected latency and cost | [performance.md](performance.md) |
| Legal and query-exposure notes | [legal.md](legal.md) |
| What leaves your machine | [adr/0011-public-metadata-collection-boundary.md](adr/0011-public-metadata-collection-boundary.md) |
| Upgrade from v1.x to v2.0 | [migration-v2.md](migration-v2.md) |

## Building against recon

| Contract | Read |
|---|---|
| JSON output schema | [schema.md](schema.md) |
| Machine-readable JSON Schema | [recon-schema.json](recon-schema.json) |
| Stable surfaces and SemVer policy | [stability.md](stability.md) |
| Runtime timeouts, caps, cache, and exit codes | [operational-contract.md](operational-contract.md) |
| Consume JSON safely in scripts | [automation-examples.md](automation-examples.md) |
| Cohort-summary and reducer output | [aggregate-state.md](aggregate-state.md) |
| Fingerprint schema | [fingerprints.md](fingerprints.md) |
| Signal schema | [signals.md](signals.md) |
| Security threat model and trust boundaries | [security.md](security.md) |
| Supply-chain and release integrity, including consumer verification | [supply-chain.md](supply-chain.md) |
| Generated CLI, MCP, schema, and maintainer context inventory | [surface-inventory.json](surface-inventory.json) |

`cli-surface.md`, `surface-inventory.json`, and `recon://surface-inventory` are
generated discovery context, not stable runtime contracts. See
[ADR-0007](adr/0007-surface-inventory-discovery-context.md).

## Contributing

| Topic | Read |
|---|---|
| Contribution workflow | [../CONTRIBUTING.md](../CONTRIBUTING.md) |
| Engineering practices | [engineering-practices.md](engineering-practices.md) |
| Catalog growth and quality strategy | [catalog-strategy.md](catalog-strategy.md) |
| Data-handling policy | [data-handling-policy.md](data-handling-policy.md) |
| Cut and verify a release | [release-process.md](release-process.md) |
| Local validation workspace | [../validation/README.md](../validation/README.md) |
| Agent integration scaffolds | [../agents/README.md](../agents/README.md) |
| Architecture decision records | [adr/README.md](adr/README.md) |
| Native acceleration decision | [adr/0010-evidence-gated-native-acceleration.md](adr/0010-evidence-gated-native-acceleration.md) |

## Project plans and process

Maintainer working documents. They describe intended work and its gates, not
shipped behavior; [../CHANGELOG.md](../CHANGELOG.md) is the record of what
actually shipped.

| Topic | Read |
|---|---|
| Canonical plan, acceptance evidence, and stop rules | [roadmap.md](roadmap.md) |
| Current step-back audit and phased execution plan | [strategic-gap-audit.md](strategic-gap-audit.md) |
| Frozen v2.11 product-quality decision rule, written before any run | [quality-baseline-preregistration.md](quality-baseline-preregistration.md) |
| Aggregate-safe product-quality scorecard harness | `scripts/quality_scorecard.py` |
| Dependency-ordered implementation plan | [engineering-refinement-plan.md](engineering-refinement-plan.md) |
| Structural maintainability audit, pinned to the revision it measured | [structural-maintainability.md](structural-maintainability.md) |
| Completed MCP 2026 compatibility matrix and adoption gate | [mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md) |
| Draft optional remote MCP and cloud framework, not provider-validated | [optional-cloud-deployment-plan.md](optional-cloud-deployment-plan.md) |
| Run maintainer validation safely | [maintainer-validation.md](maintainer-validation.md) |
| Maintainer loop contract | [maintainer-loop-runbook.md](maintainer-loop-runbook.md) |
| OpenSSF Scorecard and Best Practices posture | [openssf-posture.md](openssf-posture.md) |
| OpenSSF Best Practices Badge readiness | [openssf-badge-readiness.md](openssf-badge-readiness.md) |

## Research and assurance

The formal model, its assurance story, and the separate publication track.

| Topic | Read |
|---|---|
| Formal correlation model and robustness research program | [correlation.md](correlation.md) |
| Statistical-assurance dossier | [statistical-assurance.md](statistical-assurance.md) |
| Bayesian CPT discipline | [bayesian-cpt-discipline.md](bayesian-cpt-discipline.md) |
| Audit-ready claim to mechanism to test map | [assurance-case.md](assurance-case.md) |
| Traceability matrix | [traceability-matrix.md](traceability-matrix.md) |
| Internal proof-carrying claim contracts | [claim-contracts.md](claim-contracts.md) |
| Fail-closed material default-claim taxonomy | [default-claim-audit.md](default-claim-audit.md) |
| Related work and positioning | [related-work.md](related-work.md) |
| Artifact review guide | [artifact-review.md](artifact-review.md) |
| Submission freeze checklist | [submission-freeze-checklist.md](submission-freeze-checklist.md) |
| Archive readiness checklist | [archive-readiness.md](archive-readiness.md) |
| Outside public replication runbook | [replication-runbook.md](replication-runbook.md) |
| External write-up readiness plan and gates | [external-writeup-plan.md](external-writeup-plan.md) |
| Paper claim map | [paper-claim-map.md](paper-claim-map.md) |
| Paper figure package | [paper-figures.md](paper-figures.md) |
| Paper outline | [paper-outline.md](paper-outline.md) |
| Paper draft | [paper-draft.md](paper-draft.md) |
| Public label snapshot and public-list sampling decision | [public-label-snapshot-decision.md](public-label-snapshot-decision.md) |
| M365 tenancy corroboration decision | [m365-tenancy-decision.md](m365-tenancy-decision.md) |

## Historical records

These preserve completed decisions and audit receipts. They are not the current
roadmap or the current security posture.

| Record | Read |
|---|---|
| Completed roadmap history | [roadmap-history.md](roadmap-history.md) |
| Resolved security-audit findings | [security-audit-resolutions.md](security-audit-resolutions.md) |
| Closed certificate-transparency validation plan | [c3-ct-validation-plan.md](c3-ct-validation-plan.md) |
| Historical public claim audit refresh | [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md) |
| Historical submission-freeze local proof | [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md) |

## Governance and release records

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
