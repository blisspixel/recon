# Roadmap

The canonical plan is [docs/roadmap.md](docs/roadmap.md). This file is the short
version: where the project stands, what happens next and why, and the
boundaries that do not move. Shipped work lives in
[CHANGELOG.md](CHANGELOG.md); this file does not repeat it.

## Status

recon v2.9.0 has a complete, production-ready baseline. Shipped and now under
maintenance rather than active development: the CLI, the versioned JSON
contract, the local stdio MCP server, bounded public-metadata collectors,
generated-artifact guards, the validation gates, and a release path with
reproducible builds, provenance, SBOM, and cross-channel byte parity.

An optional authenticated remote container and draft Google Cloud Run IaC
framework now exist as low-priority accessibility and scale polish. This draft
is intended to be directionally useful, not a validated production deployment.
It does not change the local default, and the project does not operate a hosted
endpoint.

Release verification binds every published artifact to its exact tag, workflow,
signer, and commit digest, and requires SBOM provenance. One
digest-bound v2.6.3 historical exception preserves that release's published
distribution-only bundle while still requiring SBOM structure validation; every
later release fails if SBOM provenance is absent.

A complete baseline is not a finished product. Three things remain unproven,
and the plan below is about exactly those three:

- Not every default claim has been traced to the evidence that supports it.
- Stable MCP v2 compatibility is now characterized, but production adoption
  remains a separate release decision.
- Nothing measures whether probabilistic fusion, certificate-transparency
  enrichment, the fingerprint catalog, or the broad agent surface improves an
  operator outcome over deterministic evidence plus explicit abstention.

## What Is Next, and Why

Rank and urgency are different axes here, and conflating them is how the wrong
thing gets worked on. Track 1 is the standing highest priority because
truthfulness outranks features. Track 2 is the most *urgent* because it is the
only one with an external clock, and it is small. Schedule track 2 now and keep
track 1 as the default work; do not let track 2 displace it for longer than the
protocol work actually takes.

Each track below names why it sits where it does, what state it is in now, and
the evidence that closes it.

### 1. Finish the default-claim evidence audit

**Why first:** output truthfulness outranks every feature, and this defect
class is still being found one case at a time instead of swept. The most recent
instance let a queried domain report the email controls that a related domain
published, contradicting its own null DMARC policy inside the same record, and
persisted that contradiction to the result cache. A bug hunt found it. The
audit that exists to prevent it has not been run to completion. The taxonomy
now exists, but Track 3 stays blocked until the incomplete default runtime
paths are closed and the family definitions stop moving.

**State:** a fail-closed machine-readable audit now assigns all discovered
primary surfaces to 27 claim families and blocks drift across 185 JSON property
occurrences, 167 MCP tool and output surfaces, 31 panel producers, 89 agent
guidance sections, 16 insight generators, 77 score or quantitative fields, and
the remaining governed surfaces. Nineteen families are complete. Six material
runtime families still have incomplete lineage, and the two static guidance
families remain open for semantic review. Generated insights now retain the
exact generation-time rule plus evidence-occurrence or bounded-scope
associations through result-cache version 4. The narrower
`dns.dmarc.valid_policy_is_reject.v1` proof-carrying contract remains the first
fully modeled claim. See
[the default-claim audit](docs/default-claim-audit.md).

**Closed when:** every default panel insight, service label, live MCP
instruction and tool description, generated agent guidance item,
recommendation, and score label has a direct evidence-to-claim path; shared
administrative tokens, tenant IDs, and certificate overlap never become
ownership, control, or current-use claims; missing metadata stays unknown; and
explanation output reports provenance completeness rather than asserting a
complete path it does not have.

### 2. Keep final MCP v2 compatibility green before adopting it

**Why second:** the Model Context Protocol 2026-07-28 specification is a
breaking protocol release, and the official Python SDK moves on its own
schedule regardless of recon. The compatibility work is bounded and remains
blocking in CI without displacing track 1.

**State:** adopted on 2026-07-31. Production serves 2026-07-28 on the v2 SDK,
and CI keeps both pins blocking. The same registration and domain logic passes
legacy initialization and final stateless `server/discover` behavior, and the
optional remote adapter now runs on either generation.

**Closed when:** the stable matrix stays green; tool and resource order stays
deterministic; declared output schemas and structured results conform on both
generations; and the local stdio workflow remains intact. Production runs
`mcp>=2.0.0,<3`; `1.28.1` remains the documented rollback pin. The named
optional remote-access need and its separate architecture review now live in
[the cloud deployment plan](docs/optional-cloud-deployment-plan.md); that work
does not imply production v2 adoption, OAuth, Roots, Sampling, Apps, or Tasks.

### 3. Freeze a product-quality baseline, then promote or retire

**Why third, and not sooner:** it depends on the claim taxonomy from track 1.
Measuring claim families before they are defined means measuring something that
is about to be redefined. The project has extensive process evidence and no
product-outcome evidence. Green gates, a large catalog, and a broad tool
surface are supporting facts, not proof that the output improves a decision.

**Closed when:** a dated, aggregate-safe scorecard exists with reproduction
commands, environment, and revision digests; the ablation decision rule is
written before the run rather than after reading it; and the result decides
whether advanced fusion stays in the primary path or becomes an explicitly
advanced diagnostic. An inconclusive or negative result is a valid outcome and
is not reinterpreted into a promotion.

### 4. Optional operator-hosted access and scale-out

**Why fourth:** making recon easier to reach from different AI systems is useful
polish for some operators, but it does not outrank output truthfulness,
protocol compatibility, or evidence that the product improves an operator
decision.

**State:** draft shared runtime, non-root OCI container, Cloud Run Terraform,
authentication boundaries, and CI structural checks exist. They pass local
artifact checks but are not yet provider-validated or production-ready. Local
CLI and stdio MCP remain the complete default. AWS AgentCore, Azure Container
Apps, Cloudflare, Kubernetes, and per-user OAuth are research directions with
explicit stop rules rather than unvalidated placeholder IaC.

**Closed when:** one external operator has validated the chosen reference with
a real MCP client, bounded load and cost evidence, credential rotation, log
retention, and image rollback. Expansion to another provider requires named
demand and that provider's validation context.

Full architecture, research, provider choices, and sequencing:
[docs/optional-cloud-deployment-plan.md](docs/optional-cloud-deployment-plan.md).

## What Is Deliberately Not Next

Each of these is real work that is blocked on purpose, not forgotten.

| Work | Gate that unblocks it |
|---|---|
| Broad catalog growth | The independent rank, regional, vendor-seed, and drift rounds. A repeated list is a drift round, not new coverage. |
| More graph or probabilistic machinery | Measured benefit to a named user outcome, from track 3. |
| A core-versus-advanced MCP tool profile | A representative client proving material context benefit. Payload size alone is not the trigger. |
| More optional cloud provider IaC | A named operator, provider-specific identity and region context, and the acceptance gate in the optional cloud plan. |
| A project-operated public or multi-tenant service | A separate product, governance, privacy, abuse, support, and funding decision. The current plan provides operator-owned references only. |
| Promoting generated discovery artifacts to a stable contract | A named external consumer, under [ADR-0007](docs/adr/0007-surface-inventory-discovery-context.md). |
| Native acceleration in Rust, Go, or Mojo | The evidence gates in [ADR-0010](docs/adr/0010-evidence-gated-native-acceleration.md), measured on a real stage rather than a microbenchmark. |
| Dimensioned email posture scoring | An ADR plus the RFC 9989 completion audit, keeping the current stable field as a compatibility view. |
| Publication, OpenSSF questionnaire, outside replication, archive | Their own external events. These are legitimate maintainer tracks, and they do not outrank product truthfulness or measured utility. |

## Invariants

These hold across every track above and change only through an ADR. They are
what recon refuses to do, and most of the plan exists to keep them true.

**Collection boundary**

- Public metadata only: DNS, certificate transparency, unauthenticated identity
  discovery, and the standards-defined MTA-STS policy fetch.
- Google CSE and BIMI certificate fetches are explicit opt-in direct probes,
  never part of a default lookup.
- No credentials, API keys, paid feeds, port scanning, exploit checks, or
  target application crawling.

**Claim discipline**

- A domain is a query coordinate. It is not an organization, owner, account, or
  deployed product.
- Sparse evidence stays sparse. Lower confidence and abstention are correct
  answers; inventing a clean one is not.
- A source failure is an unavailable channel, never a negative observation.
- Parent-platform presence never becomes a child-product use or deployment
  claim, and missing metadata stays unknown rather than defaulting.
- A public-evidence index is never presented as overall security maturity.

**Data handling**

- No runtime aggregate database, no committed real-target corpus, and no
  per-domain rows in public artifacts.
- Public prose, examples, fixtures, and snapshots use reserved synthetic
  identities; public validation artifacts are aggregate-only.
- Maintainer-local validation data stays in the permanently ignored workspaces
  defined by [docs/data-handling-policy.md](docs/data-handling-policy.md).

**Surface stability**

- The CLI, JSON, MCP, cache, and import surfaces change only through the
  compatibility discipline in [docs/stability.md](docs/stability.md).
- Network, parser, cache, schema, and output behavior stays bounded.
- Clean repository root, canonical docs in `docs/`, source in `src/`, logs in
  ignored `logs/`, and agent work in ignored `.agent/`.

## Publication and Process Track

The external write-up, claim freeze, OpenSSF Best Practices questionnaire,
outside replication, and archive or DOI decision are legitimate maintainer
projects that run on their own external events. They do not outrank output
truthfulness, measured utility, or compatibility work, and they are not a
substitute for product-quality evidence. Their final gate is
[docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md).

The paper and artifact package is currently unfrozen: wording, packaging,
validation, and release changes have landed since the last freeze, so
maintainers must rerun the gate before any external submission or submission
packaging. The most recent completed historical public claim audit is
[validation/2026-06-29-scorecard-gate-claim-audit.md](validation/2026-06-29-scorecard-gate-claim-audit.md),
and the most recent completed historical local submission-freeze proof is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).

## Where To Read More

| Question | Document |
|---|---|
| The full plan, acceptance evidence, and stop rules | [docs/roadmap.md](docs/roadmap.md) |
| What already shipped | [CHANGELOG.md](CHANGELOG.md) |
| The current step-back audit and phased execution plan | [docs/strategic-gap-audit.md](docs/strategic-gap-audit.md) |
| How the next tracks get implemented | [docs/engineering-refinement-plan.md](docs/engineering-refinement-plan.md) |
| Source, test, and facade cleanup | [docs/structural-maintainability.md](docs/structural-maintainability.md) |
| MCP timeline, gate, and rollback criteria | [docs/mcp-2026-07-28-readiness.md](docs/mcp-2026-07-28-readiness.md) and [ADR-0009](docs/adr/0009-mcp-2026-readiness.md) |
| Optional remote MCP, cloud hosting, authentication, and scale-out | [docs/optional-cloud-deployment-plan.md](docs/optional-cloud-deployment-plan.md) |
| Catalog rounds and the promotion gate | [docs/catalog-strategy.md](docs/catalog-strategy.md) |
| The publication freeze gate | [docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md) |
| Earlier plans and superseded framing | [docs/roadmap-history.md](docs/roadmap-history.md) |
