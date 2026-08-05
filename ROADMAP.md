# Roadmap

The canonical plan is [docs/roadmap.md](docs/roadmap.md). This file is the short
version: where the project stands, the ordered path to v3.0, and the boundaries
that do not move. Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Status

recon **v2.10.2** is the current production baseline: CLI, versioned JSON,
local stdio MCP, bounded public-metadata collectors, fail-closed claim audit
gates, MCP dual-SDK matrix, and a release path with provenance, SBOM, and
channel parity. Local execution is the default, and the project does not operate
a hosted service. Optional cloud draft materials are directionally useful, not a
validated production deployment.

Release verification binds every published artifact to its exact tag, workflow,
signer, and commit digest, and requires SBOM provenance. One
digest-bound v2.6.3 historical exception preserves that release's published
distribution-only bundle while still requiring SBOM structure validation; every
later release fails if SBOM provenance is absent.

The evidence-semantic audit is complete: 27 families are complete. 0 material
runtime families carry incomplete lineage. Fail-closed inventory spans 84 score
or quantitative fields among other governed surfaces. MCP v2 adoption is
complete and both remain blocking maintenance. The open product question is
still unproven: nothing yet measures whether fusion, CT enrichment, catalog
size, or the broad agent surface improves operator decisions over deterministic
evidence plus abstention.

Publication maintainers must rerun
[docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md)
before any external submission. The most recent completed historical local
submission-freeze proof is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).

## Version path (order of operations)

No calendar estimates. Each row unlocks the next. Patch releases (2.x.y) stay
available for security, silent-failure, and contract-preserving fixes at any
point.

| Version | Theme | Why this order | Done when |
|---|---|---|---|
| **v2.10.x** | Maintenance line | Protect truthfulness and supply chain while larger work proceeds | Evidence audit green; MCP 1.28.1 + 2.0.0 pins green; no known silent fail-open on default paths |
| **v2.11.0** | Product-quality baseline | Track 3. Cannot promote or retire fusion without a predeclared scorecard | Aggregate-safe scorecard + predeclared ablation rule + dated memo; fusion path kept or demoted to advanced diagnostic by result |
| **v2.12.0** | Apply quality decision | Uses v2.11 evidence; avoids more graph work without benefit | Primary path matches scorecard outcome; docs and defaults updated; negative result accepted without reinterpretation |
| **v2.13.0** | Observation vs interpretation | Needs stable claim units from earlier tracks | Caller-held observation capsules; delta classifies observation / collection / time / interpretation; no silent additions under degraded sources |
| **v2.14.0** | Catalog quality loop | Independent of fusion promotion; blocked only by disclosure-safe rounds | Rank / regional / vendor-seed / drift rounds complete with fixtures; broad catalog growth remains gated by those rounds |
| **v2.15.0** | Agent surface cost | After quality baseline so tool cuts do not hide weak models | Measured MCP context cost; core vs advanced profile only if a real client shows material benefit |
| **v3.0.0** | Contract maturity | Major only if an additive path cannot carry the claim model | Versioned claim / observation envelope (or explicit decision that v2 stays forever); migration notes; no silent semantic change under a minor |

Optional cloud operator hosting stays a **side track** (any 2.x after local
default stays complete). It never unblocks product-quality work and never
creates a project-operated multi-tenant service without a separate product
decision.

Publication, OpenSSF questionnaire, outside replication, and archive/DOI are
**maintainer tracks** on external events. They do not displace the version
path above.

## Active tracks (why, state, close)

### 1. Evidence-semantic integrity - maintenance (highest trust rank)

Complete for the 27-family default surface. New claim surfaces reopen this
track immediately. Detail: [docs/default-claim-audit.md](docs/default-claim-audit.md).

### 2. MCP v2 compatibility - maintenance

Production on `mcp>=2.0.0,<3` with blocking 1.28.1 rollback and 2.0.0 production
rows. Detail: [docs/mcp-2026-07-28-readiness.md](docs/mcp-2026-07-28-readiness.md).

### 3. Product-quality baseline - **next build priority: v2.11**

Specified, decision rule frozen, measurement not started. Process evidence is
rich; product-outcome evidence is not. Acceptance and stop rules live in
[docs/roadmap.md](docs/roadmap.md#3-establish-a-reproducible-product-quality-baseline)
and the
[Quality Proof execution plan](docs/strategic-gap-audit.md#quality-proof-execution-plan).

The primary claim family, the four arms, the reference label, the safety
margin, and the paired decision rule were frozen on 2026-08-05 in
[docs/quality-baseline-preregistration.md](docs/quality-baseline-preregistration.md),
before any collection or run. Its power analysis supersedes the nominal
minimum-evidence floor: the selected margin needs at least 155
reference-positive and 183 reference-negative labeled units.

`scripts/quality_scorecard.py` emits the public half of the Phase 1 baseline,
network-free and corpus-free, and names every channel it cannot measure without
the private corpus or live providers.

### 4. Optional operator-hosted access - lower priority side track

Draft container + Cloud Run IaC only. Local CLI and stdio MCP remain complete.
[docs/optional-cloud-deployment-plan.md](docs/optional-cloud-deployment-plan.md).

## What Is Deliberately Not Next

| Work | Gate that unblocks it |
|---|---|
| Broad catalog growth | Independent rank, regional, vendor-seed, and drift rounds |
| More graph or probabilistic machinery | Measured benefit from the v2.11 scorecard |
| Core-versus-advanced MCP profile | Representative client proves material context benefit |
| More optional cloud provider IaC | Named operator + provider validation |
| Project-operated public multi-tenant service | Separate product, governance, and funding decision |
| Promoting surface-inventory to a stable API | Named external consumer under [ADR-0007](docs/adr/0007-surface-inventory-discovery-context.md) |
| Native acceleration (Rust/Go/Mojo) | [ADR-0010](docs/adr/0010-evidence-gated-native-acceleration.md) evidence gates |
| Dimensioned email posture scoring | ADR + RFC 9989 completion audit |
| Publication / OpenSSF / archive | Their own external events; not a substitute for product proof |

## Invariants

Change only through an ADR.

**Collection boundary** - public metadata only; MTA-STS is the sole default
target-owned HTTP request; CSE/BIMI opt-in only; no credentials, scanning, or
exploit checks.

**Claim discipline** - domain is a query coordinate; sparse stays sparse;
source failure is unavailable, never negative; parent platform is not
child-product use; public-evidence index is not overall security maturity.

**Data handling** - no committed real-target corpus; synthetic / reserved
examples; aggregate-only public validation artifacts.

**Surface stability** - CLI, JSON, MCP, cache, and import changes follow
[docs/stability.md](docs/stability.md).

## Where To Read More

| Question | Document |
|---|---|
| Full plan, acceptance evidence, stop rules | [docs/roadmap.md](docs/roadmap.md) |
| Shipped changes | [CHANGELOG.md](CHANGELOG.md) |
| Quality-proof execution | [docs/strategic-gap-audit.md](docs/strategic-gap-audit.md) |
| Engineering tracks | [docs/engineering-refinement-plan.md](docs/engineering-refinement-plan.md) |
| Catalog rounds | [docs/catalog-strategy.md](docs/catalog-strategy.md) |
| Publication freeze | [docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md) |
| Earlier plans | [docs/roadmap-history.md](docs/roadmap-history.md) |
