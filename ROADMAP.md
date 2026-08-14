# Roadmap

The canonical plan is [docs/roadmap.md](docs/roadmap.md). This file is the short
version: where the project stands, the ordered path to v3.0, and the boundaries
that do not move. Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Status

recon **v2.14.0** is the current production baseline: CLI, versioned JSON,
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
complete and both remain blocking maintenance. The v2.11 pre-collection audit
found that the frozen M365 arms cannot identify a fusion benefit: A1 collapses
to A0, A2 collapses to A3, and A3 is structurally dominated by A0. The live
window was cancelled before target contact. CT enrichment, catalog size, and
the broad agent surface still lack operator-outcome evidence.

Two emerging interchange formats are explicit design inputs, not shipped
claims: the Agent Plugins v1.0.0 working draft for portable skill and MCP
packaging, and Open Knowledge Format v0.2 for human- and agent-readable
knowledge bundles. Agent Plugins is a packaging concern distinct from MCP wire
compatibility. ADR-0014 defers an OKF projection until a named consumer can
justify its `sources`, `generated`, `verified`, lifecycle, and freshness
mapping. Any future view remains additive and never replaces recon's versioned
JSON contract.

Publication maintainers must rerun
[docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md)
before any external submission. The most recent completed historical local
submission-freeze proof is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).

## Version path (order of operations)

No calendar estimates. The rows are release-order priorities: each milestone
closes before the next version ships, while explicitly independent preparation
may run in parallel. Patch releases (2.x.y) stay available for security,
silent-failure, and contract-preserving fixes at any point.

| Version | Theme | Why this order | Done when |
|---|---|---|---|
| **v2.10.x** | Maintenance line | Protect truthfulness and supply chain while larger work proceeds | Evidence audit green; MCP 1.28.1 + 2.0.0 pins green; no known silent fail-open on default paths |
| **v2.11.0** | Product-quality baseline | Track 3. A structural preflight must prove the frozen comparison can answer its question before target collection | Aggregate-safe scorecard + dated identifiability memo; void live window recorded; fusion not promoted by the non-identifying design |
| **v2.12.0** | Apply quality decision compatibly | Uses the v2.11 structural stop without violating the stable v2 default contract | Fusion is classified as an advanced diagnostic; explicit flags are the supported transition path; v2 implicit behavior and stable JSON/MCP contracts remain intact; the default-off change is assigned to v3 |
| **v2.13.0** | Observation vs interpretation | Needs stable claim units from earlier tracks | Shipped: caller-held observation capsules; delta classifies observation / collection / time / interpretation; no silent additions or removals under unavailable source roles; ADR-0014 defers OKF without replacing JSON; full, protected-main, publication, provenance, and channel-parity gates passed |
| **v2.14.0** | Catalog quality loop | Independent of fusion promotion; rank, regional, vendor-seed, and prior-sample drift rounds are closed with aggregate-only results | Shipped: bounded provider-documented additions, frozen round contracts, aggregate-only results, explicit dispositions, and full local, protected-main, PyPI, GitHub Release, SBOM, provenance, and channel-parity proof |
| **v2.15.0** | Agent portability and surface cost - **active release priority** | Evaluate packaging and tool cuts against representative workflows from the shipped catalog baseline | Freeze tasks, clients, measures, and stop rules before implementation; validate a schema-pinned Agent Plugins candidate or explicitly defer it while the specification remains a working draft; add a core profile only if a representative client proves material benefit without losing specialist access |
| **v3.0.0** | Contract maturity | The already-deprecated fusion default change requires a major boundary; use the same boundary for any claim-envelope change that cannot remain additive | Fusion omitted-choice defaults off; explicit flags remain stable; versioned claim / observation envelope or explicit decision that v2 stays; migration notes |

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

### 3. Product-quality baseline - **v2.11 decision and v2.12 transition complete**

The network-free scorecard and aggregate-only stable-v1 live characterization
are complete. Before the declared target window, the exhaustive
[arm-identifiability audit](validation/2026-08-13-quality-arm-identifiability.md)
enumerated all 64 M365 DNS evidence-role states. It proved that the candidate
can never create the positive candidate-only discordance required by the
promotion rule. The collection window was cancelled with zero target requests.
Process evidence is rich; the stopped design supplies no population-outcome
claim.
Acceptance and stop rules live in
[docs/roadmap.md](docs/roadmap.md#3-establish-a-reproducible-product-quality-baseline)
and the
[Quality Proof execution plan](docs/strategic-gap-audit.md#quality-proof-execution-plan).

The primary claim family, four intended arms, reference label, safety margin,
and paired decision rule were frozen on 2026-08-05 in
[docs/quality-baseline-preregistration.md](docs/quality-baseline-preregistration.md),
before any collection or run. The 2026-08-13 amendment records that the arms
collapse under the shipped code and that their claimed binary emission behavior
was not operationally complete. No replacement threshold was chosen after this
finding.

`scripts/quality_scorecard.py` emits the public half of the Phase 1 baseline,
network-free and corpus-free, and names every channel it cannot measure without
the private corpus or live providers. Its first dated run is
[validation/2026-08-05-quality-baseline-scorecard.md](validation/2026-08-05-quality-baseline-scorecard.md).
The paired CT/no-CT cold-resolution, allocation, loop-lag, degradation,
warm-cache, and real MCP-result measurements are published in the aggregate-only
[2026-08-12 live-characterization memo](validation/2026-08-12-stable-v1-live-characterization.md).
The unused public population and sampling mechanism plus private-frame digest
remain recorded in the
[v2.11 frame declaration](docs/quality-evaluation-frame-declaration.md). v2.12
classifies fusion as an advanced diagnostic and begins the explicit-flag
transition without violating the stable v2 default contract. Interactive
implicit use receives a notice; redirected output remains silent. The omitted
choice changes to off only at v3, as recorded in
[ADR-0013](docs/adr/0013-fusion-non-promotion-and-v3-transition.md). v2.13
shipped the caller-held observation capsule and ADR-0014 OKF deferral after the
full, protected-main, publication, provenance, and channel-parity gates passed.
A future real-domain fusion study requires a new preregistration whose arms
first pass executable identifiability and dominance checks.

### 4. Catalog quality loop - **shipped in v2.14; maintenance gate**

The rank round is complete with a membership-bound four-band aggregate, four
bounded promoted families, explicit dispositions, and a fixed-observation
zero-regression decision. The regional round is also closed: its baseline and
clean protected-main replay each completed all 1,000 frozen rows, and its
aggregate-only
[result](validation/2026-08-13-catalog-regional-round.md) accepts six
documented provider-family additions under the fixed-observation budget. The
vendor-seed protocol, bounded source freezer, immutable receipt binding,
fail-closed preparer, evaluator, protected-main collection, and aggregate
reduction are complete. The exact 33-row HubSpot frame produced 29
corroborated and 4 observed-silent rows, with no unavailable, unmeasured, or
error outcome. No catalog rule was promoted from the evaluation holdout. This
measure is not recall because a provider relationship does not label
publication of a particular DNS record. The July baseline's 5,199 measured
rows were re-observed once from protected main under the frozen
[drift declaration](docs/catalog-drift-round-declaration.md). Its
[aggregate-only result](validation/2026-08-14-catalog-drift-round.md) reports
zero unavailable or unmeasured rows, no record-type decline beyond the
one-percent review threshold, and no catalog promotion. The result explicitly
separates the extra `_webflow` `subdomain_txt` opportunity from external DNS
drift and withholds classification comparison across unequal catalog digests.
Each contract names its independent input
stratum, or frozen prior sample for drift, plus eligibility and deduplication
rules, observation opportunities and collection options, catalog and code
digests, aggregate measures, promotion and regression budgets, and
disclosure-safe output. Preserve rejected, deferred, unavailable, and
unmeasured outcomes alongside promoted candidates.
The work measures catalog quality and freshness; it does not authorize broad
rule growth or population claims. v2.14.0 passed its full release and remote
publication gates. The v2.15 representative-client evaluation contract is now
frozen with an integrity-bound standards snapshot, three required clients,
five tasks, two full-surface variants, privacy rules, and fail-closed decisions.
After its first protected-main pass, the next operation is the schema-pinned
portable candidate and paired evaluation. No stable discovery-surface change is
authorized. Detail:
[docs/agent-portability-evaluation-declaration.md](docs/agent-portability-evaluation-declaration.md).

### 5. Optional operator-hosted access - lower priority side track

Draft container + Cloud Run IaC only. Local CLI and stdio MCP remain complete.
[docs/optional-cloud-deployment-plan.md](docs/optional-cloud-deployment-plan.md).

## What Is Deliberately Not Next

| Work | Gate that unblocks it |
|---|---|
| Broad catalog growth | Independent rank, regional, vendor-seed, and drift rounds |
| More graph or probabilistic machinery | Measured benefit from the v2.11 scorecard |
| Core-versus-advanced MCP profile | Representative client proves material context benefit |
| Portable Agent Plugins package | Pinned schema validation plus install and launch evidence from representative conformant clients; preserve native client paths |
| OKF knowledge export | A named consumer, v0.2 mapping and privacy review; ADR-0014 keeps the shipped caller-owned capsule and JSON authoritative |
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
Evidence roles are qualified on the detail and machine surfaces and may be
compacted out of the default view, never in a way that upgrades a claim
([ADR-0012](docs/adr/0012-default-view-evidence-role-visibility.md)).

**Data handling** - no committed real-target corpus; synthetic / reserved
examples; aggregate-only public validation artifacts.

**Surface stability** - CLI, JSON, MCP, cache, and import changes follow
[docs/stability.md](docs/stability.md).
Portable interchange formats remain additive projections. They do not silently
replace stable JSON, MCP, or client-specific installation contracts.

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
