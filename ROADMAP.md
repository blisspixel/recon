# Roadmap

The canonical plan is [docs/roadmap.md](docs/roadmap.md). This file is the short
version: where the project stands, the ordered path to v3.0, and the boundaries
that do not move. Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Status

recon **v2.17.12** is the current production baseline: CLI, versioned JSON,
local stdio MCP, bounded public-metadata collectors, fail-closed claim audit
gates, MCP dual-SDK matrix, and a release path with provenance, SBOM, and
channel parity. Local execution is the default, and the project does not operate
a hosted service. Optional cloud draft materials are directionally useful, not a
validated production deployment.

**The engine is feature-complete.** The surfaces are closed and mutually
consistent (one shared briefing, gated by the surface-parity matrix), the claim
contract and its provenance are enforced, the inference model is bounded and
evidence-disciplined, the release machinery is complete, and MCP compatibility is
characterized rather than expanding. No engine milestone stands between here and
"done." A v3.0 is **conditional**, not scheduled: it exists only if the
claim/observation-envelope decision (parked at the v3 boundary) resolves to a
break that cannot remain additive, and if it never does, there is no v3.0. The
long-deprecated fusion default flip is claim-neutral, schema-stable compatibility
debt that rides that major if it ships and otherwise stays deferred behind the
stable `--fusion` / `--no-fusion` flags; it is not itself a reason to cut a major
(ADR-0013 amendment, 2026-08-18). What remains is not version work: it is the
standing maintenance loops, the fingerprint-freshness loop chief among them.

Release verification binds every published artifact to its exact tag, workflow,
signer, and commit digest, and requires SBOM provenance. One
digest-bound v2.6.3 historical exception preserves that release's published
distribution-only bundle while still requiring SBOM structure validation; every
later release fails if SBOM provenance is absent.

The evidence-semantic audit is complete: 28 families are complete. 0 material
runtime families carry incomplete lineage. Fail-closed inventory spans 91 score
or quantitative fields among other governed surfaces. MCP v2 adoption is
complete and both remain blocking maintenance. The v2.11 pre-collection audit
found that the frozen M365 arms cannot identify a fusion benefit: A1 collapses
to A0, A2 collapses to A3, and A3 is structurally dominated by A0. The live
window was cancelled before target contact. CT enrichment, catalog size, and
the broad agent surface still lack operator-outcome evidence.

Two interchange formats are explicit design inputs, not shipped compatibility
claims: the Published Agent Plugins v1.0.0 specification for portable skill and
MCP packaging, and Open Knowledge Format v0.2 for human- and agent-readable
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

## Next

The next product work improves how three audiences reach the existing evidence
without expanding collection or turning observations into verdicts:

1. **Admins:** make installation identity explicit, including the running
   package, interpreter, launcher, and an actionable warning when PATH resolves
   to a different recon version.
2. **Defenders:** provide one evidence-first review workflow that leads with
   collection validity, preserves unavailable and unresolved states, and ends
   with neutral review candidates.
3. **Consultants and analysts:** compose the existing batch ecosystem and cohort
   summary into one backward-compatible JSON bundle for an operator-supplied
   domain set, without inferring ownership or ranking security.

These are workflow and diagnostic improvements inside the stable v2 engine.
They add no target interaction, active scanning, credentials, hosted service,
or overall security score.

The fingerprint-freshness loop continues alongside that work. It has no version
number because it never finishes. Monthly, plus on a missed-detection report or
a known vendor change:
confirm independently reviewed families against the vendor's current public page,
backfill `verified` dates only where that page still names the pattern, and seed
new rules from vendor documentation before a corpus row exhibits them. Most
detections still lack a `verified` date; that undated share is the backfill
queue, not a reason to stamp today's date. Coverage is
`python -m validation.audit_fingerprints --freshness`. Detail:
[docs/catalog-strategy.md](docs/catalog-strategy.md#3-freshness).

The 2026-08-20 pass raises dated coverage from 61 of 1,091 detections (5.6
percent) to 138 of 1,108 (12.5 percent). It confirms current TrendAI regional MX
and SPF patterns, Barracuda inbound MX, Cisco Cloud Gateway `iphmx.com`, all 22
AWS SES email-receiving regions, and current Google Workspace, Microsoft 365,
and AWS SES SPF values. Unverified legacy observations remain undated.
Current Akamai edge CNAME suffixes are also dated from its Property Manager
documentation. The bounded HubSpot review dates its current
`hubspotemail.net` SPF and two `hubspot.net` CNAME rules. Seven HubSpot rules
remain undated because current first-party pages do not name their exact pattern
and role. Proofpoint remains blocked because its public pages do not name the
exact gateway hosts. The bounded Marketo review dates its current
`mktomail.com` SPF, two `mktoweb.com` CNAME rules, and the exact documented
tracking-link host form. Five Marketo patterns remain undated without exact
current first-party support. The bounded Salesforce Marketing Cloud review then
dates eight CNAME and discovered-target rules for `exacttarget.com`,
`sfmc-content.com`, `sfmc-marketing.com`, `marketingcloudapis.com`, and
`exct.net`. Its `exacttarget.com` SPF and `SFMC-` TXT observations remain
undated without precise current first-party DNS-role support. The AWS
load-balancer correction then replaces seven partial regional `aws-nlb` rules
with one partition-aware ELBv2 pattern, retains the stable slug, and makes the
ALB/NLB ambiguity explicit. The API Gateway correction similarly replaces five
partial regional rules with one partition-aware pattern and excludes
edge-optimized CloudFront and private VPC endpoint forms. The Microsoft pass
then separates Azure Communication Services Email's
`ms-domain-verification=` token from Microsoft 365's `MS=ms########`, narrows
commercial Autodiscover and GCC High MX to exact current targets, and dates the
supported government SPF, government application-domain, and SharePoint roles.

v2.17.5 now carries this batch after a reviewed pull request, protected-main
checks, PyPI and GitHub publication, SBOM provenance, and exact channel-parity
verification. A follow-up review closes the named Microsoft residual queue:
current Microsoft endpoint guidance supports bounded `tm-3.office.com`,
`svc.cloud.microsoft`, and `svc.sovcloud.cn` routing observations, while
current Exchange guidance supports narrowing the broad `eo.outlook.com` rule
to the documented legacy `mail.eo.outlook.com` MX family. All four gain scoped
wording, current references, and positive plus deceptive suffix fixtures.
`msv1.invalid` remains undated because no current first-party
product page documents its exact role; its unsupported migration-state claim is
removed. Proofpoint remains blocked for the same evidence reason. Detail:
[2026-08-20 Microsoft residual review](validation/2026-08-20-microsoft-residual-review.md).

The 2026-08-21 Statuspage review then checks all seven rules after the shared
catalog reference began returning HTTP 404. Current Atlassian DNS guidance
supports the exact `status-page-domain-verification=` custom-email TXT,
`stspg-customer.com` SPF include, and `<PAGE_CODE>.stspg-customer.com`
CNAME-target family. Those three gain dates and bounded roles. The no-hyphen
TXT variant plus `statuspage.io` and `statuspageio.com` CNAME observations stay
undated because current first-party pages do not document their cataloged DNS
roles. Detail:
[2026-08-21 Statuspage fingerprint review](validation/2026-08-21-statuspage-fingerprint-review.md).

The follow-up 2026-08-21 Zendesk review checks all six rules against current
Zendesk email-domain and host-mapping guidance. It corrects the TXT observation
from an unsupported apex `zendeskverification=` value to the documented
`zendeskverification.<domain>` owner, dates the exact `mail.zendesk.com` SPF
include and both `zendesk.com` CNAME roles, and narrows every claim. The apex
`zendesk-domain-verification=` value and broad `zendesk.com` SPF family remain
undated because current first-party pages do not name those exact roles.
Detail:
[2026-08-21 Zendesk fingerprint review](validation/2026-08-21-zendesk-fingerprint-review.md).

The next 2026-08-21 pass reviews Tencent EdgeOne's five undated CNAME-target
rules. Current first-party API examples exactly support shards 0, 2, 3, and 5,
so the pass adds the missing shard 0 rule and dates those four forms. Shards 1
and 4 remain undated because the reviewed current pages do not name those exact
forms. Every description is narrowed to an observed routing relationship and
does not claim traffic, enabled CDN or WAF features, or current configuration
state. Detail:
[2026-08-21 Tencent EdgeOne fingerprint review](validation/2026-08-21-tencent-edgeone-fingerprint-review.md).

The 2026-08-30 Cloudflare review is complete. The catalog now has 1,112
detections, 157 dated (14.1 percent), with zero stale dated rules. Detail:
[2026-08-30 Cloudflare fingerprint review](validation/2026-08-30-cloudflare-fingerprint-review.md).

Agent portability stays a maintainer track, not a product milestone. The frozen
[representative-client contract](docs/agent-portability-evaluation-declaration.md)
is green offline, the pinned v1.0.0 schema bytes still match the Published
canonical schemas, and the three-client/runtime preflight passes with v2.17.5.
GPT-5.6 Luna is the declared common model and $5 is the hard total
external-charge ceiling. Collection is deferred under the frozen stop rule:
account-side hard stops and a reproducible three-desktop-client driver were not
verifiable from this environment. No model session started and external spend
is $0. Resume the complete 30-session frame only when both gates are
demonstrably enforceable; do not shrink or substitute it. Detail:
[2026-08-20 portability cost gate](validation/2026-08-20-agent-portability-cost-gate.md).

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
| **v2.15.0** | Default-view claim clarity and accessibility | Two independent black-box passes found the compact surfaces, not the data, were misreading themselves; the fix could not wait behind a milestone blocked on third-party client availability | Shipped: ADR-0015 role-split vendor claims in the default view; ADR-0016 `--plain` renders the panel with the full record behind `--full`; pre-collection flag validation so a typo cannot reach the network; docs, roadmap, and schema notes reconciled to the shipped behavior |
| **v2.16.0** | Renderer parity: one briefing in every shape | A fourth and fifth black-box round confirmed the standing defect class was presentation drift, one decision applied to one renderer and not the others. This is the reopened form of the evidence-integrity track, not a new one: a note that miscounts is a false claim recon emits about itself | Shipped: `build_briefing` shared object rendered by the panel, `--plain`, `--md`, and the MCP text surface; MCP JSON fusion populated; `--plain --full` role keys; the gated `docs/surface-parity.md` matrix that fails on cross-surface drift; ADR-0017 and the `--plain`/`--md` SemVer reconciliation. Round-5 tester pass confirmed |
| **v2.17.0** | Downstream connection map | Independent black-box feedback treated TXT, AI, senders, and related hosts as residue to hide. That is the opposite of the product: those rows are the public connection map a support bot, mail conversation, or AI-stack bias routes on | Shipped: additive JSON `connection_map` (lanes, roles, related-host classes, role-matched summaries); `--md` uses panel lanes instead of Tech Stack; `--md --full` and panel `--full` classify related hosts; default briefing cuts stay |
| **v3.0.0** *(conditional)* | Contract maturity, only if a break is required | Exists only if the claim/observation-envelope decision resolves to a change that cannot remain additive; the long-deprecated, claim-neutral fusion default flip rides that boundary as a passenger. If the envelope decision defers (the ADR-0014 pattern), there is no v3.0 and the engine stays feature-complete with the default on behind the stable flags | Either: a versioned claim / observation envelope with the fusion default flipped off and migration notes; or an explicit decision that v2 stays, in which case v3.0 is not cut |

Optional cloud operator hosting stays a **side track** (any 2.x after local
default stays complete). It never unblocks product-quality work and never
creates a project-operated multi-tenant service without a separate product
decision.

Agent portability and surface cost is a **maintainer track**, not a version-path
milestone. Published v1.0.0 and its canonical schemas now match the pinned
candidate basis, and the frozen VS Code, Cursor, Kiro, and recon-runtime
preflight passes. That readiness evidence is not compatibility or conformance.
GPT-5.6 Luna and a $5 total external-charge ceiling are declared, but the
paired frame is deferred until account hard stops and a reproducible
three-desktop-client driver are verifiable. It does not queue product work
behind it. Publication, OpenSSF questionnaire,
outside replication, and archive/DOI are the other maintainer tracks on external
events. They do not displace the version path above.

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
publication gates. The representative-client evaluation contract is now
frozen with an integrity-bound standards snapshot, three required clients,
five tasks, two full-surface variants, privacy rules, and fail-closed decisions.
Its protected-main prerequisite passed. The deterministic complete-surface
candidate under `agents/agent-plugin/` passes network-free validation against
the byte-pinned Agent Plugins v1.0.0 schemas and frozen Agent Skills field
rules. A second maintainer-local, network-free preflight on 2026-08-20 passed
with recon 2.17.4 and all three required clients available; a later rerun passed
with the exact v2.17.5 candidate and the same client versions. Zero sessions
ran. GPT-5.6 Luna is the declared common model and $5 is the hard total
external-charge ceiling, but collection is deferred because account-side hard
stops and a reproducible driver for all three desktop clients were not
verifiable. No compatibility claim or stable discovery-surface change is
authorized.
Detail:
[docs/agent-portability-evaluation-declaration.md](docs/agent-portability-evaluation-declaration.md).

### 5. Vendor-role visibility - **panel half decided; `slugs` half open**

A 2026-08-15 black-box play-test found that a record can present several
defensible surfaces that read as different answers. When a vendor's evidence
comes from an identity endpoint, `tenant_id`, `auth_type`, `cloud_instance`,
`detection_scores`, `slug_confidences`, and `evidence` all carry it, while the
compact panel named only the mail vendor in a singular, unroled `Provider` row.
Each surface was individually correct; together they let a reader who stopped at
that row take a mail-path indicator as the primary vendor.

The 2.14.1 pass populated the split on an authorized target and retired the
"document it" position: the record it found had `microsoft365` present in
`slugs` **and** `services` with the panel still withholding it, so the
documentation note did not describe the observed case, and a schema document
does not reach a reader before they read the panel.

[ADR-0015](docs/adr/0015-role-split-vendor-claims-in-the-default-view.md)
settles the rendering half. The default view names a mail vendor and an identity
vendor separately, with their roles, when the two differ; `Services` gains an
`Identity` row; `Model support` names every above-threshold tenant-class claim.
The identity role is derived from evidence provenance rather than slug category.
Single-vendor records are unchanged and no claim is upgraded.

Still open: whether `slugs` itself should carry identity-observed vendors.
`slugs` is a stable v2 field documented as fingerprint-catalog pattern matches,
so widening it is a contract change, not a rendering choice. It stays against
the v3 claim-envelope boundary and cannot change silently.

[ADR-0016](docs/adr/0016-plain-emits-the-panel-record.md) resolves the related
accessibility finding from the same two passes: `--plain` renders the panel's
rows, and the full structured record moves behind `--plain --full`. That is a
breaking change to one human-facing renderer, recorded in
[docs/stability.md](docs/stability.md) with the migration named.

A third pass confirmed both decisions on the published package and found the
`--plain` half shipped half-applied: the rows were the panel's, the *cuts* were
not, so a populated record still linearized every related domain, and the
`provider:` key the guide tells a stranger to grep went missing on the record
class the split exists for. The ADR-0016 amendment records the fix. The panel
and the linear view now share one definition of what the default briefing shows
and what it withholds, which is what kept them from drifting apart again.

### 6. Optional operator-hosted access - lower priority side track

Draft container + Cloud Run IaC only. Local CLI and stdio MCP remain complete.
[docs/optional-cloud-deployment-plan.md](docs/optional-cloud-deployment-plan.md).

## What Is Deliberately Not Next

| Work | Gate that unblocks it |
|---|---|
| Broad catalog growth | Independent rank, regional, vendor-seed, and drift rounds |
| More graph or probabilistic machinery | Measured benefit from the v2.11 scorecard |
| Core-versus-advanced MCP profile | Representative client proves material context benefit |
| Promote the portable Agent Plugins candidate | Install, discovery, launch, update, and failure evidence from every frozen representative client; preserve native client paths until all gates pass |
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
