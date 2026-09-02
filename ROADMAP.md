# Roadmap

The canonical product plan is [docs/roadmap.md](docs/roadmap.md). Shipped work
belongs in [CHANGELOG.md](CHANGELOG.md), and detailed historical planning belongs
in [docs/roadmap-history.md](docs/roadmap-history.md). This file is the short
operator and contributor view: current state, next work, boundaries, and gates.

## Status

recon **v2.18.3** is the current production baseline. The CLI, versioned JSON,
local stdio MCP server, bounded public-metadata collectors, fail-closed claim
audit, MCP dual-SDK matrix, and verified release path are complete. Local
execution is the default, and the project does not operate a hosted service.
Optional cloud materials remain a draft and are not a validated production
deployment.

The resolver and detection engine are feature-complete. The stable lookup,
briefing, full connection map, batch, capsule, and NamespaceReviewBundle
surfaces share one evidence and claim discipline. New product work must solve a
named operator handoff that the existing surfaces cannot solve. No v2.19
feature tranche is scheduled.

The evidence-semantic audit is complete: 29 families are complete. 0 material
runtime families carry incomplete lineage. Fail-closed inventory spans 91 score
or quantitative fields. Production MCP stays on `mcp>=2.0.0,<3`, with exact
1.28.1 rollback and 2.0.0 production rows blocking in CI.

Release verification binds each published artifact to its exact tag, workflow,
signer, and commit digest and requires SBOM provenance. One
digest-bound v2.6.3 historical exception preserves that release's
distribution-only bundle while
still requiring SBOM structure validation. Later releases fail if provenance is
absent.

## Current release and next steps

v2.17.12 shipped the stable engine's bounded audience-composition tranche for
admins, defenders, consultants, and analysts. It did not expand collection,
infer ownership, or add a security rating.

v2.18.0 shipped **NamespaceReviewBundle v1**. It is a caller-owned,
deterministic evidence handoff for one namespace. Its baseline bypasses the
lookup-result cache, keeps direct probes off, records CT as an explicit choice,
retains evidence and candidate identifiers, distinguishes completed and failed
workflows, and renders one role-neutral human report. Its digest detects content
modification but is not a signature or proof of collector identity. A future
operator-supplied set extension remains deferred until real use demonstrates a
handoff the single-namespace contract cannot solve.

v2.18.1 fixed the first stability-soak defect: degraded CNAME classification no
longer erases names supplied by successful certificate transparency. v2.18.2
updated dependency tooling and workflow pins without changing product behavior.
v2.18.3 tightened diagnostic and renderer truthfulness. v2.18.4 withdraws the
interactive fusion-transition notice; the implicit default remains enabled and
silent.

The ordered work now is deliberately small:

1. Fix compatibility, rendering, diagnostic, or provenance defects found by
   black-box use.
2. Keep the monthly fingerprint-freshness loop current. The closed 5,199-row
   drift round remains a measurement contract, not a source of automatic
   catalog promotion.
3. Run renderer parity review on every release that changes human output.
4. Keep the 29-family claim audit, both MCP SDK pins, full test gate, release
   provenance, and channel parity blocking.
5. Collect role-specific feedback before considering any new composition
   surface.

The portable Agent Plugins candidate remains an offline maintainer track. Its
schema validation and frozen client preflight are useful readiness evidence,
not a compatibility claim or conformance claim. Resume the paired client frame
only under the frozen rules in
[the agent-portability declaration](docs/agent-portability-evaluation-declaration.md).

## Version path (order of operations)

There are no calendar estimates. Patch releases remain available for security,
silent-failure, and contract-preserving fixes.

| Version | State | Boundary |
|---|---|---|
| v2.10 through v2.14 | Shipped | Evidence audit, MCP v2 adoption, the structural fusion decision, caller-held capsules, and catalog-quality measurement |
| v2.15 | Shipped | Default-view claim clarity, accessible `--plain`, and pre-collection validation |
| v2.16 | Shipped | One shared briefing across panel, plain, Markdown, and MCP text, plus renderer parity gates |
| v2.17 | Shipped | Additive downstream connection map while preserving briefing cuts |
| v2.18 | Stability soak | NamespaceReviewBundle v1 plus contract-preserving fixes and maintenance |
| v3.0, conditional | Not scheduled | Exists only if a genuine claim or observation contract change cannot remain additive; otherwise v2 remains current |

The fusion omitted-choice change is claim-neutral compatibility debt. The
implicit v2 default stays enabled and silent. `--fusion` and `--no-fusion` pin
behavior if an operator wants a fixed choice. A default change may ride a
genuine major boundary if one is required, but it does not justify a major
release by itself.

## Standing loops

| Loop | Cadence | Pass condition |
|---|---|---|
| Fingerprint freshness | Monthly and on a known vendor change or missed detection | Promoted rules have current public or disclosure-safe support, fictional positives, lookalike negatives, scoped wording, and provenance tests |
| Catalog drift | Quarterly or by declared window | Frozen thresholds hold; comparisons across unequal catalog digests are withheld; no promotion comes from the drift frame |
| Black-box renderer review | Per human-surface release | Compact surfaces keep their intended cuts and agree on claim meaning |
| Claim audit | Every material claim change | All discovered claim families remain fail closed with exact or explicitly bounded lineage |
| MCP compatibility | CI and SDK events | Exact 1.28.1 and 2.0.0 rows remain green |
| Dependency and supply chain | Weekly, on advisory, and per release | CI, CodeQL, Scorecard, secrets scan, dependency audit, SBOM, provenance, and artifact parity remain green |
| Release readiness | Every release | Main, tag, GitHub Release, and PyPI identify one commit and one artifact set |

Catalog detail lives in [docs/catalog-strategy.md](docs/catalog-strategy.md).
Quality and publication evidence lives in
[docs/strategic-gap-audit.md](docs/strategic-gap-audit.md). External submission
work must rerun the
[submission freeze checklist](docs/submission-freeze-checklist.md). The
[2026-06-30 local proof](validation/2026-06-30-submission-freeze-local-proof.md)
is the most recent historical public proof memo, not a freeze of the current
package.

## Active tracks

1. **Evidence-semantic integrity:** maintenance at the highest trust rank. Any
   new or stronger claim surface reopens the fail-closed audit.
2. **MCP compatibility:** keep both supported SDK generations and complete
   local resource/tool diagnostics green.
3. **Product quality:** stability soak, operator feedback, renderer parity, and
   reproducible black-box tests. Do not substitute feature count for quality.
4. **Catalog quality:** continue bounded freshness and drift work. Do not stamp
   unverifiable dates or promote from evaluation holdouts.
5. **Vendor-role visibility:** the human renderer decision is complete. Any
   change to stable `slugs` remains at the claim-envelope boundary.
6. **Optional operator-hosted access:** lower-priority draft work only. Local CLI
   and stdio MCP remain complete; the project does not operate a service.

## What Is Deliberately Not Next

| Work | Gate that could unblock it |
|---|---|
| New collectors, scores, or inference machinery | Demonstrated operator miss plus the existing evidence and stability gates |
| Set-level NamespaceReviewBundle | Stable single-namespace use plus a named consumer; membership remains caller-supplied |
| Broad catalog growth | Independently reviewed vendor evidence and the precision budget |
| Portable Agent Plugins promotion | Reproducible install, discovery, launch, update, and failure evidence from every frozen representative client |
| OKF knowledge export | Named consumer, v0.2 mapping, lifecycle model, and privacy review |
| More cloud provider infrastructure | Named operator and provider-specific validation |
| Project-operated public multi-tenant service | Separate product, governance, and funding decision |
| Native acceleration | Product-shaped profiling and the ADR-0010 evidence gates |
| Overall security or maturity rating | Out of scope; recon reports bounded public observations |

## Invariants

**Collection boundary:** public metadata only. DNS queries may be observed by
recursive and authoritative infrastructure. MTA-STS is the sole default
target-owned HTTP request. Google CSE and BIMI certificate probes are explicit
opt-in direct probes. No credentials, scanning, exploit checks, or generic
target application crawling.

**Claim discipline:** a domain is a query coordinate, not an organization
identifier. Sparse stays sparse. Source failure is unavailable, never negative.
Parent-platform presence is not child-product use. The public-evidence index is
not an overall security rating.

**Data handling:** no committed real-target corpus. Examples use synthetic or
reserved namespaces. Public validation artifacts are aggregate-only or carry a
disclosure-safe basis.

**Surface stability:** CLI, JSON, MCP, cache, and import changes follow
[docs/stability.md](docs/stability.md). Briefing and full-map surfaces keep their
separate jobs. Portable formats remain additive projections and never silently
replace stable JSON or MCP contracts.

## Where to read more

| Question | Document |
|---|---|
| Canonical plan and detailed gates | [docs/roadmap.md](docs/roadmap.md) |
| Historical planning | [docs/roadmap-history.md](docs/roadmap-history.md) |
| Shipped changes | [CHANGELOG.md](CHANGELOG.md) |
| Evidence and quality proof | [docs/strategic-gap-audit.md](docs/strategic-gap-audit.md) |
| Claim audit | [docs/default-claim-audit.md](docs/default-claim-audit.md) |
| Catalog maintenance | [docs/catalog-strategy.md](docs/catalog-strategy.md) |
| Release process | [docs/release-process.md](docs/release-process.md) |
| Publication freeze | [docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md) |
