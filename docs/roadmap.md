# Roadmap

This file is the canonical product plan and scope boundary. Shipped work belongs
in [CHANGELOG.md](../CHANGELOG.md). Historical planning lives in
[roadmap-history.md](roadmap-history.md). Release mechanics live in
[release-process.md](release-process.md). Research and publication work is
tracked separately from product work.

> **Status:** v2.5.1 is current. The stable baseline is complete: recon ships a
> local CLI, importable library, versioned JSON contract, local stdio MCP
> server, bounded passive collectors, generated-artifact guards, and a verified
> release path. The product is not "finished." The active work is to make every
> default claim evidence-tight, prove that advanced inference adds user value,
> characterize MCP v2 compatibility, and make latency, degradation, catalog
> quality, and agent context cost measurable.
>
> **Code-graph orientation:** refresh the ignored
> `.agent/codegraph/manifest.json` after each tracked milestone and read it for
> the exact build commit, trust level, checks, and counts. A current high-trust
> graph with passing integrity checks is required before broad changes. The
> graph is an implementation aid, not a substitute for source and test
> verification.

## Product Goal

recon composes typed public DNS, certificate-transparency, and unauthenticated
identity evidence around a domain query coordinate while preserving scope,
time, dependence, collection opportunity, and ambiguity. A domain is not an
organization identifier. The result is a conservative, provenance-bearing view
of its public technology and identity namespace, and its best answer is
sometimes "unresolved." It must not turn parent-platform presence, sparse
metadata, a model score, or missing public evidence into a claim about product
use, security maturity, ownership, or exploitability.

The primary workflows are:

1. Single-domain public-evidence summary.
2. Explanation and provenance for every material claim.
3. Operator-supplied comparison, batch, or related-domain analysis.

Advanced graph, posterior, hypothesis, simulation, catalog-mutation, and
fingerprint-discovery surfaces remain available for specialist workflows. They
must earn their complexity through measured value and must not obscure the
three primary workflows.

## Priority Order

### 1. Restore evidence-semantic integrity

Status: active, highest trust priority. The live MCP instruction,
score-description, parent-platform child-product, and cross-renderer provider
summary corrections ship in v2.4.0.

Why first: output truthfulness is more valuable than another feature. The
roadmap review found a sparse-output fixture that inferred Copilot use from a
parent tenant even though the evidence could not establish child-product
licensing, enablement, deployment, or use. That inference and the earlier MCP
target-interaction and score overstatements are now corrected with regression
tests. Provider topology now also uses one evidence-aware summary across panel,
JSON, CSV, MCP, and chain output. Source-derived Markdown service labels now
cross an escaped output boundary, and service sections use exact,
mutually exclusive provider grouping instead of broad substring matches. The
inference-confidence path now groups error-free source types and sources by
canonical claim, so failed or unrelated provider evidence cannot corroborate
a different claim. Duplicate result objects from one source count once, and
explanations name the exact winning claim and qualifying evidence.
The wider default-claim, generated-guidance, and recommendation audit remains
open. Current sovereignty handling preserves absent metadata as unknown; that
invariant should remain explicit and tested.

Work:

- Audit every default panel insight, service label, live MCP instruction and
  tool description, generated agent guidance item, recommendation, and score
  label against its direct provenance path.
- Treat the queried apex as a namespace coordinate, never an organization
  identity. Audit shared-token, tenant, display-name, issuer, vendor, CT, and
  related-domain language so exact observed overlap is not promoted into
  ownership, shared control, account identity, or current-use claims.
- Define one machine-readable internal claim contract before creating another
  inference layer. It must declare the narrow claim and scope, positive
  alternatives, genuine authoritative negatives, source-success preconditions,
  dependency groups, freshness, renderer obligations, generation-time rule
  lineage, and regression fixtures. Heuristic reconstruction from rendered
  insight or posture text cannot satisfy exact provenance.
  - Completed in v2.5.0 for
    `dns.dmarc.valid_policy_is_reject.v1`; see
    [claim-contracts.md](claim-contracts.md). Exact evaluator lineage reaches a
    collector-retained raw record; general generator lineage and per-query time
    remain open. No tenant field or public dossier was added. The separate
    cohort-summary contract adds 2.2 as an explicit option while 2.1 remains the
    default.
- Model construction, collection, claim state, and time as orthogonal axes.
  Design an internal observation-opportunity ledger with `not attempted`,
  `observed value`, `observed empty`, `unavailable`, `not enabled`, and `not
  applicable`; keep the stable `EvidenceRecord` and `degraded_sources` shapes as
  compatibility projections until an additive contract earns promotion.
- Prototype an internal claim dossier for that one family: four-state result,
  minimal supporting and authoritative-negative certificate antichains,
  incomplete provenance, unavailable channels, observation window, conflicts,
  and permitted resolving evidence. Use bounded frozen-set antichains, not a
  new dependency or an unreviewed broad ontology.
  - Completed for the first DMARC contract with bounded exact antichains,
    fail-closed limits, explicit provenance limitations, and replay after
    canonical ledger union.
- Encode the four states as a two-coordinate knowledge lattice. Merge canonical
  provenance ledgers by associative, commutative, idempotent unit union, then
  recompute rule closure and certificate antichains. The state projection must
  be monotone for reviewed monotone rules but is not generally a homomorphism:
  premises split across views may create a new derivation. Expiry or retraction
  must replay the remaining ledger instead of trying to invert a merge.
- Keep the shipped regression guard that rejects child-product use or
  deployment claims inferred only from a parent platform.
- Preserve missing cloud metadata as unknown.
- In human-facing output, describe `email_security_score` as a count of
  observable public email controls and the 0-100 value as a model-bound
  public-evidence index. Preserve stable JSON fields until a versioned contract
  change is justified.
- Separate observed configuration, defined public absence, and unresolved
  non-observable state in recommendations.
- State the default target-visible MTA-STS policy fetch and opt-in CSE and BIMI
  requests anywhere the product summarizes its collection boundary.
- Design, but do not expose prematurely, a defaulted provenance envelope that
  can carry record owner, source family, observation time, scope, and freshness
  semantics. Any stable schema addition follows
  [ADR-0003](adr/0003-v2-schema-lock.md).

Acceptance evidence:

- Every material default claim has a direct evidence-to-claim path.
- Every material cross-domain statement names the exact typed overlap and keeps
  alternative explanations open; shared administrative tokens, tenant IDs,
  broad providers, and public issuers do not become ownership verdicts.
- The first claim contract has positive, explicit-disconfirming, conflict,
  unavailable, empty, invalid, stale, time-unknown, and duplicate-derivation
  fixtures in `tests/test_claim_contract.py`. Its result is invariant to
  duplicate renderings of one evidence unit. Empty DNS results remain
  unresolved until authority or authenticated-denial provenance is retained.
- Property tests establish canonical-ledger union laws, duplicate invariance,
  monotone state projection, and a cross-view conjunction whose support appears
  only after merged-ledger closure. Adding evidence cannot erase an already
  established sign under the reviewed monotone rule system.
- Explanation output reports provenance completeness and disconnected terminal
  claims instead of asserting a complete path when none exists.
- Sparse golden outputs contain no product-use inference derived solely from a
  parent platform.
- Missing sovereignty metadata never produces a commercial-cloud conclusion.
- No default output presents a public-evidence index as overall security
  maturity.
- Existing v2 JSON compatibility remains green unless an explicitly versioned,
  additive schema change is approved.
- Relevant golden, cache, schema, explanation, panel, and MCP tests pass.

Stop rule: do not add new inference or scoring semantics while a known default
claim lacks adequate evidence.

### 2. Characterize MCP v2 beta compatibility before 2026-07-28

Status: ready. The previous waiting trigger was met when official Python SDK
`2.0.0b1` shipped on 2026-06-30.

Why second: the final MCP 2026-07-28 specification and stable Python SDK are
time-bound external changes. Production remains on the stable v1 SDK line until
the candidate passes recon's gates.

Work:

- Exact-pin `mcp==2.0.0b1` in an isolated compatibility environment. Do not
  publish or widen the production dependency to a prerelease.
- Exercise server import, stdio startup, `recon mcp doctor`, discovery, tool
  calls, resource reads, structured output, errors, and deterministic listing
  under v1.28.1 and the v2 beta.
- Record a migration result for `FastMCP`, protocol types, `ToolError`,
  annotations, discovery, wire aliases, and synchronous resource handlers.
- Review shared catalog and cache behavior under the v2 worker-thread model.
- Either prove the declared `mcp>=1.0` floor in CI or raise it to the first
  supported version.

Acceptance evidence:

- A dated compatibility matrix covers both SDK generations.
- Tool and resource order is deterministic.
- Declared output schemas and structured results conform under both tested
  generations.
- Every complete `server/discover`, `tools/list`, supported resource-list, and
  resource-read result carries valid `ttlMs` and `cacheScope` hints as required
  by the draft caching specification.
- The local stdio workflow remains intact.
- Production stays on `<2` until the stable v2 SDK and final specification pass
  the full gate.
- Remote HTTP, OAuth, Roots, Sampling, Apps, Tasks, and protocol logging are not
  added without a named product need and a separate architecture review.

Detailed work and rollback criteria live in
[mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md) and
[ADR-0009](adr/0009-mcp-2026-readiness.md).

### 3. Establish a reproducible product-quality baseline

Status: specified, depends on the claim taxonomy from priority 1.

Why third: the project has extensive implementation and assurance checks, but
it does not yet measure whether probabilistic fusion, CT enrichment, a large
fingerprint catalog, or a broad MCP surface materially improves a predeclared
operator outcome over deterministic evidence plus explicit abstention.

Work:

- Create an aggregate-safe scorecard using synthetic fixtures plus
  maintainer-local, disclosure-controlled real-domain evaluation.
- Measure claim-family precision where independent labels exist, unsupported
  claim rate, abstention and unresolved rate, explanation completeness,
  classified versus unclassified observable surface, degraded-source rate,
  p50/p95 cold and warm latency, peak allocation, CT marginal signal gain, and
  MCP discovery and result payload bytes.
- Run a predeclared ablation with four distinct arms: deterministic evidence
  plus abstention, per-slug evidence strength, the strongest reviewed evidence
  unit, and the current Bayesian network. Treat a negative result as useful
  evidence, not as a reason to adjust the decision rule after seeing results.
- Require each future source, inference, catalog, or graph change to name the
  metric it should improve and the regression budget it must preserve.
- Run the stable-v1 resolver, allocation, CT-value, and schema characterization
  before completing the scorecard. It supplies performance inputs to this
  priority; only candidate-SDK deltas wait for the MCP v2 matrix.

Primary evaluation design:

- Operator decision: for one material claim in a single-domain summary, should
  the operator accept it as supported by the public channel or see it remain
  unresolved?
- Unit: predeclare one primary claim family, the current Bayesian candidate, and
  the deterministic comparator. Each unique domain contributes one frozen
  `(domain, claim_family, observation_time)` row and one independent reference
  label, and every arm receives the same raw snapshot. Admit at most one domain
  from each known administrative, ownership, or tenant cluster in the primary
  analysis. This keeps the domain row identical to the Bernoulli unit used by
  the paired decision rule. Unknown cross-domain dependence remains a
  limitation. A clustered multi-domain analysis is secondary until it defines
  a cluster-level estimand, outcome, and decision rule. Domain groups are kept
  intact across parameter-development, calibration, and evaluation splits. Any
  corpus that informed a prior or likelihood is a development corpus and cannot
  supply primary rows. Repeated observations, other claim families, and other
  arm contrasts are sensitivity analyses only and cannot change the primary
  decision.
- Sampling model: before collection, name the target population, eligibility
  window, positive- and negative-stratum sampling frames, and sampling
  mechanism. Population-coverage interpretation for the paired
  Clopper-Pearson bounds and prospective power analysis requires independent
  exchangeable Bernoulli units within each stratum after known-cluster
  exclusion, or a probability sampling design with matching design-based
  inference. For a fixed or purposively selected corpus, `(b-c)/n` is only the
  exact empirical corpus effect. Any binomial interval is then model-based on
  an unverified exchangeability assumption and cannot support population
  promotion.
- Labels: an independent provider-owned endpoint, standards-defined public
  record, or other predeclared authoritative source that is not an input to the
  compared predictor. A family without an independent reference reports only
  coverage, provenance, and disagreement diagnostics, never precision.
- Primary benefit estimand: **reference-positive support rate**, the number of
  independently labeled positive units emitted as supported divided by all
  independently labeled positive units. Candidate-minus-baseline is positive
  when the candidate supports more true claims.
- Primary safety estimand: **reference-negative unsupported-emission rate**, the
  number of independently labeled negative domains emitted as supported divided
  by all reference-negative domains. Candidate-minus-baseline is positive when
  the candidate causes more unsupported emissions. The negative-stratum
  denominator prevents the safety metric from changing with an intentionally
  stratified label mix. Also report selective risk, unsupported emissions
  divided by all supported emissions, but do not use that unstable ratio as the
  primary gate when an arm emits nothing.
- Secondary evaluation: report abstention, overall emission rate,
  distinct-score or tie-preserving reliability, provenance completeness,
  latency, and allocation. Report Brier and log score only for an arm whose
  total frozen forecast is explicitly interpreted as
  `P(reference-positive | frozen inputs)` on every eligible two-class row, with
  a predeclared abstention convention. An arbitrary evidence-strength score
  qualifies only after its mapping is fitted on disjoint development data and
  frozen. Otherwise exclude the arm from proper-score comparison or label any
  plug-in loss descriptive, not proper-score evidence. Any interval must name
  its resampling unit and assumptions. Do not call a model calibrated from an
  overlapping, one-sided, or parameter-development reference.
- Prevalence-sensitive secondary metrics: when label strata have different
  sampling rates, pooled abstention, unresolved, overall emission,
  proper-score risk, reliability, and selective risk require known inclusion
  probabilities and frozen design or post-stratification weights for the target
  population. Without them, report stratum-specific or fixed-sample descriptive
  values and make no population rate or calibration claim.
- Minimum evidence for a decision: at least 100 independently labeled unique
  primary units, including at least 30 reference-positive and 30
  reference-negative units. This floor is not a power claim. Before collection,
  run a power analysis under the exact paired rule, the selected safety margin,
  and plausible discordance rates, then increase the sample if needed. Report
  every arm's emission and discordance counts. Selective risk for an arm with
  fewer than 30 supported-emission unique domains is descriptive only. A corpus
  that misses either primary label stratum is ineligible for the decision gate.
- Boundary-valid paired rule: within each label stratum, count candidate-only
  supported decisions `b`, baseline-only supported decisions `c`, and unique
  domains `n`. Construct a conservative one-sided 95 percent bound on
  `(b - c) / n` by subtracting Bonferroni-adjusted one-sided
  Clopper-Pearson bounds for the two discordance proportions. Use a lower bound
  for benefit in the positive stratum and an upper bound for safety in the
  negative stratum. This remains uncertain when both arms make zero unsupported
  emissions; unlike a percentile bootstrap, it cannot collapse to a false
  `[0, 0]` safety conclusion at the boundary.
- Promotion rule: before reading outputs, choose and justify a small positive
  absolute safety noninferiority margin, freeze the tail probability and
  implementation, and require both co-primary conditions: the benefit lower
  bound is above zero, and the safety upper bound is below that margin. Also
  require the empirical zero-regression safeguard `b_negative == 0`: the
  candidate may not introduce an unsupported emission on any negative domain
  that the baseline left unresolved. A zero margin would be strict safety
  superiority, not noninferiority, and is prohibited under the boundary case.
  Because both co-primary conditions must pass, this is an intersection-union
  decision; additional arm or family claims need a predeclared multiplicity
  procedure.
- Reporting: publish raw paired counts and candidate-minus-baseline effect
  bounds. Under simple exchangeable sampling within label strata, a paired
  domain bootstrap may be reported only as a secondary sensitivity analysis:
  resample the positive and negative strata separately, apply the same sampled
  units to every arm, and preserve both denominators. Under a complex
  probability design, any resampling interval must reproduce the frozen
  strata, primary sampling units, and inclusion weights or use a valid survey
  bootstrap. Otherwise label it a fixed-sample sensitivity with no
  design-based coverage interpretation. Repeated observations belong only in a
  separate longitudinal sensitivity analysis clustered by domain. Neither
  analysis can rescue an inconclusive primary result. An inconclusive or
  negative result moves fusion to an explicitly advanced diagnostic.

Acceptance evidence:

- A dated baseline, reproduction command, environment description, and
  aggregate result memo exist.
- No real apex, organization name, tenant ID, or per-domain row is committed.
- The ablation decision rule is written before the run.
- The result determines whether advanced fusion remains in the primary path or
  becomes an explicitly advanced diagnostic.
- Coverage remains above the enforced 90.2 percent branch-aware project gate and
  the 80 percent user bar, with no regression from the current baseline, and
  the full local CI mirror passes.

Stop rule: do not expand graph or probabilistic machinery without measured
benefit to a named user outcome.

## Next

These tracks follow the top three in dependency order. The stable-v1 portion of
the async and schema characterization is a supporting input to priority 3 and
runs before its scorecard; only candidate-SDK deltas wait for priority 2.

### Separate observation change from interpretation change

The shipped delta path compares rendered snapshot outputs. A catalog, model,
software version, normalizer, evaluation time, collection option, resolver
vantage, cache state, or source failure can change those outputs without a
public target-state change. Immediate degradation-aware suppression keeps
unavailable previous channels from becoming confirmed additions, unavailable
current channels from becoming confirmed removals, and dependent scalar
comparisons from proceeding without both observation opportunities. Exact
temporal semantics require replayable local observation capsules.

After the observation ledger and first claim contract are stable, define a
caller-held capsule containing replayable raw response content or references,
normalized observations, per-source opportunity states, observation windows, a
frozen evaluation `as_of`, cache and vantage metadata, collection options,
software and normalizer versions, catalog and model digests, and a content
digest. Compare public observations by applying one frozen normalizer to both
raw capsules. Classify comparison results as observation, collection-regime,
time-evaluation, or interpretation deltas. Store stable signal identifiers
instead of reconstructing them from human-facing insight prose.

Acceptance evidence:

- current v2 delta fields remain compatible and incomplete comparisons name the
  degraded sources and withheld changes;
- replaying the same capsule under the same version is deterministic apart from
  excluded render timestamps;
- replaying one capsule under a different explicit `as_of` produces only a
  time-evaluation delta and resulting freshness-state changes;
- replaying the same facts under different catalog or model versions creates
  interpretation deltas only;
- unavailable previous sources cannot create fact additions, unavailable
  current sources cannot create fact removals, and dependent scalar changes
  require both endpoint opportunities;
- every confirmed fact delta names comparable source roles and observation
  windows;
- storage remains local and caller-owned; monitoring and longitudinal retention
  require a separate privacy and architecture review.

### Prototype provenance-constrained claim robustness after the baseline

The advanced correlation thesis is not a narrower heuristic interval around one
committed posterior. It begins with separate Boolean must/may envelopes for
positive public support and authoritative public disconfirmation over explicit
evidence-removal, evidence-planting, dependence, and parameter assumptions. A
robust score envelope is secondary. Neither is a probability bound or
identification region. The formal proposal and promotion requirements are in
[correlation.md](correlation.md).

Start only after the priority 3 decision rule and evidence-unit taxonomy are
frozen. Classify units as provider-attested, functionally routing,
standards-declarative, administrative, historical structural, or derived. Make
manipulation costs claim-specific and expose them as assumptions. Scalar
budgets require a predeclared strictly positive additive cost for every
admissible nonidentity manipulation; identity has cost zero, and forbidden
actions are excluded or assigned infinite cost. Prefer Pareto or lexicographic
budgets over unlike action classes instead of summed ranks. Under either vector
budget, every nonidentity action has a componentwise nonnegative, nonzero cost
vector, and only identity has the zero vector. The first prototype remains an
advanced diagnostic and must not change the stable schema.

Acceptance evidence:

- Exhaustive enumeration and the optimized solver agree on bounded fixtures.
- Boolean positive and authoritative-negative must/may results are primary; a
  graded score never overrides a supported, disconfirmed, conflicted, or
  unresolved Boolean state.
- In the separately labeled forward-planting sensitivity, administrative-only
  additions cause zero transitions from initially unresolved or not-supported
  cases to supported at the predeclared support threshold.
- Every lower and upper bound names an attaining witness for the finite
  prototype, or an epsilon-optimal witness with a declared tolerance, plus the
  dependency unit, provenance path, threat model, and budget.
- Budget monotonicity, zero-budget collapse, dependency-unit invariance, and
  inverse compatibility-certificate replay pass as property tests. Separately
  named forward flip certificates also replay exactly.
- Bounded fixtures enumerate the complete primary inverse Boolean
  decision-flip antichain for the selected four-state decision. Secondary score
  lowering or raising antichains are named separately and never substitute for
  the Boolean family. Any forward deletion or addition sensitivity is also
  separately named and tested. A production cap carries an explicit
  `enumeration_complete=false` diagnostic rather than implying completeness.
- Where independent verification can exclude an observed-unit planting action,
  the prototype may report a minimum-cost conditional inspection set that
  intersects every selected adverse Boolean witness's verifiable observed-unit
  set. It must state that witness blocking depends on the favorable
  "confirmed genuine" outcomes and expose the verification-cost model as an
  assumption. If any witness has no such unit, the result reports that
  existing-fact verification cannot block all admitted adverse witnesses.
- Collector failure remains unobserved rather than becoming evidence of
  absence.
- The prototype beats deterministic evidence plus abstention on a predeclared
  operator outcome or is retired without reinterpretation.
- Probability or partial-identification language remains prohibited until a
  coherent normalized joint law over claims, full latent target state, and
  observation-process state, plus a possibly claim-dependent observation
  kernel, is specified and independently reviewed.

### Qualify or demote CT graph correlation before adding graph machinery

The current graph is a clique projection of certificate SAN sets. Its Louvain
edge weight is shared-certificate count; modularity is not a calibrated quality
score, and seed-sweep ARI does not measure sensitivity to missing or noisy CT
entries. Compare the current projection with fixed-total certificate weighting,
a certificate-host bipartite representation, or a native hypergraph view before
considering CPM, Leiden, or a stochastic block model.

Acceptance evidence:

- provenance, typed namespace topology, and inferred co-occurrence graphs remain
  separate objects;
- every cross-domain edge names its direction, roles, provenance, observation
  window, interaction class, and specificity class;
- Synthetic fixtures include heavy-tailed SAN counts, multi-tenant hub
  certificates, missing entries, and bridge noise.
- Operator-supplied grouping evaluations report pairwise false co-membership,
  precision, recall, ARI or variation of information, coverage, and abstention.
- Optimizer, data, and model stability are measured separately.
- A degree-aware null comparison is included.
- Hub-dominated, truncated, or data-unstable graphs abstain rather than emit
  relationship-looking connected components.
- cohort-local ubiquity filters use all eligible observation opportunities and
  disclose their denominator; capped output carries `enumeration_complete` and
  omitted edge or member counts before absence is interpretable;
- The simplest representation meeting predeclared quality and runtime budgets
  wins. No new dependency is added without a measured residual gap.

### Dimension public email posture without breaking compatibility

The current five-point value mixes sender-authentication declarations,
transport policy, branding, and observation presence. A proposed reporting
dimension would add DMARC aggregate reporting and TLSRPT, but reporting is not
part of the current score. Current standards give all of these different
semantics. Write an ADR for a dimensioned model:

- sender authentication declaration: DMARC, SPF, and observed DKIM;
- transport policy: validated MTA-STS mode and, only if feasible,
  DNSSEC-validated DANE;
- reporting: DMARC aggregate reporting and TLSRPT;
- brand presentation: BIMI;
- observation confidence and degraded-source state.

Audit RFC 9989 completion, including bounded DNS Tree Walk behavior and the
current meanings of `np`, `psd`, `t`, and historic `pct`. Treat an MTA-STS TXT
record as different from a valid enforcing HTTPS policy. Treat TLSRPT as
reporting, not enforcement. Give DANE credit only when the MX and TLSA data are
DNSSEC-secure. Keep the existing stable field as a compatibility view until a
versioned migration is approved.

### Evaluate modern standards-defined passive DNS surfaces

RFC 9460 SVCB and HTTPS records expose typed alternative endpoints and
connection parameters without opening a target connection. RFC 9848, published
in 2026, standardizes ECH configuration bootstrapping through those records.
SMTP DANE in RFC 7672 exposes authenticated transport policy only when the MX
and TLSA chain is DNSSEC-secure. These are plausible additions to recon's public
namespace model, not automatic fingerprint or security-score inputs.

Evaluate them after the product baseline and claim contract identify a named
operator outcome. Keep the first pass observational: priority, target name,
parameter keys, and DNSSEC state. Do not decode ECH configuration into product
identity, infer live protocol use, or make a connection attempt. DANE must
distinguish secure, insecure, bogus, and indeterminate DNSSEC results; raw TLSA
presence alone receives no transport-assurance claim.

Acceptance evidence:

- standards parsers have bounded positive, malformed, unknown-key, alias-loop,
  and hostile-size fixtures;
- every observation has owner, subject, source, time, and interaction semantics;
- no target connection or hidden direct probe is introduced;
- incremental classified-surface or operator value beats a DNS-type-presence
  baseline on a predeclared aggregate metric;
- unsupported product, protocol-use, and security-maturity conclusions remain
  impossible by construction;
- any stable output follows the additive schema gate and preserves older
  consumers.

### Add measured async and schema-interoperability characterization

Run representative synthetic single, batch, graph, and MCP workflows with
asyncio debug mode, an explicit slow-callback threshold, wall-time measurement,
and peak-allocation tracking. Classify each resolver path as async I/O, bounded
CPU, bounded local I/O, or justified offload. Move only measured blocking I/O
to `asyncio.to_thread` or a bounded executor, and do not thread non-thread-safe
DNS detector state.

Validate canonical MCP schemas with an independent JSON Schema 2020-12
validator. Do not rely on `format` as portable semantic validation, do not
resolve external schema references from the network, and keep schema depth,
size, and validation time bounded.

### Gate native acceleration on product-shaped evidence

Keep the default runtime and distribution pure Python under
[ADR-0010](adr/0010-evidence-gated-native-acceleration.md). First complete the
stable-v1 stage characterization above, then measure Python-side improvements
to catalog loading, regex dispatch, repeated inference calculations, and any
other observed local hotspot. Do not infer end-to-end value from a kernel or
microbenchmark.

The first Python optimization pass is complete in v2.5.1. A bounded compiled
regex cache reduced the checked 1,000-value by 298-rule stage from 348 ms to
115 ms while preserving exact matches and catalog lifecycle behavior. One
batch-local Bayesian configuration snapshot reduced the checked 25-record
fusion stage from 864 ms to 355 ms without a process-global cache. CT stability
reuses its primary partition instead of recomputing one of the same eight
seeds. Hermetic retry and resolution tests plus file-grouped test workers cut
the measured full-suite wall time from 330.53 seconds serial without coverage
to 88.83 seconds with branch coverage. These are dated local diagnostics, not
product SLOs; [performance.md](performance.md) records the fixtures and limits.

The next optimization order is evidence-gated:

1. Keep split YAML canonical, generate a deterministic packaged built-in
   catalog representation, enforce byte-for-byte drift checking, and require
   semantic equality plus at least a five-times Python 3.14 cold-load gain.
2. Characterize a batch-scoped SSRF-safe HTTP pool. Preserve request-specific
   timeouts, retries, cancellation, rebinding checks, CT policy, and degraded
   results before considering promotion.
3. Bound non-streaming scheduling, summary-mode discarded work, pairwise
   ecosystem overlap, and peer-list materialization before increasing
   concurrency. Test sparse and adversarial dense cohorts through the existing
   10,000-domain input cap and report omitted counts rather than silently
   truncating evidence.

An optional Rust extension may enter an isolated prototype only when a stable,
deterministic, coarse-grained stage remains above 250 ms p95 on a representative
warm fixture or at least 20 percent of warm end-to-end p95 after a Python
optimization pass. These are conservative provisional governance floors, not
product SLOs; the stable-v1 baseline must replace them with operation-specific
budgets before a prototype. They exclude microhotspots, require Amdahl-relevant
pressure, and demand enough improvement to repay native release maintenance.
Promotion requires at least a 3 times stage-p95 improvement
and also a 20 percent warm end-to-end p95 improvement, 25 percent sustained
batch-throughput improvement, or 30 percent peak-allocation improvement. It
also requires exact Python-reference parity, compiler-free installation on
every advertised platform, native quality gates, a multi-ecosystem SBOM,
reproducibility, provenance, and a visible Python fallback.

Do not add Go without an independently valuable hosted or worker boundary. Do
not add Mojo without a measured tensor, GPU, or accelerator kernel and a stable
cross-platform release contract. Neither exists in the current product.

### Turn catalog quality into the detection-improvement loop

The current catalog has 847 entries. Establish classified-surface and stale-rule
baselines before adding broad new families. Every promoted rule needs a current
public reference or disclosure-safe aggregate basis, a `verified` date,
positive and lookalike-negative fixtures, sparse-result wording, and provenance
tests. Prioritize regional and record-type gaps by aggregate frequency. Do not
add higher-order motifs until direct fingerprint quality is measured.

Do not keep vendor-name-only proposals. A catalog candidate enters the backlog
only with an exact record type and pattern, a source or disclosure-safe
aggregate basis, an identifier, and an explicit pending, rejected, promoted, or
deferred disposition.

See [catalog-strategy.md](catalog-strategy.md).

### Simplify operator and agent discovery using measurements

Separate primary workflows from specialist workflows in documentation now.
Measure CLI help and MCP discovery cost before introducing a core-versus-
advanced toolset. If the measurement shows material context waste, design a
backward-compatible discovery profile while preserving full access and stable
tool names. Generated discovery artifacts remain non-contractual under
[ADR-0007](adr/0007-surface-inventory-discovery-context.md) until a concrete
external consumer needs a stable subset.

### Reduce remaining interface hotspots after semantics stabilize

The high-trust graph identifies two critical interface hotspots:

- `src/recon_tool/formatter/panel.py`: critical blast radius, broad outgoing
  dependency surface, and a special file-size ratchet;
- `src/recon_tool/server/introspection.py`: critical blast radius, broad
  dependency and incoming-reference surface, plus framework registration
  behavior.

Read the current ignored code-graph manifest, impact records, and hotspots for
exact counts rather than copying volatile graph metrics into this roadmap.

Keep each public module as a compatibility orchestrator and extract only
cohesive, stateless sections. Preserve byte-equivalent panel output, MCP
registration order, generated inventory, public imports, and schema behavior.
`merger.py` follows only after the lower-risk interface splits.

## Shipped Foundation

The following are maintenance concerns, not active feature projects:

- Package-local CLI, formatter, MCP server, and MCP client boundaries, guarded
  by [ADR-0008](adr/0008-interface-package-locality.md) and interface-layout
  checks.
- Typed `LookupOptions` at the CLI boundary.
- Raw-preserving compact caps for the named high-volume MCP graph and
  correlation tools.
- Bounded config, cache, delta, CT, regex, and formatting-control readers.
- Scheduled provider-drift checks, generated schema and surface-inventory
  checks, release readiness, Trusted Publishing, provenance, external SBOM,
  and reproducible-build verification.
- RFC 9989 parser and scoring work already recorded in the changelog. The
  remaining work is a completion audit against the final standard, not a claim
  that the protocol is entirely implemented.

Detailed shipped records are in [CHANGELOG.md](../CHANGELOG.md),
[roadmap-history.md](roadmap-history.md), and the ADR index.

## Publication and Process Track

The external write-up, claim freeze, OpenSSF Best Practices questionnaire,
outside replication, and archive or DOI decision are legitimate maintainer
projects. They do not outrank product truthfulness, compatibility, measured
utility, catalog quality, or operator usability.

The write-up remains governed by
[external-writeup-plan.md](external-writeup-plan.md),
[paper-claim-map.md](paper-claim-map.md), and
[submission-freeze-checklist.md](submission-freeze-checklist.md). Public-list numbers remain robustness checks rather than population rates. M365 tenancy
evidence remains corroboration rather than independent calibration. The latest
local proof record is
[2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md).

The current review and external-event boundaries are in
[strategic-gap-audit.md](strategic-gap-audit.md),
[artifact-review.md](artifact-review.md),
[public-label-snapshot-decision.md](public-label-snapshot-decision.md),
[m365-tenancy-decision.md](m365-tenancy-decision.md),
[replication-runbook.md](replication-runbook.md), and
[archive-readiness.md](archive-readiness.md).

## Success Metrics

The product-quality baseline will set dated values and regression budgets. The
roadmap tracks at least:

- unsupported default claim rate;
- abstention and unresolved rate by claim family;
- independently corroborated precision where a suitable reference exists;
- explanation and provenance completeness;
- claim-contract coverage, minimal-certificate replay, and abstention-reason
  completeness for material default claims;
- observation-versus-interpretation delta replay stability;
- typed graph enumeration completeness and eligible-denominator disclosure;
- classified share of the observable record surface and stale-rule count;
- cold and warm p50/p95 latency, peak allocation, timeout, and degraded-source
  rate;
- marginal CT signal gain relative to latency cost;
- MCP discovery bytes and representative workflow context cost;
- deterministic CLI, JSON, and MCP behavior;
- the enforced 90.2 percent branch-aware project gate, above the 80 percent user
  bar, with no coverage regression;
- green local and remote CI, reproducible artifacts, and release provenance.

Green process gates are necessary but are not proof of product utility.

## Invariants

- Public metadata only: DNS, certificate transparency, unauthenticated identity
  discovery, and the documented standards-compliant MTA-STS policy fetch.
  Google CSE and BIMI certificate fetches remain explicit opt-in direct probes.
- No credentials, API keys, paid feeds, port scanning, exploit checks, or
  target application crawling.
- No runtime aggregate database. No real-target corpus or per-domain rows are
  committed or published; maintainer-local validation data stays in the
  permanently ignored workspaces defined by the data-handling policy.
- Public examples are fictional, synthetic, reserved, or aggregate-only.
- Observations are hedged and provenance-bearing. Sparse or degraded evidence
  lowers confidence and may require abstention.
- Stable CLI, JSON, MCP, cache, and import surfaces change only through their
  documented compatibility discipline.
- Bounded network, parser, cache, schema, and output behavior.
- A clean root, canonical docs in `docs/`, source in `src/`, logs in ignored
  `logs/`, and agent work only in ignored `.agent/`.

## Intentionally Not Doing

- Active scanning, port enumeration, vulnerability or exploit testing.
- Credentialed tenant or SaaS enumeration.
- Remote hosted MCP, OAuth, or multi-tenant service operation without a named
  consumer, threat model, and architecture review.
- Company ownership, firmographics, news, financial, or hiring inference.
- Security verdicts, certifications, confirmed-vulnerability claims, or claims
  about controls that are not publicly observable.
- Speculative dependencies, abstraction layers, scoring dimensions, or
  fingerprint grammars without measured pressure.
- Publication process as a substitute for product-quality evidence.

## Current External Basis

Checked 2026-07-11 against primary sources:

- [MCP 2026-07-28 release candidate](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP draft tools specification](https://modelcontextprotocol.io/specification/draft/server/tools)
- [MCP draft caching specification](https://modelcontextprotocol.io/specification/draft/server/utilities/caching)
- [MCP Python SDK release history](https://pypi.org/project/mcp/)
- [RFC 9989: DMARC](https://www.rfc-editor.org/info/rfc9989/)
- [RFC 3986: URI generic syntax](https://www.rfc-editor.org/info/rfc3986/)
- [RFC 2308: DNS negative caching](https://www.rfc-editor.org/rfc/rfc2308)
- [RFC 4035: authenticated DNSSEC denial](https://www.rfc-editor.org/rfc/rfc4035#section-5.4)
- [RFC 9824: compact DNSSEC denial](https://www.rfc-editor.org/rfc/rfc9824)
- [Provenance semirings](https://web.cs.ucdavis.edu/~green/papers/pods07.pdf)
- [RFC 8461: MTA-STS](https://www.rfc-editor.org/info/rfc8461/)
- [RFC 8460: TLSRPT](https://www.rfc-editor.org/info/rfc8460/)
- [RFC 7672: SMTP security via DANE](https://www.rfc-editor.org/info/rfc7672/)
- [Python asyncio development guidance](https://docs.python.org/3.14/library/asyncio-dev.html)
- [Python free-threading guidance](https://docs.python.org/3/howto/free-threading-python.html)
- [PyO3 free-threading guidance](https://pyo3.rs/main/free-threading)
- [PyO3 ABI feature guidance](https://pyo3.rs/main/features)
- [Maturin distribution guidance](https://www.maturin.rs/distribution.html)
- [Mojo versioning and stability FAQ](https://docs.modular.com/mojo/faq)
- [JSON Schema 2020-12 validation](https://json-schema.org/draft/2020-12/json-schema-validation)
- [Manski on partial identification with missing data](https://doi.org/10.1016/j.ijar.2004.10.006)
- [Zhang and Peixoto on statistically significant community structure](https://arxiv.org/abs/2006.14493)
- [Conformal Risk Control, revision 2025-06-13](https://arxiv.org/abs/2208.02814)

When an external standard changes, update the dated readiness or design plan
before changing production behavior.
