# Engineering Refinement Plan

Status: active implementation plan
Review date: 2026-07-10

This plan translates the canonical [roadmap](roadmap.md) into bounded
engineering tracks. It does not authorize unrelated runtime expansion. Every
track preserves the public-metadata-only boundary in
[ADR-0001](adr/0001-passive-zero-credential.md), adversarial missing-data
discipline in [ADR-0002](adr/0002-mnar-adversarial-absence.md), and stable v2
contract discipline in [ADR-0003](adr/0003-v2-schema-lock.md).

## Baseline

- v2.3.8 is current on GitHub and PyPI.
- Local and remote release readiness pass on current main.
- Meaningful branch-aware coverage is approximately 89 percent, above the 82
  percent enforced project gate and the 80 percent user bar.
- The ignored local code graph was refreshed from clean main on 2026-07-10 and
  reported high trust, every graph check passing, and no import cycles. Read
  `.agent/codegraph/manifest.json` for exact current counts and refresh it after
  tracked changes.
- Interface locality, typed lookup options, named high-volume MCP caps,
  generated schema and surface guards, provider-drift checks, and release
  provenance are shipped.

Graph trust is high, not absolute. Runtime registration, dynamic dispatch,
reflection, monkeypatching, and framework behavior must still be verified with
source and tests before a wide change.

## Decision Filter

Accept work when it does at least one of these:

- Corrects a claim that is stronger than its public evidence.
- Proves compatibility with an imminent external standard or dependency.
- Establishes a reproducible user-value or reliability measure.
- Reduces cognitive load or blast radius in a measured hotspot.
- Improves catalog quality, provenance, degradation behavior, or deterministic
  output without weakening sparse-result honesty.

Defer work that mainly adds abstraction, dependencies, protocol surface,
inference layers, or catalog entries without a named consumer, measured gap,
or failing guard.

## Track 1: Evidence-Semantic Integrity

Status: active; live MCP boundary and score wording corrected in Unreleased
Dependencies: none
Risk: high product-trust risk, high compatibility sensitivity

### Scope

1. Inventory material claims emitted by the default panel and primary MCP
   workflows.
2. Classify each claim as directly observed, derived from a documented rule,
   defined public absence, or unresolved.
3. Remove parent-platform child-product claims next. The live MCP
   collection-boundary instructions and model-bound score wording were the
   first completed correction. Preserve and test the existing behavior that
   keeps absent sovereignty metadata unknown.
4. Preserve current stable JSON names while correcting presentation and
   inference semantics.
5. Draft a provenance-envelope ADR before changing `EvidenceRecord` or public
   schemas. The ADR must define source family, record owner, observation time,
   scope, and freshness semantics, plus migration and cache behavior.

### Graph and test guidance

- `models.py` is deceptively central: the graph sees 508 high-confidence
  symbol-import edges and 669 cross-file call edges into its model surface.
- `merger.py` is high blast radius with fan-out 31 and contract risk.
- Consult `impact.jsonl`, `edges.jsonl`, `refs.jsonl`, and `checks.json` before
  touching either file.
- Likely tests include panel golden and disclosure tests, cache round trips,
  schema contracts, explanation DAGs, staleness timestamps, MCP structured
  output, server instructions, generated agent guidance, and merger tests.

### Acceptance

- Every default material claim has a direct provenance path.
- Sparse output contains no inferred child-product use from parent-platform
  presence.
- Unknown sovereignty metadata remains unknown.
- Public-evidence values are not described as overall security scores.
- Stable JSON remains compatible unless an additive change completes the full
  schema-lock process.
- Full local CI passes with no coverage regression.

### Stop rule

Do not combine this work with a broad model, schema, or interface refactor.
Correct the smallest evidence-to-claim path first.

## Track 2: MCP 2026-07-28 Compatibility Matrix

Status: ready, external trigger met 2026-06-30
Dependencies: none; this time-bound stream can proceed independently of Track 1
Risk: time-bound dependency and protocol compatibility

The official Python MCP SDK `2.0.0b1` now exposes the draft 2026-07-28
behavior. The production dependency remains on stable v1.28.1 and `<2` while an
isolated exact-pinned environment characterizes the migration.

### Scope

- Test server import, stdio startup, doctor, discovery, representative tool
  calls, resource reads, error behavior, structured content, schemas, and
  deterministic order on v1.28.1 and v2 beta.
- Record an explicit migration decision for `FastMCP`, protocol type imports,
  `ToolError`, annotations, snake-case SDK attributes, `discover()`, and
  `model_dump(by_alias=True)` where required on the wire.
- Review synchronous resource handlers and shared catalog or cache state under
  v2 worker-thread execution.
- Give every complete `server/discover`, `tools/list`, supported resource-list,
  and resource-read response valid `ttlMs` and `cacheScope` hints. Record a
  disposition for every other cacheable operation exposed by the server.
- Prove the declared `mcp>=1.0` floor in a lowest-supported-dependency job or
  raise it to the first version the project actually supports.
- Keep stdio as the supported surface. Do not add remote transport or unused
  extensions.

### Acceptance

- A dated matrix records pass, fail, migration action, and rollback pin.
- The current production path stays green throughout the spike.
- Tool and resource inventories remain deterministic.
- Declared output schemas conform to JSON Schema 2020-12 and returned
  structured content conforms to those schemas.
- Required caching hints are present and valid on every complete cacheable
  result recon exposes under the draft 2026 protocol.
- Full gates pass before any dependency-range change.

Detailed phases are in
[mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md).

## Track 3: Product-Quality Baseline and Ablation

Status: specified
Dependencies: Track 1 claim taxonomy
Risk: measurement-design and disclosure risk

### Scope

Build one reproducible, aggregate-safe scorecard with synthetic fixtures and
maintainer-local real-domain evaluation. Record only disclosure-reviewed
aggregates.

Metrics:

- independently corroborated precision by claim family where a suitable label
  exists;
- unsupported claim, false-confidence, abstention, and unresolved rates;
- explanation and provenance completeness;
- classified share of observable record values and stale-rule count;
- degraded-source and partial-result rates;
- p50/p95 cold and warm latency and peak allocation;
- marginal CT signal gain and latency cost;
- MCP discovery bytes and representative workflow result bytes.

The resolver latency, allocation, CT-value, and current-schema measurements are
produced by Track 5's stable-v1 characterization and consumed by this scorecard;
they are not measured twice.

Run a predeclared ablation comparing the current inference path against
deterministic evidence plus explicit abstention. Freeze the decision rule before
the run. Do not tune it after seeing the result.

Primary design:

- Operator decision: accept one material single-domain claim as supported by
  the public channel, or leave it unresolved.
- Unit: `(domain, claim_family, observation_time)`, with domain groups kept
  intact across design and evaluation splits.
- Independent labels: provider-owned endpoints, standards-defined records, or
  other predeclared authoritative sources not consumed by the compared
  predictor. Unlabeled families report coverage and corroboration diagnostics,
  not precision.
- Minimum: 100 independently labeled units per primary family, including at
  least 30 reference-positive, 30 reference-negative, and 30 emitted-claim
  units. Smaller strata are descriptive only.
- Go or no-go: fusion remains primary only when a predeclared paired 95 percent
  interval shows a positive supported-claim coverage gain and its upper bound
  shows no increase in unsupported emitted claims relative to deterministic
  evidence plus abstention. Inconclusive or negative results move fusion to an
  advanced diagnostic.

### Acceptance

- A dated method, environment, reproduction command, result memo, and
  regression-budget proposal exist.
- Per-unit rows may exist only in the permanently ignored
  `validation/runs-private/` or `validation/local/` workspaces. They are never
  committed or published. Each run uses the ignored manual `RETENTION.md`
  control defined in `maintainer-validation.md` and removes superseded rows
  when they no longer support a reviewed aggregate memo or named longitudinal
  comparison.
- A negative or mixed result is recorded without relabeling it as success.
- Each proposed inference, source, graph, or catalog change names a target
  metric before implementation.

## Track 4: Dimensioned Email Observations

Status: design after Track 3 baseline
Dependencies: Tracks 1 and 3
Risk: stable-contract and user-interpretation risk

Write an ADR before implementation. Separate:

- sender-authentication declarations;
- transport policy;
- reporting configuration;
- brand presentation;
- observation confidence and degraded-source state.

Complete an RFC 9989 behavior audit. Distinguish MTA-STS record presence from a
valid `enforce` policy, TLSRPT reporting from transport enforcement, and BIMI
from authentication. Evaluate DANE only as a bounded feasibility design; any
credit requires DNSSEC-validated MX and TLSA data. Preserve the existing
five-point field as a compatibility view until a versioned migration is
approved.

### Acceptance

- An accepted ADR defines the dimensions, compatibility view, evidence
  requirements, and migration boundary.
- An RFC 9989 matrix covers record discovery, supported tags, historic `pct`,
  malformed records, and bounded-query behavior.
- MTA-STS, TLSRPT, BIMI, and any DANE proposal receive only their
  standards-supported semantics.
- The DANE feasibility step records an explicit implement or defer decision;
  no credit is possible without DNSSEC-validated MX and TLSA data.
- Existing stable JSON remains unchanged unless the schema-lock process closes.

## Track 5: Measured Async and Schema Interoperability

Status: stable-v1 characterization ready; v2 deltas follow Track 2
Dependencies: none for resolver and current-schema baselines; Track 2 only for
candidate-SDK deltas
Risk: concurrency and brittle-benchmark risk

### Scope

- Run representative synthetic single, batch, graph, and MCP calls with
  asyncio debug mode and an explicit slow-callback threshold.
- Record wall time, peak allocations, and blocked-loop observations. Treat
  profiler output as characterization, not a brittle CI timing assertion.
- Classify each resolver-reachable call as async I/O, bounded CPU, bounded
  local I/O, or justified offload.
- Move only measured blocking I/O to `asyncio.to_thread` or a bounded executor.
- Validate canonical schemas with an independent Draft 2020-12 validator.
- Reject external network resolution for schema references, reliance on
  `format` as semantic validation, and unbounded schema depth or validation
  time.

### Acceptance

- A dated performance artifact records the environment and stage measurements.
- Cancellation, aggregate timeout, and partial-result behavior remain intact.
- Non-thread-safe DNS detector state is never moved across threads.
- Compact MCP modes retain deterministic caps, omitted counts, and raw parity.
- Every changed path has a regression test or a documented no-change result.
- Stable-v1 resolver and schema measurements remain separately reproducible
  from v2-specific compatibility deltas.

## Track 6: Catalog Quality and Lifecycle

Status: baseline after Track 3
Dependencies: Track 3 measurement definitions
Risk: false-positive and regional-selection bias

- Measure classified surface by record type and stratum before broad catalog
  expansion.
- Ratchet current public references and `verified` dates. New undated rules are
  not accepted.
- Prioritize regional and non-CNAME gaps by aggregate frequency.
- Resolve each current candidate as promoted, rejected, or explicitly
  deferred.
- Require positive, lookalike-negative, sparse, and provenance tests for every
  promoted rule.
- Keep the expression-grammar proposal conditional on demonstrated multi-field
  rule pressure or a measured matcher bottleneck.

See [catalog-strategy.md](catalog-strategy.md).

### Acceptance

- A dated baseline names the exact catalog revision, corpus strata, record-type
  classified surface, unresolved share, stale-rule count, and corroboration
  diagnostics.
- Precision is claimed only for independently labeled units, with the Track 3
  minimum and uncertainty rule; low corroboration alone is not called a false
  positive.
- Every promoted rule has a reference or disclosure-safe basis, `verified`
  date, positive, lookalike-negative, sparse, and provenance tests.
- Classified surface improves without a statistically supported precision
  regression, and each candidate has an exact pattern plus a disposition.

## Track 7: Operator and Agent Surface Simplification

Status: measure before design
Dependencies: Track 3 context-cost baseline
Risk: compatibility and discoverability risk

Document the three primary workflows separately from specialist graph,
posterior, hypothesis, simulation, catalog-mutation, and discovery workflows.
Measure CLI help and MCP discovery cost. Introduce a backward-compatible core
versus advanced discovery profile only if the measured reduction is material.
Do not rename or remove stable tools as a documentation cleanup.

### Acceptance

- Primary workflows fit on one reader screen and do not require graph,
  posterior, or catalog internals.
- A dated baseline records CLI help size, MCP discovery bytes, and
  representative workflow result bytes.
- No discovery profile is implemented unless its threshold is predeclared. If
  implemented, the core profile reduces discovery bytes by at least 30 percent
  on the recorded catalog while the full profile and stable tool names remain
  unchanged.

## Track 8: Interface Hotspot Decomposition

Status: later, after semantic and MCP changes stabilize
Dependencies: Tracks 1 and 2
Risk: critical blast radius

The high-trust graph identifies `formatter/panel.py` and
`server/introspection.py` as the next interface hotspots. Keep their public
modules as compatibility orchestrators and extract cohesive, stateless
sections. Require byte-equivalent panel golden output, unchanged MCP
registration order, unchanged generated inventories, no import cycle, and
tighter file-size ratchets. Consider `merger.py` only after the interface splits.

### Acceptance

- Panel golden output is byte-equivalent and MCP registration order and
  generated inventories are unchanged.
- No import cycle or public-import change is introduced.
- At least one special file-size allowance is removed or lowered by at least 20
  percent without moving complexity into another oversized module.
- Focused likely-test sets from `impact.jsonl` plus the full local gate pass.

## Completed or Maintenance-Only Work

- Package-local interface boundaries and typed lookup options.
- Compact output caps for every currently named high-volume MCP target.
- The July 10 hostile-input bounds for MCP config, delta JSON, CT retention,
  regex admission, and formatting controls. Add new fixtures only for a
  concrete uncovered parser or collector boundary.
- Current release publication, attestations, SBOM, reproducible builds,
  provider drift, and generated-artifact checks.
- Publication, OpenSSF process, independent replication, and archive planning.
  Maintain these separately; they are not product-runtime dependencies.

## Global Non-Goals

- No remote MCP server, OAuth, Apps, Tasks, Roots, Sampling, or protocol logging
  without a named consumer and new architecture review.
- No active probing, port scanning, credentialed access, paid feeds, or broader
  target-side HTTP behavior.
- No blanket executor around resolver or detector logic.
- No stable JSON, CLI, MCP, cache, or import change outside its compatibility
  process.
- No new inference, motif, scoring dimension, or abstraction without measured
  evidence and a declared success metric.

## Execution Order

1. Treat evidence-semantic corrections and the time-bound MCP v2 matrix as two
   independent Now streams. Keep one atomic implementation item in progress at
   a time, but do not make either stream wait on a false technical dependency.
2. Run the stable-v1 resolver, allocation, CT-value, and schema
   characterization from Track 5.
3. Complete the product-quality scorecard and ablation using that artifact.
4. Decide the dimensioned email-observation model from measured evidence.
5. Apply candidate-SDK deltas to the Track 5 characterization after Track 2.
6. Baseline and improve catalog quality.
7. Measure and, only if justified, simplify operator and agent discovery.
8. Decompose critical interface hotspots without changing behavior.

Each step closes only with its named acceptance evidence, full local CI, the 82
percent branch-aware project gate, no regression from the current coverage
baseline, and no known unaddressed issue in scope.
