# Roadmap

This file is the canonical product plan and scope boundary. Shipped work belongs
in [CHANGELOG.md](../CHANGELOG.md). Historical planning lives in
[roadmap-history.md](roadmap-history.md). Release mechanics live in
[release-process.md](release-process.md). Research and publication work is
tracked separately from product work.

> **Status:** v2.3.9 is current. The stable baseline is complete: recon ships a
> local CLI, importable library, versioned JSON contract, local stdio MCP
> server, bounded passive collectors, generated-artifact guards, and a verified
> release path. The product is not "finished." The active work is to make every
> default claim evidence-tight, prove that advanced inference adds user value,
> characterize MCP v2 compatibility, and make latency, degradation, catalog
> quality, and agent context cost measurable.
>
> **Code-graph orientation:** the ignored `.agent/codegraph/manifest.json` was
> refreshed from clean main on 2026-07-10 and reported a high-trust full graph,
> all graph checks passing, and no import cycles. Refresh the local graph after
> tracked changes and read the manifest for exact current counts. The graph is
> an implementation aid, not a substitute for source and test verification.

## Product Goal

recon turns public DNS, certificate-transparency, and unauthenticated identity
metadata into conservative, provenance-bearing observations about a domain's
external technology and identity configuration. Its best answer is sometimes
"unresolved." It must not turn parent-platform presence, sparse metadata, a
model score, or missing passive evidence into a claim about product use,
security maturity, ownership, or exploitability.

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
summary corrections are in Unreleased.

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
- Run a predeclared ablation comparing the default reasoning path with
  deterministic evidence plus abstention. Treat a negative result as useful
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
- Unit: one `(domain, claim_family, observation_time)` tuple. Domain groups are
  kept intact across any design and evaluation split.
- Labels: an independent provider-owned endpoint, standards-defined public
  record, or other predeclared authoritative source that is not an input to the
  compared predictor. A family without an independent reference reports only
  coverage, provenance, and disagreement diagnostics, never precision.
- Minimum evidence for a decision: at least 100 independently labeled units per
  primary family, including at least 30 reference-positive, 30
  reference-negative, and 30 emitted-claim units. Smaller strata are descriptive
  only.
- Decision rule: fusion remains in the primary path only if a predeclared
  paired 95 percent interval shows a positive supported-claim coverage gain and
  its upper bound shows no increase in unsupported emitted claims versus
  deterministic evidence plus abstention. An inconclusive or negative result
  moves fusion to an explicitly advanced diagnostic. Secondary metrics cannot
  override this rule after results are visible.

Acceptance evidence:

- A dated baseline, reproduction command, environment description, and
  aggregate result memo exist.
- No real apex, organization name, tenant ID, or per-domain row is committed.
- The ablation decision rule is written before the run.
- The result determines whether advanced fusion remains in the primary path or
  becomes an explicitly advanced diagnostic.
- Coverage remains above the enforced 82 percent branch-aware project gate and
  the 80 percent user bar, with no regression from the current baseline, and
  the full local CI mirror passes.

Stop rule: do not expand graph or probabilistic machinery without measured
benefit to a named user outcome.

## Next

These tracks follow the top three in dependency order. The stable-v1 portion of
the async and schema characterization is a supporting input to priority 3 and
runs before its scorecard; only candidate-SDK deltas wait for priority 2.

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

- `src/recon_tool/formatter/panel.py`: critical blast radius, 44 outgoing
  dependencies, and a special file-size ratchet;
- `src/recon_tool/server/introspection.py`: critical blast radius, 28 outgoing
  dependencies, 12 incoming references, and framework registration behavior.

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
- classified share of the observable record surface and stale-rule count;
- cold and warm p50/p95 latency, peak allocation, timeout, and degraded-source
  rate;
- marginal CT signal gain relative to latency cost;
- MCP discovery bytes and representative workflow context cost;
- deterministic CLI, JSON, and MCP behavior;
- the enforced 82 percent branch-aware project gate, above the 80 percent user
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

Checked 2026-07-10 against primary sources:

- [MCP 2026-07-28 release candidate](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP draft tools specification](https://modelcontextprotocol.io/specification/draft/server/tools)
- [MCP draft caching specification](https://modelcontextprotocol.io/specification/draft/server/utilities/caching)
- [MCP Python SDK release history](https://pypi.org/project/mcp/)
- [RFC 9989: DMARC](https://www.rfc-editor.org/info/rfc9989/)
- [RFC 8461: MTA-STS](https://www.rfc-editor.org/info/rfc8461/)
- [RFC 8460: TLSRPT](https://www.rfc-editor.org/info/rfc8460/)
- [RFC 7672: SMTP security via DANE](https://www.rfc-editor.org/info/rfc7672/)
- [Python asyncio development guidance](https://docs.python.org/3.14/library/asyncio-dev.html)
- [JSON Schema 2020-12 validation](https://json-schema.org/draft/2020-12/json-schema-validation)

When an external standard changes, update the dated readiness or design plan
before changing production behavior.
