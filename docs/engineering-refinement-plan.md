# Engineering Refinement Plan

Status: active planning track
Review date: 2026-07-09

This plan records the parts of the recent architecture feedback that are worth
turning into project work, and the parts that should stay deferred until there
is evidence. It does not authorize runtime expansion. Each item must preserve
the passive, zero-credential invariant in
[ADR-0001](adr/0001-passive-zero-credential.md), the adversarial missing-data
rule in [ADR-0002](adr/0002-mnar-adversarial-absence.md), and the v2 schema
discipline in [ADR-0003](adr/0003-v2-schema-lock.md).

## Baseline

The interface locality refactor is complete and recorded in
[ADR-0008](adr/0008-interface-package-locality.md). The old top-level
`cli_*`, `formatter_*`, `server_*`, and `mcp_*` implementation pattern has
been replaced by `recon_tool.cli`, `recon_tool.formatter`,
`recon_tool.server`, and `recon_tool.mcp_client`, with compatibility shims
kept for bounded import stability. The Typer lookup boundary now constructs a
typed `LookupOptions` value, and `cli.lookup.lookup` receives `domain` plus
that options object rather than a wide flat flag list.

The remaining refinement work is not a broad rewrite. It is a set of small,
evidence-gated tracks that make the already-strong core easier to maintain,
test, and explain.

## Decision Filter

Accept a refinement only when it does at least one of these:

- Reduces cognitive load in a path that maintainers or agents edit often.
- Lowers blast radius for CLI, MCP, JSON, or resolver changes.
- Adds validation evidence for existing behavior without broadening the claim.
- Documents a cross-cutting invariant that future edits could otherwise break.

Defer a refinement when it mainly adds abstraction, dependencies, or protocol
surface without a named consumer, measured bottleneck, or failing guard.

## Accepted Tracks

### 1. MCP 2026-07-28 Readiness

The MCP release candidate contains breaking protocol changes, but recon's
current server is local stdio through FastMCP, not a remote authenticated HTTP
deployment. The useful work is readiness and compatibility testing, not an
early protocol fork. The detailed plan is
[mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md), and the decision is
recorded in [ADR-0009](adr/0009-mcp-2026-readiness.md).

Acceptance:

- `recon mcp doctor` works with the current installed SDK and has a clear
  migration path when the Python SDK exposes the 2026-07-28 protocol.
- Structured-output tests continue to prove that data tools advertise schemas
  and return navigable content.
- No Roots, Sampling, or MCP Logging support is added.
- Remote HTTP, OAuth, Apps, and Tasks remain non-goals until there is a real
  product need.

### 2. Compact Agent Output for High-Volume MCP Tools

`lookup_tenant(format="text")` is already compact enough for agent use. The
remaining risk is high-volume graph, chain, catalog, and export surfaces where
large arrays can waste context. Add compact detail modes only where they
reduce actual payload size while preserving raw structured access.

Target surfaces:

- `chain_lookup`
- `export_graph`
- `get_infrastructure_clusters`
- `cluster_verification_tokens`
- any future graph or batch MCP tool that can return large arrays

Design rule:

- Preserve the existing raw result path.
- Add an explicit detail or verbosity option only when the default contract can
  remain backward compatible.
- A compact response must include omitted counts, top-N selection rules, and a
  pointer to the raw path.
- Do not summarize away evidence that is needed for provenance, reproducible
  scoring, or schema validation.

Acceptance:

- Contract tests prove raw outputs remain unchanged.
- Compact tests prove caps, omitted counts, deterministic ordering, and no
  instruction-like rendering of domain-controlled text.
- Documentation names which tools are compact by default or by option.

### 3. Targeted Async and Blocking Audit

The broad recommendation to wrap deep work in a large `ThreadPoolExecutor` is
not a fit for the current design. recon already uses async DNS and async HTTP
in the main resolver path, and the DNS sub-detector context is deliberately
not thread-safe. The right work is an audit with evidence, followed by small
offloads only where a real blocking call is found inside the event loop.

Audit scope:

- DNS and identity source collectors.
- Certificate transparency and certificate parsing paths.
- Cache and local data reload paths used by MCP tools.
- Any synchronous library call reachable during `resolve_tenant`.

Acceptance:

- Each event-loop blocking candidate is classified as async, bounded CPU,
  bounded local I/O, or requiring offload.
- Any offload uses an explicit bounded executor or `asyncio.to_thread` at the
  narrow call site, with cancellation and timeout behavior documented.
- No thread is introduced around non-thread-safe detector contexts.
- A regression test or profiling note covers every changed path.

### 4. Target-Side Poisoning Hardening

The existing code already has many caps and parser-isolation points. This
track strengthens validation evidence against hostile public data rather than
claiming a new security feature.

Fixture classes:

- Oversized TXT, SPF, DMARC, DKIM, BIMI, and verification-token records.
- Deep CNAME chains and repeated related-domain enrichment candidates.
- Malformed, oversized, or unusual certificate SAN and issuer structures.
- CT provider responses with malformed rows, duplicated names, and cap-heavy
  subdomain lists.
- Domain-controlled strings that look like prompts or terminal control data.

Acceptance:

- Hostile fixtures cannot crash the lookup, hang the resolver, or produce
  unbounded memory growth.
- Degraded-source reporting remains explicit.
- Sanitization tests prove observed strings are treated as data, not
  instructions.

### 5. Architecture Records for Stable Invariants

Add ADRs only for decisions that future maintainers could plausibly reverse by
accident.

Candidate ADRs:

- MCP 2026 readiness and why recon waits for SDK support before protocol
  adoption. Completed as [ADR-0009](adr/0009-mcp-2026-readiness.md).
- Resolver enrichment bounding and non-recursive related-domain policy.
- Fingerprint safety model and why regex-based matching remains the default.

Acceptance:

- Each ADR has one decision, clear consequences, and links to the tests or
  docs that enforce it.
- Routine implementation cleanup stays in the roadmap or changelog, not ADRs.

## Conditional Tracks

### Fingerprint Expression Grammar or AST Evaluator

Do not rewrite the fingerprint engine just because the catalog is growing. The
current YAML catalog, validation guard, regex safety heuristics, and matching
path are a good fit for the present rule shapes. An expression grammar becomes
worth building only if one of these triggers appears:

- Public-source-backed rules need true multi-observable boolean logic that is
  awkward or ambiguous in the current schema.
- Profiling shows fingerprint evaluation is a material bottleneck after DNS,
  identity, CT, and cache costs are accounted for.
- Maintainers need short-circuiting cost controls across genuinely expensive
  fields, not just ordinary string matches.

Minimum design before implementation:

- Backward-compatible schema versioning for existing fingerprints.
- A small expression grammar with explicit allowed fields and operators.
- A compiler from YAML to typed expression nodes.
- Short-circuit evaluation with per-node cost accounting.
- Deterministic error messages from `validate-fingerprints`.
- Migration tests proving all existing fingerprints keep their behavior.

## Non-Goals

- No dependency additions for speculative architecture.
- No remote MCP server or OAuth surface as part of this refinement track.
- No change to the stable v2 JSON contract unless ADR-0003 discipline is
  followed.
- No active probing, port scanning, credentialed access, or target-side HTTP
  expansion.
- No blanket thread-pool wrapper around resolver or detector logic.

## Execution Order

1. Keep the roadmap and ADRs current.
2. Finish MCP 2026 readiness before the final 2026-07-28 spec lands.
3. Add compact MCP output only for measured high-volume tools.
4. Run the async/blocking audit and fix only proven event-loop blockers.
5. Expand target-poisoning fixtures around existing caps.
6. Reconsider fingerprint expressions only after a trigger is met.
