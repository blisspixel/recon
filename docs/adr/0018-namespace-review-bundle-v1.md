# ADR-0018: Define a fresh single-namespace review bundle

- **Status:** Accepted
- **Date:** 2026-08-30

## Context

The evidence-first defender workflow composes one explained lookup with one
hardening-gap derivation. Without a dedicated contract, a client can mistake an empty
candidate list for a stage that never ran, treat partial collection as a
negative observation, or assign a freshness claim that recon does not support.

The existing stable lookup JSON is a runtime result. Batch JSON owns ordered
multi-domain results and ecosystem summaries. Observation capsules own
collection replay and classified change. Expanding any of those contracts would
mix distinct lifecycle and trust semantics.

## Decision

recon will ship NamespaceReviewBundle v1 as a separate additive contract in
v2.18.0 with these boundaries:

- One bundle covers one validated canonical namespace and exactly one baseline
  that bypasses the lookup-result cache. CT may use its separately documented
  cache, whose provider, age, and attempt outcome remain explicit.
- Direct probes are fixed off. Certificate-transparency collection is optional
  and the selected policy is recorded.
- Review candidates derive from the same in-memory baseline. A failed baseline
  cannot produce observations or candidates.
- Workflow status distinguishes `completed` from `failed`. Collection validity
  distinguishes `complete_for_recorded_opportunities`, `partial`, `unavailable`,
  and `not_observed`. A failed baseline is not represented by an empty
  successful result.
- The artifact is role-neutral. Defender, consultant, analyst, and admin views
  use the same object and deterministic section order.
- Every retained evidence item has a stable content-derived `evidence_id`.
  Every candidate has a stable `candidate_id` and records its supporting
  `evidence_ids`.
- The artifact records temporal facts while assigning
  `workflow.freshness_assessment` the value `not_assigned`. recon does not
  define a universal freshness threshold for heterogeneous public metadata.
- A deterministic SHA-256 digest detects content modification. It is not a
  signature, collector identity, timestamp attestation, or authenticity proof.
- Bundles remain local and caller-owned. recon adds no upload, hosted retention,
  scheduling, monitoring, or automatic longitudinal storage.
- The stable lookup, batch, capsule, and MCP contracts remain unchanged.
- Delivery uses `recon review <domain>` and the MCP `build_review_bundle` tool.
  Both expose the same v1 object and collection boundary.

The additive schema and role-neutral renderer justify a minor release under the
project's v2 stability policy, so the first contract ships as v2.18.0 rather
than a patch release.

An operator-supplied set extension is deferred. It requires a later compatible
contract that preserves ordered typed member failures, declares membership as
caller-supplied, and does not infer ownership, control, organizational
relationships, relative security, or portfolio completeness.

## Consequences

- A caller can hand off one self-contained evidence review without relying on a
  client model to reconstruct workflow state or claim boundaries.
- Cache bypass increases collection work but removes ambiguity about whether the
  baseline was served from a prior lookup-result cache entry.
- CT remains optional, so two bundles can have different collection regimes.
  Consumers must read the recorded option and source states before comparing
  them.
- The deterministic Markdown renderer is a projection of the JSON artifact, not
  a branded report, risk register, scorecard, or remediation ranking.
- The digest provides integrity checking only. Cross-boundary authenticity still
  requires an external signing and timestamp system.
- Review bundles may contain context-sensitive public identifiers and tokens.
  Operators must protect and review them before sharing.
- Replay, delta classification, set membership, divergence, dashboards, and
  monitoring stay outside this contract.
