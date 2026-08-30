# Namespace Review Bundles

NamespaceReviewBundle v1 is recon's separate, caller-owned contract for a
deterministic evidence handoff about one public namespace. It does not add fields
to or replace the stable lookup, batch, capsule, or MCP contracts. Its first
slice is intentionally role-neutral: defenders, consultants, analysts, and
admins receive the same artifact and the same human rendering.

Use `recon review <domain>` for the role-neutral Markdown view, add `--json` for
the structured artifact, or add `--output <path>` to persist that JSON locally.
The MCP `build_review_bundle` tool returns the same structured artifact, and the
`domain_report` prompt composes its briefing from one call to that tool.

## Collection contract

One bundle describes one validated canonical namespace and exactly one baseline
collection. The baseline always bypasses the lookup-result cache. This avoids a
hidden reused tenant result and ensures that every review candidate is derived
from the same in-memory baseline. Certificate-transparency collection may use
its separately documented cache; provider, cache age, and attempt outcome are
recorded under `collection.cache`.

The CLI and MCP adapters control that collection path. The pure core composer
also rejects a non-null lookup `cached_at` value and requires its collection
context to attest `result_cache=bypassed` and `direct_probes=false`. External
callers that bypass the supported adapters own that acquisition attestation;
they cannot relabel a known cache hit as fresh.

- Direct probes are fixed `false`.
- Certificate-transparency collection is the one optional collection lane and
  its choice is recorded.
- No recursive lookup, related-domain expansion, exposure scoring, simulation,
  posture profile, credentials, port scan, or target mutation runs as part of
  the bundle.
- Normal apex reduction remains visible through the requested and canonical
  namespace fields. The bundle does not infer an organization from either.

## Artifact contract

The authoritative artifact is versioned JSON under a separate Draft 2020-12
schema. It records:

- the bundle schema, generation time, recon version, and interpretation digests;
- the caller-supplied single-namespace scope and collection options;
- bounded source-opportunity states;
- explicit baseline and candidate-stage outcomes;
- the explained lookup baseline, retained evidence ledger, and hardening review
  candidates when the baseline succeeds;
- the standing scope statement and limitation identifiers; and
- a deterministic SHA-256 content digest.

Every retained evidence item has an `evidence_id`. Every review candidate has a
`candidate_id` and lists the `evidence_ids` that support it. IDs are stable for
the same normalized content. They are references within the artifact, not
claims that a source is authoritative or that an observation proves product
use, ownership, or operational state.

The content digest detects modification. It is not a digital signature, does
not authenticate the collector, and is not proof that collection occurred at a
particular location or under a particular identity.

## Workflow and collection states

Workflow status and bounded collection validity are separate.
`workflow.status` is `completed` for a successful baseline and `failed` for a
typed baseline error. `workflow.collection_validity` is one of:

- `complete_for_recorded_opportunities`: every recorded source opportunity was
  observed with a value or an observed empty result;
- `partial`: at least one recorded opportunity was degraded or unavailable;
- `unavailable`: every recorded opportunity was unavailable; or
- `not_observed`: no source opportunity was recorded.

The complete state is deliberately bounded. It does not claim that every
public or private control was observable. A failed workflow has no explained
baseline, evidence ledger, or candidate report.

A candidate stage that did not run is explicit. It is never serialized or
rendered as an empty successful candidate list. Conversely, a successful stage
with no candidates has an empty list and remains distinguishable from failure.

## Temporal facts, not a freshness verdict

The bundle records collection and generation timestamps as facts. Because the
baseline bypasses the lookup-result cache, it does not combine the review with a
silently reused tenant result. The bundle still assigns
`workflow.freshness_assessment` the explicit state `not_assigned`. CT cache
provenance remains separately visible and does not become a freshness verdict.

recon has no universal fresh or stale threshold for heterogeneous DNS,
certificate-transparency, and identity metadata. A consumer may apply its own
policy after reading the timestamps, but it must not describe that policy as a
recon freshness verdict.

## Deterministic human rendering

The Markdown projection uses the same artifact for every audience and renders
these sections in this exact order:

1. Collection validity
2. Observed mail and identity configuration
3. Public connection indicators
4. Evidence and lineage
5. Review candidates grouped by `observation_state`
6. Unresolved and unavailable evidence
7. Scope statement

The renderer treats all retained text as untrusted observed data. Dynamic text
is stripped of control characters and escaped for Markdown before insertion.
The evidence section keeps the complete retained ledger separate from mail and
identity observations. It pairs each explained baseline item with its lineage
state and evidence identifiers, so infrastructure, connection, mail, identity,
and confidence evidence cannot be mistaken for one another. Candidate
identifiers remain visible so a reader can trace a prompt back to the structured
artifact.

A failed baseline renders collection failure and the scope statement only. It
does not render empty observation or candidate sections. A partial bundle names
degraded or unavailable evidence before presenting bounded observations.

Candidate severity is retained because it belongs to the existing gap record,
but the renderer groups candidates by `observation_state` and does not rank
them. The artifact and renderer provide no overall security score, maturity
grade, vulnerability verdict, compliance result, remediation priority, or
cross-domain comparison.

## Privacy and retention

Bundles may retain public DNS values, verification tokens, tenant identifiers,
related domains, and collection metadata. Publicly observable does not mean
context-free or harmless to redistribute. Protect the artifact under the
operator's data policy and review it before sharing.

recon does not upload, schedule, monitor, or retain review bundles. Local output
remains caller-owned. Longitudinal storage, signatures, hosted retention, and
automated monitoring require separate decisions.

## Deferred set extension

ReviewBundle v1 does not define an operator-supplied set, portfolio manifest,
divergence record, or set renderer. The existing batch portfolio evidence
bundle remains available for those workflows. A future set extension must wait
until the single-namespace contract is stable, preserve ordered typed member
failures, and declare membership as caller-supplied. It must not infer ownership,
control, a corporate relationship, relative security, or portfolio completeness.
