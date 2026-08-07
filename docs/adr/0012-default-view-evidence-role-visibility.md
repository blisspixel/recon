# ADR-0012: Split evidence-role visibility between the default and detailed views

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

Every human-facing service label carried the record role that established it,
inline and in full prose: `Slack (public TXT account indicator)`,
`Okta (CNAME endpoint binding)`, `Microsoft 365 (MX delivery path)`,
`Yahoo Small Business (role unavailable)`. The renderer obligation on claim
family `runtime.service-label.v1` required the qualification, and the
obligation is right: a catalog name alone does not establish a role, and a TXT
account record is not a deployment.

The implementation of that obligation was wrong for the default view. The
qualifier repeated once per service, and often several times per line, so the
answer to "what do they run" arrived buried under the answer to "how do we
know", which the operator had not asked for yet. On a dense apex the Provider
row spent two wrapped lines saying `(MX delivery path)` twice. The
`(role unavailable)` case was worse than noise: it occupied a row to report
that recon could not say why it named the vendor at all.

The claim-discipline invariant in `ROADMAP.md` treats this qualification as a
default-surface obligation, so relaxing it needs a decision record rather than
a rendering tweak.

## Decision

Evidence roles move from "always inline" to "in the view that asks for them".

- The **default** panel, `--plain`, `--md`, and the `--chain` tree render
  service and provider labels without their record-role qualifier.
- `--explain`, `--verbose`, and `--full` render every qualifier exactly as
  before, unchanged byte for byte.
- Every **machine** surface is unchanged: the `--json` record (including the
  stable `provider` field), `--csv`, and the MCP tool payloads keep the full
  prose roles. Agents and scripts lose nothing.
- A label whose role is **unavailable** is *omitted* from the default view
  rather than rendered bare. Stripping the qualifier in place would promote an
  unattributed catalog match into an asserted observation, which inverts the
  obligation instead of relocating it.
- Two qualifiers survive compaction in shortened form because they hedge the
  claim rather than name a record type: a non-MX provider renders as
  `(likely downstream)`, and a gateway with no observed downstream renders as
  `(downstream unobserved)`.
- The provider row re-hedges instead of dropping, as `(no supporting record)`.
  It is the panel's single answer to "who handles their mail"; dropping the
  segment would leave the row silent, and rendering it bare would assert a
  delivery path no retained record supports.
- A default view that left something out says so, once, pointing at
  `--explain`, and naming `--full` with a count when unattributed matches were
  omitted. A view that compacted nothing carries no note.

The obligation on `runtime.service-label.v1` and `runtime.email-topology.v1`
is restated accordingly: roles must be qualified on the evidence surfaces and
must never be *implied* on the default surface. Compaction that would upgrade
a claim is prohibited; compaction that only relocates a role is required.

## Consequences

- The default view answers the question the operator asked. Role detail is one
  documented flag away, and the panel says which flag.
- The claim model is unchanged in substance. No default-view label asserts more
  than it did before; the unattributed case now asserts strictly less.
- The default view is no longer a complete enumeration of catalog matches.
  Unattributed matches appear only under `--full` and in the JSON record, so
  any consumer counting rows must use the JSON record, not the panel.
- `--json` and the panel now differ in wording by design. `docs/stability.md`
  already excludes panel prose from the contract and keeps the JSON `provider`
  field stable; this ADR is the record of that divergence being deliberate.
- A new role qualifier must be added to the compaction table in
  `formatter/classify.py` at the same time it is added to the label producers,
  or it will leak into the default view. The golden renders in
  `tests/test_golden_renders.py` are the regression guard.
