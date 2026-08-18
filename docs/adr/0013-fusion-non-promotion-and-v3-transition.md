# ADR-0013: Apply fusion non-promotion through a compatible v2 transition

- **Status:** Accepted
- **Date:** 2026-08-13

## Context

The v2.11 pre-collection audit exhaustively evaluated all 64 combinations of
the frozen Microsoft 365 DNS evidence roles. The candidate Bayesian arm never
supports a case where the deterministic comparator abstains. Its
candidate-only positive discordance count is therefore always zero, so the
preregistered benefit lower bound cannot become positive at any sample size.
The live window was cancelled before any target request or private-row access.

The preregistered disposition for an inconclusive or negative result was to
move fusion out of the primary product path and retain it as an advanced
diagnostic. Applying that decision by changing the CLI default in v2.12 would,
however, violate the project's stability policy. That policy explicitly says
that changing an existing default relied on by a consumer is breaking and
requires a major release plus a deprecation window. Since v2.0, both `lookup`
and `batch` have enabled fusion when neither `--fusion` nor `--no-fusion` was
supplied.

The MCP surface has no conflict. `lookup_tenant` already returns the
deterministic observation record, while `get_posteriors` and `explain_dag` are
separate explicit diagnostic tools. Stable JSON fields also already represent
both states through `fusion_enabled`, an empty `slug_confidences` object, and an
empty `posterior_observations` array when fusion does not run.

## Decision

Fusion is classified and documented as an advanced diagnostic immediately,
but the v2 runtime default is preserved through a compatibility transition.

- `--fusion` and `--no-fusion` remain stable and unchanged.
- In v2, omitting both flags retains the v2.0 behavior and computes fusion.
  An interactive terminal notice says that the implicit default is deprecated
  and asks the operator to choose a flag explicitly.
- Redirected and machine-oriented invocations remain silent. A transition
  notice must never contaminate stdout or make JSON, NDJSON, or CSV unparsable.
- `--explain-dag` remains an explicit request for the diagnostic and continues
  to imply fusion without an additional notice.
- Documentation and examples treat deterministic output as the primary
  interpretation path and name `--fusion` as the explicit advanced path.
- MCP tool names, parameters, and behavior do not change. Ordinary lookup
  stays deterministic; `get_posteriors` and `explain_dag` remain explicit.
- The v3 major boundary changes the omitted CLI choice to fusion off. Explicit
  flags and the stable JSON field shapes remain unchanged.
- A future proposal to restore fusion to a primary path requires a new
  preregistration with executable arm-identifiability and dominance checks
  before target collection.

## Consequences

- v2.12 applies the product-positioning decision without silently breaking a
  stable default or forcing a premature major release.
- Operators can make behavior invariant across the v3 boundary now by passing
  either flag. Automation that already passes a flag is unaffected.
- The implicit v2 path remains computationally more expensive until v3. This is
  deliberate compatibility debt with a named removal boundary, not evidence
  that fusion remains the recommended interpretation path.
- The JSON schema does not change. Consumers continue to branch on
  `fusion_enabled` rather than infer execution from missing fields.
- The roadmap must distinguish the completed v2.12 transition from the v3
  default flip. A minor release must not claim the latter has already shipped.

## Amendment, 2026-08-18: the flip is claim-neutral debt, not a required milestone, and v2.16 changed the MCP premise

Two things changed after this ADR was accepted, and a panel review reconciled
them.

**The "MCP surface has no conflict" premise is now false.** v2.16 ("MCP JSON
stops hiding fusion") made `lookup_tenant(format="json")` apply the fusion layer
unconditionally, and `docs/surface-parity.md` now pins fusion present on both
`--json` and `mcp json`. `lookup_tenant` has no fusion flag, so MCP JSON computes
fusion by default and always, and an MCP consumer cannot pin fusion-on the way a
CLI consumer can with `--fusion`; its only protection across any future flip is
the `fusion_enabled` field. The consequence is that the flip is no longer
CLI-only: flipping the CLI default off while leaving MCP JSON on would reopen the
CLI-versus-MCP divergence v2.16 fixed as a bug and the parity gate now guards. A
future flip must therefore either also change MCP JSON, which touches near-stable
MCP behavior, or record an explicit fusion-state exception in the parity
contract. The original claim above that ordinary MCP lookup stays deterministic
is superseded.

**The flip is claim-neutral, not merely schema-stable.** The v2.11 identifiability
finding, re-confirmed by the 2026-08-17 adversarial corpus (zero of seven
administrative-only plants moved a gated node; the record-role gate holds),
establishes that fusion cannot add a supported claim the deterministic layer does
not already make. Flipping the default off therefore changes only which of three
diagnostic fields are populated (`fusion_enabled`, `slug_confidences`,
`posterior_observations`), not any claim recon emits, and no shipped consumer
reads those fields from a default no-flag invocation: the canonical sample ships
generated with `--no-fusion`, and the SIEM and automation examples branch on the
stable key set.

**Reclassification.** The flip remains breaking under the stability policy (a
changed stable default), so it may not ship in a minor. But it does not warrant,
and should not define, a major release. It is reclassified from "the v3 default
flip" to deferred, optional, claim-neutral compatibility debt that rides a
genuine contract-maturity major (the claim/observation-envelope decision) if and
when one ships, and otherwise does not happen: the v2 default stays on behind the
stable `--fusion` / `--no-fusion` flags. A v3.0 is now conditional on the envelope
decision, not on this flip. Until a flip is committed to a specific release, the
interactive deprecation notice should name the advanced-diagnostic positioning
without promising a v3 flip that may not occur; that notice rewording is a
runtime change and rides the release that next touches `cli/shared.py`.
