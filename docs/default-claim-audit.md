# Default claim audit

The canonical machine-readable inventory is
[`default-claim-audit.json`](default-claim-audit.json). It assigns every
discovered primary claim surface to a claim family, records the direct
producer, evidence, renderer, and regression-test paths for that family, and
states known limits. The queried domain remains a public namespace coordinate.
No family may silently promote it into an organization, owner, operator,
account holder, or current product user.

This is an implementation audit, not a replacement for the product roadmap or
the narrower proof-carrying claim-contract design in
[`claim-contracts.md`](claim-contracts.md). An `open` family identifies work
that remains. It is not evidence that the runtime already satisfies the stated
obligations.

## Coverage contract

`scripts/check_default_claim_audit.py` discovers and fails closed over:

- generated insight functions;
- every Rich panel renderer and material panel projection;
- every property occurrence in the stable JSON schema, including nested
  definitions;
- every MCP tool and top-level structured-output property;
- generated agent-guidance sections, excluding fenced examples and front
  matter;
- recommendation producers;
- public score, confidence, posterior, interval, contribution, and stability
  fields; and
- the MCP instruction preamble and named sections.

Root JSON fields and schema definitions have explicit family owners. MCP tools
normally own their top-level fields; `reevaluate_domain` replays the full JSON
result and therefore inherits each JSON root field's claim owner. Exact SHA-256
digests bind the sorted JSON-property and MCP-surface identifiers. A new field
changes a digest and blocks the gate even when it falls under an existing
owner, so updating a digest is never a substitute for reviewing the field.

Family references are role-aware. Producers and evidence must resolve inside
their canonical repository roots. Regression references must be Python files
under `tests/`. Absolute paths, traversal, backslash aliases, repository
internals, missing paths, escaped symlinks, and nonexistent Python symbols are
rejected.

## Family states

- `classification` says whether the output is a direct observation, documented
  derivation, bounded absence, unresolved state, static product contract, or
  non-claim transport.
- `lineage_status: exact` requires a direct generation path. Heuristic recovery
  from rendered text does not qualify.
- `lineage_status: incomplete` records a known missing link and cannot be paired
  with `audit_status: complete` for a material family.
- `lineage_status: static` applies to instructions and documentation whose
  runtime observations remain governed by separate claim families.
- `audit_status: open` means the family still requires implementation or review.

At the 2026-08-01 checkpoint, the inventory contains 27 families and covers 89
agent-guidance sections, 16 insight generators, 197 JSON property occurrences,
167 MCP tool and output surfaces, 31 panel producers, 3 recommendation
producers, 78 quantitative or categorical score fields, and 8 MCP instruction
sections. 23 families are complete. 2 material runtime families
have incomplete lineage: hardening guidance and the exposure index. Service
labels now derive a bounded role from retained,
collection-observable record evidence and render missing roles as unavailable.
Posture observations now carry their exact emitter, branch-local retained
evidence occurrences, and typed metadata predicates through CLI, MCP, profile,
and explanation paths. A metadata-only or profile-relative observation retains
an exact rule dependency but remains graph-disconnected from raw evidence, and
profile expectations are withheld whenever collection is degraded. Profiles
remain explicitly relative lenses, not scores or universal recommendations.
Explanation records now label
exact evidence-and-rule associations, exact rule-only associations,
reconstructed associations, and unsupported associations. The additive
`exact_provenance_complete` and `lineage_disconnected_terminals` diagnostics
require an explicit evidence-to-rule path while preserving the stable
schema-version-1 reachability fields. Generated insights
now retain their exact generator rule plus supporting evidence occurrences or
bounded observation scope through live, projected, enriched, and cache-served
results. Positive catalog and service claims require a retained occurrence, so
related-namespace inventory without subject-qualified evidence cannot become a
queried-namespace insight or declarative signal. Canonical observation scopes
fail closed when any required collection opportunity is unavailable, including
Autodiscover and OIDC metadata subchannels. Current cache reads and writes also
reject incomplete or inconsistent generated-insight lineage while preserving
valid degraded results. Role-specific claims such as an MX gateway attach only
the occurrences that established that role. The two static guidance families
remain open for semantic review. Rich panel and MCP text assembly now retain
the queried namespace coordinate, use the same projected values as structured
output, and exclude raw evidence from unavailable channels when deriving
panel-only summaries. An unavailable Autodiscover channel also projects a
cached tenant default domain back to the queried namespace on every format.

## Update procedure

1. Regenerate the JSON schema and surface inventory before changing ownership.
2. Run `uv run python scripts/check_default_claim_audit.py`. Review every
   missing or stale surface and decide whether an existing family is genuinely
   correct or a narrower family is required.
3. Add direct producer and evidence references, renderer obligations, known
   limits, and focused regression tests. Keep the family open and its lineage
   incomplete until the runtime path is exact.
4. Run `uv run python scripts/check_default_claim_audit.py --print-digests` and
   copy a changed digest only after that semantic review.
5. Run the complete local gate with `uv run python scripts/check.py`.

Track completion and dependency order remain in
[`docs/roadmap.md`](roadmap.md). Shipped behavior belongs in the root
[`CHANGELOG.md`](../CHANGELOG.md).
