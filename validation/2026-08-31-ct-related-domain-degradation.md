# CT related-domain degradation review

Date: 2026-08-31 PDT

Status: complete; implementation, synthetic cross-surface regression, and the
full repository gate pass.

## Trigger and scope

A black-box pass against the published `v2.18.0` tag, commit `93956634`,
reported one lookup with a successful CertSpotter result and 100 CT names but
an empty `related_domains` inventory on every output surface after
`dns:cname` degraded. The pass used aliases only and filed no issue. This
review does not retain target names or private dumps and does not repeat live
target collection.

The change is a stability-soak repair inside the existing lookup contract. It
does not add a collector, command, flag, public JSON field, classification
rule, ownership claim, or direct probe.

## Root cause

`related_domains` is a mixed-source inventory. The CT collector populated it
before CNAME-chain enrichment, but the collection-observable projection
treated `dns:cname` as owner of the entire field and replaced the inventory
with an empty tuple. CT provider metadata, certificate counts, and lexical
insights survived, leaving a contradictory record with successful collection
and no hosts.

Preserving the entire mixed inventory would be too broad. It could expose a
CNAME-only name after the channel that established it became unavailable. The
repair therefore records the exact CT-contributed subset as internal
collection provenance and intersects that subset with `related_domains` only
when CNAME enrichment degrades.

## Contract decisions

- Successful live, partial, and local-cache CT paths record their exact names.
- Whole-DNS failure still empties all DNS-derived related-name state.
- CNAME-dependent surface attributions, unclassified chains, and motifs remain
  empty when `dns:cname` is unavailable.
- Lexical observations and their rendered insights are recomputed from the CT
  names that remain visible.
- The internal provenance persists additively in the current result-cache
  format but is omitted from stable lookup JSON.
- Older cache entries without this provenance stay conservative and emit no
  related names under degraded CNAME collection.
- Default briefing ranking remains unchanged. Full views still retain every CT
  name, including test and environment-shaped names, under the existing host
  classes.

## Regression frame

All fixtures use reserved `.invalid` names. The bounded regression combines
four CT names, one CNAME-only name, successful CT metadata, and a degraded
`dns:cname` marker. It verifies:

- live and cached CT collection provenance;
- source-result and merged-result projection;
- legacy-cache fail-closed behavior;
- stable lookup JSON without internal-field leakage;
- default Markdown, full Markdown, full plain text, panel, and MCP JSON parity;
- connection-map host classes and full-view retention of a test-shaped name;
- empty CNAME surface attribution; and
- NamespaceReviewBundle embedding of the same corrected stable lookup.

The focused final regression gate completed with 230 passing tests and one
unrelated skip. The canonical `uv run python scripts/check.py` gate then passed
on the final tree: 6,604 main tests and 38 MCP doctor tests passed, 32 tests were
skipped, total branch coverage was 91.11 percent against a 90.2 percent floor,
and every schema, surface-parity, claim, documentation, text-hygiene, and
file-size stage passed.
