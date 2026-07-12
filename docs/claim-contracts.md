# Internal Claim Contracts

Status: first bounded contract implemented internally after v2.4.0

This document specifies recon's executable claim-contract substrate. It is an
internal assurance and research surface, not a tenant JSON, cache, MCP, or
package contract. The first implementation deliberately evaluates one narrow
public observation before any broader claim registry or robustness solver is
built. Opt-in cohort schema 2.2 consumes transient claim-state and effective-
policy projections and emits no per-domain dossier or private annotation.

## First Contract

Contract identifier: `dns.dmarc.valid_policy_is_reject.v1`

Claim:

> At the frozen evaluation time, a fresh valid DMARC policy record retained at
> the exact `_dmarc.<queried-apex>` TXT publication point declares `p=reject`.

This does not claim that mail receivers will reject a message, that DMARC
validation will pass, that every relevant author domain inherits this policy,
or that the domain is secure. RFC 9989 explicitly separates the published
Domain Owner Assessment Policy from receiver handling and defines a DNS tree
walk for applicable-policy discovery. recon's first contract is only about the
record directly observed at the queried apex.

The current rules are:

- a fresh parser-validated explicit `p=reject` record establishes positive support;
- a fresh parser-validated explicit `p=none` or `p=quarantine` record establishes an
  explicit disconfirmation of this exact `p=reject` claim;
- positive and disconfirming certificates remain independent, so comparable
  contradictory observation units produce conflict;
- empty, malformed, multiple-record, unavailable, time-unknown, stale, or
  scalar-only observations establish neither sign.

Empty and invalid results are intentionally unresolved in v1. The current DNS
adapter returns the same empty list for `NXDOMAIN`, `NoAnswer`, and a
safety-suppressed private canonical target. It retains neither the response's
authority section nor DNSSEC denial validation. RFC 2308 authority semantics,
RFC 4035 authenticated denial, and RFC 9824 compact denial therefore cannot be
reconstructed after collection. Treating this operational empty result as an
authoritative or authenticated absence certificate would overstate the stored
evidence.

## Four Orthogonal Axes

The implementation keeps four concepts separate.

Construction state:

- `complete`: the typed observation can enter rule closure;
- `invalid`: observed material did not form one valid contract input;
- `incomplete`: required typed lineage is missing;
- `mixed`: a dossier contains more than one construction state.

Collection state:

- `not_attempted`;
- `observed_value`;
- `observed_empty`;
- `unavailable`;
- `not_enabled`;
- `not_applicable`.

Time state uses `TenantInfo.resolved_at`, the completion time of the whole
resolution, because the current DNS collector does not retain a per-query DMARC
timestamp. That approximation is recorded as a provenance limitation.

The states are:

- `current` within the contract's 24-hour window;
- `stale` after that window;
- `unknown` when the observation time is missing, naive, invalid, or future;
- `mixed` when a ledger contains more than one time state.

Claim state is the two-coordinate projection of certificate-family presence:

| Positive certificates | Negative certificates | State |
|---|---|---|
| empty | empty | `unresolved` |
| nonempty | empty | `supported` |
| empty | nonempty | `disconfirmed_within_public_model` |
| nonempty | nonempty | `conflicted` |

The information order is componentwise. It is not a truth, severity, maturity,
or confidence ranking. Conflict is more informed than either one-sided state,
not more true.

## Dependency Units And Certificates

One post-resolution DMARC compatibility projection becomes one dependency unit.
Parser fields, service labels, signals, scores, explanations, and renderer views
derived from its retained record do not become independent corroboration.
Duplicate `EvidenceRecord` renderings are deduplicated before an unambiguous
canonical JSON payload is hashed for the unit identifier. A merged scalar
conflict without raw candidate lineage remains incomplete rather than being
promoted into two certificates.

Each unit records:

- a content-derived canonical identifier;
- the exact record owner and source family;
- collection, construction, and resolution-completion time state;
- the parser-owned atoms established by the observation;
- retained raw `EvidenceRecord` origins;
- whether the current contract has enough lineage to issue a certificate.

The current adapter records only the vantage class as the system-configured
recursive path. It does not retain the resolver identity, DNS response code,
authority section, safety-suppression reason, per-query timestamp, or DNSSEC
validation status. The dossier reports these limitations explicitly.

Certificates are antichains of frozen dependency-unit identifiers. Alternative
derivations are antichain union. Conjunctive premises use pairwise unit-set
union followed by removal of redundant supersets. Contracts must be acyclic;
the evaluator computes their finite monotone Horn closure in a deterministic
topological order. Grouping all rules for a conclusion before checking the
final antichain makes the certificate bound independent of rule names and
temporary nonminimal proofs. Duplicate derivations are idempotent, and one
inconsistent sign never erases the other.

Ledger union is associative, commutative, and idempotent. Rule closure is
recomputed after union because premises split across views can establish a
claim that neither reduced view established alone. Expiry is removal followed
by replay from the remaining ledger, not an inverse merge.

## Exact Bounds

The first evaluator is intentionally bounded:

- at most 32 dependency units;
- at most 32 atoms;
- at most 16 rules;
- at most 128 minimal certificates per atom;
- at most 4,096 raw alternatives in one conjunctive certificate product;
- at most 4,096 raw conjunctive alternatives cumulatively across the complete
  evaluation.

These are implementation-safety bounds, not product SLOs or evidence weights.
The conjunction bound is a deterministic pre-allocation resource guard and may
refuse a product whose later antichain would have collapsed below the certificate
bound. If evaluation would cross a declared bound, the evaluator raises
`ClaimEvaluationLimitError`. It never truncates proofs and then presents the
result as complete.

## Verification

The direct proving suite is `tests/test_claim_contract.py`. It covers:

- positive, explicit disconfirming, conflict, and unresolved states;
- unavailable, empty, invalid, stale, future, naive-time, and missing-lineage
  behavior;
- canonical raw-origin units and duplicate invariance;
- scalar-to-raw policy binding and delimiter-safe canonical identities;
- associative, commutative, and idempotent ledger union;
- monotone sign retention and replay after expiry;
- a cross-view conjunction that appears only after merged-ledger closure;
- exact agreement with independent exhaustive enumeration;
- order-independent fail-closed unit, atom, rule, per-conjunction, cumulative-
  conjunction, and final-certificate bounds;
- an inclusive exact 24-hour freshness boundary and stale classification one
  microsecond beyond it;
- provenance-incomplete admission rejection;
- adjacent cohort tests for the opt-in 2.2 consumer, frozen batch evaluation
  time, strict-versus-atemporal isolation, raw-bound effective policy, and both
  private transient projections;
- unchanged tenant JSON and package facade.

Run the focused proof and adjacent regressions with:

```bash
uv run pytest tests/test_claim_contract.py tests/test_dmarc.py \
  tests/test_cohort_summary.py tests/test_cohort_summary_cli.py \
  tests/test_source_status.py tests/test_collection_view.py -q
```

The full project gate remains authoritative:

```bash
uv run python scripts/check.py
```

## Non-Goals And Next Gate

The first contract does not add a generic ontology, probability, confidence
weight, Belnap operator library, recursive Datalog runtime, incremental
retraction algorithm, minimum cut, hitting-set solver, or public dossier field.

The first consumer is the opt-in in-core cohort schema 2.2 selected with
`recon batch --summary --summary-schema 2.2`. It freezes one `as_of` for the
batch, evaluates each original `TenantInfo`, and adds the four-state value plus
a raw-evidence-bound effective policy to a transient mapping. Both private
fields are discarded with that mapping. The DMARC metric kind is
`contract_scoped_observed_rate`. The released schema 2.1 remains the default and
does not consume the contract.

The standalone aggregate sidecar consumes stable tenant JSON, which deliberately
omits `resolved_at`. With `--schema-version 2.2`, it therefore cannot claim the
24-hour contract and labels its raw-evidence-bound compatibility view
`atemporal_explicit_policy_rate`. It reparses `t` and historic `pct` from the
same retained record. The next new consumer is the predeclared product-quality
baseline. It may enroll this contract as one deterministic claim arm only after
its units and labels are kept disjoint. Empty-result negative semantics require
richer DNS authority or authenticated-denial provenance, not a prompt rule or
post-hoc assumption.

## Primary Sources

- [RFC 9989, DMARC](https://www.rfc-editor.org/info/rfc9989/), May 2026.
- [RFC 3986, URI Generic Syntax](https://www.rfc-editor.org/info/rfc3986/), January 2005.
- [RFC 2308, Negative Caching of DNS Queries](https://www.rfc-editor.org/rfc/rfc2308), March 1998.
- [RFC 4035, DNSSEC Protocol Modifications](https://www.rfc-editor.org/rfc/rfc4035#section-5.4), March 2005.
- [RFC 9824, Compact Denial of Existence in DNSSEC](https://www.rfc-editor.org/rfc/rfc9824), September 2025.
- [Belnap, A Useful Four-Valued Logic](https://doi.org/10.1007/978-94-010-1161-7_2), 1977.
- [Green, Karvounarakis, and Tannen, Provenance Semirings](https://web.cs.ucdavis.edu/~green/papers/pods07.pdf), PODS 2007.
- [de Kleer, An Assumption-Based TMS](https://cdn.aaai.org/AAAI/1988/AAAI88-034.pdf), AAAI 1988.
