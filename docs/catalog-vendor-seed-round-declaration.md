# v2.14 Catalog Vendor-Seed Round Declaration

Status: protocol implementation complete; private source dossier and frame not
yet frozen; target collection has not started

Protocol frozen: 2026-08-13

This declaration fixes the vendor-seed label, denominator, exclusions,
disclosure rules, collection boundary, and interpretation before any selected
namespace is contacted. The exact provider sources, member rows, frame, catalog
digest, and execution digest will be added only after a private dossier passes
the fail-closed preparer and the resulting commitments merge through protected
main. Until then, this is a protocol declaration, not a completed round.

## Question

> How often does recon independently corroborate provider-controlled customer
> relationship evidence on a disjoint, provider-stratified holdout using its
> bounded public-metadata collection?

The label is a provider relationship. It is not a label for a particular DNS
record. A provider may name a customer even when the customer's apex publishes
no catalog-readable record for that provider, uses the service on a different
namespace, or has changed configuration since the source was published.

The reported measure is therefore a **provider-relationship corroboration
rate**, not recall, precision, prevalence, or a false-negative rate:

```math
\text{corroboration rate} = \frac{C}{C + S}
```

Here, $C$ is the number of relationship-labeled rows where the frozen provider
slug is observed, and $S$ is the number of rows where an eligible
catalog path was measured but the provider slug was not observed. Unavailable,
unmeasured, and error rows stay outside that denominator and are reported
separately. Each provider receives its own point estimate and 95% Wilson score
interval. Provider strata are not pooled into a population claim.

## Eligibility and independence

The private source dossier must satisfy all of these rules before a frame can
exist:

- Every provider is already represented by a stable fingerprint slug in the
  frozen catalog. The preparer records every catalog detection type attached to
  that slug, and the evaluator fails if those types drift before reduction.
- Every member is tied to a specific archived provider-controlled HTTPS source
  that explicitly supplies the relationship label. Search results, technology
  databases, reseller lists, inferred logos, and third-party directories are
  ineligible.
- Every provider stratum contains at least 20 unique registrable apexes. This is
  both the public small-cell disclosure floor and a minimum descriptive sample,
  not a claim of statistical representativeness.
- The complete development corpus, unseen vertical holdout, rank frame,
  regional frame, prior case-study spot-check rows, and any earlier vendor-seed
  observations are frozen exclusions. An apex cannot occur in two provider
  strata.
- The dossier, archived source bytes, member-to-source mapping, provider
  membership, and exclusion membership stay in ignored private storage. The
  public repository receives only provider names, aggregate counts, reviewable
  source citations in the final memo, and cryptographic commitments.

These rules make the holdout disjoint from catalog development and earlier
measurement. They do not turn a provider relationship into an authoritative
label for DNS publication.

## Frozen collection and scoring behavior

The round uses the ordinary documented recon collection boundary. Certificate
transparency on or off must be chosen in the private dossier and then committed
before target contact. Direct CSE and BIMI probes are always disabled. The
generic schema-version-2 catalog-round manifest binds the normalized frame,
source contract, catalog, execution code, dependency lock, collection options,
recurrence thresholds, and promotion budget.

For each provider row, the evaluator emits exactly one outcome:

| Outcome | Meaning |
|---|---|
| `corroborated` | The frozen provider slug is present in recon's result. |
| `observed_silent` | At least one catalog path eligible for that slug was measured, but the slug was not observed. This is silence, not a false negative. |
| `unavailable` | No eligible path was measured successfully and at least one was unavailable. |
| `unmeasured` | The result contains no measurement for an eligible path. |
| `error` | The namespace produced an error record. |

The reducer requires every frozen member exactly once, verifies source and
membership digests, verifies catalog record-type stability, writes no target
identifier to stdout or the public aggregate, and refuses to replace an
existing artifact. A provider result below the 20-row disclosure floor cannot
be published.

This evaluator characterizes the frozen catalog. It does not tune a rule from
holdout outcomes. Any later candidate catalog must be derived independently,
carry the normal current public reference, review date, positive,
lookalike-negative, sparse, and provenance fixtures, and pass a separate
fixed-observation zero-regression comparison before promotion.

## Implementation and next operation

The network-free implementation consists of:

- `validation/prepare_vendor_seed_round.py`, which validates provider sources,
  exclusions, membership, catalog slugs, minimum stratum size, and the generic
  round contract;
- `validation/evaluate_vendor_seed_round.py`, which reduces a complete result
  set into per-provider disclosure-safe corroboration counts and Wilson
  intervals; and
- `tests/test_vendor_seed_round.py`, which exercises normalization,
  exclusivity, source and catalog drift, incomplete results, denominator
  semantics, and identifier absence.

The next operation is to assemble and archive the private provider-controlled
source dossier, freeze the provider set and exclusion union, run the preparer
with zero target requests, and add the resulting aggregate commitments to this
declaration. Collection remains blocked until those commitments and the exact
implementation pass protected-main CI.
