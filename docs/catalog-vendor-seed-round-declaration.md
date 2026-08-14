# v2.14 Catalog Vendor-Seed Round Declaration

Status: closed; frozen 33-row collection and aggregate reduction complete; no
catalog rule promoted

Protocol frozen: 2026-08-13
Result recorded: 2026-08-14

This declaration fixed the vendor-seed label, denominator, exclusions,
disclosure rules, collection boundary, and interpretation before any selected
namespace was contacted. The private dossier passed the fail-closed preparer
after bounded source acquisition and with zero target requests. Exact member
rows and archived source bytes remain
private. The disclosure-safe commitments below merged through protected main
before collection began. The completed aggregate result is published in
[the vendor-seed memo](../validation/2026-08-14-catalog-vendor-seed-round.md).

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
  release-bound built-in catalog. Operator-local custom and process-local
  ephemeral fingerprints are excluded. The preparer records every built-in
  detection type attached to that slug, and the evaluator fails if those types
  drift before reduction.
- Every member is tied to a specific archived provider-controlled HTTPS source
  that explicitly supplies the relationship label. Search results, technology
  databases, reseller lists, inferred logos, and third-party directories are
  ineligible.
- Provider source acquisition starts from a strict private plan. For each
  provider, the curator declares an existing catalog slug, the registrable
  provider domains that may be contacted, exact HTTPS URLs, and expected media
  types. The declaration is an explicit curator assertion of provider control,
  not an automated corporate-ownership finding.
- The source freezer makes one sequential GET per declared URL with redirects,
  credentials, compression, and retry disabled. It rejects non-public or
  out-of-provider hosts, non-200 responses, media-type drift, empty bodies, and
  responses above 10 MiB each or 128 MiB in aggregate. It contacts no selected
  namespace and atomically writes the exact source plan, a private receipt, and
  the archived response bytes. The preparer requires the receipt's source-plan
  and implementation digests to match before it can freeze a frame.
- The schema-version-2 dossier must bind every source to that receipt's
  provider, source ID, URL, retrieval time, archive path, byte count, and
  SHA-256 digest. A substituted or unused source blocks frame preparation.
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

## Frozen pre-collection contract

The final frame contains one eligible provider stratum. The provider-owned
[HubSpot case-study index](https://www.hubspot.com/case-studies/all) exposed 459
case-study routes. The mapping sample was fixed as
the first 40 unique routes in provider document order. Thirty-three archived
pages exposed exactly one company-domain link through HubSpot's dedicated
company-link field and remained disjoint from the complete prior-observation
union. Seven pages without that exact mapping were excluded before the final
source plan. The resulting HubSpot stratum contains 33 rows and measures the
release-bound `cname`, `cname_target`, `spf`, and `txt` paths for the `hubspot`
slug.

Other researched providers were rejected before collection rather than forced
into weak strata:

- all 48 deterministically mapped rows from the
  [Shopify case-study index](https://www.shopify.com/case-studies) overlapped
  the frozen prior-work union;
- the [Webflow customer-story index](https://webflow.com/customers) did not
  expose a deterministic company-domain link on enough archived stories;
- the [Vercel customer index](https://vercel.com/customers) exposed 13
  server-rendered story routes; and
- the [Intercom customer index](https://www.intercom.com/customers) exposed 3
  server-rendered story routes.

The exclusion union contains 17,952 canonical namespaces derived from 74
development and prior-frame inputs plus 85 retained prior-result inputs. No
selected namespace was contacted while source pages, exclusions, membership,
or the contract were prepared. Certificate transparency and direct probes are
both disabled for this round. Minimum recurrence remains two occurrences
across two distinct namespaces, but this holdout cannot tune the evaluated
catalog.

| Commitment | SHA-256 or count |
|---|---|
| Round ID | `catalog-vendor-seed-20260813-hubspot` |
| Final provider source plan | `40ac18589437e272143e038964a0b508d475bebe44c9810205ed42a9239911b3` |
| Immutable source receipt | `a7d21625d826ca18157cc883c40f81a599a6ddbea4f02741d988c5da64621207` |
| Final source archive | 33 pages, 18,691,543 bytes |
| Private dossier | `c44f8dbab5cf09956b581ebfda58d429861d32c834f346b55848080405e99ad7` |
| Canonical exclusion union | `1f90120dce54c8efc74797864f75545c27ed03b1126cd0bfcfa9f7324de228e3` |
| Source contract | `a49f93324437900e4ae1bab2125127c427dfa49abe5fa9f7717ed4992e0b899c` |
| Source content | `a897e25b22bfaddfa940ab55dbfa3046a27d54ae7db1c5d8a3bbc2b46e0469e7` |
| Frame and HubSpot member set | `37bb3e9f2609b9f4470d637d60f42077593169522b117af9660ac3058516728b` (33 rows) |
| Generic round plan | `bbacaf9ec89d5518014288394c187b3afdd3f7659794d857a1c55e7a1ff0e8d0` |
| Generic round manifest | `74c2bf7989f81a72d853132c74eddf3bd3f061aaf8168836d825fe3f5166eeb3` |
| Built-in catalog | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Execution surface | `dcc4bb3713070559e9248c0382a6ad4f439fddec882362c1e94d0273bc3636b0` |

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

## Completed aggregate result

The exact frame ran once from clean protected main at
`d6e7b17aa3686a83cf004e8cd93415aa411ec423`. All 33 rows completed with no
error. HubSpot was independently corroborated on 29 rows; 4 rows were observed
silent; and 0 were unavailable, unmeasured, or errors. The resulting
provider-relationship corroboration rate is 0.878788, with a Wilson 95%
interval from 0.726745 to 0.951838.

The typed queue contained one recurrent SPF bucket and three recurrent TXT
buckets. Nine CNAME gaps were singletons below the frozen threshold. No rule is
promoted because this evaluation holdout cannot tune the catalog and recurrence
alone is not an independent provider basis. Exact commitments, aggregate
counts, candidate dispositions, and the non-recall interpretation are in the
[result memo](../validation/2026-08-14-catalog-vendor-seed-round.md) and its
[machine-readable aggregate](../validation/2026-08-14-catalog-vendor-seed-aggregate.json).

## Implementation and next operation

The implementation has one bounded provider-source acquisition step and keeps
frame preparation and result reduction network-free:

- `validation/archive_vendor_seed_sources.py`, which performs bounded
  provider-source acquisition, atomically archives the exact response bytes,
  and emits an integrity-checked private receipt without printing URLs or
  target identifiers;
- `validation/prepare_vendor_seed_round.py`, which validates provider sources,
  the acquisition receipt, exclusions, membership, catalog slugs, minimum
  stratum size, and the generic round contract;
- `validation/evaluate_vendor_seed_round.py`, which reduces a complete result
  set into per-provider disclosure-safe corroboration counts and Wilson
  intervals; and
- `tests/test_vendor_seed_source_archive.py` and
  `tests/test_vendor_seed_round.py`, which exercise destination and response
  policy, atomicity, receipt integrity, normalization, exclusivity, source and
  catalog drift, incomplete results, denominator semantics, and identifier
  absence.

The vendor-seed round is closed. The next operation is to freeze and re-observe
a prior sample as the drift round, preserving repeated-frame evidence as drift
rather than independent coverage. No later result may retroactively add
members, change this denominator, or tune a catalog rule from this holdout.
