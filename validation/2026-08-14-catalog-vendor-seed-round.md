# Catalog Vendor-Seed Round Result

**Date:** 2026-08-14

**Decision:** Vendor-seed round complete; accept the bounded characterization
and promote no catalog rules. The later frozen-sample drift round is closed.

**Disclosure:** Aggregate only. No selected namespace, record value,
organization name, tenant identifier, or per-domain row is included.

## Question and boundary

The frozen question was how often recon independently corroborates
provider-controlled customer evidence on a disjoint holdout using its bounded
public-metadata collection. The provider evidence labels a relationship. It
does not label publication of a particular DNS record, current product use, or
ownership.

The reported metric is therefore provider-relationship corroboration, not
recall, precision, prevalence, a false-negative rate, or a population
estimate. Observed silence remains silence. The contract, source acquisition,
exclusion union, disclosure floor, and pre-collection commitments are in the
[vendor-seed declaration](../docs/catalog-vendor-seed-round-declaration.md).

## Frozen execution

The exact 33-row HubSpot frame ran once from clean protected main after its
commitments and corrected reproduction command passed the complete hosted
matrix. Certificate transparency and opt-in CSE and BIMI probes were disabled.
The scan produced all 33 result rows with no error row or timeout. Six records
were partial on at least one broader catalog source, but every row had a
measured path eligible for the frozen HubSpot slug.

| Commitment | Value |
|---|---|
| Clean protected-main revision | `d6e7b17aa3686a83cf004e8cd93415aa411ec423` |
| Frame rows | 33 |
| Frame SHA-256 | `37bb3e9f2609b9f4470d637d60f42077593169522b117af9660ac3058516728b` |
| Manifest SHA-256 | `74c2bf7989f81a72d853132c74eddf3bd3f061aaf8168836d825fe3f5166eeb3` |
| Catalog SHA-256 | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Execution-surface SHA-256 | `dcc4bb3713070559e9248c0382a6ad4f439fddec882362c1e94d0273bc3636b0` |
| Result-set SHA-256 | `c7bb4d9631d17e05193f606e12554c276e340f993ed4979ddbfe1ca4b3b4e921` |
| Pooled aggregate SHA-256 | `17bb0c65ed885be1e8f918e1c0f56e37976115697b2571c196bfad2c45131c24` |
| Vendor-seed reducer SHA-256 | `56cbcc0298756f74eb42d8f5991b40a71ebe0749ba46ab8e095c57c715d2493e` |
| Exact public aggregate file SHA-256 | `fd9d5d06fb1068746246a37b12149755ab0d2077be88b2c9b71ff2a577ad8ab8` |
| Reducer network requests / identifiers printed | 0 / 0 |

The exact reducer output is the
[aggregate JSON](2026-08-14-catalog-vendor-seed-aggregate.json). Its environment
and generated timestamp are descriptive execution metadata, not part of the
provider relationship label.

## Provider-level result

| Provider | Frame | Corroborated | Observed silent | Unavailable | Unmeasured | Error | Rate | Wilson 95% interval |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| HubSpot | 33 | 29 | 4 | 0 | 0 | 0 | 0.878788 | 0.726745 to 0.951838 |

The denominator is 29 corroborated plus 4 observed-silent rows. The four silent
rows do not show that recon missed a published HubSpot record. A relationship
may apply to another namespace, may have changed since the provider story was
published, or may not require a catalog-readable apex record.

## Candidate dispositions

The legacy CNAME gap queue contained nine single-occurrence suffixes. Every one
was below the frozen floor of two occurrences across two distinct namespaces,
so none entered triage. The typed reducer separately retained one recurrent SPF
bucket with two occurrences across two namespaces and three recurrent TXT
buckets with 13 total occurrences; each TXT bucket spanned three to five
namespaces.

No recurrent bucket is promoted. This holdout evaluates the frozen catalog and
cannot tune it. Recurrence alone is not a provider label, and the round did not
predeclare an independent documentation-and-fixture basis for those values.
The private values remain uncommitted and are not transferred into a proposal
queue. The public disposition is therefore:

| Outcome | Count | Disposition |
|---|---:|---|
| CNAME singleton gaps | 9 | Rejected from triage: below recurrence floor |
| Recurrent SPF buckets | 1 | Deferred from promotion: evaluation holdout cannot tune the catalog |
| Recurrent TXT buckets | 3 | Deferred from promotion: evaluation holdout cannot tune the catalog |
| Promoted fingerprint families | 0 | No independently justified candidate |

This decision preserves the frozen zero-regression budget because no candidate
catalog is applied. It also avoids converting a relationship-labeled holdout
into a discovery sample after outcomes are known.

## Decision and next operation

The vendor-seed round is closed. It establishes a bounded 87.88% HubSpot
relationship-corroboration yield for this exact disjoint frame and no broader
coverage, recall, or population claim. It justifies no catalog promotion.

The later [drift result](2026-08-14-catalog-drift-round.md) closes the July
baseline's 5,199 measured rows with complete measurement, no threshold breach,
one explicit catalog-driven measurement-surface change, withheld
classification comparison, and no rule promotion. Repeated-frame evidence
remains separate from independent coverage evidence. Agent Plugins packaging
remains v2.15 work. OKF v0.2 remains a future named-consumer, caller-owned
projection rather than a replacement for recon's versioned JSON or catalog
evidence model.
