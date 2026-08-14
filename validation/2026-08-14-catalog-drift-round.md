# Catalog Prior-Sample Drift Round Result

**Date:** 2026-08-14

**Decision:** Drift round complete; accept the bounded observation-summary
comparison, record the catalog-driven measurement-surface change explicitly,
promote no catalog rules, and close the v2.14 evidence loop

**Disclosure:** Aggregate only. No selected namespace, record value,
organization name, tenant identifier, candidate pattern, or per-domain row is
included.

## Question and boundary

The frozen question was which retained bounded-path observation summaries
changed when the measured portion of the July 17 typed baseline was observed
again. This is temporal re-observation of one convenience sample. It is not an
independent coverage round, a population estimate, a precision or recall
study, or evidence about any particular namespace.

The reducer compares only `availability`, `opportunity_count`,
`observed_count`, and `truncated`. A changed outcome can reflect public DNS
change, resolver variability, source degradation, or a changed collection
regime. Catalog interpretation is separately non-comparable because the
catalog digests differ and the prior run predates execution-digest
commitments.

## Frozen execution

The exact 5,199-row frame ran once from clean protected main after the
declaration, implementation, corrected commitments, and full hosted matrix
passed. Certificate transparency and opt-in direct probes were disabled.
Concurrency remained four. The scan produced all 5,199 result rows with no
error, unavailable, unmeasured, or truncated row. The run completed in 65
minutes 32 seconds.

| Commitment | Value |
|---|---|
| Clean protected-main revision | `2ab1e4a99faac761313e7260fa79818425fa376e` |
| Frame rows | 5,199 |
| Frame SHA-256 | `d1400df98f3b083dbd0176b1805c95c8204f254c9fa1d2bf2dabe58f61d0b9cd` |
| Manifest SHA-256 | `0bb7c32ea9bb63452f5d800cf93acc5c6d794263c63fe4465709accc92830f53` |
| Drift sidecar SHA-256 | `0a7b8398cb78bc5244635886591d1e63be1fe5cc79ea2b2779dacc80e73809a1` |
| Prior catalog SHA-256 | `f755f5c4626e9d525510c471b84a6f5633e19a81e5792b8a50cb547b0919cc1f` |
| Current catalog SHA-256 | `206ee855ba9f5107634f0876b66ed46306dbecfaaaff6c8a10a089ac4678baa2` |
| Current execution-surface SHA-256 | `01069211619b8be43f4b28e49856cbf5b42269806c549063e7d2485cf7bef309` |
| Prior result-set SHA-256 | `39655fc31713302803d37a17345f30f3b2a8253da082e3c47509db25e16db7ed` |
| Current result-set SHA-256 | `3e75953869a88494114f0a1d60b29fb8568cf1224cb3f8ae5fc7bfc91e10936b` |
| Current pooled aggregate file SHA-256 | `5992c38a540401a742648e731c2cbea8f95e9a3240bc47bb1e15dd47e8dfb423` |
| Drift reducer SHA-256 | `71c7ac87887e45adb631b02067281a2879c444587105a6b0f7a20f0fd68eb33c` |
| Exact public aggregate file SHA-256 | `03c1184b22a6f9d73a64f8bb955a28e7e09e29f22d41349a206ef34b696f907c` |
| Reducer network requests / identifiers printed | 0 / 0 |

The exact reducer output is the
[aggregate JSON](2026-08-14-catalog-drift-aggregate.json). Its generated
timestamp is descriptive execution metadata.

## Observation-summary result

Every row is measured. The namespace-level precedence reports 5,199 changed,
0 unavailable, 0 unmeasured, and 0 no-change rows. That result must not be read
as 5,199 namespaces changing externally. The next section identifies the
catalog-driven measurement-surface change that deterministically makes every
namespace changed.

| Record type | Opportunities before | Opportunities after | Observed before | Observed after | Observed delta | Changed | No change | Change rate | Budget exceeded |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `caa` | 5,199 | 5,199 | 7,118 | 7,188 | +70 | 42 | 5,157 | +0.9834% | no |
| `cname` | 10,398 | 10,398 | 3,164 | 3,163 | -1 | 69 | 5,130 | -0.0316% | no |
| `cname_target` | 17,367 | 17,384 | 17,367 | 17,384 | +17 | 208 | 4,991 | +0.0979% | no |
| `dmarc_rua` | 5,199 | 5,199 | 5,194 | 5,207 | +13 | 55 | 5,144 | +0.2503% | no |
| `mx` | 5,199 | 5,199 | 11,786 | 11,738 | -48 | 43 | 5,156 | -0.4073% | no |
| `ns` | 5,199 | 5,199 | 18,317 | 18,307 | -10 | 40 | 5,159 | -0.0546% | no |
| `spf` | 5,348 | 5,349 | 13,039 | 13,034 | -5 | 86 | 5,113 | -0.0383% | no |
| `srv` | 25,995 | 25,995 | 4,304 | 4,295 | -9 | 28 | 5,171 | -0.2091% | no |
| `subdomain_txt` | 25,995 | 31,194 | 2,439 | 2,964 | +525 | 5,199 | 0 | +21.5252% | no |
| `txt` | 5,199 | 5,199 | 81,361 | 82,312 | +951 | 966 | 4,233 | +1.1689% | no |

No bounded record type breached the predeclared greater-than-1-percent
observed-count decline threshold. There were zero unavailable, unmeasured, or
truncated outcomes. Partial availability remains recorded in the exact JSON;
it is not hidden inside the totals.

## Measurement-surface disposition

The July catalog contained five `subdomain_txt` owners. The current catalog
contains six because the regional evidence round added the provider-documented
Webflow `_webflow` verification owner. The extra owner creates exactly one new
opportunity per frozen row: 31,194 minus 25,995 equals 5,199. Because
`opportunity_count` is one of the frozen comparison fields and `changed` has
precedence over `no_change`, this instrumentation change makes all 5,199
namespace summaries changed even when their other bounded summaries are
unchanged.

This is a valid measurement-surface change, not evidence of universal external
DNS drift. It is disclosed rather than normalized away after outcomes are
known. The per-record-type table remains the interpretable comparison. Future
drift rounds that need an external-change estimate must freeze the owner set as
an observation contract independent of the catalog under evaluation.

Classification comparison is also withheld. The status is
`not_comparable_catalog_changed`; added and removed assignments are `null`.
This follows the predeclared rule requiring both equal catalog digests and
equal interpretation-execution digests.

## Candidate dispositions

The legacy gap path produced 1,039 gaps and 9 candidates after triage. The
typed aggregate retained 840 recurrent candidate buckets across the ten
bounded record types. Drift is an evaluation round, not independent discovery
evidence, and its frozen decision forbids catalog promotion. Every aggregate
candidate group is therefore deferred from promotion pending a separate
provider-controlled basis, current review date, fictional positive,
lookalike-negative and sparse fixtures, and provenance assertions.

| Outcome | Count | Disposition |
|---|---:|---|
| Legacy gaps | 1,039 | Private review input; not a promotion basis |
| Legacy candidates after triage | 9 | Deferred from promotion |
| Typed recurrent candidate buckets | 840 | Deferred from promotion |
| Promoted fingerprint families | 0 | Drift cannot authorize promotion |

No candidate pattern, record value, or namespace is transferred into this
public result.

## Decision and next operation

The final v2.14 evidence round is closed. Rank, regional, vendor-seed, and
prior-sample drift now have immutable contracts, aggregate results, and
explicit candidate dispositions. This result supports no population claim and
no catalog promotion. It records one measurement-surface change and no
record-type decline beyond the frozen review threshold.

At round closure, the next operation was the coherent v2.14.0 release gate. It
has now passed with aligned version and release metadata, complete local and
hosted matrices, one tag-bound GitHub and PyPI release, attestations, SBOM
provenance, and verified channel parity. The active next operation is the
network-free v2.15 representative-client evaluation contract. Agent Plugins
conformance and measured agent-surface cost remain v2.15 work. OKF v0.2
remains a future named-consumer,
caller-owned projection rather than a replacement for recon's versioned JSON
or observation capsules.
