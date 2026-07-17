# Typed DNS Catalog Baseline and Promotion Gate

Status: baseline and unseen vertical holdout complete

Date: 2026-07-17

This memo records a disclosure-safe catalog baseline over one private convenience
sample. It is a maintenance measurement, not a population estimate, precision
study, recall study, or claim about any queried organization. The private input
manifest, target names, target-owned records, tenant identifiers, detailed gap
queue, and per-domain output remain in ignored local workspaces. GitHub receives
only aggregate counts, generic provider patterns, provider-controlled references,
and fictional regression fixtures.

## Frozen collection

| Field | Value |
|---|---|
| Collection revision | `1c130ee7c6c6687491e4423e3987587a4f39b571` |
| Catalog at collection | 850 entries, 1,051 detections |
| Catalog digest | `f755f5c4626e9d525510c471b84a6f5633e19a81e5792b8a50cb547b0919cc1f` |
| Result digest | `39655fc31713302803d37a17345f30f3b2a8253da082e3c47509db25e16db7ed` |
| Output records | 5,202 |
| Successfully measured inputs | 5,199 |
| Validation errors | 3 |
| Duplicate input rows removed before collection | 39 |
| Partial result records | 527 |
| CT collection | Disabled |
| Opt-in direct probes | Disabled |
| Concurrency and per-input timeout | 4 and 120 seconds |
| Truncated typed paths | 0 |

The three validation errors are counted as unmeasured on every typed path. A
partial row means at least one source degraded; it is not converted into a
negative observation. No typed path had an `unavailable` row in this run.

## Bounded-path baseline

`Available / partial / unmeasured` is a namespace count. `Opportunities` is the
number of bounded owner or chain positions the collector attempted. `Observed`
counts unique values on that path. The classified share is `classified /
observed`, not accuracy and not coverage of an entire DNS zone.

| Record path | Available / partial / unmeasured | Opportunities | Observed | Classified | Unclassified | Classified share |
|---|---:|---:|---:|---:|---:|---:|
| `cname_target` | 4,838 / 361 / 3 | 17,367 | 17,367 | 13,669 | 3,698 | 0.787 |
| `cname` | 4,838 / 361 / 3 | 10,398 | 3,164 | 1,802 | 1,362 | 0.570 |
| `txt` | 5,161 / 38 / 3 | 5,199 | 81,361 | 56,374 | 24,987 | 0.693 |
| `spf` | 5,161 / 38 / 3 | 5,348 | 13,039 | 8,925 | 4,114 | 0.684 |
| `mx` | 5,161 / 38 / 3 | 5,199 | 11,786 | 9,762 | 2,024 | 0.828 |
| `ns` | 5,162 / 37 / 3 | 5,199 | 18,317 | 13,372 | 4,945 | 0.730 |
| `caa` | 5,158 / 41 / 3 | 5,199 | 7,118 | 4,787 | 2,331 | 0.673 |
| `dmarc_rua` | 5,161 / 38 / 3 | 5,199 | 5,194 | 3,065 | 2,129 | 0.590 |
| `subdomain_txt` | 5,154 / 45 / 3 | 25,995 | 2,439 | 1,509 | 930 | 0.619 |
| `srv` | 5,141 / 58 / 3 | 25,995 | 4,304 | 3,021 | 1,283 | 0.702 |

The degraded-source counts were: `dns:a` 201, `dns:apex_txt` 38, `dns:bimi`
44, `dns:caa` 41, `dns:cname` 361, `dns:dkim` 55, `dns:dmarc` 38,
`dns:mta_sts` 40, `dns:mx` 38, `dns:ns` 37, `dns:srv` 58,
`dns:subdomain_txt` 45, `dns:tls_rpt` 44, `http:mta_sts_policy` 15,
`identity:autodiscover` 8, and `source:google_identity` 1.

## Frozen promotion decision

The private recurrence queue was frozen before research. Ten recurrent patterns
crossed the occurrence and distinct-namespace floors and were confirmed against
provider-controlled documentation. Counts below are aggregate. They do not
identify which namespaces published a value and do not establish a current
commercial relationship.

| Type | Generic pattern | Observations / distinct namespaces | Public basis |
|---|---|---:|---|
| CAA | `awstrust.com` | 218 / 165 | [AWS Certificate Manager](https://docs.aws.amazon.com/acm/latest/userguide/setup.html) |
| CAA | `amazonaws.com` | 300 / 222 | [AWS Certificate Manager](https://docs.aws.amazon.com/acm/latest/userguide/setup.html) |
| CAA | `ssl.com` | 430 / 226 | [SSL.com](https://www.ssl.com/how-to/configure-caa-records-to-authorize-ssl-com/) |
| CAA | `globalsign.com` | 314 / 237 | [GlobalSign](https://support.globalsign.com/customer/portal/articles/2851274-how-to-add-dns-caa-record-to-a-dns-zone-file) |
| CAA | `godaddy.com` | 183 / 136 | [GoDaddy](https://www.godaddy.com/help/edit-a-caa-record-27289) |
| CAA | `entrust.net` | 86 / 68 | [Entrust CPS](https://www.entrust.com/sites/default/files/documentation/licensingandagreements/entrust-certificate-services-cps-3-29.pdf) |
| CNAME | exact `cdn.webflow.com` | 69 / 69 | [Webflow](https://help.webflow.com/hc/en-us/articles/33961239562387-Manually-connect-a-custom-domain) |
| SPF | suffix `_d.easydmarc.pro` | 46 / 46 | [EasyDMARC](https://support.easydmarc.com/knowledge-base/faq) |
| SPF | suffix `_nspf.vali.email` | 48 / 48 | [Valimail](https://support.valimail.com/en/articles/9143142-valimail-spf-macro-syntax) |
| TXT | prefix `cloudflare_dashboard_sso=` | 133 / 129 | [Cloudflare](https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/) |

Together these patterns cover 1,827 previously unclassified observations in
the frozen sample. A separate Webflow `_webflow` TXT rule was admitted as a
provider-documented vendor seed. It is excluded from the 1,827 because the
baseline catalog did not yet name that owner, and unknown TXT owners are not
enumerable through this bounded passive workflow.

The Valimail pattern is explicitly labeled legacy and medium-confidence because
the vendor says that form is no longer needed. CAA results use distinct
authorization slugs and say only that a CA was authorized; they do not claim a
certificate was issued or deployed.

## Matcher-boundary replay

The promotion patch also replaces broad substring checks with DNS-label suffix
matching for SPF and MX, label-aware NS matching, and parsing limited to CAA
`issue` and `issuewild` issuer fields. A deterministic replay over retained
private evidence produced both additions and retractions:

| Type | Newly classified by accepted rules | Previous classifications retracted | Projected classified / observed | Projected share |
|---|---:|---:|---:|---:|
| `caa` | 1,531 | 24 | 6,294 / 7,118 | 0.884 |
| `cname` | 69 | 0 | 1,871 / 3,164 | 0.591 |
| `spf` | 94 | 26 | 8,993 / 13,038 | 0.690 |
| `txt` | 133 | 0 | 56,507 / 81,361 | 0.695 |
| `mx` | 0 | 45 | 9,717 / 11,786 | 0.824 |
| `ns` | 0 | 49 | 13,323 / 18,317 | 0.727 |

One malformed SPF mechanism-like token is no longer counted as an observed SPF
target, which changes that replay denominator from 13,039 to 13,038. In total,
the accepted rules add 1,827 classifications and the boundary corrections
retract 144, for a net projected increase of 1,683 across the affected paths.
A retraction means the retained value no longer satisfies the exact matcher
contract. It is not an independently labeled false positive.

## Unseen vertical holdout

After revision `9ab8a79282df228b2b836b59c69fae329cb296be` was committed and
the full repository gate passed, 30 private `industry-*` strata were normalized
and cumulatively deduplicated against the development baseline and each earlier
holdout stratum. This left 366 previously unseen namespaces. No rule or
threshold was changed after observing them.

| Field | Value |
|---|---|
| Catalog | 855 entries, 1,062 detections |
| Catalog digest | `2a9fa2fc1961d6ce81bcae1caa3f198f446d8f50e43ebfac6b5ad12f818a9d71` |
| Result digest | `5d61ce6f841b3d1d981928330984bc5e1298b9f4ee5fd84d93f7159b218aa4fe` |
| Measured inputs / batch errors | 366 / 0 |
| Partial result records | 53 |
| Unavailable / unmeasured typed rows | 0 / 0 |
| Truncated typed paths | 0 |
| CT collection / opt-in direct probes | Disabled / disabled |
| Concurrency / elapsed collection time | 5 / 436.5 seconds |

The complete aggregate by bounded path was:

| Record path | Available / partial | Opportunities | Observed | Classified | Unclassified | Share | Recurrent private buckets |
|---|---:|---:|---:|---:|---:|---:|---:|
| `cname_target` | 325 / 41 | 1,200 | 1,200 | 997 | 203 | 0.831 | 0 |
| `cname` | 325 / 41 | 732 | 244 | 161 | 83 | 0.660 | 4 |
| `txt` | 365 / 1 | 366 | 6,402 | 4,291 | 2,111 | 0.670 | 42 |
| `spf` | 365 / 1 | 383 | 1,056 | 707 | 349 | 0.670 | 19 |
| `mx` | 365 / 1 | 366 | 770 | 643 | 127 | 0.835 | 1 |
| `ns` | 365 / 1 | 366 | 1,357 | 989 | 368 | 0.729 | 33 |
| `caa` | 365 / 1 | 366 | 400 | 340 | 60 | 0.850 | 3 |
| `dmarc_rua` | 365 / 1 | 366 | 396 | 224 | 172 | 0.566 | 5 |
| `subdomain_txt` | 365 / 1 | 2,196 | 116 | 64 | 52 | 0.552 | 3 |
| `srv` | 363 / 3 | 1,830 | 407 | 290 | 117 | 0.713 | 4 |

Recurrent bucket counts use the frozen minimum of two observations across two
distinct namespaces. Candidate keys and examples remain private. The degraded
source counts were: `dns:a` 15, `dns:apex_txt` 1, `dns:bimi` 1, `dns:caa` 1,
`dns:cname` 41, `dns:dkim` 4, `dns:dmarc` 1, `dns:mta_sts` 1, `dns:mx` 1,
`dns:ns` 1, `dns:srv` 3, `dns:subdomain_txt` 1, `dns:tls_rpt` 1,
`http:mta_sts_policy` 2, and `identity:autodiscover` 1.

Every admitted pattern appeared at least once in the unseen holdout:

| Pattern | Observations / distinct namespaces |
|---|---:|
| CAA `awstrust.com` | 12 / 11 |
| CAA `amazonaws.com` | 17 / 14 |
| CAA `ssl.com` | 21 / 11 |
| CAA `globalsign.com` | 23 / 17 |
| CAA `godaddy.com` | 8 / 6 |
| CAA `entrust.net` | 7 / 7 |
| CNAME exact `cdn.webflow.com` | 1 / 1 |
| SPF suffix `_d.easydmarc.pro` | 4 / 4 |
| SPF suffix `_nspf.vali.email` | 3 / 3 |
| TXT prefix `cloudflare_dashboard_sso=` | 18 / 15 |
| Owner-qualified `_webflow` TXT | 2 / 2 |

The 10 baseline-backed rules accounted for 114 holdout observations. The
owner-qualified Webflow seed accounted for two more. At least one new rule
fired on 59 distinct holdout namespaces. This is evidence that the documented
record shapes recur outside the development sample, not an independent label
for precision, recall, current product use, or population prevalence.

The old broad substring semantics would also have classified 11 values that
the patched runtime left unclassified: one CAA value, four MX values, and six
NS values. SPF had no such holdout near-miss. These are matcher-contract
retractions, not independently adjudicated false positives.

## Interpretation limits and next gate

- The input is a convenience sample with overlapping source lists. These
  descriptive shares must not be generalized to the public DNS population.
- Passive DNS cannot enumerate arbitrary TXT owners, DKIM selectors, SRV owner
  names, or complete zone contents. "All records" means every bounded path the
  collector attempted, with availability and truncation reported.
- A matched fingerprint is probabilistic public metadata. It does not prove
  current product use, ownership, account control, or exploitability.
- Neither the development sample nor the unseen vertical round is an
  independently labeled precision or recall set. The next catalog rounds
  should add rank and regional sampling before any broad coverage claim.
