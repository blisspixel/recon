# Typed DNS Catalog Baseline and Promotion Gate

Status: baseline complete; unseen vertical holdout pending

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

## Interpretation limits and next gate

- The input is a convenience sample with overlapping source lists. These
  descriptive shares must not be generalized to the public DNS population.
- Passive DNS cannot enumerate arbitrary TXT owners, DKIM selectors, SRV owner
  names, or complete zone contents. "All records" means every bounded path the
  collector attempted, with availability and truncation reported.
- A matched fingerprint is probabilistic public metadata. It does not prove
  current product use, ownership, account control, or exploitability.
- The development sample cannot serve as an independent precision or recall
  label set. The next gate is a predeclared set of previously unseen vertical
  namespaces, run after the catalog patch without further tuning.
