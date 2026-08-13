# Catalog Rank-Round Result

**Date:** 2026-08-13

**Decision:** Rank round complete; promote four documented families and move to
the regional round

**Disclosure:** Aggregate only. No selected namespace, record value,
organization name, tenant identifier, or per-domain row is included.

## Question and boundary

The frozen question was whether independently selected Tranco head and tail
rank bands expose different recurrent gaps across recon's bounded DNS catalog
paths. Four bands each received an equal 250-namespace discovery quota. Those
quotas are not population weights, so the results are descriptive for this
private frame and are not Internet prevalence estimates.

Preparation, selection, and collection commitments are in the
[rank-round declaration](../docs/catalog-rank-round-declaration.md). The
baseline run completed all 1,000 rows with zero error rows and 61 partial rows.
Certificate transparency and opt-in direct probes were disabled by contract.

| Commitment | Value |
|---|---|
| Frozen frame rows | 1,000 |
| Frozen frame SHA-256 | `ae9d0242bcb3eaa82c1d381ae8f0340cf17d9aa3fa8fe281989658aa696a5ee2` |
| Baseline result SHA-256 | `cb3dc327f5d914a537dfb019834fd41045844b1241856ea62344bb460773a35f` |
| Baseline manifest SHA-256 | `b6aba9c257716a0fc74401fc31acf8c5de21d4fe22c71a90a3021e506c6e99de` |
| Baseline catalog SHA-256 | `dd72dda192fb625d0f90c7475ff00f90be53d8da5363075c195b317691ac6ce2` |
| Stratified aggregate file SHA-256 | `58a332dd3b3ba81c7eba1deb488cc34174a48c885e3bddafe9c12d6e198436d7` |
| Stratified reducer SHA-256 | `810740ccea0db6d66ce16d9248dd171392d876399853f8754f5f3a1e6a638b2d` |

## Descriptive band result

Classification rates use observed values as their denominators. `Stratum 0`
through `Stratum 3` preserve the frozen order: ranks 1-1,000, 1,001-10,000,
10,001-100,000, and 100,001-1,000,000.

| Record type | Stratum 0 | Stratum 1 | Stratum 2 | Stratum 3 |
|---|---:|---:|---:|---:|
| `cname_target` | 0.617418 | 0.615385 | 0.652330 | 0.675000 |
| `cname` | 0.302083 | 0.444444 | 0.411111 | 0.265957 |
| `txt` | 0.687413 | 0.706165 | 0.673554 | 0.762673 |
| `spf` | 0.593548 | 0.614173 | 0.596026 | 0.516364 |
| `mx` | 0.685139 | 0.763326 | 0.632319 | 0.595745 |
| `ns` | 0.542584 | 0.702395 | 0.579866 | 0.546851 |
| `caa` | 0.792717 | 0.876812 | 0.908046 | 0.944954 |
| `dmarc_rua` | 0.358974 | 0.380282 | 0.392857 | 0.366197 |
| `subdomain_txt` | 0.022556 | 0.002725 | 0.076923 | 0.000000 |
| `srv` | 0.400000 | 0.777778 | 0.688525 | 0.606557 |

The round answers its question descriptively: the bands expose materially
different gap shapes. For example, MX and NS classification are highest in
Stratum 1 and lower in the tail, CAA classification rises across the ordered
bands, and `subdomain_txt` remains sparse everywhere. The recurrent candidate
bucket counts were 55, 21, 12, and 29 in frozen stratum order. These differences
prioritize research; they do not establish population rates or causal reasons.

## Candidate dispositions

Four families cleared the complete gate. Their record meanings come from
provider-controlled documentation, not recurrence alone:

| Disposition | Rule | Aggregate basis | Claim boundary and primary reference |
|---|---|---:|---|
| Promoted | Cloudflare Email Routing, MX suffix `mx.cloudflare.net` | 21 previously unclassified values | Inbound mail routes through Cloudflare Email Routing; no CDN, security, or outbound-sending claim. [Cloudflare Email Service domain configuration](https://developers.cloudflare.com/email-service/configuration/domains/) |
| Promoted | Alibaba Cloud DNS, NS suffix `alidns.com` | 30 previously unclassified values | Alibaba Cloud DNS is authoritative; no application-hosting claim. [Alibaba Cloud DNS nameserver documentation](https://www.alibabacloud.com/help/en/dns/pubz-modify-dns-server-for-alibaba-cloud-domain-name) |
| Promoted | Alibaba Cloud ALB, CNAME suffix `alb.aliyuncsslbintl.com` | 5 previously unclassified values | An international Application Load Balancer endpoint binding is observed; no workload-ownership claim. [Alibaba Cloud ALB endpoint upgrade](https://www.alibabacloud.com/help/en/slb/product-overview/alb-and-nlb-domain-name-upgrade-announcement) |
| Promoted | Yandex 360 for Business, MX `mx.yandex.net` and SPF `_spf.yandex.net` | 9 MX and 10 SPF values | MX establishes inbound routing; SPF only authorizes sending. [Yandex 360 DNS setup](https://yandex.com/support/yandex-360/business/admin/en/domains/dns/) |

Every promoted detection carries `verified: 2026-08-13`. Reserved fictional
tests cover positive matches, deceptive DNS-suffix lookalikes, sparse results,
exact evidence occurrences, and catalog-match provenance. The ALB rule is
infrastructure-tier so it cannot displace a more specific application-tier
attribution.

The higher-frequency `ms` and `asv` TXT prefixes were rejected because they are
not vendor-specific identifiers. Generic `l.google.com` CNAME and SRV shapes,
Yahoo shared endpoints, DMARC aggregate-report recipients, undocumented
registrar forwarding hosts, and other candidates without an exact current
product basis remain deferred. A DMARC report destination is not a trust score
or a general adoption claim. No rule was promoted from a vendor guess or a
private target sample.

Unavailable outcomes are retained as the 61 partial baseline rows, distributed
17, 18, 14, and 12 across the four strata. CT-dependent CNAME breadth and
opt-in direct-probe evidence were unmeasured by design.

## Promotion budget and live replay

The frozen budget required at least 0.001 classified-rate uplift in every
affected record type and zero regression in every protected type. A second live
pass completed all 1,000 rows with zero errors and 65 partial rows. Its result
SHA-256 was
`4c99b04ed5657ac444736a0286516846d870e215d220b4eb1e73502b8b8eaad6`.
The pooled CNAME gap count fell from 185 to 184 and its immediate triage queue
from three to two. Public DNS also changed between passes, including one
unrelated TXT classification loss, so the live pass is an operational replay,
not the causal zero-regression comparison.

The fixed-observation evaluator therefore applied only the five candidate
rules to the exact retained baseline observations. It performed zero network
requests and kept every baseline denominator unchanged.

| Record type | Baseline classified / observed | Added | Counterfactual rate | Delta |
|---|---:|---:|---:|---:|
| `cname_target` | 940 / 1,497 | 5 | 0.631263 | +0.003340 |
| `mx` | 1,152 / 1,716 | 30 | 0.688811 | +0.017482 |
| `ns` | 1,971 / 3,318 | 30 | 0.603074 | +0.009041 |
| `spf` | 740 / 1,268 | 10 | 0.591483 | +0.007887 |

All six unaffected record types had exactly 0.000000 change. All four affected
types exceeded the 0.001 minimum, all four candidate families were observed,
and no type exceeded the zero-regression budget. The decision is accepted.

| Counterfactual commitment | Value |
|---|---|
| Candidate catalog SHA-256 | `725061f850fb058d2277bf133472bfea6cc1bd606fa72fe6d2aa087a4377e642` |
| Evaluator SHA-256 | `eceb64058f338edf23787dab1d9c49ca929ff62beb6145a30d3280211873a573` |
| Canonical main revision with identical evaluator and catalog bytes | `ea289b7010e7774f70ab78cfc8751d04c71791b3` |
| Counterfactual file SHA-256 | `36d6c187c3ef1ce88b872022dc0f66553fc0e686bed6c35df60b0700b06c6ae7` |
| Network requests | 0 |
| Identifiers printed | 0 |

## Decision and next operation

The rank round is closed. It supports four bounded additions and explicitly
does not support broad catalog growth or a population coverage claim. The next
v2.14 operation is to freeze the regional question, independent strata,
eligibility and overlap rules, catalog and execution digests, collection
options, and zero-regression budget before any regional target contact. Vendor
seed and drift remain after the regional round. Agent Plugins packaging stays
in v2.15, and OKF v0.2 remains a future caller-owned projection rather than a
replacement for recon's versioned JSON or catalog evidence model.
