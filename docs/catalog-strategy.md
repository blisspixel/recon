# Catalog Growth and Quality Strategy

Status: measurement-first maintenance plan
Review date: 2026-08-13

This document is the plan for growing and maintaining the fingerprint catalog
(`src/recon_tool/data/fingerprints/*.yaml`) so coverage, precision, and
freshness improve deliberately rather than by accretion. It sets direction; it
does not change runtime behavior. All corpora and per-domain scan outputs stay
private and off GitHub per [data-handling-policy.md](data-handling-policy.md).
New review artifacts use aggregate patterns, generic tooling, and explicit
synthetic examples under reserved namespaces. The release gate rejects the
retired fictional target vocabulary across current public text artifacts.
Real vendor and product names, plus provider-controlled domains used in generic
fingerprint rules, may be committed. The evaluated target names, target-owned
records, and per-domain results may not.
This plan implements the catalog-quality track in the canonical
[roadmap](roadmap.md). Catalog size is not a success metric; classified public
surface and independently supported precision are.

## How the catalog grows today

The catalog carries 868 entries and 1,091 detection rules across nine populated
types: `cname_target`, `cname`, `txt`, `spf`, `dmarc_rua`, `mx`, `ns`, `caa`,
and `subdomain_txt`. The grammar and runtime also support `srv`, but the built-in
catalog currently has no `srv` rules. New rules come from a corpus-mining loop:

1. A private domain corpus is run through `recon batch --include-unclassified`
   (`validation/scan.py` or `validation/run_corpus.py`), with output written to
   gitignored private directories (`validation/runs-private/`, `live_runs/`).
2. `validation/find_gaps.py` retains the established CNAME-chain queue, while
   `validation/catalog_baseline.py` separately aggregates every bounded catalog
   path, ranks private recurrence buckets, and emits a target-free count report.
3. `validation/triage_candidates.py` drops already-covered and
   intra-organizational suffixes and applies both occurrence and distinct-
   namespace floors.
4. Each surviving candidate is verified against public vendor documentation and
   promoted with a scoped pattern, a `reference`, a category mapping, a
   regression test, and hedged wording.

The loop is disciplined and effective, but the available corpus remains a
convenience sample with selection bias. The first frozen typed baseline is
recorded in
[the 2026-07-17 aggregate memo](../validation/2026-07-17-typed-catalog-baseline.md);
the independent rank and regional rounds are complete. Vendor-seed and drift
rounds remain open, and most legacy detections still lack a freshness date.

Current round status:

| Round | Status |
|---|---|
| Convenience-sample baseline | Complete, aggregate-only memo published |
| Unseen vertical holdout | Complete, 366 normalized namespaces, no post-holdout tuning |
| Rank bands | Complete; four-band aggregate, dispositions, and zero-regression decision published |
| Regional / ccTLD | Complete; baseline, fixed-observation decision, and clean-main replay published |
| Vendor seed | One documented Webflow owner seed exercised; broader round pending |
| Drift | Pending |

## 1. A stratified, reproducible sampling frame

The catalog can only recognize vendors the corpus exposes, so one list biases
the catalog toward that list's population. Replace the single corpus with
purpose-built strata, each curated and stored privately:

- **Rank-stratified backbone.** Use Tranco (a research-grade, manipulation-
  resistant top-sites list) in rank bands (1-1k, 1k-10k, 10k-100k, 100k-1M).
  Head and tail run different stacks, and Tranco is reproducible and citable for
  the write-up.
- **Vertical lists.** Fintech, healthcare, public sector, higher education,
  retail, legal, media. Each vertical has its own vendor ecosystem. Many source
  directories are public (the `.gov` zone, accreditation registries, regulator
  member lists).
- **Regional / ccTLD lists.** The current catalog skews toward US and English
  vendors; this is the largest blind spot. The first round groups only exact
  ASCII two-letter IANA country-code TLDs through their matching UN M49
  ISO-alpha2 entries in the five canonical M49 regions, then samples equal
  discovery quotas from several ccTLDs per region. Archive and digest both raw
  official pages before deriving the mapping; count and exclude regionless M49
  entries explicitly. A ccTLD is a namespace attribute, not evidence of
  registrant location, organizational presence, or service geography.
  Globally marketed ccTLDs remain in their delegated grouping, so the result is
  descriptive for the frozen namespace frame and is not a regional prevalence
  estimate.
- **Vendor-seed lists (reverse direction).** For a target vendor, collect its
  public customer list (case-study pages, "powered by" searches), observe those
  domains, and both tighten the pattern and measure recall.
- **TLD-scale mining.** ICANN CZDS zone files are free and give every domain in
  a TLD for aggregate pattern mining. Mine patterns only; never persist
  per-domain data (the no-aggregate-database invariant).

"More rounds" should mean more diverse lists, not re-scanning the same corpus,
which mostly re-finds known vendors.

### Round protocol

A round evaluates domain query coordinates, not websites. It does not crawl
pages or infer the company behind an apex. Each round has one predeclared
sampling purpose and a private, frozen input manifest:

| Round | Private input stratum | Primary question |
|---|---|---|
| 0. Baseline | Deduplicated current corpus | What is measured, unmeasured, classified, and unresolved at the current catalog revision? |
| 1. Rank bands | Independent samples from several popularity bands | Do head and tail namespaces expose different high-frequency gaps? |
| 2. Region | Country-code and regional samples | Which provider patterns are missing outside the current geographic concentration? |
| 3. Vertical | Separately sampled public-sector, education, finance, healthcare, retail, legal, and media sets | Which gaps recur within a domain class without being pooled into a population claim? |
| 4. Vendor seed | Provider-documented customer examples split from development rows | Does a specific verified rule recover its intended public record shape on a holdout set? |
| 5. Drift | A frozen prior sample observed again later | Which rules or public record shapes changed, appeared, or disappeared? |

Before collection, normalize each input through the same apex reducer used by
the product, reject malformed rows, and deduplicate within the round. When
reporting a pooled descriptive count across overlapping strata, count each apex
once. Keep stratum membership, source list revisions, and every domain row only
in the ignored private workspace. A corpus used to develop a rule cannot also
serve as its independent precision or recall holdout.

Every round records the catalog digest, collection options, source-success
counts, observation-opportunity counts, unresolved counts, and gap counts by
record type. Re-run the frozen round after a candidate patch and report only
aggregate before-and-after deltas. Do not publish a target sample to explain a
rule. The rule itself, a provider-controlled public reference, reserved
synthetic fixtures, and aggregate counts are sufficient for review.

Stop adding inputs when a round does not answer a new sampling question. Stop a
promotion pass when the highest-frequency survivors lack an independent public
basis, fail a lookalike negative, or exceed the predeclared precision regression
budget. Two scans of the same list are a drift check, not two coverage rounds.

The first rank-round selection and completed observation pass are recorded in
the [catalog rank-round declaration](catalog-rank-round-declaration.md). Its
four equal discovery quotas are not population weights. The membership-bound
stratified aggregate, candidate dispositions, and fixed-observation
zero-regression decision are published in the aggregate-only
[rank-round result](../validation/2026-08-13-catalog-rank-round.md). The official
source mapping and independent five-stratum frame are frozen in the
[regional declaration](catalog-regional-round-declaration.md). The
aggregate-only
[result](../validation/2026-08-13-catalog-regional-round.md) records the
complete baseline, accepted fixed-observation decision, and clean protected-main
replay. The rank result does not substitute for it.

## 2. Measurement: coverage, recall, precision

Growth without measurement cannot tell 40% coverage from 90%. Three metrics
close the loop:

- **Coverage / unclassified rate.** `find_gaps.py` retains the historical
  frequency-ranked CNAME-terminal list. The opt-in discovery envelope now also
  emits typed, bounded accounting for every direct catalog path, and
  `catalog_baseline.py` writes separate private recurrence queues plus one
  aggregate-only report. Track "share of observed DNS surface classified" by
  type. TXT tokens, mail routes, issuers, and hostnames are never forced into
  one suffix metric.
- **Recall, via vendor-seed lists.** On a vendor's known customers, do we detect
  it? Directly measurable per vendor.
- **Precision, only with independent labels.** Measure false attribution only
  where a provider-owned endpoint, standards-defined record, or other
  predeclared authoritative source supplies a label that the matcher did not
  consume. Apply the product-quality plan's minimum sample and uncertainty
  rule; otherwise report no precision estimate.
- **Corroboration diagnostic.** Signal disagreement and single-signal matches
  are useful review queues, but they are not false-positive denominators or
  independent correctness labels.

All measurement outputs are aggregate and disclosure-controlled; no apexes,
organization names, or per-domain rows leave the maintainer machine.

The first dated record-type baseline reports availability, observed and
unclassified values, partial collection, truncation, and the exact catalog
revision. Later strata must retain that accounting and add the unresolved,
freshness, and corroboration measures relevant to their question. Every
promotion should name the aggregate gap it is intended to reduce and a
precision regression budget.

The record-type accounting target is:

| Catalog type | Bounded observation surface | Current corpus-wide gap queue |
|---|---|---|
| `cname_target` | Related-subdomain CNAME chains found by bounded probes or CT | Implemented and frequency-ranked |
| `cname` | Apex and `www` CNAME targets | Typed accounting and private recurrence queue implemented |
| `txt` | Non-SPF apex TXT values | Typed accounting and private prefix or exact-repeat queue implemented |
| `spf` | Apex SPF include and redirect targets | Typed accounting and private hostname queue implemented |
| `mx` | Apex MX routing hosts | Typed accounting and private hostname queue implemented |
| `ns` | Apex NS hosts | Typed accounting and private hostname queue implemented |
| `caa` | Apex CAA issuer values | Typed accounting and private issuer queue implemented |
| `dmarc_rua` | Valid aggregate-report destination domains | Typed accounting and private hostname queue implemented |
| `subdomain_txt` | TXT owners explicitly named by catalog rules | Typed accounting implemented; unknown owner names remain non-enumerable and outside the denominator |
| `srv` | The bounded common SRV owner list queried by recon | Typed accounting implemented; the built-in catalog still has no `srv` rules |

An empty queue means no recurrent candidate crossed the frozen thresholds, not
that the catalog is complete. "All records" means all bounded observation
opportunities recon actually attempted.
It cannot mean every record in a DNS zone: unknown TXT owners, DKIM selectors,
and SRV owner names are not generally enumerable through passive DNS queries.

## 3. Freshness

Vendors change domains, get acquired, and sunset products, so a rule with no
re-check is a slow source of false positives and negatives. Each detection now
supports an optional `verified` date (`YYYY-MM-DD`) recording when its pattern
was last confirmed against a public source or corpus observation. It is advisory
and does not affect matching.

Run the no-network auditor:

```bash
python -m validation.audit_fingerprints --freshness
```

It reports verified-date coverage and the count of detections older than a
staleness threshold. The diff-aware `scripts/check_fingerprint_freshness.py`
gate permits the legacy undated backlog but requires every new detection to
carry a valid, non-future `verified` date. As rules are promoted, backfill the
recently confirmed vendor families in batches. Once coverage is high enough,
raise the gate to reject dates older than the chosen threshold. A dead-reference
URL check remains an opt-in local tool, not a CI gate, because the committed
gates run at zero network and zero paid-API cost.

## 4. Higher-order signals

Beyond listing vendors:

- **Stack archetypes.** Recognizable combinations (enterprise M365 + gateway +
  federated SSO; modern edge + managed database + hosted auth) are higher-signal
  and more memorable than a flat vendor list, and fit the existing motif layer.
- **Typed overlap characterization.** Shared declarative values such as SPF
  includes, provider-attested tenant IDs, DMARC `rua` destinations, and exact
  verification tokens can group domains by the observed overlap type. Each
  grouping must retain stale, copied, delegated, and broad-provider explanations
  and must not become entity resolution, ownership, or control inference. Its
  value is descriptive comparison, especially within an operator-supplied
  portfolio.

## 5. Boundaries

The invariants are the moat and constrain this plan: passive in collection
scope, zero credentials, zero paid feeds, and no active scanning. Specifically
out of scope for catalog work: ASN / GeoIP / IP-based fingerprinting, generic
target-owned HTTP-header probing or crawling, and ingesting a third-party
technology
database. The frontier stays in DNS-name, certificate-transparency, and
declarative-token space.

## 5b. What collection already yields that the catalog does not read

Catalog growth has been mined in one direction: run a corpus, collect the
strings no rule matched, triage them. That direction is close to exhausted at
the current catalog size. The 2026-07-17 round produced 780 candidate buckets,
and the promotion pass two hours later closed the queue's verifiable entries in
a single commit. What remains is unnamed prefixes and target-owned
infrastructure, neither of which is promotable.

A second direction is available and cheaper, because the records are already
being collected and simply are not read. Each row below is evidence recon
already holds at the end of a normal lookup.

| Surface | Current state | Why it matters |
|---|---|---|
| MTA-STS policy body | Fetched over HTTPS, only `mode:` parsed; the `mx:` lines are discarded | An operator-published, authoritative list of the domain's mail hosts, arriving over a different channel than the MX lookup. It corroborates mail attribution without a second DNS query. |
| TLS-RPT `rua=` | Presence only | The reporting destination names the vendor exactly as DMARC `rua` does, and that path already carries 42 rules. |
| CAA parameters | `issue` and `issuewild` values are matched; `iodef`, `accounturi`, and `validationmethods` are not parsed | `accounturi` identifies the issuing account and ACME client; `iodef` names a security-contact destination. |
| SRV | Five owners probed, zero catalog rules; attribution runs through a hardcoded table | The record type carries service, target, port, priority, and weight. Standards-defined mail autoconfiguration owners under RFC 6186 name the mail host directly. |
| DKIM selectors | About thirteen probed, attributed by CNAME target | Selector names are themselves vendor-assigned, so a selector that resolves is evidence even when its target does not match a known hint. |
| MX preference and SRV priority | Discarded after matching | A primary and backup split across two vendors is a topology observation that a flat vendor list cannot express. |
| Certificate transparency | Disabled in the 2026-07-17 round | Chain discovery ran on the common-subdomain probe alone. CT is where the existing `cname_target` rules came from. |

These are ranked deliberately. The first three add an evidence path to slugs
that already exist, which is worth more than a new vendor: 569 of 679 slugs
define exactly one detection type, so no amount of new single-path vendors
improves the share of claims that can be corroborated. See
[the 2026-07-25 base-rate memo](../validation/2026-07-25-pattern-base-rates.md).

## 5c. Inverting the discovery direction

Corpus mining finds a vendor only after some sampled namespace already uses it,
so it systematically misses the long tail and cannot anticipate a vendor at
all. The inverse is to enumerate vendors and read each vendor's own published
DNS requirements, deriving the pattern before it appears in any corpus.

This stays inside the invariants. Vendor documentation is provider-owned public
text, no target is queried, and the resulting candidate carries a reference by
construction rather than needing one found afterwards. It also produces the
disclosure-safe artifact the promotion gate wants: a vendor, a record type, a
pattern, and a citation, with the corpus supplying only an aggregate
observation count if the pattern is present at all.

The standard the catalog actually applies is a prefix that names its vendor
plus a vendor-owned reference; existing rules such as
`^anthropic-domain-verification=` cite a documentation index rather than a page
documenting the string, because vendors issue these tokens through an admin
console and do not publish the prefix. A pattern whose prefix does not name a
vendor cannot meet that standard from either direction and belongs in the
deferred queue, not the proposal queue.

## 6. Prioritized backlog

The canonical release order controls execution. Runtime evidence-path
expansion below is a separate feature track because it changes collection,
claim, schema, or network semantics and cannot silently enter a catalog
measurement round.

1. Preserve the completed rank-stratified aggregate, candidate dispositions,
   and fixed-observation zero-regression decision.
2. Preserve the completed regional baseline, accepted fixed-observation
   decision, and clean-main replay from the
   [regional result](../validation/2026-08-13-catalog-regional-round.md).
3. Freeze and run disjoint vendor-seed holdouts. Admit a candidate only with an
   identifier, exact record type and pattern, source or disclosure-safe
   aggregate basis, and explicit pending, promoted, rejected, or deferred
   disposition.
4. Re-observe the frozen prior sample as the drift round. Do not describe a
   repeated frame as independent coverage.
5. Backfill `verified` dates only in reviewed families and raise the freshness
   ratchet only when observed coverage supports a new threshold.
6. Keep the opt-in unmatched-observation envelope and private ranking tool
   covered by per-type bounds, reserved synthetic fixtures, and default-output
   absence tests.
7. Evaluate vertical rounds only if they answer a question not already covered
   by the completed unseen-vertical holdout; never pool them into population
   rates.

Separately gated future feature work, after v2.14 evidence closes:

1. Read already collected MTA-STS `mx:` lines, TLS-RPT `rua=` destinations,
   and CAA `accounturi` or `iodef` parameters only under a new claim and schema
   contract.
2. Replace hardcoded SRV attribution with a catalog-driven path and consider
   additional standards-defined owners only with an explicit collection and
   compatibility review.
3. Reopen CT-enabled catalog discovery only through a separately frozen round;
   it cannot be compared to the CT-off regional contract as if collection were
   unchanged.

No promotion is complete without a current public reference or
disclosure-safe aggregate basis, a `verified` date, a positive fixture, a
lookalike-negative fixture, a sparse-result fixture, and provenance assertions.
