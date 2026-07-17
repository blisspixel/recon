# Catalog Growth and Quality Strategy

Status: measurement-first maintenance plan
Review date: 2026-07-17

This document is the plan for growing and maintaining the fingerprint catalog
(`src/recon_tool/data/fingerprints/*.yaml`) so coverage, precision, and
freshness improve deliberately rather than by accretion. It sets direction; it
does not change runtime behavior. All corpora and per-domain scan outputs stay
private and off GitHub per [data-handling-policy.md](data-handling-policy.md);
only aggregate patterns, generic tooling, and fictional examples are committed.
Real vendor and product names, plus provider-controlled domains used in generic
fingerprint rules, may be committed. The evaluated target names, target-owned
records, and per-domain results may not.
This plan implements the catalog-quality track in the canonical
[roadmap](roadmap.md). Catalog size is not a success metric; classified public
surface and independently supported precision are.

## How the catalog grows today

The catalog carries 855 entries and 1,062 detection rules across nine populated
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
independent rank, regional, vendor-seed, and drift rounds remain open, and most
legacy detections still lack a freshness date.

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
  vendors; this is the largest blind spot. Per-country sweeps surface regional
  hosting, email, identity, CDN, and consent vendors that never appear in a US
  list.
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
rule. The rule itself, a provider-controlled public reference, fictional
fixtures, and aggregate counts are sufficient for review.

Stop adding inputs when a round does not answer a new sampling question. Stop a
promotion pass when the highest-frequency survivors lack an independent public
basis, fail a lookalike negative, or exceed the predeclared precision regression
budget. Two scans of the same list are a drift check, not two coverage rounds.

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

## 6. Prioritized backlog

1. Freeze the round manifest and record the current classified-surface,
   observation-opportunity, unresolved, and stale-rule baseline across the
   implemented typed extractors.
2. Admit a candidate to the proposal queue only when it has an identifier,
   exact record type and pattern, source or disclosure-safe aggregate basis,
   and explicit pending, promoted, rejected, or deferred disposition. A vendor
   name alone is not an actionable candidate.
3. Keep the opt-in unmatched-observation envelope and private ranking tool
   covered by per-type bounds, fictional fixtures, and default-output absence
   tests.
4. Stand up a rank-stratified private corpus and run it once to produce the
   first comparable multi-record baseline and prioritized growth queues.
5. Add regional strata (the largest expected coverage gap) and promote the
   verified regional vendors they surface.
6. Add vertical rounds without pooling them into population rates.
7. Backfill `verified` dates and raise the freshness auditor toward a ratchet.
8. Measure recall on disjoint vendor-seed holdouts for the top vendors.

No promotion is complete without a current public reference or
disclosure-safe aggregate basis, a `verified` date, a positive fixture, a
lookalike-negative fixture, a sparse-result fixture, and provenance assertions.
