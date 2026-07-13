# Catalog Growth and Quality Strategy

Status: measurement-first maintenance plan
Review date: 2026-07-10

This document is the plan for growing and maintaining the fingerprint catalog
(`src/recon_tool/data/fingerprints/*.yaml`) so coverage, precision, and
freshness improve deliberately rather than by accretion. It sets direction; it
does not change runtime behavior. All corpora and per-domain scan outputs stay
private and off GitHub per [data-handling-policy.md](data-handling-policy.md);
only aggregate patterns, generic tooling, and fictional examples are committed.
This plan implements the catalog-quality track in the canonical
[roadmap](roadmap.md). Catalog size is not a success metric; classified public
surface and independently supported precision are.

## How the catalog grows today

The catalog carries 847 entries across `cname_target`, `txt`, `spf`,
`dmarc_rua`, `mx`, `ns`, `caa`, `srv`, and `subdomain_txt` detection types. New
rules come from a corpus-mining loop:

1. A private domain corpus is run through `recon batch --include-unclassified`
   (`validation/scan.py` or `validation/run_corpus.py`), with output written to
   gitignored private directories (`validation/runs-private/`, `live_runs/`).
2. `validation/find_gaps.py` aggregates the unclassified CNAME-chain terminals
   across the whole run and ranks them by frequency.
3. `validation/triage_candidates.py` drops already-covered and
   intra-organizational suffixes and applies a minimum-count floor.
4. Each surviving candidate is verified against public vendor documentation and
   promoted with a scoped pattern, a `reference`, a category mapping, a
   regression test, and hedged wording.

The loop is disciplined and effective, but it has three structural limits that
this plan addresses: the corpus is a single convenience sample (selection bias),
only CNAME gaps are ranked corpus-wide, and until now there was no freshness
signal.

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

## 2. Measurement: coverage, recall, precision

Growth without measurement cannot tell 40% coverage from 90%. Three metrics
close the loop:

- **Coverage / unclassified rate.** `find_gaps.py` already produces a
  frequency-ranked list of unclassified CNAME terminals; that ranking is the
  prioritized backlog (add the most common unclassified pattern first for the
  largest coverage gain per rule). Track "share of observed DNS surface
  classified" as a north-star number. Extension: emit unclassified SPF includes,
  NS, and MX values (alongside `unclassified_cname_chains` in `cache.py`) so the
  same ranking works for those record types, not just CNAME.
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

Before the next broad promotion pass, record a dated baseline by record type
and corpus stratum. The baseline must also report unresolved share, stale-rule
count, low-corroboration attribution count, and the exact catalog revision.
Every promotion should name the aggregate gap it is intended to reduce and a
precision regression budget.

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
staleness threshold. Backfill plan: require `verified` for new rules, then
are promoted, backfill the recently-confirmed vendor families in batches, and
once coverage is high enough, promote the auditor from a report to a ratchet
(no new undated rules, no rule left stale past the threshold). A dead-reference
URL check is deliberately kept as an opt-in local tool, not a CI gate, because
the committed gates run at zero network and zero paid-API cost.

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

1. Record the classified-surface and stale-rule baseline before adding broad
   new families.
2. Admit a candidate to the proposal queue only when it has an identifier,
   exact record type and pattern, source or disclosure-safe aggregate basis,
   and explicit pending, promoted, rejected, or deferred disposition. A vendor
   name alone is not an actionable candidate.
3. Stand up a Tranco-stratified corpus and run it once to produce a coverage
   baseline and the unclassified-pattern ranking (the prioritized growth list).
4. Add regional strata (the largest coverage gap) and promote the verified
   regional vendors they surface.
5. Backfill `verified` dates and raise the freshness auditor toward a ratchet.
6. Extend the unclassified-pattern ranking beyond CNAME to SPF and NS.
7. Measure recall on vendor-seed lists for the top vendors.

No promotion is complete without a current public reference or
disclosure-safe aggregate basis, a `verified` date, a positive fixture, a
lookalike-negative fixture, a sparse-result fixture, and provenance assertions.
