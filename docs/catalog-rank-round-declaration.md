# Catalog Rank-Round Selection Declaration

**Frozen:** 2026-08-13T16:23:43.917496Z

**Collection status:** Not started

**Target-network requests during preparation:** 0

This declaration commits the v2.14 catalog rank round before any selected
namespace is contacted. Membership, source paths, the sampling key, and every
per-domain row remain in the ignored private workspace. Only aggregate counts
and cryptographic commitments are public.

## Question and interpretation boundary

The round asks whether independently sampled Tranco head and tail bands expose
different recurrent catalog gaps by bounded DNS record type. It is a discovery
round. Its equal allocation of 250 namespaces per band gives each band the same
opportunity to surface recurrent patterns. It is not population weighting, a
prevalence estimate, a census of the Internet, or a basis for claims about any
organization.

The archived source is Tranco list [`26J79`](https://tranco-list.eu/list/26J79/1000000),
the same source revision already frozen for the cancelled v2.11 evaluation.
The whole prior development corpus is excluded before sampling without
case-by-case reuse.

| Source measure | Frozen value |
|---|---:|
| Tranco rows | 1,000,000 |
| Tranco SHA-256 | `b2cadaa39f3c14045b5b3d748cf3143dffd386ac01d0844e522510711aacc06b` |
| Rows changed by apex normalization | 82 |
| Invalid source rows excluded | 8 |
| Canonical source duplicates removed | 3 |
| Development-corpus input rows | 5,241 |
| Development-corpus canonical rows | 5,199 |
| Development-corpus SHA-256 | `87178ba2b8ce596eaec26a59a1e57cdefe080a1f1109c1efcac19c24cf9cfdef` |
| Development overlaps excluded | 4,186 |
| Eligible source rows across all bands | 995,803 |

## Frozen selection rule

Within each band, eligible canonical apexes are ordered by:

```text
HMAC-SHA256(private_key, ASCII(context || ":" || band_id) || NUL || ASCII(apex))
```

Ties are resolved by original rank and canonical apex. The first 250 rows in
each band are selected. The private 256-bit key came from the operating-system
CSPRNG. Publishing only its SHA-256 commitment prevents reconstruction of the
sample from the public Tranco list while allowing a private auditor to reproduce
it exactly.

| Selection measure | Frozen value |
|---|---|
| Method | `hmac-sha256-rank-without-replacement-v1` |
| Domain-separation context | `v214-catalog-rank-26J79-20260813-01` |
| Private-key SHA-256 | `bed1c5e5bc28ee0daed1d17cb7698c8263c538666eb1d1c0dfe17d25da405d95` |
| Private selection-plan SHA-256 | `4a76eb731733497bb66b3cf86d7309313a408b6d8c2ec057fe1b3ab2cbeb1044` |
| Private selection-manifest canonical digest | `d19324960c4b5690addc8ebaafc2ec0b4273a70247e3f735640bf19bb3c980d8` |
| Combined canonical frame rows | 1,000 |
| Combined canonical frame SHA-256 | `ae9d0242bcb3eaa82c1d381ae8f0340cf17d9aa3fa8fe281989658aa696a5ee2` |

| Band | Canonical source rows | Development overlaps excluded | Eligible rows | Selected rows | Inclusion probability | Private frame SHA-256 |
|---|---:|---:|---:|---:|---:|---|
| 1-1,000 | 1,000 | 239 | 761 | 250 | `250/761` | `88ca39ee77254911c60f0e913eeaea24a7b91a0a28401a4e26577ffbc28bbd29` |
| 1,001-10,000 | 8,999 | 955 | 8,044 | 250 | `250/8044` | `2c1fea6cdad3325a9e5c3aa6b82c5d8eecb3f23d7994272b1a1a498a989d3b52` |
| 10,001-100,000 | 89,997 | 1,989 | 88,008 | 250 | `250/88008` | `37d62d27830d2501acf23fcf1cb58853b649b47efabe64363d71c555b9e2a5e4` |
| 100,001-1,000,000 | 899,993 | 1,003 | 898,990 | 250 | `250/898990` | `e3070580b987d9b269020bdb37c87249b56c13d06b6971830d183aa9e05a6708` |

## Collection gate

Selection is complete, but collection remains blocked until this declaration
is merged to protected `main`. After merge, the private catalog-round contract
must be regenerated with schema version 2. That contract commits the combined
frame, catalog digest, execution-code and lockfile digest, CT-off setting,
direct-probes-off setting, recurrence thresholds, and promotion and regression
budget. `scan.py` must revalidate every commitment before its first target
request. The reducer repeats the checks before it emits an aggregate.

The round uses the normal documented DNS and identity-discovery boundary with
CT disabled and no opt-in direct probes. Public outputs may contain aggregate
record-type opportunity, availability, classification, unresolved, candidate,
and disposition counts only. They may not contain evaluated apexes, target
record values, organization names, tenant identifiers, or per-domain rows.

Every candidate remains pending until it has an exact record type and pattern,
an independent provider-controlled reference or disclosure-safe aggregate
basis, a recon review date, fictional positive, lookalike-negative, and sparse
fixtures, provenance assertions, and a replay result within the frozen
zero-regression budget.
