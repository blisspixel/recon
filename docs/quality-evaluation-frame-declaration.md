# v2.11 quality-evaluation frame declaration

**Frozen 2026-08-12, before reference-label collection, DNS collection, arm
evaluation, or outcome inspection.**

This is the public frame definition and private-membership commitment required
by the
[product-quality preregistration](quality-baseline-preregistration.md#6-sampling-frame-and-corpus-disjointness).
The enumerated domains and 256-bit sampling key remain in the ignored
maintainer-local workspace. Only counts, rules, public-source metadata, public
domain-separation contexts, and SHA-256 commitments appear here.

No evaluation target may be contacted until the Git commit containing this
exact declaration is publicly reachable. If that does not happen before the
eligibility window opens, the window is void and a dated amendment must be
published before any collection.

## Target population and source

The target population is the set of syntactically valid canonical registrable
apexes derived from ranks 1 through 1,000,000 of the standard pay-level
[Tranco list `26J79`](https://tranco-list.eu/list/26J79/1000000), generated
2026-08-12, after excluding the complete existing 5,241-row development corpus.

Tranco reports that this archived list combines CrUX, Farsight, Majestic,
Cloudflare Radar, and Cisco Umbrella ranks from 2026-07-14 through 2026-08-12
with the Dowdall rule, retains only pay-level domains, and archives the exact
list under a permanent ID. The ranking is a defensible and reproducible popular
domain frame, not a census of the Internet. Its component traffic, browser,
DNS, crawl, and link signals impose selection biases that remain limitations.

| Source measure | Frozen value |
|---|---:|
| Tranco list ID | `26J79` |
| Ranked-source rows | 1,000,000 |
| Ranked-source SHA-256 | `b2cadaa39f3c14045b5b3d748cf3143dffd386ac01d0844e522510711aacc06b` |
| Rows changed by recon apex normalization | 82 |
| Invalid ranked rows excluded | 8 |
| Canonical ranked duplicates removed | 3 |
| Development-corpus input rows | 5,241 |
| Development-corpus canonical rows | 5,199 |
| Development-corpus SHA-256 | `87178ba2b8ce596eaec26a59a1e57cdefe080a1f1109c1efcac19c24cf9cfdef` |
| Ranked rows excluded for development-corpus overlap | 4,186 |
| Eligible first-stage universe | 995,803 |

The whole development corpus is excluded regardless of whether an individual
row informed a prior, likelihood, diagnostic, catalog decision, or earlier
characterization. No case-by-case reuse is permitted.

## First-stage screening frame

The first-stage sample is a simple random sample without replacement,
implemented as deterministic keyed HMAC-SHA-256 ranking:

```text
key(domain) = HMAC-SHA256(private_key, ASCII(context) || NUL || ASCII(canonical_domain))
```

Sort by `(key, original_rank, canonical_domain)` and take the first 2,500
eligible rows. This fixes equal first-stage inclusion probability for every
eligible universe member.

| Sampling measure | Frozen value |
|---|---:|
| Sample size | 2,500 |
| Public sampling context | `v211-screening-frame-20260812-01` |
| Sampling method | `hmac-sha256-rank-without-replacement-v1` |
| Private key size | 256 bits, generated once with the operating-system CSPRNG |
| Private key SHA-256 | `ebdcdfb22dd35ce071098ea4d4fb98e78395cf8e987585865166ceca9e967eca` |
| First-stage inclusion probability | `2500/995803` |
| Private frame serialization | UTF-8 CSV, LF endings, header `rank,domain` |
| Private frame SHA-256 | `e9e6c435c22d47007c12612b71684326624af548b169f749bca35cf8429406a7` |

Publishing a conventional seed would make membership reconstructible from the
public Tranco source. The actual key is therefore private and only its SHA-256
commitment is public. The public context supplies domain separation, not secret
entropy. A private auditor with the key, source, and excluded corpus can
reproduce the exact frame; the committed materials alone cannot enumerate it.

The private key and frame are immutable. Any byte change, missing file, or
digest mismatch voids the primary evaluation. The frame was prepared with zero
target-network requests and aggregate-only console output reporting zero
identifiers and zero per-domain rows.

## Eligibility window and collection boundary

The eligibility window is **2026-08-17T00:00:00Z through
2026-08-23T23:59:59Z**. Each first-stage domain receives one bounded collection
attempt in that window. All rows use the same software revision, catalog
revision, options, timeout policy, and empty-cache starting condition, recorded
in the private run manifest and eventual aggregate memo.

Collection is limited to:

- DNS-channel inputs needed by the four frozen arms;
- Microsoft `GetUserRealm` and OIDC discovery responses used only for the
  frozen reference label; and
- local derivation, serialization, and validation.

Certificate transparency, MTA-STS, Google CSE, BIMI certificate retrieval, and
all other target-owned HTTP are disabled. An endpoint's shipped bounded retry
behavior is part of its single collection attempt. There is no manual retry,
replacement domain, or reclassification after an arm output is available.

The reference-label conditions remain exactly those in the preregistration:

- reference-positive: `GetUserRealm` returns `Federated` or `Managed`, and OIDC
  discovery resolves a tenant;
- reference-negative: `GetUserRealm` returns a non-tenant namespace type and
  OIDC discovery returns `invalid_tenant`; and
- ineligible: the endpoints disagree, either endpoint is unavailable, or
  either response is malformed.

The identity responses are label-only. The evaluation harness must fail closed
if any arm receives an identity-endpoint input.

## Known-cluster exclusion

Known dependence is removed before label-stratum sampling or arm computation.
Build connected components from exact nonempty shared Microsoft tenant IDs and
exact shared administrative verification tokens in the frozen raw snapshot.
Within each component retain the row with the smallest HMAC key under the same
private key and this public context:

```text
v211-cluster-representative-20260812-01
```

Singletons remain unchanged. Report only aggregate component and exclusion
counts, suppressing any cell below 10. No organization name, cluster member,
tenant ID, or token leaves the private workspace.

This rule covers administrative and tenant clusters visible in the collected
channels. No external ownership table is joined to the frame. Unknown
cross-domain ownership or dependence remains an explicit limitation and cannot
be described as resolved.

## Second-stage label-stratum sample

After reference classification and known-cluster exclusion, but before any arm
output is computed or inspected, rank rows separately inside each label stratum
with the same keyed construction and this distinct public context:

```text
v211-label-stratum-20260812-01
```

For each stratum, retain `min(200, N_stratum)` rows. The conditional
second-stage inclusion probability is therefore
`min(200, N_stratum)/N_stratum`, reported with the aggregate stratum count.
Different label-stratum sampling rates are intentional; pooled rates are not
population estimates without the corresponding frozen weights.

The primary run is prohibited unless at least 155 reference-positive and 183
reference-negative unique post-cluster units remain. If either minimum is
missed, publish only aggregate screening counts and follow the preregistration's
amendment policy. Do not compute or inspect the primary arm contrast.

Every selected unit then receives all four arms over the same frozen DNS-only
snapshot. A0 versus A3 remains the sole decision contrast. A1 and A2 remain
secondary, and no threshold, rule, prior, weight, source, or replacement row
may change after collection begins.

## Reproduction

Download the permanent public source into the ignored private corpus area.
Generate the private key exactly once; the command prints only its commitment
and refuses to replace an existing key:

```bash
python -m validation.prepare_quality_evaluation_frame generate-key \
  --output validation/corpus-private/v211-sampling-key-20260812.hex
```

Then run the aggregate-only preparer first with `--preflight`:

```bash
python -m validation.prepare_quality_evaluation_frame prepare \
  --ranked-source validation/corpus-private/tranco-26J79-top1m.csv \
  --exclude-corpus validation/corpus-private/consolidated.txt \
  --output validation/corpus-private/v211-screening-frame-26J79-hmac-v1.csv \
  --sampling-key-file validation/corpus-private/v211-sampling-key-20260812.hex \
  --tranco-list-id 26J79 \
  --expected-source-rows 1000000 \
  --sample-size 2500 \
  --sampling-context v211-screening-frame-20260812-01 \
  --preflight
```

Replace only the final flag with `--write-private-frame` after reviewing the
aggregate. The writer refuses to replace an existing frame. Recompute the
private-key, ranked-source, and frame SHA-256 commitments before any collection;
a mismatch stops the run. Never print or commit the private key.

## Disclosure and interpretation

Never commit or publish the screening frame, label table, raw snapshot,
selected domains, organization names, tenant IDs, administrative tokens,
per-domain arm outputs, or unsuppressed small strata. The result memo may contain
only the aggregates permitted by the preregistration and data-handling policy.

The source design supports inference only to the declared Tranco-derived
population under the stated exchangeability and known-cluster assumptions. It
does not support an Internet-wide, organization-wide, or security-maturity
claim. Microsoft endpoint labels remain channel-split corroboration with a
shared tenant-provisioning common cause, not independent calibration.
