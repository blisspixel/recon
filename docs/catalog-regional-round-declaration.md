# v2.14 Catalog Regional Round Declaration

Status: complete; protected-main live replay and aggregate disposition passed

Frozen: 2026-08-13

This declaration fixes the regional catalog-quality question, official source
inputs, selection method, private frame commitments, collection options, and
decision budget before recon contacts any selected namespace. It publishes no
apex, organization, tenant identifier, target-owned record, or per-domain row.

## Question and interpretation boundary

Primary question:

> Which recurrent bounded record-type catalog gaps appear across equal
> discovery quotas from large eligible ccTLD namespaces in each canonical UN
> M49 region?

This is a comparison of ccTLD namespace strata selected from one frozen
popularity list. It does not identify registrant location, organizational
presence, service geography, or regional Internet prevalence. Equal quotas are
discovery budgets, not population weights. Globally marketed ccTLDs remain in
their exact IANA and UN M49 grouping.

## Official source freeze

At `2026-08-13T21:01:51.567080Z`, the source freezer made exactly two bounded
HTTPS requests and archived the returned bytes privately. It rejected
redirects and made zero selected-namespace requests.

| Input | Rows or bytes | SHA-256 |
|---|---:|---|
| [IANA Root Zone Database](https://www.iana.org/domains/root/db) raw HTML | 377,758 bytes | `70d00752308e17229606b6437c7b78b1a1b5b447ce0925e53330c0910805c0d8` |
| [UN M49 overview](https://unstats.un.org/unsd/methodology/m49/overview/) English-table raw HTML | 1,721,568 bytes | `748f6ff7380c8a50ea9448f068b79e3a1ee31be63207249e8cc89bf1eb969d11` |
| Exact ASCII two-letter IANA country-code and UN ISO-alpha2 intersection | 247 rows | `5ce172cd569baeae3ce2c1d4608b28eef336f36f7d19a45a842f1ef5124b9942` |

The IANA input contains 255 ASCII two-letter country-code TLDs. The UN input
contains 248 ISO-alpha2 rows, of which one regionless row is explicitly
excluded. The exact intersection contains 247 rows across all five canonical
regions. Eight IANA ASCII country-code TLDs have no matching canonical-region
UN row. The private source-manifest commitment is
`12f7b57388f444b33e0bae321d002555ac12861d1a65f9b23c050ad50e00792d`.

## Selection contract

The source population is the frozen Tranco `26J79` top-one-million list with
SHA-256
`b2cadaa39f3c14045b5b3d748cf3143dffd386ac01d0844e522510711aacc06b`.
The selector excludes the complete canonical development corpus and every
namespace observed in the completed rank round. Their union contains 6,199
canonical apexes. The cancelled v2.11 frame is not an observation exclusion
because it made zero target requests.

The selection method is
`hmac-sha256-ccTLD-within-m49-region-v1`. Its private 32-byte key is not
published; the key commitment is
`ce103286ff825b964da4b2d26424cf51d84fa84274a2429da52ff987b35b037e`.
Within each region, the selector chooses the four largest eligible ccTLD
universes with a lexical tie break, then takes 50 secret-keyed rows without
replacement from each ccTLD. Each region therefore contributes 200 rows and
the combined frame contains 1,000 unique apexes.

| UN M49 stratum | Eligible ccTLDs | Selected ccTLDs | Rows | Private frame SHA-256 commitment |
|---|---:|---|---:|---|
| Africa | 30 | `.io`, `.za`, `.ng`, `.ma` | 200 | `1766d60d0d33c7ad5bf936e810a6be05db2a0c9d0865b74edddd0f271bd1b780` |
| Americas | 28 | `.br`, `.co`, `.ca`, `.us` | 200 | `842bbef5e265a593949a66f849130a37ffd874f98562a861e6cc405a36abcb7e` |
| Asia | 44 | `.jp`, `.in`, `.cn`, `.id` | 200 | `8167598d1a9eec53152638036b665fc4ad6c322ce06149d4f3d8b63721f4c31f` |
| Europe | 41 | `.ru`, `.de`, `.nl`, `.fr` | 200 | `92c4c7387dc149bab6a9f07aef432c226cc181e397ab8e35d92112893f8d91e1` |
| Oceania | 10 | `.au`, `.cc`, `.tv`, `.nz` | 200 | `469da3ce8b1716283e9be4f9333fb1eafee8bb319e964cd0c7de1714791a1a02` |

The selection plan commitment is
`52ac4f1459be08d5170ef6f9c557704b11b667c2b5de0d6844ff36a8c6bc20a5`.
The private selection-manifest commitment is
`dc3a26ab1dff98d47d1de9282e04939ab3fb3ffe002cfa1c52d744998aeb43cd`.

## Collection and decision contract

The frozen round uses these options:

- certificate transparency disabled;
- direct probes disabled;
- minimum recurrence of 3 occurrences across at least 2 distinct namespaces;
- overlap rejected;
- classified-opportunity share measured separately by bounded record type;
- minimum accepted improvement of 0.001;
- maximum protected record-type regression of 0.0.

A recurrent candidate remains pending until it also has an exact record type
and pattern, a current provider reference or disclosure-safe aggregate basis,
a recon review date, a fictional positive fixture, a lookalike negative, a
sparse-result fixture, scoped wording, and provenance assertions. A regional
count does not establish a population rate or an independent precision label.

| Commitment | SHA-256 |
|---|---|
| Regional source payloads | `cdf97fcba5d37ad997f9df6d38260040fceee83a18db1ab952e8e612ae1906c3` |
| Combined 1,000-row frame | `02544fe04b9c21fa74f1334d1884db2044dd3de2ac30686db661eb5590a5d7e3` |
| Fingerprint catalog | `78e9641abb60fd310a834b141d2d2c553afe7026893526f4af733221124534c8` |
| Collection implementation | `3fe0fd7e539c35c07f3f559779df1da1301df62a9b5826ee7d1734c24ec80cfb` |
| Round plan | `bb73891df121a7d4c75a5e06d40bafe6e767f8d2f71b23b50dfd3ac0511a1f3e` |
| Private round manifest | `7209b80ef5b248802a6b0fe0ecb8f9d53889a26aaae7b46272d7e28fcfbcad4b` |

The implementation was frozen against protected `main` commit
`2900404a15c8d701599117c2cdcf2f15a7b82a71`. The private contract was
independently reloaded and validated against the exact frame, catalog,
implementation, collection settings, recurrence thresholds, and digest chain.

## Pre-collection gate

Before this declaration, selected-namespace request count is zero. Collection
may start only after this declaration and the aligned current-plan updates pass
the full local documentation gates, merge through protected main, and receive
green post-merge CI. Results remain private until the aggregate reducer has
verified complete frame membership and disclosure safety. Every candidate must
end as promoted, rejected, deferred, unavailable, or unmeasured.

## Post-collection status

The baseline completed all 1,000 frozen rows with zero errors and 45 partial
rows. The aggregate-only
[result](../validation/2026-08-13-catalog-regional-round.md) records the
stratified classification rates, explicit dispositions, and an accepted
fixed-observation zero-regression decision for six documented provider
families. It publishes no target identifier or per-domain row.

The accepted catalog and tests merged through protected main at
`d19b888e3f6826df33994be3b46d91751438a7bd` after all 27 hosted checks passed.
A live operational pass then replayed this exact frozen frame with 1,000 of
1,000 rows, zero errors, and 39 partials. All five membership-bound strata
reduced completely, and the clean-main counterfactual reproduced the accepted
fixed-observation result. The regional round is closed; vendor-seed contract
freeze is next.
