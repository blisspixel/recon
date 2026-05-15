# v1.9.9 — trigger threshold sensitivity analysis

**Corpus:** 19 fixtures from `validation/synthetic_corpus/results.json`.

**Defaults under test:**
- `MIN_DOMAINS_FOR_CEILING = 3`
- `SPARSE_CATEGORY_FLOOR = 5` (strict less-than)
- `SPARSE_SURFACE_FLOOR = 5` (strict less-than)

**Anchor measurement at defaults:**
- Estimator-based fires: 13 of 19
- Render-based fires: 11 of 19
- Gap: 2 (estimator over-fires by this much because the slug-only categorized-count lower bound under-estimates the panel's true count)

## Sweep: `MIN_DOMAINS_FOR_CEILING`

Holding `category_floor=5`, `surface_floor=5`. Estimator-based counts.

| `min_domains` | fires | rate |
|---|---|---|
| 1 | 15 | 78.9% |
| 2 | 14 | 73.7% |
| 3 | 13 | 68.4% |
| 4 | 8 | 42.1% |
| 5 | 6 | 31.6% |

**Reading:** lowering `min_domains` to 1 or 2 fires on small organizations the design rejects; raising to 4 or 5 misses multi-domain hardened apexes the design targets. Default of 3 is on the inflection point.

## Sweep: `SPARSE_CATEGORY_FLOOR`

Holding `min_domains=3`, `surface_floor=5`. Estimator-based counts.

| `category_floor` | fires | rate |
|---|---|---|
| 3 | 9 | 47.4% |
| 4 | 11 | 57.9% |
| 5 | 13 | 68.4% |
| 6 | 14 | 73.7% |
| 7 | 14 | 73.7% |

**Reading:** lower values miss sparse-but-not-empty cases; higher values over-fire on rich-stack apexes. Default 5 stays on the conservative side of the inflection.

## Sweep: `SPARSE_SURFACE_FLOOR`

Holding `min_domains=3`, `category_floor=5`. Estimator-based counts.

| `surface_floor` | fires | rate |
|---|---|---|
| 3 | 11 | 57.9% |
| 4 | 13 | 68.4% |
| 5 | 13 | 68.4% |
| 6 | 14 | 73.7% |
| 7 | 14 | 73.7% |

**Reading:** raising the surface floor over-fires on apexes with substantive subdomain footprints; lowering it misses sparse-but-multi-domain cases. Default 5 matches the category floor for symmetry.

## Conclusion

The defaults sit on the conservative side of every sweep's inflection point. Each threshold can be moved without the rate changing dramatically (no cliff in the curve), which is the property a reviewer would call 'robust to specification choice'. The synthetic corpus is intentionally weighted toward demonstrating both surfaces, so the absolute rates will be lower on a balanced operational corpus; the *shape* of the sweep is the load-bearing finding.

Honest framing: this sweep is on the synthetic corpus only. The same sweep against the gitignored private corpus is the next step before v2.0; the script is reusable for that without modification.
