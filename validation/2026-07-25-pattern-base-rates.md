# Per-Pattern Base Rates and Corroboration

Status: first measurement complete; no scoring change made

Date: 2026-07-25

This memo records disclosure-safe per-pattern base rates over one frozen private
convenience sample. It is a maintenance measurement, not a population estimate,
a precision study, a recall study, or a claim about any queried organization.
The input manifest, target names, target-owned records, and per-domain output
remain in ignored local workspaces. GitHub receives only aggregate counts and
generic provider-owned patterns.

## Why this measurement exists

Evidence weight in recon is a function of source type alone.
`fusion.SOURCE_WEIGHTS` keys on `EvidenceRecord.source_type`, and
`merger._build_detection_weight_map` keys on `(slug, detection type)` taking the
maximum across every detection sharing that pair. Neither consults how
discriminative an individual pattern is. `specificity.py` models specificity
only as a binary admission gate against a synthetic adversarial corpus, so a
pattern that survives admission carries the same weight as any other pattern of
its type.

The catalog's per-fingerprint `confidence` field is carried to output and cache
but never reaches either scoring path, and `DetectionRule.weight` is set on 4 of
1,064 detections. The mechanism for graded weighting therefore exists and is
effectively unused. This memo supplies the empirical input it would need.

## Frozen inputs

| Field | Value |
|---|---|
| Source run | `quality-proof-baseline-2026-07-17` |
| Collection revision | `1c130ee7c6c6687491e4423e3987587a4f39b571` |
| Results digest | `39655fc31713302803d37a17345f30f3b2a8253da082e3c47509db25e16db7ed` |
| Output records | 5,202 |
| Successfully measured namespaces | 5,199 |
| Validation errors | 3 |
| Catalog at measurement | 856 entries, 1,064 detections |
| CT collection during the run | Disabled |
| Reducer | `validation/pattern_base_rates.py` |

The reducer never reads `queried_domain`, `display_name`, `tenant_id`,
`related_domains`, or `tenant_domains`. It consumes only
`evidence[].source_type` and `evidence[].raw_value`, and represents namespace
identity as the record's ordinal position in the input stream, discarded after
aggregation. A runtime guard asserts the restriction so a later edit cannot
quietly widen the read set.

Raw values are re-matched with the helpers the production detectors use, so a
fire counted here is a fire recorded by recon: regex search for TXT-shaped
paths, and DNS-label suffix or dotless substring semantics elsewhere.

Base-rate denominators are the observation opportunities recorded in the run's
own gap aggregate (`available + partial` namespaces per path), not the count of
namespaces that produced an attribution. Using attributions as the denominator
would condition it on a match having already happened and inflate every rate.

## Measurable surface

| Detection type | Detections | Measurable |
|---|---:|---|
| `cname_target` | 434 | No |
| `txt` | 299 | Yes |
| `cname` | 98 | Yes |
| `spf` | 84 | Yes |
| `ns` | 45 | Yes |
| `mx` | 43 | Yes |
| `dmarc_rua` | 42 | Yes |
| `caa` | 13 | Yes |
| `subdomain_txt` | 6 | Yes |

630 of 1,064 detections are measurable from this run. The 434 `cname_target`
rules are not: the run disabled CT collection, and `surface_attributions`
retains the attributed slug and tier but not the CNAME target that matched, so a
fire cannot be traced to an individual pattern. Attributing `cname_target`
requires either a CT-enabled round or retaining the matched target in the run
output. Those 434 detections are recorded as unmeasured, not as zero.

## Result: discriminative power spans a factor of 3,800

Of the 630 measurable detections, 410 fired at least once and 220 never fired
across 5,199 namespaces.

Among patterns that fired, the base rate ranges from 0.000192 to 0.7294. Stated
as information content (`-log2(base rate)`), the observations recon treats as
interchangeable range from 0.5 bits to 12.3 bits.

| Information content | Patterns |
|---|---:|
| Under 2 bits (near-universal) | 8 |
| 2 to 5 bits | 69 |
| 5 to 8 bits | 138 |
| 8 bits or more (highly specific) | 195 |

The single most common pattern, `^google-site-verification=`, fired on 72.9
percent of measured namespaces and carries 0.5 bits. It currently contributes
the same TXT evidence weight as `^krisp-domain-verification=`, which fired on
0.19 percent and carries 9.0 bits.

## Result: corroboration is a sharper discriminator than prevalence

Corroboration here means the attributed slug also had evidence from a different
source type on the same namespace. It is only interpretable for slugs whose
catalog entry defines two or more detection types; for a single-type slug it is
structurally zero and says nothing. Of the 145 patterns with at least 50 fires,
82 belong to single-type slugs and are excluded from this reading.

Of the remaining 63:

- 7 corroborate on 90 percent or more of their fires.
- 20 corroborate on under 5 percent of their fires.

Prevalence and corroboration are close to independent. The Microsoft 365 apex
verification TXT prefix is common (base rate 0.512) and corroborates on 100
percent of fires. It is named descriptively here rather than quoted, because the
tracked-artifact hygiene gate treats a verification prefix followed by any value
as a token and cannot distinguish a catalog pattern from a real one.
`mail.protection.outlook.com`
(0.227) and `aspmx.l.google.com` (0.211) likewise corroborate at 1.00 and 0.95.
A common observation is not automatically a weak one.

The 20 patterns that fire often and are almost never corroborated are the
actionable set, because each one produces a service attribution that no other
observed evidence supports. The largest by volume:

| Type | Pattern | Slug | Fires | Base rate | Corroboration |
|---|---|---|---:|---:|---:|
| `txt` | `^atlassian-domain-verification=` | atlassian | 2,129 | 0.410 | 0.02 |
| `txt` | `^docusign=` | docusign | 1,434 | 0.276 | 0.00 |
| `cname` | `cloudfront.net` | aws-cloudfront | 1,065 | 0.205 | 0.00 |
| `cname` | `.elb.` | aws-elb | 558 | 0.107 | 0.00 |
| `txt` | `^stripe-verification=` | stripe | 457 | 0.088 | 0.02 |
| `cname` | `elb.amazonaws.com` | aws-elb | 450 | 0.087 | 0.00 |
| `cname` | `fastly.net` | fastly | 370 | 0.071 | 0.00 |
| `dmarc_rua` | `dmarcian.com` | dmarcian | 266 | 0.051 | 0.00 |

Two explanations are compatible with this pattern and this measurement cannot
separate them: a verification token can persist after the service is dropped,
which the catalog descriptions already flag as stale residue, or the vendor can
issue the token broadly enough that it does not imply a deployed integration.
Neither reading is an accuracy finding. Both mean the observation is weaker than
an equally weighted corroborated one.

## Result: pattern ambiguity is rare but concentrated

18 patterns matched raw values that also matched a different slug's pattern of
the same type. The maximum was 8 competing slugs, on `_spf.google.com`, which is
expected: many vendors instruct customers to include Google's SPF record, so the
value is shared infrastructure rather than a discriminating mark.

## Result: 220 measurable patterns never fired

| Type | Never fired |
|---|---:|
| `spf` | 71 |
| `txt` | 64 |
| `cname` | 54 |
| `caa` | 10 |
| `dmarc_rua` | 10 |
| `subdomain_txt` | 6 |
| `mx` | 4 |
| `ns` | 1 |

A pattern that never fires on 5,199 namespaces is not necessarily wrong. It may
target a vendor absent from this convenience sample, or a namespace shape this
corpus does not contain. It is, however, unvalidated by observation: nothing in
this run distinguishes a correct rule for a rare vendor from a rule that cannot
match anything. These belong in the freshness and drift queues rather than in a
weighting change.

## What this does and does not authorize

This is the measurement, not a scoring change. No weight, prior, or threshold
was modified. A per-pattern weight derived from these rates is the obvious next
step and it is explicitly gated: under the roadmap's third priority, the
ablation decision rule must be frozen before the run that would justify
promoting it, and a convenience sample cannot support a population claim.

The measurement does support three conclusions that need no further evidence:

1. The flat weighting discards a factor-of-3,800 spread in observed prevalence
   and a 24-fold spread in information content.
2. Prevalence alone is the wrong weight. A corroboration term is required, and
   it is only meaningful for slugs with two or more detection types.
3. `merger` and `fusion` maintain two different weight models over the same
   evidence, one keyed on `(slug, type)` and one on source type alone. Any
   weighting work should reconcile them before adding a third.

## Limitations

- One private convenience sample, industry-stratified. Every rate here is an
  exact fixed-corpus descriptive value with no population interpretation and no
  design-based coverage.
- CT collection was disabled, so `cname_target`, the largest single detection
  type, is unmeasured rather than measured at zero.
- The catalog moved from 850 entries at collection to 856 at measurement.
  Patterns added after the run cannot fire and are indistinguishable from
  patterns that fired zero times.
- Corroboration uses distinct source types as the independence proxy. Two source
  types can share an upstream cause, so it bounds independence loosely.
- The run predates the related-domain enrichment fix shipped in v2.6.13, so
  email-control slugs could be attributed from a related namespace. That fix
  removes borrowed control labels and would change some `txt` corroboration
  values in a future round.

## Reproduction

```bash
python validation/pattern_base_rates.py \
  validation/runs-private/20260717-202753Z \
  --out validation/local/pattern-base-rates-20260725.json
```

Both paths are permanently ignored workspaces. The reducer is deterministic
given the same run directory and catalog.
