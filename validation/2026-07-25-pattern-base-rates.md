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

`raw_value` is a rendering of the observed record rather than the parsed target
the live detector matched, so each type is normalized before matching. Taking
the last whitespace field is correct for MX, SRV, and NS but corrupts the rest:
a CAA value carries a tag and an opening quote and may carry trailing
parameters, an SPF record holds many mechanisms of which the last is not
privileged, a DMARC `rua` target sits after `mailto:` and `@`, and a CNAME
rendering prefixes the owner and may chain through `->`. A `subdomain_txt`
pattern is `owner:regex`, and only the regex half is matched against the value.

An earlier revision of this measurement used the last whitespace field
everywhere, matched the whole `owner:regex` string as a regex, and tested only
`cname` rules against CNAME evidence. It understated 114 rows, reported all 13
CAA patterns and all 6 `subdomain_txt` patterns as never firing, and treated
434 `cname_target` rules as unmeasurable. The reconciliation described under
Measurable surface exists to catch that class of error.

Base-rate denominators are the observation opportunities recorded in the run's
own gap aggregate (`available + partial` namespaces per path), not the count of
namespaces that produced an attribution. Using attributions as the denominator
would condition it on a match having already happened and inflate every rate.

## Measurable surface

All 1,064 detections are measurable from this run. The surface-attribution
pipeline emits its chain matches as `CNAME` evidence whose `raw_value` carries
the full resolved chain, so a `cname_target` rule can be attributed to any hop
of that chain even though CT collection was disabled for the run. An earlier
revision of this memo recorded the 434 `cname_target` rules as unmeasurable;
that was a limitation of the reducer, not of the data.

Coverage was verified by reconciling against production's own attributions:
for every source type, the set of slugs this reducer credits is a superset of
the set production attributed in the same run, with no production-only slug
left unexplained. The only intentional excess is the four CAA issuer rules
promoted after the run.

## Result: discriminative power spans a factor of 3,800

Of the 1,064 measurable detections, 856 fired at least once and 208 never
fired across 5,199 namespaces.

Among patterns that fired, the base rate ranges from 0.000192 to 0.7294. Stated
as information content (`-log2(base rate)`), the observations recon treats as
interchangeable range from 0.5 bits to 12.3 bits.

| Information content | Patterns |
|---|---:|
| Under 2 bits (near-universal) | 10 |
| 2 to 5 bits | 123 |
| 5 to 8 bits | 224 |
| 8 bits or more (highly specific) | 499 |

The single most common pattern, `^google-site-verification=`, fired on 72.9
percent of measured namespaces and carries 0.5 bits. It currently contributes
the same TXT evidence weight as `^krisp-domain-verification=`, which fired on
0.19 percent and carries 9.0 bits.

## Result: corroboration is a sharper discriminator than prevalence

Corroboration here means the attributed slug also had evidence from a different
source type on the same namespace. It is only interpretable for slugs whose
catalog entry defines two or more detection types; for a single-type slug it is
structurally zero and says nothing. Of the 231 patterns with at least 50 fires,
105 belong to single-type slugs and are excluded from this reading.

Of the remaining 126:

- 12 corroborate on 90 percent or more of their fires.
- 42 corroborate on under 5 percent of their fires.

Prevalence and corroboration are close to independent. The Microsoft 365 apex
verification TXT prefix is common (base rate 0.512) and corroborates on 100
percent of fires. It is named descriptively here rather than quoted, because the
tracked-artifact hygiene gate treats a verification prefix followed by any value
as a token and cannot distinguish a catalog pattern from a real one.
`mail.protection.outlook.com`
(0.227) and `aspmx.l.google.com` (0.211) likewise corroborate at 1.00 and 0.95.
A common observation is not automatically a weak one.

The 42 patterns that fire often and are almost never corroborated are the
actionable set, because each one produces a service attribution that no other
observed evidence supports. The largest by volume:

| Type | Pattern | Slug | Fires | Base rate | Corroboration |
|---|---|---|---:|---:|---:|
| `txt` | `^atlassian-domain-verification=` | atlassian | 2,129 | 0.410 | 0.02 |
| `txt` | `^docusign=` | docusign | 1,434 | 0.276 | 0.00 |
| `cname` | `cloudfront.net` | aws-cloudfront | 1,065 | 0.205 | 0.00 |
| `cname_target` | `cloudfront.net` | aws-cloudfront | 1,065 | 0.205 | 0.00 |
| `cname` | `.elb.` | aws-elb | 558 | 0.107 | 0.00 |
| `dmarc_rua` | `vali.email` | valimail | 464 | 0.089 | 0.00 |
| `txt` | `^stripe-verification=` | stripe | 457 | 0.088 | 0.02 |
| `cname` | `elb.amazonaws.com` | aws-elb | 450 | 0.087 | 0.00 |
| `cname` | `fastly.net` | fastly | 370 | 0.071 | 0.00 |

Two explanations are compatible with this pattern and this measurement cannot
separate them: a verification token can persist after the service is dropped,
which the catalog descriptions already flag as stale residue, or the vendor can
issue the token broadly enough that it does not imply a deployed integration.
Neither reading is an accuracy finding. Both mean the observation is weaker than
an equally weighted corroborated one.

## Result: one fifth of firing patterns are ambiguous

184 of the 856 firing patterns matched a raw value that also matched a different
slug's pattern of the same type. The maximum was 60 competing slugs, on
`_spf.google.com`. That concentration is expected rather than alarming: many
vendors instruct customers to include Google's SPF record, so a single SPF
record legitimately names many providers at once and the value is shared
infrastructure rather than a discriminating mark. It does mean an SPF fire
should not carry the same weight as an exclusive one.

## Result: 208 measurable patterns never fired

| Type | Never fired |
|---|---:|
| `cname_target` | 81 |
| `txt` | 64 |
| `cname` | 45 |
| `spf` | 8 |
| `mx` | 4 |
| `subdomain_txt` | 3 |
| `dmarc_rua` | 2 |
| `ns` | 1 |
| `caa` | 0 |

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
  Because current patterns are re-matched against the retained raw values, a
  rule promoted after the run is evaluated retroactively rather than being
  invisible. The four CAA issuer rules promoted two hours after this run fire on
  68 to 237 namespaces here, which is a retrospective check on those promotions
  and not evidence of a live detection gap.
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
