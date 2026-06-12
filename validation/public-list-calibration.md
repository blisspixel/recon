# Public-list calibration cross-check (preliminary, reproducible)

> **What this is, and is not.** This is a *preliminary* calibration
> cross-check against a **public, reproducible** list of ~210 well-known
> organization domains across seven verticals (banking, healthcare, SaaS,
> higher-ed, public-sector, retail, tech), n≈30 each. It is **not** the
> private-corpus tier-4 record in
> [reference-calibration.md](reference-calibration.md), and it does not
> change any dossier tier. Its value is twofold: (1) it confirms the
> harnesses run end-to-end on real data and the numbers are in the same
> place as the private corpus, and (2) because the list is public and
> reproducible, the numbers themselves are checkable by anyone, which is
> exactly the reproducibility posture the [paper](../docs/paper-outline.md)
> is built around. The domain list lives outside the repository and is
> never committed (data-handling-policy.md); only these aggregates are.

The list is a convenience sample of large, well-known organizations, so it
skews toward DMARC-mature, M365-heavy targets — the higher-ed and retail
strata are what bring the `p=none` and Google-Workspace diversity. Read
every number through that bias; a balanced or long-tail list would move the
base rates. n≈30 per stratum means per-stratum figures carry wide Wilson
intervals (the harness prints them) and the interior reliability bins stay
thin. This is a smoke-plus-signal pass, not the calibration.

## Email-policy node vs the DMARC record (CAL3/CAL4)

Harness: `validation/reference_calibration.py --stratify-dir`. Two
constructions: the full posterior (DMARC is an input, so the populated bins
are largely a definitional agreement check) and the held-out residual (the
`dmarc_policy` unit masked, so predictor and label are disjoint — the clean
construction).

**Full posterior, pooled (n=209 with a published policy):**

```
base rate enforcing:  0.876
log score (proper):   0.057
Brier:                0.0043
ECE:                  0.061
agreement:            1.000  Wilson80 (0.992, 1.000)
reliability:  [0.00,0.10) rate 0.000 n 26   <- the p=none negative class
              [0.80,0.90) rate 1.000 n 23
              [0.90,1.00) rate 1.000 n 160
```

The result lands at ECE 0.061, consistent with (slightly better than) the
private-corpus 0.077, and the diverse list populates the low bin: 26 domains
with empirical enforcing rate 0.000, correctly predicted low. That negative
class is what the enterprise-only smoke could not produce — higher-ed
(base rate 0.47) carries most of it.

**Per-stratum (full posterior), ECE / agreement / base rate:**

| stratum | n | ECE | agree | base |
|---|---|---|---|---|
| banking | 30 | 0.060 | 1.000 | 1.00 |
| healthcare | 30 | 0.060 | 1.000 | 0.90 |
| higher-ed | 30 | 0.073 | 1.000 | 0.47 |
| public-sector | 29 | 0.050 | 1.000 | 0.93 |
| retail | 30 | 0.060 | 1.000 | 0.93 |
| saas | 30 | 0.063 | 1.000 | 1.00 |
| tech | 30 | 0.060 | 1.000 | 0.90 |

**Held-out residual, pooled (n=209):** the `dmarc_policy` unit masked, so
the predictor sees only strict-SPF + MTA-STS and the DMARC record is purely
the label. As designed the residual is a weak predictor (it lives at
~0.45), so judge its calibration, not its strength: in the `[0.40,0.50)`
bin (n=202) the empirical enforcing rate is 0.871, i.e. the residual is
conservative (under-predicts), the same direction as the full posterior.
The **higher-ed stratum** is the informative one — ECE 0.017, agreement
0.533 — because it is the only stratum with real label spread (base 0.47),
so the residual has both classes to separate. The all-enforcing strata
(banking, saas, base 1.00) show the residual "disagreeing" only because it
honestly declines to assert enforcement from SPF/MTA-STS alone.

## M365 tenancy vs the provider endpoints (CAL3/CAL4 tenancy extension)

Harness: `validation/tenancy_reference_calibration.py --stratify-dir`.
Predictor is the tenancy posterior from the **DNS channel alone**; label is
Microsoft's own endpoint attestation (tenant ID / namespace positive; OIDC
HTTP 400 / NameSpaceType Unknown negative) — disjoint observation channels.

**M365 DNS-only corroboration, pooled (n=208 with a provider label):**

```
base rate tenant:     0.952
log score (proper):   0.165
Brier:                0.043
ECE:                  0.082
agreement:            0.933  Wilson80 (0.907, 0.952)
reliability:  [0.20,0.30) rate 0.611 n 18   <- sparse-DNS M365 tenants
              [0.90,1.00) rate 0.995 n 186
```

The honest finding is the `[0.20,0.30)` bin: 18 domains where the DNS-only
posterior is low but the endpoint confirms a tenant. That is the
passive-observation ceiling made visible — DNS alone under-claims tenancy
that the provider registry sees — and it is precisely why the endpoint is a
real external attestor rather than redundant with DNS. The `saas` stratum
is the weakest (ECE 0.243): SaaS firms' DNS footprints indicate M365 least
cleanly.

**GWS one-sided check:** only 2 attested-federated tenants in the whole
list (the rest are managed, which recon's passive Google channel cannot
attest, and there is no authoritative negative), recall 1.0 on those two.
This is exactly the one-sided shape the channel supports — reported as a
recall check, never a calibration — and the small n confirms why
`google_workspace_tenant` stays tier 3.

## Distribution-free conformal coverage

Harness: `validation/conformal_coverage.py` (split conformal on the
email-policy node, 20 random calibration/test splits averaged).

```
n=207, 20 splits, target coverage 0.90
mean coverage:      0.986
worst-split cover:  0.846
mean set size:      0.986   (1.0 fully decisive, 2.0 always abstaining)
```

The distribution-free guarantee holds on this list: averaged coverage 0.986
sits at or above the 0.90 target, and the prediction sets are decisive (mean
size ~1.0, not abstaining to the full {enforcing, not} set). The guarantee is
for typical, exchangeable targets and explicitly not for adversarially
hardened ones — the same boundary the suppression theorem names
(correlation.md 4.3), demonstrated as a falsifiability case in the harness's
unit tests.

## Posture distributions (information recovered; interval width)

Harness: `validation/posture_distributions.py`.

**Information recovered (CAL10), per-domain entropy reduction in nats (n=210):**

| bucket | n | p25 | p50 | p75 |
|---|---|---|---|---|
| overall | 210 | 1.534 | 1.967 | 2.260 |
| direct / sparse | 17 | 0.742 | 0.999 | 1.260 |
| direct / moderate | 47 | 1.417 | 1.699 | 2.004 |
| edge-proxied / moderate | 128 | 1.714 | 2.105 | 2.260 |
| edge-proxied / rich | 8 | 2.615 | 2.699 | 3.055 |

The instructive result: the **sparse evidence tier is the hardening signal**,
not the edge-proxied flag. `direct / sparse` (little fired) leaks the least
(median ~1.0 nats); `edge-proxied / rich` leaks the most (median ~2.7). That
inverts the naive "edge-proxying hides things" hypothesis, for a good reason
the harness made visible: an *edge-proxied* domain here is one where a CDN was
**detected** (cdn_fronting posterior ≥ 0.5), and detecting a CDN is itself
information — it fires a node — so it raises entropy reduction. What hides
information is the absence of any strong signal, which the *sparse* tier
captures directly. The overall median (~2.0 nats) is well above the prior
private-corpus pass (~0.85), as expected for a list of large, heavily-
instrumented organizations. The honest north-star number for "what the channel
leaks after hardening" is therefore the sparse-tier figure, ~1.0 nats, not the
list-wide median.

**Interval width vs evidence (CAL7 diagnostic), mean 80% width by n_eff:**

| n_eff bucket | ungrouped width (n) | grouped width (n) |
|---|---|---|
| ceiling (≤4) | 0.451 (849) | 0.557 (162) |
| 5–6 | 0.177 (411) | 0.189 (461) |
| 7–9 | — | 0.056 (7) |

Two things this shows. Evidence-responsiveness: width falls sharply as n_eff
rises, on both grouped and ungrouped nodes (0.45 → 0.18 ungrouped; 0.56 →
0.19 → 0.06 grouped). And the CAL7 correction working as intended: grouped
nodes are **not narrower** than ungrouped at matched n_eff (if anything
slightly wider at the ceiling), i.e. the co-firing reduction is preventing the
over-confidence it was designed to prevent — the three M365 indicators
contribute one effective unit, not three, so the node stays in a lower-n_eff
(wider) bucket rather than collapsing to a falsely tight interval.

## Bottom line

On a public, reproducible list, all four harnesses run end-to-end and land
where the theory predicts:

- email-policy calibration ECE 0.061 (private corpus: 0.077), with the
  `p=none` negative class finally populated by the diverse list;
- M365 tenancy corroboration ECE 0.082, predictor (DNS) and label (provider
  endpoint) disjoint by observation channel;
- conformal coverage 0.986 ≥ 0.90 target, decisive sets;
- posture distributions showing the sparse tier as the genuine hardening
  signal (~1.0 nats leaked) and the CAL7 grouping correction holding.

This is a preliminary cross-check, not the tier-4 record; the larger private
corpus run (next session) remains what the dossier tier rests on, and no tier
moved on the strength of n≈210. The standing value is that these specific
numbers are re-derivable by anyone from a public list — the reproducibility
the [paper](../docs/paper-outline.md) is built around, and a candidate
second (public, reproducible) calibration column beside the private-corpus
one.

A bug this pass earned its keep: the live run caught that `conformal_coverage`
had broken when the reference collector started returning `CalibrationPair`
(the held-out residual change) — the unit tests missed it because the network
orchestration was untested. Fixed, and pinned by a monkeypatched
`main()` contract test (`tests/test_conformal_coverage.py::TestCollectorContract`)
so the cross-harness shape can't silently drift again. That is the case for
running the harnesses on a real list, not just unit-testing their parts.
