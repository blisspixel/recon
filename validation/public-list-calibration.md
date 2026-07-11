# Public-list calibration cross-check (preliminary, reproducible)

> **What this is, and is not.** This is a *preliminary* diagnostic
> cross-check against **three separately assembled, public, reproducible** lists of
> well-known organization domains. **List A** is ~210 domains across seven
> verticals (banking, healthcare, SaaS, higher-ed, public-sector, retail,
> tech), n≈30 each. **List B** is ~175 domains across seven *different*
> sectors (automotive, consumer-internet, energy/industrial, media,
> nonprofit, telecom, travel), n≈25 each. **List C** is ~190 domains across
> eight further sectors (pharma/biotech, semiconductors, airlines,
> hospitality, insurance, logistics, space/government, international tech),
> n≈24 each. The reported sector labels are disjoint by construction, but the
> domains are convenience samples chosen through related processes. These are
> not independent random samples. Together they contain about 575 domains across
> 22 non-overlapping reported sectors. Their value is threefold: (1) they confirm the harnesses
> run end-to-end on real data and the numbers land where the private corpus
> put them; (2) because the lists are public and reproducible, the numbers
> themselves are checkable by anyone, the reproducibility posture the
> [paper](../docs/paper-outline.md) is built around; and (3) similarity across
> separately assembled sector sets provides selected-list corroboration. That
> similarity does not establish a method-level population property or remove
> shared selection bias. The domain lists live outside the repository and are never
> committed (data-handling-policy.md); only these aggregates are.

All three lists are convenience samples of large, well-known organizations, so
all skew toward DMARC-mature, M365-heavy targets  -  within List A the higher-ed
and retail strata bring the `p=none` and Google-Workspace diversity; within
List B the automotive, media, and nonprofit strata do; within List C the
pharma, semiconductor, and space/government strata do. Read every number
through that shared bias; a balanced or long-tail list would move the base
rates on all three. n≈24-30 per stratum means the naive iid Wilson diagnostic
ranges are wide and the interior reliability bins
stay thin. This is a smoke-plus-signal pass, not a population calibration
study. The cross-list similarity is descriptive corroboration.

The recorded email-policy runs used the historical publisher-conditional label
cohort: domains without a published DMARC policy were excluded even after a
successful lookup. The current harness labels successfully observed no-record
as 0 and excludes collection failures. These values are preserved as historical
diagnostics; a current rerun uses a broader cohort and is not directly
comparable without reconstructing the former selection rule.

## The headline: three selected lists have similar diagnostics

The side-by-side view shows whether the reported aggregates are sensitive to
these three selected sector mixes. It does not estimate the behavior of an
unsampled population or supply independent replication:

| metric | List A (n≈210) | List B (n≈175) | List C (n≈190) | spread |
|---|---|---|---|---|
| email-policy ECE (full posterior) | 0.061 | 0.069 | 0.068 | 0.008 |
| email-policy base rate (enforcing) | 0.876 | 0.878 | 0.832 | 0.046 |
| email-policy agreement rate | 1.000 | 1.000 | 1.000 | 0.000 |
| `p=none` negative class populated | yes | yes | yes |  -  |
| M365 DNS-only corroboration ECE | 0.082 | 0.105 | 0.046 | 0.059 |
| M365 base rate (tenant) | 0.952 | 0.942 | 0.936 | 0.016 |
| M365 DNS-only agreement rate | 0.933 | 0.884 | 0.947 | 0.063 |
| conformal mean empirical label-inclusion across re-splits | 0.986 | 1.000 | 1.000 | 0.014 |
| summed marginal entropy change, overall p50 | 1.967 | 1.932 | 1.846 | 0.121 |

The selected lists produce email-policy ECE values within 0.008 and M365 ECE
values within 0.059. The email-policy comparison substantially reuses the DMARC
label as an input, and the M365 channels share tenant provisioning, so this is
aggregate robustness evidence rather than independent calibration. Differences
in list composition are not causal explanations. The summed marginal entropy
diagnostic lies within 0.12 nats across lists but is partly construction-driven.

### Descriptive pool across all 22 reported sectors (n≈575)

Treating the three lists as one selected comparison set across 22 reported
sectors gives a pooled descriptive figure. Every stratum clears the
n≥10 reporting gate, so nothing is suppressed:

| pooled metric (22 strata) | value |
|---|---|
| email-policy ECE (full posterior) | 0.066 (n=565) |
| email-policy agreement (naive-iid Wilson range80) | 1.000 (0.997, 1.000) |
| email-policy Brier / log-score | 0.005 / 0.063 |
| per-stratum ECE range | 0.050 - 0.092 |
| M365 DNS-only corroboration ECE | 0.076 (n=568) |
| M365 DNS-only agreement (naive-iid Wilson range80) | 0.921 (0.905, 0.934) |
| M365 base rate (tenant) | 0.944 |
| GWS one-sided recall | 0.8 (n=5 attested) |

The selected pool reports email-policy ECE 0.066 over 565 domains and a
threshold-agreement naive-iid Wilson diagnostic range of 0.997 to 1.000. This
range has no population-coverage interpretation for the selected rows. Because DMARC defines
the label and is also the dominant input, this is overlapping corroboration.
The M365 DNS-only comparison reports ECE 0.076 and agreement 0.921 over 568
domains. Its DNS predictor and provider label use different observation
channels, but both arise from tenant provisioning. These are reproducible
descriptive metrics for the selected pool, not population calibration.

## Email-policy node vs the DMARC record (CAL3/CAL4)

Harness: `validation/reference_calibration.py --stratify-dir`. Two
constructions: the full score (DMARC is an input, so the populated bins
are largely a definitional agreement check) and the held-out residual (the
`dmarc_policy` unit masked, so predictor and label are disjoint inside recon's
computation). The residual evaluation does not establish statistically
independent observations or remove selection bias.

**Full posterior, pooled:**

| | List A (n=209) | List B (n=172) | List C (n=184) |
|---|---|---|---|
| base rate enforcing | 0.876 | 0.878 | 0.832 |
| log score (proper) | 0.057 | 0.067 | 0.067 |
| Brier | 0.0043 | 0.006 | 0.006 |
| ECE | 0.061 | 0.069 | 0.068 |
| agreement (naive-iid Wilson range80) | 1.000 (0.992, 1.000) | 1.000 (0.990, 1.000) | 1.000 (0.991, 1.000) |

List A reliability: `[0.00,0.10)` rate 0.000 n=26; `[0.80,0.90)` rate 1.000
n=23; `[0.90,1.00)` rate 1.000 n=160. List B reliability: `[0.00,0.10)` rate
0.000 n=21; `[0.80,0.90)` rate 1.000 n=32; `[0.90,1.00)` rate 1.000 n=119.
List C reliability: `[0.00,0.10)` rate 0.000 n=31; `[0.80,0.90)` rate 1.000
n=33; `[0.90,1.00)` rate 1.000 n=120. All three land at ECE ~0.06-0.07,
consistent with (slightly better than) the private-corpus 0.077, and  -  the
part the enterprise-only smoke could not produce  -  all populate the
empirical-zero negative class (26 / 21 / 31 domains with empirical enforcing
rate 0.000, correctly predicted low). List C's larger negative class (n=31, the
pharma / semiconductor / space-gov mix) leaves its ECE unchanged.

**Per-stratum (full posterior), ECE / agreement / base rate:**

| List A stratum | n | ECE | agree | base | | List B stratum | n | ECE | agree | base |
|---|---|---|---|---|---|---|---|---|---|---|
| banking | 30 | 0.060 | 1.000 | 1.00 | | automotive | 24 | 0.067 | 1.000 | 0.71 |
| healthcare | 30 | 0.060 | 1.000 | 0.90 | | consumer-internet | 25 | 0.066 | 1.000 | 1.00 |
| higher-ed | 30 | 0.073 | 1.000 | 0.47 | | energy-industrial | 24 | 0.058 | 1.000 | 0.92 |
| public-sector | 29 | 0.050 | 1.000 | 0.93 | | media | 25 | 0.066 | 1.000 | 0.88 |
| retail | 30 | 0.060 | 1.000 | 0.93 | | nonprofit | 24 | 0.092 | 1.000 | 0.83 |
| saas | 30 | 0.063 | 1.000 | 1.00 | | telecom | 25 | 0.066 | 1.000 | 0.88 |
| tech | 30 | 0.060 | 1.000 | 0.90 | | travel | 25 | 0.066 | 1.000 | 0.92 |

The per-stratum ECE is remarkably flat across fourteen strata from two lists
(0.050-0.092), and the strata that bring label spread differ by list:
higher-ed (base 0.47) is List A's diversity source, automotive (base 0.71)
and nonprofit (base 0.83) are List B's. The node behaves the same regardless
of which sectors supply the negatives.

**Predictor-disjoint residual, descriptively pooled** (the `dmarc_policy` unit
masked, so the predictor sees only strict-SPF + MTA-STS and the DMARC record is
used only as the label inside the harness). As designed the residual is a weak
predictor that lives at ~0.45. List B pooled (n=172): the
`[0.40,0.50)` bin (n=168) realizes empirical enforcing rate 0.875  -  i.e. the
residual under-predicts the selected-list enforcing rate, in the same direction
and almost the same magnitude as List A's `[0.40,0.50)` bin (n=202, rate 0.871).
Two separately assembled lists put the residual's populated bin at 0.871 versus
0.875. That is descriptive corroboration, not an independence or population
claim. The per-stratum residual "disagreement" is highest
where the base rate is near 1.0 (the residual honestly declines to assert
enforcement from SPF/MTA-STS alone) and lowest where there is real label
spread to separate  -  automotive (base 0.71) is List B's informative stratum
here, as higher-ed was List A's.

## M365 tenancy vs the provider endpoints (CAL3/CAL4 tenancy extension)

Harness: `validation/tenancy_reference_calibration.py --stratify-dir`.
Predictor is the tenancy posterior from the **DNS channel alone**; label is
Microsoft's own endpoint attestation (tenant ID / namespace positive; OIDC
HTTP 400 / NameSpaceType Unknown negative)  -  disjoint observation channels.

**M365 DNS-only corroboration, pooled:**

| | List A (n=208) | List B (n=173) | List C (n=187) |
|---|---|---|---|
| base rate tenant | 0.952 | 0.942 | 0.936 |
| log score (proper) | 0.165 | 0.221 | 0.166 |
| Brier | 0.043 | 0.067 | 0.041 |
| ECE | 0.082 | 0.105 | 0.046 |
| agreement (naive-iid Wilson range80) | 0.933 (0.907, 0.952) | 0.884 (0.850, 0.912) | 0.947 (0.921, 0.964) |

List A reliability: `[0.20,0.30)` rate 0.611 n=18; `[0.90,1.00)` rate 0.995
n=186. List B reliability: `[0.20,0.30)` rate 0.667 n=27; `[0.30,0.40)` rate
1.000 n=1; `[0.90,1.00)` rate 0.993 n=145. The honest finding reproduces on
both: the `[0.20,0.30)` bin holds domains where the DNS-only model score is low
but the endpoint attests a tenant. This demonstrates disagreement between two
related observation channels, not a calibrated false-negative rate. List B has
more such rows (n=27 vs 18), which lowers its threshold agreement. The data do
not identify a causal sector explanation. The weakest strata are correspondingly different:
was `saas` (ECE 0.243), List B's are `media` (0.274) and `consumer-internet`
(0.166)  -  but the *mechanism* (low-DNS-visibility M365 tenants land in the
0.2-0.3 bin) is the same on both, and the well-instrumented strata agree
tightly (List B automotive ECE 0.026, energy-industrial 0.041, travel 0.066).

**GWS one-sided check:** List A had 2 attested-federated tenants, List B had
1; recall 1.0 on both. The rest are managed Workspace, which recon's passive
Google channel cannot attest, and there is no authoritative negative. This is
exactly the one-sided shape the channel supports  -  reported as a recall check,
never a calibration  -  and the tiny n on both lists confirms why
`google_workspace_tenant` stays tier 3 regardless of how many lists we run.

## Conformal re-split diagnostics

Harness: `validation/conformal_coverage.py` (split conformal on the
DMARC-overlapping email-policy score, with 20 dependent re-splits of each
selected list).

| | List A | List B | List C |
|---|---|---|---|
| n / splits | 207 / 20 | 172 / 20 | 184 / 20 |
| nominal 1-alpha reference | 0.90 | 0.90 | 0.90 |
| mean empirical label-inclusion across re-splits | 0.986 | 1.000 | 1.000 |
| minimum empirical label-inclusion across re-splits | 0.846 | 1.000 | 1.000 |
| mean singleton-set rate | not recorded | not recorded | not recorded |
| mean multi-label-set rate | not recorded | not recorded | not recorded |
| mean empty-set rate | not recorded | not recorded | not recorded |
| mean set size (legacy diagnostic) | 0.986 | 1.000 | 1.000 |

The recorded label-inclusion means are descriptive averages over dependent re-splits
of each same selected list. They are not independent repetitions, and neither
the mean nor the observed minimum is a coverage guarantee. The pure rank-
quantile helper has the standard theorem only for a scorer fixed independently
of calibration and exchangeable future data. Scorer-development disjointness is
not established for this experiment, so no future-point coverage theorem is
claimed. The full score also consumes the DMARC declaration used as the label,
so these results are overlap-aware diagnostics.

The legacy run recorded only mean set size. Mean set size cannot distinguish
singleton calls from a mixture of multi-label and empty sets, so no decisiveness
claim follows from these values. The harness now reports singleton, multi-label,
and empty-set rates separately; a future live rerun is required to populate
them. A deliberately shifted unit-test split demonstrates failure outside the
exchangeability condition. None of these results validates recon's
model-relative uncertainty band.

## Posture distributions (signed entropy change; uncertainty-band width)

Harness: `validation/posture_distributions.py`.

**Summed signed marginal entropy change, per domain in nats:**

| bucket | List A p25/p50/p75 (n) | List B p25/p50/p75 (n) | List C p25/p50/p75 (n) |
|---|---|---|---|
| overall | 1.534 / 1.967 / 2.260 (210) | 1.518 / 1.932 / 2.213 (175) | 1.518 / 1.846 / 2.179 (192) |
| direct / sparse | 0.742 / 0.999 / 1.260 (17) | 0.490 / 0.742 / 0.999 (15) | 0.450 / 0.721 / 0.999 (20) |
| direct / moderate | 1.417 / 1.699 / 2.004 (47) | 1.417 / 1.739 / 1.987 (38) | 1.301 / 1.653 / 1.923 (41) |
| edge-proxied / moderate | 1.714 / 2.105 / 2.260 (128) | 1.811 / 1.978 / 2.217 (106) | 1.809 / 1.977 / 2.226 (116) |
| edge-proxied / rich | 2.615 / 2.699 / 3.055 (8) | 2.844 / 2.859 / 2.906 (4) | 2.647 / 2.733 / 2.825 (4) |

The same descriptive association appears in all three lists: `direct / sparse`
has the lowest median signed marginal entropy change and `edge-proxied / rich`
the highest. The posture labels are themselves derived from model outputs and
evidence counts, so this is partly construction-driven. The sum can double count
dependent nodes and is not information recovered from the world. It does not
identify hardening, causal leakage, or a security posture effect.

**Uncertainty-band width versus display mass, mean 80% width:**

| n_eff bucket | A ungrouped | A grouped | B ungrouped | B grouped | C ungrouped | C grouped |
|---|---|---|---|---|---|---|
| floor (≤4) | 0.451 | 0.557 | 0.450 | 0.551 | 0.454 | 0.547 |
| 5-6 | 0.177 | 0.189 | 0.170 | 0.198 | 0.177 | 0.191 |
| 7-9 |  -  | 0.056 |  -  | 0.047 |  -  | 0.047 |

Mean observed width falls as `n_eff` rises in these samples. For a fixed
posterior that follows from the construction; across rows the posterior also
changes, so this is not a general monotonicity theorem. Group reduction keeps
the three M365 indicators at one counted unit, but matched-bucket width alone
cannot prove conservative coverage or independence. The descriptive means
agree across the lists to about 0.01.

## Bottom line

Run on three public, separately assembled lists, about 575 domains across 22
reported sectors, all four harnesses execute end to end and produce broadly
similar aggregate diagnostics:

- email-policy DMARC-overlapping ECE 0.061 / 0.069 / 0.068 (A/B/C), all at agreement
  1.000, all populating the empirical-zero `p=none` negative class even as the
  base rate ranges 0.832-0.878 across the sector mixes (private corpus: ECE
  0.077);
- M365 tenancy corroboration ECE 0.082 / 0.105 / 0.046, predictor (DNS) and
  label (provider endpoint) disjoint by observation channel, the same
  low-DNS-visibility 0.2-0.3 reliability bin showing up on all three;
- conformal empirical label-inclusion averaged 0.986 / 1.000 / 1.000 across
  dependent re-splits; legacy runs did not record the set-composition rates
  needed to characterize singleton, multi-label, and empty outputs;
- posture diagnostics showing lower signed marginal entropy change in sparse
  buckets and matched-bucket band widths agreeing across lists to about 0.01.

This is a preliminary cross-check. The standing value is reproducibility of the
harness and rough aggregate agreement across these selected lists. Similarity
does not remove selection bias, make the lists independent random samples, or
validate model probabilities. Public lists remain robustness checks, not
population estimates or independent calibration.

A bug an earlier pass earned its keep: the live run caught that
`conformal_coverage` had broken when the reference collector started returning
`CalibrationPair` (the held-out residual change)  -  the unit tests missed it
because the network orchestration was untested. Fixed, and pinned by a
monkeypatched `main()` contract test
(`tests/test_conformal_coverage.py::TestCollectorContract`) so the
cross-harness shape can't silently drift again. The same lesson drove the
`--json` structured-output mode on both calibration harnesses (used to produce
the side-by-side tables above) to ship with its own monkeypatched `main()`
integration tests (`TestJsonMain` in both calibration test files), so the
machine-readable path that the multi-list comparison and the PV2 drift loop
depend on is covered, not just the pure functions. That is the case for
running the harnesses on real lists  -  plural  -  not just unit-testing their
parts.
