# Public-list calibration cross-check (preliminary, reproducible)

> **What this is, and is not.** This is a *preliminary* calibration
> cross-check against **two independent, public, reproducible** lists of
> well-known organization domains. **List A** is ~210 domains across seven
> verticals (banking, healthcare, SaaS, higher-ed, public-sector, retail,
> tech), n≈30 each. **List B** is ~175 domains across seven *different*
> sectors (automotive, consumer-internet, energy/industrial, media,
> nonprofit, telecom, travel), n≈25 each. The sector sets are disjoint by
> construction, so the two runs are independent samples, not a re-shuffle of
> one. Neither is the private-corpus tier-4 record in
> [reference-calibration.md](reference-calibration.md), and neither changes
> any dossier tier. Their value is threefold: (1) they confirm the harnesses
> run end-to-end on real data and the numbers land where the private corpus
> put them; (2) because the lists are public and reproducible, the numbers
> themselves are checkable by anyone, the reproducibility posture the
> [paper](../docs/paper-outline.md) is built around; and (3) — the point of
> running *two* — **agreement between two independently-drawn, sector-disjoint
> lists is a far stronger signal than any single list's number**, because it
> shows the result is a property of the method, not of one convenience
> sample's bias. The domain lists live outside the repository and are never
> committed (data-handling-policy.md); only these aggregates are.

Both lists are convenience samples of large, well-known organizations, so
both skew toward DMARC-mature, M365-heavy targets — within List A the
higher-ed and retail strata bring the `p=none` and Google-Workspace
diversity; within List B the automotive, media, and nonprofit strata do. Read
every number through that shared bias; a balanced or long-tail list would move
the base rates on both. n≈25–30 per stratum means per-stratum figures carry
wide Wilson intervals (the harness prints them) and the interior reliability
bins stay thin. This is a smoke-plus-signal pass, not the calibration — but
two of them agreeing is the part worth reading.

## The headline: two independent lists agree

The single most informative view is the side-by-side. If the harnesses were
fitting noise in one list, the second (disjoint sectors) would not reproduce
the numbers. It does, to within the sampling slack n≈30 buys:

| metric | List A (n≈210) | List B (n≈175) | Δ |
|---|---|---|---|
| email-policy ECE (full posterior) | 0.061 | 0.069 | 0.008 |
| email-policy base rate (enforcing) | 0.876 | 0.878 | 0.002 |
| email-policy agreement rate | 1.000 | 1.000 | 0.000 |
| `p=none` negative class populated | n=26, rate 0.000 | n=21, rate 0.000 | — |
| M365 DNS-only corroboration ECE | 0.082 | 0.105 | 0.023 |
| M365 base rate (tenant) | 0.952 | 0.942 | 0.010 |
| M365 DNS-only agreement rate | 0.933 | 0.884 | 0.049 |
| conformal mean coverage (target 0.90) | 0.986 | 1.000 | — both ≥ target |
| posture entropy reduction, overall p50 | 1.967 | 1.932 | 0.035 |

The email-policy node agrees almost exactly (ECE within 0.008, base rate
within 0.002, both at agreement 1.000, both correctly populating the
empirical-zero `p=none` bin). The tenancy node agrees a little less tightly
(ECE within 0.023, base rate within 0.010), and the place it diverges is
itself interpretable — see the M365 section. The posture median entropy
reduction lands within 0.035 nats. None of these were tuned to match; List B
was built and run after List A was already written up.

## Email-policy node vs the DMARC record (CAL3/CAL4)

Harness: `validation/reference_calibration.py --stratify-dir`. Two
constructions: the full posterior (DMARC is an input, so the populated bins
are largely a definitional agreement check) and the held-out residual (the
`dmarc_policy` unit masked, so predictor and label are disjoint — the clean
construction).

**Full posterior, pooled:**

| | List A (n=209) | List B (n=172) |
|---|---|---|
| base rate enforcing | 0.876 | 0.878 |
| log score (proper) | 0.057 | 0.067 |
| Brier | 0.0043 | 0.006 |
| ECE | 0.061 | 0.069 |
| agreement (Wilson80) | 1.000 (0.992, 1.000) | 1.000 (0.990, 1.000) |

List A reliability: `[0.00,0.10)` rate 0.000 n=26; `[0.80,0.90)` rate 1.000
n=23; `[0.90,1.00)` rate 1.000 n=160. List B reliability: `[0.00,0.10)` rate
0.000 n=21; `[0.80,0.90)` rate 1.000 n=32; `[0.90,1.00)` rate 1.000 n=119.
Both land at ECE ~0.06–0.07, consistent with (slightly better than) the
private-corpus 0.077, and — the part the enterprise-only smoke could not
produce — both populate the empirical-zero negative class: 26 and 21 domains
respectively with empirical enforcing rate 0.000, correctly predicted low.

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
(0.050–0.092), and the strata that bring label spread differ by list:
higher-ed (base 0.47) is List A's diversity source, automotive (base 0.71)
and nonprofit (base 0.83) are List B's. The node behaves the same regardless
of which sectors supply the negatives.

**Held-out residual, pooled** (the `dmarc_policy` unit masked, so the
predictor sees only strict-SPF + MTA-STS and the DMARC record is purely the
label). As designed the residual is a weak predictor that lives at ~0.45, so
judge its calibration, not its strength. List B pooled (n=172): the
`[0.40,0.50)` bin (n=168) realizes empirical enforcing rate 0.875 — i.e. the
residual is conservative (under-predicts), the same direction and almost the
same magnitude as List A's `[0.40,0.50)` bin (n=202, rate 0.871). Two
independent lists put the residual's one populated bin at 0.871 vs 0.875: the
near-prior-but-honestly-conservative behavior is a property of the
construction, reproduced. The per-stratum residual "disagreement" is highest
where the base rate is near 1.0 (the residual honestly declines to assert
enforcement from SPF/MTA-STS alone) and lowest where there is real label
spread to separate — automotive (base 0.71) is List B's informative stratum
here, as higher-ed was List A's.

## M365 tenancy vs the provider endpoints (CAL3/CAL4 tenancy extension)

Harness: `validation/tenancy_reference_calibration.py --stratify-dir`.
Predictor is the tenancy posterior from the **DNS channel alone**; label is
Microsoft's own endpoint attestation (tenant ID / namespace positive; OIDC
HTTP 400 / NameSpaceType Unknown negative) — disjoint observation channels.

**M365 DNS-only corroboration, pooled:**

| | List A (n=208) | List B (n=173) |
|---|---|---|
| base rate tenant | 0.952 | 0.942 |
| log score (proper) | 0.165 | 0.221 |
| Brier | 0.043 | 0.067 |
| ECE | 0.082 | 0.105 |
| agreement (Wilson80) | 0.933 (0.907, 0.952) | 0.884 (0.850, 0.912) |

List A reliability: `[0.20,0.30)` rate 0.611 n=18; `[0.90,1.00)` rate 0.995
n=186. List B reliability: `[0.20,0.30)` rate 0.667 n=27; `[0.30,0.40)` rate
1.000 n=1; `[0.90,1.00)` rate 0.993 n=145. The honest finding reproduces on
both: the `[0.20,0.30)` bin holds domains where the DNS-only posterior is low
but the endpoint confirms a tenant — the passive-observation ceiling made
visible, DNS alone under-claiming tenancy that the provider registry sees,
and exactly why the endpoint is a real external attestor rather than
redundant with DNS. List B simply has more of them (n=27 vs 18), which is why
its agreement rate is a touch lower (0.884 vs 0.933): List B's sector mix
(consumer-internet, media) leans toward firms whose M365 footprint is less
visible in DNS. The weakest strata are correspondingly different — List A's
was `saas` (ECE 0.243), List B's are `media` (0.274) and `consumer-internet`
(0.166) — but the *mechanism* (low-DNS-visibility M365 tenants land in the
0.2–0.3 bin) is the same on both, and the well-instrumented strata agree
tightly (List B automotive ECE 0.026, energy-industrial 0.041, travel 0.066).

**GWS one-sided check:** List A had 2 attested-federated tenants, List B had
1; recall 1.0 on both. The rest are managed Workspace, which recon's passive
Google channel cannot attest, and there is no authoritative negative. This is
exactly the one-sided shape the channel supports — reported as a recall check,
never a calibration — and the tiny n on both lists confirms why
`google_workspace_tenant` stays tier 3 regardless of how many lists we run.

## Distribution-free conformal coverage

Harness: `validation/conformal_coverage.py` (split conformal on the
email-policy node, 20 random calibration/test splits averaged).

| | List A | List B |
|---|---|---|
| n / splits | 207 / 20 | 172 / 20 |
| target coverage | 0.90 | 0.90 |
| mean coverage | 0.986 | 1.000 |
| worst-split coverage | 0.846 | 1.000 |
| mean set size | 0.986 | 1.000 |

The distribution-free guarantee holds on both lists: averaged coverage sits
at or above the 0.90 target (0.986 and 1.000), and the prediction sets are
decisive (mean size ~1.0, not abstaining to the full {enforcing, not} set).
List B's perfect coverage reflects its slightly cleaner bimodal split. The
guarantee is for typical, exchangeable targets and explicitly not for
adversarially hardened ones — the same boundary the suppression theorem names
(correlation.md 4.3), demonstrated as a falsifiability case in the harness's
unit tests.

## Posture distributions (information recovered; interval width)

Harness: `validation/posture_distributions.py`.

**Information recovered (CAL10), per-domain entropy reduction in nats:**

| bucket | List A p25/p50/p75 (n) | List B p25/p50/p75 (n) |
|---|---|---|
| overall | 1.534 / 1.967 / 2.260 (210) | 1.518 / 1.932 / 2.213 (175) |
| direct / sparse | 0.742 / 0.999 / 1.260 (17) | 0.490 / 0.742 / 0.999 (15) |
| direct / moderate | 1.417 / 1.699 / 2.004 (47) | 1.417 / 1.739 / 1.987 (38) |
| edge-proxied / moderate | 1.714 / 2.105 / 2.260 (128) | 1.811 / 1.978 / 2.217 (106) |
| edge-proxied / rich | 2.615 / 2.699 / 3.055 (8) | 2.844 / 2.859 / 2.906 (4) |

The instructive result reproduces on both lists: the **sparse evidence tier
is the hardening signal**, not the edge-proxied flag. `direct / sparse`
(little fired) leaks the least (median ~0.7–1.0 nats); `edge-proxied / rich`
leaks the most (median ~2.7–2.9). That inverts the naive "edge-proxying hides
things" hypothesis, for a reason the harness makes visible on both lists: an
*edge-proxied* domain here is one where a CDN was **detected**
(cdn_fronting posterior ≥ 0.5), and detecting a CDN is itself information — it
fires a node — so it raises entropy reduction. What hides information is the
absence of any strong signal, which the *sparse* tier captures directly. Both
overall medians (~1.93–1.97 nats) are well above the prior private-corpus pass
(~0.85), as expected for lists of large, heavily-instrumented organizations.
The honest north-star number for "what the channel leaks after hardening" is
therefore the sparse-tier figure, ~0.7–1.0 nats, not the list-wide median —
and it agrees across both lists.

**Interval width vs evidence (CAL7 diagnostic), mean 80% width by n_eff:**

| n_eff bucket | List A ungrouped (n) | List A grouped (n) | List B ungrouped (n) | List B grouped (n) |
|---|---|---|---|---|
| ceiling (≤4) | 0.451 (849) | 0.557 (162) | 0.450 (731) | 0.551 (137) |
| 5–6 | 0.177 (411) | 0.189 (461) | 0.170 (319) | 0.198 (384) |
| 7–9 | — | 0.056 (7) | — | 0.047 (4) |

Two things, both reproduced. Evidence-responsiveness: width falls sharply as
n_eff rises, on both grouped and ungrouped nodes and on both lists (≈0.45 →
0.18 ungrouped; ≈0.55 → 0.19 → 0.05 grouped). And the CAL7 correction working
as intended: grouped nodes are **not narrower** than ungrouped at matched
n_eff (slightly wider at the ceiling on both lists), i.e. the co-firing
reduction is preventing the over-confidence it was designed to prevent — the
three M365 indicators contribute one effective unit, not three, so the node
stays in a lower-n_eff (wider) bucket rather than collapsing to a falsely
tight interval. The matched-bucket widths agree across lists to within ~0.01.

## Bottom line

Run on **two independent, sector-disjoint, public, reproducible lists**, all
four harnesses run end-to-end and land where the theory predicts — and, more
to the point, they land in the *same* place on both lists:

- email-policy calibration ECE 0.061 (A) vs 0.069 (B), base rate 0.876 vs
  0.878, both at agreement 1.000, both populating the empirical-zero `p=none`
  negative class (private corpus: ECE 0.077);
- M365 tenancy corroboration ECE 0.082 (A) vs 0.105 (B), predictor (DNS) and
  label (provider endpoint) disjoint by observation channel, the same
  low-DNS-visibility 0.2–0.3 reliability bin showing up on both;
- conformal coverage 0.986 (A) and 1.000 (B), both ≥ the 0.90 target, decisive
  sets;
- posture distributions showing the sparse tier as the genuine hardening
  signal (~0.7–1.0 nats leaked) and the CAL7 grouping correction holding, with
  matched-bucket widths agreeing to ~0.01.

This is a preliminary cross-check, not the tier-4 record; the larger private
corpus run remains what the dossier tier rests on, and no tier moved on the
strength of n≈210 + n≈175. **The standing value is the agreement itself:** two
lists drawn from disjoint sectors, built and run separately, reproduce each
other's numbers — which is the evidence that the harnesses measure a property
of the method rather than of one sample's bias. That is exactly why multiple
public lists beat one private corpus for the *reproducibility* claim (anyone
can re-derive these from public records), even though the private corpus is
what carries the *tier*. The paper can therefore report a public, reproducible
calibration column with a built-in robustness check, beside the private-corpus
one.

A bug an earlier pass earned its keep: the live run caught that
`conformal_coverage` had broken when the reference collector started returning
`CalibrationPair` (the held-out residual change) — the unit tests missed it
because the network orchestration was untested. Fixed, and pinned by a
monkeypatched `main()` contract test
(`tests/test_conformal_coverage.py::TestCollectorContract`) so the
cross-harness shape can't silently drift again. The same lesson drove the
`--json` structured-output mode on both calibration harnesses (used to produce
the side-by-side tables above) to ship with its own monkeypatched `main()`
integration tests (`TestJsonMain` in both calibration test files), so the
machine-readable path that the multi-list comparison and the PV2 drift loop
depend on is covered, not just the pure functions. That is the case for
running the harnesses on real lists — plural — not just unit-testing their
parts.
