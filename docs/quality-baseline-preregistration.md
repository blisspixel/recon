# Product-quality baseline preregistration

**Status: frozen 2026-08-05, before any evaluation collection or run.**

This document fixes every choice that must be made before results are visible,
for the track 3 / v2.11.0 product-quality baseline described in
[roadmap.md](roadmap.md#3-establish-a-reproducible-product-quality-baseline)
and the
[Quality Proof execution plan](strategic-gap-audit.md#quality-proof-execution-plan).

Its purpose is narrow and its value is entirely dependent on its timing. The
decision rule below is worth something only because it was written before
anybody saw an outcome. A rule chosen after reading a result is not a decision
rule, it is a description. Amendments are governed by
[section 13](#13-amendment-policy).

## What this document freezes

| Frozen here | Section |
|---|---|
| The one primary claim family, chosen by elimination | [1](#1-primary-claim-family) |
| The operator decision under test and its emission form | [2](#2-operator-decision-under-test) |
| Four arms, pinned to code paths, with emission behavior fixed | [3](#3-arms) |
| The reference label and its disjointness argument | [4](#4-reference-label) |
| The analysis unit, clustering rule, and group integrity | [5](#5-unit-and-clustering) |
| The sampling frame and the corpus-disjointness requirement | [6](#6-sampling-frame-and-corpus-disjointness) |
| Both primary estimands | [7](#7-estimands) |
| The paired decision rule, the safety margin, and the safeguard | [8](#8-decision-rule) |
| Required sample sizes from a power analysis under the exact rule | [9](#9-power-analysis) |
| Which analyses are explicitly non-decisional | [10](#10-secondary-and-sensitivity-analyses) |

## 1. Primary claim family

**Chosen: `runtime.identity-and-tenant.v1`, narrowed to the Microsoft 365
tenancy support decision.**

This is a selection by elimination, not a preference. The
[external evidence ledger](statistical-assurance.md#external-evidence-ledger)
already grades every candidate on the one property this evaluation requires: a
two-class reference whose inputs are disjoint from the predictor.

| Candidate family | Reference status | Eligible |
|---|---|---|
| `m365_tenant` under `runtime.identity-and-tenant.v1` | Level 3 channel split: DNS-only predictor against provider endpoint attestation, with both label classes available | **Yes** |
| `google_workspace_tenant` | Level 3, but one-sided routing attestation with no authoritative negative class | No: cannot supply the reference-negative stratum |
| `email_security_policy_enforcing` | Level 3, but DMARC is the dominant predictor input; the input-disjoint residual reuses parameter-development data | No: fails predictor-input disjointness |
| Hideable IdP, gateway, CDN, hosting posteriors | Level 2, exact model computation only | No: no training-disjoint, predictor-input-disjoint two-class reference |
| Per-slug evidence strength, fingerprint slugs and signals | Level 2, deterministic rules and fixtures | No: no fitted two-class likelihood |
| Uncertainty band, CT graph partition, cohort summaries | Level 2 or lower | No: no external reference |

Every other family in the 27-family
[default claim audit](default-claim-audit.md) is either a static product
contract, a non-claim transport, or a derivation whose reference reduces to one
of the rows above. `m365_tenant` is the only remaining choice, which is a
finding worth stating plainly rather than a convenience.

A family without an independent reference reports coverage, provenance, and
disagreement diagnostics only, never precision. That restriction continues to
apply to all of the ineligible rows above.

## 2. Operator decision under test

For one material claim in a single-domain public-evidence summary: **should the
operator accept that the queried domain is served by a Microsoft 365 or Entra ID
tenant, or should that claim remain unresolved?**

The emission is binary and is the thing an operator actually acts on:

- **supported**: the arm presents the tenancy claim as observed.
- **unresolved**: the arm abstains.

This is deliberately not a probability. Three of the four arms do not produce a
frozen calibrated forecast on every eligible row, so a proper-score comparison
across arms is not identified. See [section 10](#10-secondary-and-sensitivity-analyses)
for what may still be reported and under what restriction.

The queried domain remains a public namespace coordinate throughout. A
supported tenancy emission is a statement about observable provisioning in the
public channel. It is not a claim about ownership, control, an account
operator, a corporate group, or current product use.

## 3. Arms

All four arms are computed at one frozen code revision and one frozen catalog
revision, recorded in the run manifest. Every arm receives **the same raw
snapshot** for a given domain.

| Arm | Definition | Pinned to |
|---|---|---|
| **A0 baseline** | Deterministic evidence plus explicit abstention. Emits supported only when a deterministic DNS-channel rule fires. | Catalog rules under `src/recon_tool/data/fingerprints/`, matched via `src/recon_tool/fingerprints.py` |
| A1 | Per-slug evidence strength, the Beta-shaped additive score | `compute_slug_posteriors` in `src/recon_tool/fusion.py` |
| A2 | Strongest reviewed evidence unit, the maximum absolute log-likelihood-ratio binding in each group | `_binding_llr` and the group reduction in `src/recon_tool/bayesian.py` |
| **A3 candidate** | Current Bayesian network posterior for the `m365_tenant` node | `infer` in `src/recon_tool/bayesian.py`, node `m365_tenant` in `src/recon_tool/data/bayesian_network.yaml` |

**The decision contrast is A3 minus A0.** A1 and A2 are secondary contrasts and
cannot change the primary decision ([section 10](#10-secondary-and-sensitivity-analyses)).

### Emission thresholds

Each arm uses **its shipped default emission behavior**. No threshold is fitted,
swept, or selected for this evaluation.

This is the point of the constraint. A threshold tuned on the evaluation sample
would convert the study into a search for a configuration that wins, and a
threshold tuned on development data would still require a development corpus
this evaluation has deliberately excluded ([section 6](#6-sampling-frame-and-corpus-disjointness)).
Using shipped defaults also keeps the measured object identical to what an
operator actually receives, which is the outcome the roadmap asks about.

### Channel restriction

Every arm reads **DNS-channel inputs only**. No arm may read a Microsoft
identity endpoint, because those endpoints supply the reference label
([section 4](#4-reference-label)). This restriction is a property of the
evaluation harness, not of shipped behavior, and the harness must fail closed
if an arm observes an identity-endpoint source result.

## 4. Reference label

**Label source: Microsoft provider identity endpoints, read independently of
the arms.**

| Label class | Condition |
|---|---|
| reference-positive | `GetUserRealm` returns `NameSpaceType` in {`Federated`, `Managed`}, or OIDC discovery resolves a tenant for the domain |
| reference-negative | `GetUserRealm` returns a non-tenant `NameSpaceType` **and** OIDC discovery returns `invalid_tenant` |
| ineligible | The two endpoints disagree, either endpoint is unavailable, or either answer is malformed |

Ineligible rows are excluded before analysis and their count is reported. An
excluded row may not be reclassified after any arm output is read.

The label channel produces clean two-class answers in practice. Both classes
were observed live on 2026-08-05 against reserved domains: `example.com`
returned `NameSpaceType: Federated` with an OIDC tenant, and `example.org`
returned `NameSpaceType: Unknown` with OIDC `AADSTS90002: Tenant not found`.

### Disjointness and its limit

Predictor inputs and label inputs are disjoint **by construction**: the arms see
the DNS channel, the label sees the identity channel, and
[section 3](#3-arms) makes that a fail-closed property of the harness.

The limit is named and is not removed by this design. Both channels depend on
the upstream common cause of the domain being provisioned in Microsoft 365 or
Entra ID. Per the
[M365 tenancy corroboration decision](m365-tenancy-decision.md), results from
this construction must be described as **channel-split corroboration with a
shared tenant-provisioning common-cause caveat**. The following wording is
prohibited in any output of this evaluation:

- "independent calibration" or "independently calibrated"
- "clean independent reference"
- any level 4 language from
  [statistical-assurance.md](statistical-assurance.md)

## 5. Unit and clustering

- One frozen `(domain, claim_family, observation_time)` row per unique domain.
- At most one domain from each known administrative, ownership, or tenant
  cluster enters the primary analysis. This keeps the row identical to the
  Bernoulli unit assumed by the paired rule in [section 8](#8-decision-rule).
- Domain groups stay intact across any parameter-development and evaluation
  split. A group is never split across roles.
- Unknown cross-domain dependence remains a stated limitation. No analysis in
  this document repairs it.
- Repeated observations of the same domain belong only to a separate
  longitudinal sensitivity analysis clustered by domain, and are non-decisional.

## 6. Sampling frame and corpus disjointness

**The evaluation sample is drawn entirely outside the existing 5,241-domain
calibration corpus.**

The corpus is excluded whole rather than adjudicated in parts. 3,296 of its
domains supplied the 2026-06-28 M365 development aggregate recorded in the
evidence ledger, which makes those rows development data by the roadmap's own
definition. Rather than argue about which of the remaining domains stayed clean
of every likelihood and weight, the frame excludes all of them. That is the only
stance that needs no case-by-case defense, and the cost is bounded because the
required sample is a few hundred domains ([section 9](#9-power-analysis)).

Two facts that support but do not license reuse:

- The `m365_tenant` prior is hand-set at 0.30 and was deliberately **not**
  grounded on the corpus, precisely because the corpus is enterprise-skewed by
  construction. See the CAL12 priors ledger in
  [bayesian-cpt-discipline.md](bayesian-cpt-discipline.md#the-priors-ledger-cal12).
- The one corpus-grounded prior, `email_security_policy_enforcing` at 0.62,
  belongs to a family already ruled ineligible in
  [section 1](#1-primary-claim-family).

Neither fact makes the 2026-06-28 diagnostic rows eligible as primary rows.

### Frame declaration required before collection

The following must be written down and committed **before any domain is
collected**, and the evaluation is void without them:

1. The target population and the eligibility window.
2. The positive-stratum and negative-stratum sampling frames.
3. The sampling mechanism and the known inclusion probability for each stratum.

### Stratification consequence

Reaching the required negative-stratum size ([section 9](#9-power-analysis))
against a population where Microsoft 365 provisioning is common requires
sampling the two strata at **different rates**. That has a hard consequence
which is frozen here:

Pooled abstention, pooled emission rate, selective risk, reliability, and any
proper-score risk are **not population rates** without frozen design or
post-stratification weights. Absent those weights, only stratum-specific or
fixed-sample descriptive values may be reported, and no population rate or
calibration claim may be made from them. The primary estimands in
[section 7](#7-estimands) are defined per stratum precisely so that they are
unaffected by the stratified label mix.

## 7. Estimands

Both are defined within a label stratum, and both are reported as
candidate minus baseline, that is A3 minus A0.

**Primary benefit: reference-positive support rate.**

$$\text{benefit} = \frac{\#\{\text{reference-positive units emitted as supported}\}}{\#\{\text{reference-positive units}\}}$$

Candidate minus baseline is positive when the candidate supports more true
claims.

**Primary safety: reference-negative unsupported-emission rate.**

$$\text{safety} = \frac{\#\{\text{reference-negative units emitted as supported}\}}{\#\{\text{reference-negative units}\}}$$

Candidate minus baseline is positive when the candidate causes more unsupported
emissions. The denominator is the negative stratum, which is what stops this
metric from moving when the label mix is intentionally stratified.

Selective risk, unsupported emissions divided by all supported emissions, is
also reported, but it is **not** a gate: it is unstable and undefined for an arm
that emits nothing.

## 8. Decision rule

Within each label stratum, count over unique domains $n$:

- $b$ = candidate-only supported decisions, where A3 supports and A0 does not
- $c$ = baseline-only supported decisions, where A0 supports and A3 does not

Construct a conservative one-sided 95 percent bound on $(b - c)/n$ by combining
Bonferroni-adjusted one-sided Clopper-Pearson bounds for the two discordance
proportions, at $\alpha = 0.05/2$ each:

$$\text{benefit lower} = \text{CP}_{\text{lower}}(b_{\text{pos}}, n_{\text{pos}}) - \text{CP}_{\text{upper}}(c_{\text{pos}}, n_{\text{pos}})$$

$$\text{safety upper} = \text{CP}_{\text{upper}}(b_{\text{neg}}, n_{\text{neg}}) - \text{CP}_{\text{lower}}(c_{\text{neg}}, n_{\text{neg}})$$

This construction is chosen over a percentile bootstrap because it stays valid
at zero discordance. A bootstrap can collapse to a false $[0, 0]$ safety
conclusion exactly at the boundary case that matters most.

### Safety margin

$$\delta = 0.02$$

Justification, fixed before any run:

- $\delta = 0$ is prohibited. It would be strict safety superiority rather than
  noninferiority, and it is unreachable under the boundary case.
- $\delta = 0.05$ is reachable with only 72 negative units but tolerates up to
  five added unsupported emissions per hundred reference-negative domains. For a
  tool whose stated product boundary is hedged observation with explicit
  abstention, that is too permissive to defend.
- $\delta = 0.01$ would require 368 reference-negative units
  ([section 9](#9-power-analysis)), which is a materially larger collection for
  a marginal gain in strictness.
- $\delta = 0.02$ requires 183 reference-negative units, which is achievable,
  and it caps the tolerated added unsupported-emission rate at two per hundred.

Note what $\delta$ is actually doing. Because the zero-regression safeguard
below admits **no** added unsupported emission on the evaluation sample,
$\delta$ bounds sampling uncertainty rather than licensing real regressions.

### Promotion rule

The candidate is promoted only if **all three** hold:

1. $\text{benefit lower} > 0$
2. $\text{safety upper} < \delta$
3. $b_{\text{negative}} = 0$, the empirical zero-regression safeguard: the
   candidate may not introduce an unsupported emission on any reference-negative
   domain that the baseline left unresolved.

Conditions 1 and 2 are co-primary, which makes this an intersection-union
decision. Any additional arm or family claim requires a predeclared
multiplicity procedure, which this document does not provide and which
therefore may not be added later.

### Outcome handling

- **Promoted**: fusion stays in the primary path.
- **Not promoted, for any reason including inconclusive**: fusion moves to an
  explicitly advanced diagnostic. An inconclusive result stays inconclusive. It
  is not re-analyzed until it resolves.
- A negative result is useful evidence and is published as such. It is not a
  reason to adjust this decision rule.

## 9. Power analysis

Run under the exact paired rule above, with exact Clopper-Pearson bounds
computed by binomial-CDF bisection. The roadmap requires this analysis and
states that its own minimum-evidence floor "is not a power claim." That warning
is correct, and the numbers show the floor is far from sufficient.

Every table below is reproduced by:

```bash
uv run python validation/quality_power_analysis.py
```

### The roadmap floor cannot certify a strict margin

With a **perfect** negative-stratum record, $b_{\text{neg}} = 0$ and
$c_{\text{neg}} = 0$:

| $n_{\text{neg}}$ | Achievable safety upper bound |
|---:|---:|
| 30 | 0.1157 |
| 50 | 0.0711 |
| 100 | 0.0362 |
| **183** | **0.0200** |
| 200 | 0.0183 |
| 300 | 0.0122 |
| 500 | 0.0074 |

At the roadmap's floor of 30 reference-negative units, the tightest safety
statement obtainable even with a flawless result is $\delta \approx 0.12$. Any
margin below that is unreachable at $n = 30$ regardless of how the candidate
performs.

### Required reference-negative size by margin

Given the $b_{\text{negative}} = 0$ safeguard:

| $\delta$ | $c_{\text{neg}} = 0$ | $c_{\text{neg}} = 1\%$ | $c_{\text{neg}} = 5\%$ |
|---:|---:|---:|---:|
| 0.01 | 368 | 305 | 131 |
| **0.02** | **183** | 171 | 99 |
| 0.03 | 122 | 121 | 84 |
| 0.05 | 72 | 72 | 59 |
| 0.10 | 36 | 36 | 33 |

### Required reference-positive size by discordance

| $b$ rate | $c$ rate | Net effect | Minimum $n_{\text{pos}}$ |
|---:|---:|---:|---:|
| 0.20 | 0.05 | +0.15 | 83 |
| 0.10 | 0.00 | +0.10 | 86 |
| 0.15 | 0.05 | +0.10 | 144 |
| **0.10** | **0.02** | **+0.08** | **155** |
| 0.05 | 0.00 | +0.05 | 171 |
| 0.05 | 0.01 | +0.04 | 310 |

At $n_{\text{pos}} = 30$ the candidate must win on at least 9 of 30
reference-positive domains with zero losses merely to clear zero. Requiring a
30 percent raw discordance with a flawless record is not a realistic
detection target.

### Frozen minimum sample

$$n_{\text{pos}} \ge 155, \qquad n_{\text{neg}} \ge 183$$

Roughly 340 independently labeled unique domains after cluster exclusion and
ineligible-row removal, against the roadmap's nominal 100 total with 30 and 30.
The larger figure is what the selected margin and plausible discordance
actually cost.

If collection cannot reach $n_{\text{neg}} = 183$, the permitted response is to
**raise $\delta$ to the value the achieved sample supports and record that
change here before unblinding**, not to run the decision at an unsupported
margin.

## 10. Secondary and sensitivity analyses

All of the following are reported and **none of them can change the primary
decision**:

- The A1 and A2 contrasts against A0.
- Abstention rate, overall emission rate, and coverage.
- Provenance completeness and classified versus unclassified observable surface.
- Latency and peak allocation.
- Tie-preserving reliability diagnostics.
- A paired domain bootstrap, permitted only under simple exchangeable sampling
  within label strata, resampling the two strata separately, applying the same
  sampled units to every arm, and preserving both denominators. Under any
  complex probability design it must reproduce the frozen strata, primary
  sampling units, and inclusion weights, or be labeled a fixed-sample
  sensitivity with no design-based coverage interpretation.
- A longitudinal analysis over repeated observations, clustered by domain.

Brier and log score are reported **only** for an arm whose total frozen forecast
is explicitly interpreted as $P(\text{reference-positive} \mid \text{frozen inputs})$
on every eligible two-class row under a predeclared abstention convention. A1
and A2 produce arbitrary evidence-strength scores and are therefore excluded
from proper-score comparison unless a development-disjoint fitted probability
mapping is frozen first, which this evaluation does not do.

Neither a bootstrap nor a longitudinal analysis can rescue an inconclusive
primary result.

## 11. Stop rules

- Do not expand graph or probabilistic machinery without measured benefit to a
  named user outcome.
- Do not tune any threshold, prior, weight, or catalog rule after reading any
  evaluation output.
- Do not reinterpret a negative result. Retire complexity that cannot beat the
  simpler comparator on a named outcome.
- A corpus missing either primary label stratum is ineligible for the decision
  gate.
- Selective risk computed on fewer than 30 supported-emission unique domains is
  descriptive only.

## 12. Disclosure controls

The evaluation runs maintainer-local against a private frame. Only aggregates
leave that boundary.

Never committed: real apex domains, organization names, tenant IDs, per-domain
rows, unsuppressed small strata, or any list that would reconstruct the frame.

Committed: the dated aggregate memo, raw paired counts $b$, $c$, $n$ per
stratum, the computed bounds, ineligible-row counts, the code and catalog
revision digests, the environment description, and the reproduction command.

This matches the existing data-handling boundary in
[data-handling-policy.md](data-handling-policy.md) and the aggregate-only rule
enforced by `scripts/check_validation_hygiene.py`.

## 13. Amendment policy

Any change to this document after the frozen date at the top must be recorded
below with its date and rationale.

A change made **after any evaluation output has been read** invalidates the
primary decision for that run. The permitted response is to record the change,
discard the run as non-decisional, and collect a fresh sample.

The single exception is the margin adjustment described at the end of
[section 9](#9-power-analysis), which must be recorded before unblinding.

| Date | Change | Rationale | Made before unblinding |
|---|---|---|---|
| 2026-08-05 | Initial freeze | Preregistration created before any collection or run | Yes |
