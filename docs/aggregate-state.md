# Aggregate state: local cohort summaries over recon output

> Status: methodology and reference implementation (v2.1a). This is a downstream
> sidecar, not part of recon core. recon core stays frozen, stateless, and
> single-domain; nothing here changes the locked v2.0 schema.

## 1. Scope

Aggregate state is recon's uncertainty discipline applied across a caller-owned
set of domains. A single lookup answers "what does the public channel reveal
about this domain, with provenance and honest uncertainty." A cohort summary
answers the same question over a set the caller supplies: "across this cohort,
what did the public channel reveal, how observable was it, and how uncertain are
we." It is a population lens over the per-domain output, computed live and then
discarded.

The reducer reads recon's `--json` or `--ndjson` for a batch and emits an
aggregate-only object: observability, prevalence, posterior-claim summaries,
mix concentration, and distinctive indicators per caller group. It never names a
domain in its output, stores nothing, and ships no baselines.

## 2. Non-goals

These are out of scope by design, because they break recon's invariants:

- No persistent store. The summary is computed and discarded; there is no
  SQLite, DuckDB, or accumulated vector pool. With nothing persisted, no
  differential privacy is needed.
- No shipped or accumulated industry baselines. recon never compares a cohort to
  a built-in "what fintech looks like" distribution. Any comparison is between
  two sets the caller supplies.
- No anomaly scoring against a baseline (no Mahalanobis or Z-score versus a
  shipped centroid), because there is no baseline to score against.
- No inference of unobserved services from priors. The reducer reports what was
  seen; it does not predict hidden infrastructure from cohort co-occurrence.
- No company scoring, ranking, maturity grade, or risk verdict.
- No real-company data in the public repo. Committed examples are fully
  synthetic; real groupings stay local and gitignored.

## 3. Inputs

- Per-domain recon output, as a JSON array, an NDJSON stream, or a batch
  `{"results": [...]}` wrapper. Each record carries the fields recon already
  emits: `provider`, `dmarc_policy`, `mta_sts_mode`, `email_gateway`, `slugs`,
  `cloud_instance`, `degraded_sources`, and `posterior_observations`.
- An optional caller-owned grouping file, a two-column `domain,label` CSV. The
  caller chooses the grouping (industry, portfolio, vendor set, location, type).
  This file stays local and is never committed.

## 4. The aggregate-state object

Per cohort (the global cohort, and one per caller group), the reducer reports
four blocks:

- **Observability.** Cohort size, how many domains resolved, the degraded-source
  rate, and the mean sparse share across the Bayesian nodes. This is the
  denominator story, reported first, not buried.
- **Prevalence.** For each signal, the observability-adjusted triple (below).
- **Posterior claims.** For each Bayesian node, the aggregated posterior mass and
  a separate high-confidence share (below).
- **Mix.** For provider and cloud, the share vector with its concentration
  (entropy and HHI).

Across groups, when at least two are supplied, a **distinctiveness** block ranks
the slugs most characteristic of each group versus the rest of the caller's
cohort.

## 5. Metrics

### 5.1 Observability-adjusted prevalence

recon's channel is missing-not-at-random for hideable infrastructure: a signal
can be absent because it is genuinely absent or because the target hid it. A
single "62% adoption" number hides which. So for a binary signal in a cohort of
size $N$, with $p$ positives among $m$ domains where the signal was observable,
the reducer reports three numbers and an interval, never one:

$$
\text{observed rate} = \frac{p}{m}, \qquad
\text{lower bound} = \frac{p}{N}, \qquad
\text{observability fraction} = \frac{m}{N}.
$$

The interval on the observed rate is an 80% Wilson score interval (closed form,
matching recon's 80% house style):

$$
\frac{\hat p + \frac{z^2}{2m} \pm z\sqrt{\frac{\hat p(1-\hat p)}{m} + \frac{z^2}{4m^2}}}{1 + \frac{z^2}{m}},
\qquad \hat p = \frac{p}{m}, \quad z = z_{0.9}.
$$

A Jeffreys interval from a $\mathrm{Beta}(p + \tfrac12, m - p + \tfrac12)$
posterior is the Bayesian sibling; the reference reducer uses Wilson for the
closed form.

Declarative signals (DMARC, MTA-STS) are observable whenever DNS resolved, so
their observability fraction is near one and the lower bound nearly equals the
observed rate. Hideable claims (an M365 tenant) are observable only where the
node fired with enough evidence to be non-sparse, so the observability fraction
falls below one and the gap between the observed rate and the lower bound is the
honest measure of what the channel could not see.

### 5.2 Aggregate posterior mass

For a Bayesian node, hard-thresholding each domain to yes or no and tallying
throws away the credible interval. Instead the reducer aggregates the posterior:

$$
\text{expected prevalence} = \frac{1}{N}\sum_{i=1}^{N} P_i(X), \qquad
\text{high-confidence share} = \frac{\#\{i : P_i(X) > 0.8 \text{ and not sparse}_i\}}{N}.
$$

These answer different questions. The first is "the model leans this way on
average"; the second is "this fraction had dense enough public evidence to say so
confidently." The reducer also reports the mean interval width and the sparse
share, so a cohort that is confident is distinguishable from one that is merely
not-sparse.

### 5.3 Compositional concentration

Provider and cloud shares are parts of a whole, not independent percentages, so
the reducer summarizes their shape with concentration rather than treating each
share alone. For a share vector $\mathbf{q}$ over $k$ non-empty categories:

$$
H_{\text{norm}}(\mathbf{q}) = \frac{-\sum_j q_j \log_2 q_j}{\log_2 k} \in [0, 1],
\qquad \mathrm{HHI}(\mathbf{q}) = \sum_j q_j^2 \in [0, 1].
$$

Normalized entropy near zero (and HHI near one) is a single-vendor monoculture;
high entropy (low HHI) is a fragmented best-of-breed mix.

### 5.4 Distinctive slugs

To rank which slugs are characteristic of a group versus the rest of the caller's
cohort, the reducer uses the weighted log-odds-ratio with a Dirichlet prior (the
Monroe, Colaresi, and Quinn method), which shrinks unstable rare counts so one
odd domain cannot manufacture a finding. With group slug-count $y_w$, background
count $x_w$, group total $n_y$, background total $n_x$, symmetric prior
$\alpha_w$, and $\alpha_0 = \sum_w \alpha_w$:

$$
\delta_w = \log\frac{y_w + \alpha_w}{n_y + \alpha_0 - y_w - \alpha_w}
         - \log\frac{x_w + \alpha_w}{n_x + \alpha_0 - x_w - \alpha_w}, \qquad
z_w = \frac{\delta_w}{\sqrt{1/(y_w + \alpha_w) + 1/(x_w + \alpha_w)}}.
$$

Slugs are ranked by $z_w$ and filtered by a minimum support floor.

### 5.5 Partial pooling (optional, multi-stratum only)

When the caller's batch has multiple strata, group rates can be partially pooled
toward the caller's own global, $\mathrm{logit}(\theta_j) \sim \mathcal{N}(\mu, \tau^2)$,
so a small stratum borrows strength from the caller's larger set rather than
swinging on a handful of domains. The pooling target is always the caller's own
data, never a shipped baseline. A single cohort has nothing to pool toward and
uses the Wilson interval directly. The reference reducer reports the unpooled
numbers; pooling is a documented option for callers who want it.

## 6. Statistical honesty rules

- **Cohort, not census.** The caller chose the set, so every number is "within
  this cohort," never "in this industry." The output carries this disclaimer.
- **Ecological-fallacy discipline.** Phrase findings as "within this cohort
  tagged X, among observable signals, we saw Y," never "industry X does Y." A
  group relationship does not transport to any individual member.
- **Absence is ambiguous.** The observability fraction rides next to every
  prevalence number, because absence on a hideable signal can mean hiding.
- **Small-cell suppression and the small-n warning.** Raw counts in $[1, 10]$ are
  withheld as a friction, and a cohort below 30 carries a small-n warning. The
  honest limit: a published rate over a known denominator can still imply a small
  count (observed rate times observable count recovers it), so suppression is not
  a re-identification guarantee. The small-n warning is the real disclosure
  signal: do not publish a summary of a cohort below the threshold if its
  composition is sensitive. The aggregate output never contains a domain name
  regardless.
- **Multiplicity.** When comparing many groups across many metrics, control the
  false-discovery rate (Benjamini-Hochberg) rather than reading every gap as
  real.

## 7. Privacy and publication rules

- No real apex names, no group-membership files, and no per-domain output in the
  public repo, including issues, comments, and test fixtures.
- Committed examples are fully synthetic, using Microsoft's fictional sample
  brands and fabricated numbers.
- Real groupings and real cohort results stay in gitignored local runs.

## 8. Synthetic worked example

The numbers below come from running the reference reducer on the synthetic
fixture in `validation/aggregate/` (24 fabricated domains across three illustrative
labels). Every value is invented to exercise the method; none is measured from
anyone.

Global cohort observability shows a fully resolving set with a mean sparse share
of 0.43, so roughly two in five node observations carried thin evidence.

The prevalence block shows the MNAR split clearly. The M365 tenant claim reads:

```
m365_tenant:
  observed_rate: 1.00  (interval 0.92 to 1.00)
  lower_bound_over_cohort: 0.79
  observability_fraction: 0.79
```

Every domain where the tenant was observable was M365, but it was observable for
only 79% of the cohort, so the honest lower bound is 0.79, not 1.00. The
declarative signals tell the opposite story: `dmarc_enforcing` has an
observability fraction of 1.00, so its observed rate and lower bound coincide at
0.58. The posterior-claims block confirms the missingness model: the declarative
`email_security_policy_enforcing` node has a sparse share of 0.00 (absence is
informative, never sparse), while the hideable `google_workspace_tenant` node has
a sparse share of 0.79 (mostly not determinable).

Concentration separates the groups. The fabricated fintech group is a provider
monoculture (normalized entropy 0.00, HHI 1.00); the saas group is fragmented
(normalized entropy 0.95). Distinctiveness ranks, for the fintech group,
indicators like `proofpoint`, `splunk`, and `stripe` highest by weighted
log-odds, with their supports suppressed because the group has fewer than eleven
domains.

To regenerate the fixture and the example output:

```bash
python validation/aggregate/make_synthetic_cohort.py
python validation/aggregate/aggregate_state.py \
    validation/aggregate/synthetic_cohort.ndjson \
    --group-by validation/aggregate/synthetic_groups.csv
```

## 9. Local-only workflow

```text
caller domain set + local grouping
        |
recon batch domains.txt --ndjson        (recon core, unchanged)
        |
aggregate_state.py reducer               (downstream sidecar)
        |
aggregate-only cohort object             (no domain names, no storage)
        |
private local memo or downstream dashboard
```

Public artifacts: this methodology and the synthetic example. Local artifacts:
the real grouping files and the real cohort results.

## 10. Reference implementation

`validation/aggregate/aggregate_state.py` is a pure-standard-library reducer (no
pandas, numpy, or scipy) that implements every metric above.
`validation/aggregate/make_synthetic_cohort.py` regenerates the synthetic
fixture deterministically. The reducer takes a list of recon records and returns
the aggregate object with no side effects, so it is straightforward to embed in a
caller's own local pipeline.

## 11. The in-core surface (shipped v2.1)

The thinnest possible surface ships in v2.1 as `recon batch --summary` (add
`--json` for machine output): one cohort at a time, carrying its own
`cohort_summary` record type and `schema_version` 2.1, with no grouping logic, no
baselines, and no persistence. Grouping, comparison, distinctiveness, and pooling
stay in the downstream reducer. That keeps recon core a single-domain passive
primitive and the cohort analysis a thing the operator owns.

## 12. References

The methods above are standard; these are the canonical sources, one per choice:

- Wilson, E. B. (1927). Probable inference, the law of succession, and
  statistical inference. Journal of the American Statistical Association 22(158).
  The score interval used for proportions.
- Monroe, B. L., Colaresi, M. P., and Quinn, K. M. (2008). Fightin' Words:
  Lexical Feature Selection and Evaluation for Identifying the Content of
  Political Conflict. Political Analysis 16(4). The weighted log-odds with a
  Dirichlet prior used for distinctive slugs.
- Aitchison, J. (1986). The Statistical Analysis of Compositional Data. Chapman
  and Hall. Treats provider and cloud mixes as compositional, motivating entropy,
  divergence, and log-ratios over independent percentages.
- Benjamini, Y., and Hochberg, Y. (1995). Controlling the False Discovery Rate.
  Journal of the Royal Statistical Society, Series B 57(1). Multiplicity control
  across many cohort comparisons.
- Gelman, A., and Hill, J. (2007). Data Analysis Using Regression and
  Multilevel/Hierarchical Models. Cambridge University Press. Partial pooling
  across the caller's own strata.
- Manski, C. F. (2003). Partial Identification of Probability Distributions.
  Springer. Bounded inference when the channel cannot identify the state, the
  basis for the observability lower bound and the "we cannot tell" posture.

The Bayesian-layer foundations this builds on (virtual evidence, adversarial
missingness, and the calibration-language discipline) are cited in
[docs/correlation.md](correlation.md).
