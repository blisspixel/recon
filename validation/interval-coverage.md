# Uncertainty-band perturbation experiment (2026-06)

Interpretation corrected 2026-07-10. The recorded measurements are unchanged.

Harness: `validation/interval_coverage.py`. CI gate:
`tests/test_interval_coverage.py`. Synthetic-only, offline, fixed-seed, and free
to run.

## Question

The shipped `interval_low` and `interval_high` values are an 80 percent
evidence-responsive uncertainty band centered on the committed Bayesian model's
posterior. For posterior `p` and hand-set effective display mass `n_eff`, the
post-inference display uses `alpha = p * n_eff` and
`beta = (1 - p) * n_eff`. When both parameters are at least one, it uses central
80 percent Beta quantiles if they contain `p`; otherwise it uses a clamped
mean-centered normal approximation. This mixed rule ensures the reported mean
stays in the displayed band.

This experiment asks one finite sensitivity question:

> Under selected multiplicative perturbations of the evidence likelihoods, how
> often does the shipped model's band contain the perturbed model's conditional
> probability?

This is scenario containment. It is not:

- Bayesian credible interval coverage;
- frequentist confidence interval coverage;
- empirical coverage against real-world truth;
- a bound over all CPT, prior, dependence, or missingness uncertainty;
- evidence that the 80 percent nominal width has a calibrated interpretation.

## Method

For each perturbation level `delta`:

1. Copy the shipped network.
2. Scale each evidence likelihood and declarative `group_absence` value by an
   independently sampled factor in `[1 - delta, 1 + delta]`, clipped to the open
   unit interval.
3. Sample synthetic states and observations from each perturbed network.
4. Run the shipped model on those observations.
5. Compute the perturbed network's conditional probability through the separate
   full-joint reference implementation.
6. Record whether the shipped uncertainty band contains that conditional.

At `delta = 0`, the perturbed world equals the shipped model, so total
containment is a construction sanity check. It is not validation evidence.

The harness also reports a fully observed Bernoulli diagnostic in which every
binding's fired or non-fired outcome is observed and every non-fire contributes
its complement. This is a nonfire-informative synthetic model, not a MAR
missing-data mechanism. The shipped policy ignores non-fire for hideable nodes.
That comparison measures a synthetic conditioning mismatch; it does not reveal
the real observation mechanism. Aggregate JSON retains the historical keys
`mar_coverage` and `mar_fired_coverage` only so recorded artifacts and consumers
remain readable. Those names do not assert MAR semantics.

## Recorded results

Configuration: seed 1729, 10 worlds, 300 samples per perturbation level.

| delta | worst node containment | worst fired containment | first node to degrade |
|---|---:|---:|---|
| 0.00 | 1.000 | 1.000 | none, construction row |
| 0.10 | 1.000 | 1.000 | none |
| 0.20 | 0.999 | 0.999 | `email_security_policy_enforcing` |
| 0.30 | 1.000 | 1.000 | none |
| 0.50 | 0.985 | 0.980 | `email_security_policy_enforcing` |
| 0.70 | 0.958 | 0.963 | `email_security_policy_enforcing`, `google_workspace_tenant` |

The non-monotone sampled rows are expected from finite random perturbation sets;
they are another reason not to read the table as a nested uncertainty bound.

At `delta = 0.2`, every recorded node exceeded 0.999 containment in this finite
scenario. At larger perturbations, the narrow policy-node band degraded first.
This establishes that the harness can detect at least some over-tightening and
that the current band has substantial slack for the sampled scenarios. It does
not establish general parameter robustness.

## CI gate

The reduced gate uses three worlds and 80 samples at `delta = 0.2`:

- `delta = 0` must have total containment as a truth-path sanity check;
- `delta = 0.2` must meet the historical nominal 0.80 threshold for every node
  in the sampled scenario;
- `delta = 0.9` must make at least one node fall below total containment, proving
  the check can fail;
- hand-computed anchors check the fully observed Bernoulli likelihood path and empty-evidence
  enumeration.

The threshold is a regression contract for this experiment, not a statistical
coverage guarantee.

## Residual gaps

- Priors and CPT rows are not perturbed.
- Dependency groups and conditional-independence assumptions are fixed.
- Missingness policies are fixed.
- Perturbations are independent and multiplicative, not learned from data.
- A finite sampled set cannot establish worst-case bounds.
- The band remains centered on the potentially wrong shipped posterior.

The product-quality ablation in `docs/roadmap.md` is the next decision gate. The
claim-robustness envelope proposed in `docs/correlation.md` addresses explicit
model sets and evidence transformations rather than reinterpreting this display
band.
