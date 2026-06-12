# Credible-interval perturbation coverage (2026-06)

The roadmap's post-2.0 assurance track calls for a coverage check on
the 80% credible intervals, "even a proxy-label or case-study version,
framed exactly as honestly as CAL1 requires." This memo records the
first standing version of that check and the gate it leaves behind.

Harness: `validation/interval_coverage.py`. CI gate:
`tests/test_interval_coverage.py`. Synthetic-only, offline, free to
run; aggregate numbers only.

## What is being claimed, and what is not

The interval's stated job (README, `correlation.md` 4.4) is to carry
the model's honest uncertainty: it widens when evidence is thin, and
its width also has to absorb the acknowledged imprecision of the
hand-elicited CPT likelihoods, which are directionally-accurate
corpus-grounded estimates, not values precise to many decimals.

That second half is testable without real-world labels. If the
likelihoods recon believes are off by up to a multiplicative band, the
interval should still contain the conditional probability a
correctly-parameterized model would report. So the harness builds
"worlds" whose evidence likelihoods (and declarative `group_absence`
pairs) are each scaled by an independent factor in `[1-d, 1+d]`,
samples synthetic domains from those worlds, runs the shipped model on
the observations, and measures how often the shipped 80% interval
contains the world's own conditional probability. The truth path is
the independent full-joint reference from
`differential_verification.py`, not the engine.

Per CAL13, this is model-internal coverage against parameter
misspecification. It is not ground-truth calibration, which no passive
tool can observe, and the word "calibrated" is still reserved for what
CAL3 would demonstrate. The `d = 0` row is a consistency sanity check
in the CAL1 sense (the world equals the model, so coverage is total by
construction); the informative rows are `d > 0`.

## Results (2026-06, seed 1729, 10 worlds x 300 samples per delta)

Coverage is the share of samples where the shipped interval contains
the perturbed world's conditional under the model's own conditioning
semantics; `cov|f` restricts to samples where at least one binding
fired for the node (the regime where the model makes a claim).
`email_security_modern_provider` is a pure-propagation node with no
evidence bindings by design, so its fired columns are empty.

At the CAL8 band (`d = 0.2`, the documented likelihood-imprecision
sensitivity level), per-node coverage was at or above 0.999 on every
node, marginal and fired-conditional. The intervals carry real
headroom against the imprecision they claim to absorb.

| delta | worst node coverage | worst fired coverage | first node to degrade |
|---|---|---|---|
| 0.00 | 1.000 | 1.000 | none (sanity row) |
| 0.10 | 1.000 | 1.000 | none |
| 0.20 | 0.999 | 0.999 | email_security_policy_enforcing |
| 0.30 | 1.000 | 1.000 | none |
| 0.50 | 0.985 | 0.980 | email_security_policy_enforcing |
| 0.70 | 0.958 | 0.963 | email_security_policy_enforcing, google_workspace_tenant |

The check has discriminating power: under gross misspecification
(`d >= 0.5`, far outside the elicitation band) coverage degrades first
on the node with the narrowest intervals (`email_security_policy_enforcing`,
mean width about 0.16, the declarative CAL14 node whose informative
absences raise `n_eff`). That is the expected failure order: the
narrowest interval has the least slack, so a future change that
over-tightens intervals would surface here first. The falsifiability
test in the CI gate pins this property at `d = 0.9`.

## The MAR diagnostic (reported, not gated)

The harness also reports coverage against the raw generative
conditional, where a non-fired binding counts as disconfirming
evidence for every node. The shipped model deliberately refuses that
conditioning for hideable nodes (the MNAR absence rule,
`correlation.md` 4.3), so this column quantifies what that refusal
costs in a synthetic world where absence happens to be genuine
evidence:

- Marginal MAR coverage on hideable, richly-bound nodes is low
  (`m365_tenant` about 0.28, `aws_hosting` about 0.36): with nothing
  fired, the model reports the prior with a wide interval while the
  MAR conditional has already dropped near zero. This is the
  documented sacrifice, stated in the synthetic-calibration memo as
  "we sacrifice marginal calibration to refuse overconfident verdicts
  on hardened targets," now with a number attached.
- Fired-conditional MAR coverage sits in the 0.6 to 0.9 range across
  nodes: once evidence fires, the model's claim and the MAR world's
  conditional mostly agree to within the interval.
- The declarative node holds about 0.9 MAR coverage in both regimes,
  which is the CAL14 design working: for public-declaration signals
  the model already treats absence as evidence.

## The gate

`tests/test_interval_coverage.py` runs a reduced sweep in CI (3 worlds
x 80 samples at `d = 0.2`, seed-pinned, a few seconds, no network):

- `d = 0`: coverage must be total (truth-path sanity).
- `d = 0.2`: every node's marginal and fired-conditional coverage must
  meet the interval's nominal 80%. The measured value is at or above
  0.999, so the floor has headroom and is not tuned-to-pass.
- `d = 0.9`: at least one node's coverage must drop below 1.0, so the
  check provably retains the power to fail.
- Anchors: the MAR likelihood path is checked against a hand-computed
  case, and the enumeration helper is checked against the engine at
  the empty evidence configuration (where the differential harness
  already verified the engine).

## Residuals

- Priors and CPT rows are not perturbed here; the interval's `n_eff`
  machinery keys off the evidence model, and prior grounding is
  tracked separately as CAL12. A prior-perturbation variant is a
  natural extension if the CAL12 work changes the priors materially.
- This check cannot substitute for CAL3 empirical coverage against
  ground truth; it bounds a different failure mode (elicitation
  imprecision overwhelming the interval width).
