# CAL8 historical likelihood-perturbation sensitivity record

Status: historical result. The table below was produced on 2026-06-04 at commit
[`76b31c72`](https://github.com/blisspixel/recon/commit/76b31c7207f826ac75eb15db30e05fb3d5361bb9),
before CAL14 declarative missingness shipped at commit
[`957e1f6d`](https://github.com/blisspixel/recon/commit/957e1f6d109faf04ceb80c7eabe90105c5c4ddca).
It does not describe the current network's numerical output.

The likelihoods in `src/recon_tool/data/bayesian_network.yaml` are manually
encoded and human-reviewed. Some current parameters were informed by aggregate
development-corpus observations, so they are not independent validation data.
CAL8 asks a narrower question: within this synthetic diagnostic, how much do the
recorded posteriors and threshold decisions change when binding likelihoods are
perturbed? The current script remains synthetic-only and uses no real targets:

    uv run python validation/likelihood_sensitivity.py --samples 4000 --trials 10 --seed 1729

## Method

For the recorded run, generative truth was held fixed and only inference was
perturbed.

1. Draw one fixed synthetic dataset from the baseline network (4,000 domains:
   a ground-truth assignment plus the pattern produced by the diagnostic's
   independent-binding generator).
2. Build 12 perturbed networks: two systematic corners (every binding likelihood
   x1.2 and every binding likelihood x0.8) plus a 10-network random jitter
   ensemble (each binding likelihood scaled independently by a factor in
   [0.8, 1.2]), clipped to the valid open interval.
3. Re-run inference on the same observations under the baseline and every
   perturbed network. Score each node's posteriors against the fixed ground
   truth (Brier, ECE) and against the baseline run (decision flips: does
   `posterior >= 0.5` still match).

The generator samples each binding independently conditional on its node state.
It does not enforce correlation-group exclusivity or generate declarative
group-absence units according to the shipped observation semantics. The
perturbation also excludes `group_absence` parameters. Brier and ECE therefore
describe this synthetic generator, not calibration under the shipped observation
model. The script reports measurements and always exits successfully after a
valid run; it has no acceptance threshold.

## Historical result (2026-06-04, commit `76b31c72`)

Configuration: n = 4,000, 12 perturbed networks, seed 1729.

Each row is the baseline metric, then the worst deviation any perturbation
produced.

| node | Brier | dBrier | ECE | dECE | flip% |
|---|---|---|---|---|---|
| m365_tenant | 0.115 | 0.001 | 0.215 | 0.001 | 1.3 |
| google_workspace_tenant | 0.103 | 0.003 | 0.205 | 0.020 | 0.0 |
| federated_identity | 0.132 | 0.002 | 0.254 | 0.005 | 0.0 |
| okta_idp | 0.039 | 0.001 | 0.124 | 0.001 | 0.0 |
| email_gateway_present | 0.063 | 0.002 | 0.148 | 0.010 | 0.0 |
| email_security_modern_provider | 0.216 | 0.001 | 0.253 | 0.009 | 0.0 |
| email_security_policy_enforcing | 0.137 | 0.016 | 0.267 | 0.032 | 0.0 |
| cdn_fronting | 0.143 | 0.000 | 0.249 | 0.000 | 0.0 |
| aws_hosting | 0.152 | 0.002 | 0.290 | 0.009 | 0.0 |

**Worst case across all nodes: dECE <= 0.032, decision flips <= 1.3%, Brier
shift <= 0.016.**

## Reading

- In this recorded pre-CAL14 run, the selected +/-20% binding-likelihood
  perturbations changed the reported metrics and decisions by the amounts above.
  That is evidence of model-relative output stability only within this finite
  diagnostic. It is not evidence that the model is calibrated.
- The most perturbation-sensitive node was
  `email_security_policy_enforcing` (dECE 0.032). CAL14 subsequently changed that
  node's missingness semantics, and later parameter regrounding changed its
  MTA-STS and SPF likelihoods. The historical row must not be projected onto the
  current model.

## Scope (what this is not)

This is a historical **sensitivity measurement**, not a calibration-quality
claim, a robustness certificate, or a current proof gate. The baseline ECE
values are relative to the harness's misspecified independent-binding generator.
The experiment does not cover structural model changes, dependency-group
assumptions, grouped-absence parameters, real-world distribution shift, or the
development-corpus and validation-corpus overlap documented elsewhere. A current
run can measure sensitivity of the current model, but its output requires review
because the harness intentionally has no pass threshold.
