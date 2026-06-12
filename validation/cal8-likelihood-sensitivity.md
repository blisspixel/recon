# CAL8 - likelihood-perturbation sensitivity

The CPT likelihoods in `recon_tool/data/bayesian_network.yaml` are
hand-elicited (concept-first, not corpus-fitted; see `CONTRIBUTING.md`
CPT-change discipline). A fair challenge to the calibration story is: do the
numbers depend sensitively on those exact hand-picked values? CAL8 answers it
with a sensitivity analysis. Reproducible and synthetic-only (no real targets):

    python validation/likelihood_sensitivity.py --samples 4000 --trials 10 --seed 1729

## Method

Generative truth is held fixed; only inference is perturbed.

1. Draw one fixed synthetic dataset from the baseline network (4,000 domains:
   a ground-truth assignment plus the evidence pattern recon would observe).
2. Build 12 perturbed networks: two systematic corners (every likelihood x1.2
   and every likelihood x0.8) plus a 10-network random jitter ensemble (each
   likelihood scaled independently by a factor in [0.8, 1.2]), clipped to the
   valid open interval.
3. Re-run inference on the same observations under the baseline and every
   perturbed network. Score each node's posteriors against the fixed ground
   truth (Brier, ECE) and against the baseline run (decision flips: does
   `posterior >= 0.5` still match).

## Result (n = 4,000, 12 perturbed networks, seed 1729)

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

- The metrics barely move under a +/-20% perturbation of every likelihood. The
  calibration is robust to the hand-elicited values, not knife-edge dependent on
  the exact CPT numbers. That is the defensibility claim CAL8 exists to support.
- The most perturbation-sensitive node is `email_security_policy_enforcing`
  (dECE 0.032). This is consistent with its status as the least-settled node:
  it carries the known conditional-overconfidence that the CAL14 node-dependent
  missingness change is meant to address. The most sensitive node is the one we
  already flag as needing the most work.

## Scope (what this is not)

This is a **stability** result, not a calibration-quality claim. The baseline
ECE values are marginal ECE, which is high by design for the asymmetric absence
model (it includes the sparse / no-binding-fired cohort; see CAL9 and the
evidence-responsive framing in CAL13). CAL8 says only that whatever the
calibration is, it does not swing on small changes to the elicited likelihoods.
It complements, and does not replace, the calibration-quality work (the
reference-backed calibration and the CAL14 missingness fix).
