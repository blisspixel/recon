# Final Claim Audit Public Memo (2026-06-28)

Harnesses:

`python -m validation.reproduce_paper_numbers --profile smoke --stamp discussion-claim-audit-smoke-20260628`

`python -m validation.reproduce_paper_numbers --profile paper --stamp discussion-claim-audit-paper-20260628`

Generated at: `2026-06-28T22:43:02.518083+00:00`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- Local manifests, stdout, and stderr artifacts remain under the ignored local
  validation workspace and are not committed.
- This is a final public claim-audit pass for the current draft state after the
  discussion and conclusion were tightened to match the claim map. It
  regenerates the public synthetic and model-internal rows, not the
  maintainer-local private-corpus calibration rows.

## Smoke Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 15.98 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 1.05 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 0.53 | Synthetic interval-coverage harness health |
| `likelihood-sensitivity` | pass | 2.59 | Likelihood perturbation harness health |
| `layer-ablation` | pass | 1.14 | Synthetic Bayesian and graph-layer ablation harness health |

## Full Public Proof Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 16.52 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 62.82 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 162.13 | Paper-sized synthetic interval-coverage sweep under the CAL8 likelihood band |
| `likelihood-sensitivity` | pass | 886.14 | Paper-sized likelihood perturbation sweep over 4,000 synthetic domains |
| `layer-ablation` | pass | 357.89 | Paper-sized synthetic Bayesian and graph-layer ablations |

## Interpretation

The final claim audit proves that the current paper package has a passing public
smoke run, a passing full public proof run, a passing claim-map audit, a passing
figure drift check, a passing full local gate, and passing remote release
readiness.

The public proof rows cover suppression monotonicity and planted-evidence
perturbation measurement, differential verification, synthetic interval
coverage, likelihood sensitivity, and layer ablations. The planted evidence
boundary remains a synthetic model-internal perturbation result, not attacker
prevalence, exploitability, or a real-world false-positive rate.

The discussion and conclusion now preserve the final evidence tier: no clean
independent calibration result, the DMARC-held-out residual as a negative
result, M365 as channel-split corroboration, and Google Workspace as one-sided
recall on attested positives.

The interval result remains model-internal perturbation coverage, not
ground-truth frequentist coverage. The layer-ablation rows remain synthetic
layer-contribution checks under the model assumptions, not real-world validity
claims.

Private-corpus calibration rows, public-list calibration reruns without a frozen
list, and posture distributions that require a caller-supplied domain list remain
out of this memo by design.
