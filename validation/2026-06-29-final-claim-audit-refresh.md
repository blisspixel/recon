# Final Claim Audit Refresh Public Memo (2026-06-29)

Harnesses:

`python -m validation.reproduce_paper_numbers --profile smoke --stamp metric-lineage-claim-audit-smoke-20260629`

`python -m validation.reproduce_paper_numbers --profile paper --stamp metric-lineage-claim-audit-paper-20260629`

Generated at: `2026-06-29T00:22:26.411583+00:00`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- Local manifests, stdout, and stderr artifacts remain under the ignored
  validation workspace and are not committed.
- This refresh reruns the final public claim-audit pass after the paper draft,
  outline, and claim map were tightened to align metric-lineage wording with the
  June 28 calibration refresh. It regenerates the public synthetic and
  model-internal rows, not the maintainer-local private-corpus calibration rows.

## Smoke Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 18.46 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 1.12 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 0.53 | Synthetic interval-coverage harness health |
| `likelihood-sensitivity` | pass | 2.82 | Likelihood perturbation harness health |
| `layer-ablation` | pass | 1.23 | Synthetic Bayesian and graph-layer ablation harness health |

## Full Public Proof Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 16.71 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 51.90 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 151.09 | Paper-sized synthetic interval-coverage sweep under the CAL8 likelihood band |
| `likelihood-sensitivity` | pass | 830.58 | Paper-sized likelihood perturbation sweep over 4,000 synthetic domains |
| `layer-ablation` | pass | 314.00 | Paper-sized synthetic Bayesian and graph-layer ablations |

## Interpretation

The final claim audit refresh proves that the current paper package has a
passing public smoke run, a passing full public proof run, a passing claim-map
audit, a passing metric-lineage wording check, a passing figure drift check,
passing release readiness, and a passing full local gate. The local gate result
was 3,677 passed, 6 skipped, 4 deselected, with 86.59 percent coverage.

The public proof rows cover suppression monotonicity and planted-evidence
perturbation measurement, differential verification, synthetic interval
coverage, likelihood sensitivity, and layer ablations. The planted evidence
boundary remains a synthetic model-internal perturbation result, not attacker
prevalence, exploitability, or a real-world false-positive rate.

The refreshed paper wording now preserves metric lineage: the June 28 calibration
refresh reports fixed-bin ECE and equal-mass, mean-confidence ECE side by side,
while older memos keep their dated estimator labels unless their corpus runs are
rerun.

The discussion and conclusion still preserve the final evidence tier: no clean
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
