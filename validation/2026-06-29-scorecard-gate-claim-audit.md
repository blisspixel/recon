# Scorecard Gate Final Claim Audit Public Memo (2026-06-29)

Status: historical proof for the repository and paper-package state recorded
on 2026-06-29. It is not proof for the current unfrozen package.

Harnesses:

`python -m validation.reproduce_paper_numbers --profile smoke --stamp scorecard-gate-claim-audit-smoke-20260629`

`python -m validation.reproduce_paper_numbers --profile paper --stamp scorecard-gate-claim-audit-paper-20260629`

Generated at: `2026-06-29T08:41:04.030029+00:00`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- Local manifests, stdout, and stderr artifacts remain under the ignored
  validation workspace and are not committed.
- This refresh reruns the final public claim-audit pass after the claim map,
  artifact guide, release process, supply-chain, OpenSSF posture, and strategic
  audit were tightened around the new public Scorecard API release-readiness
  gate. It regenerates the public synthetic and model-internal rows, not the
  maintainer-local private-corpus calibration rows.

## Smoke Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 17.64 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 1.05 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 0.49 | Synthetic interval-coverage harness health |
| `likelihood-sensitivity` | pass | 2.63 | Likelihood perturbation harness health |
| `layer-ablation` | pass | 1.20 | Synthetic Bayesian and graph-layer ablation harness health |

## Full Public Proof Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 17.08 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 66.56 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 170.09 | Paper-sized synthetic interval-coverage sweep under the CAL8 likelihood band |
| `likelihood-sensitivity` | pass | 809.21 | Paper-sized likelihood perturbation sweep over 4,000 synthetic domains |
| `layer-ablation` | pass | 343.20 | Paper-sized synthetic Bayesian and graph-layer ablations |

## Interpretation

For the package state recorded on 2026-06-29, the Scorecard gate final claim
audit produced a passing public smoke run, a passing full public proof run, a
passing claim-map audit, a passing figure drift check, passing release readiness
with public Scorecard API freshness, and a passing full local gate. The local
gate result was 3,701 passed, 5 skipped, 4 deselected, with 86.61 percent
coverage.

The public proof rows cover suppression monotonicity and planted-evidence
perturbation measurement, differential verification, synthetic interval
coverage, likelihood sensitivity, and layer ablations. The planted evidence
boundary remains a synthetic model-internal perturbation result, not attacker
prevalence, exploitability, or a real-world false-positive rate.

The release-state rows now include the public Scorecard API freshness check:
`scripts/release_readiness.py --remote` verifies that the public Scorecard API
reports the exact `HEAD`, the current score floor, and the expected code-owned
controls before checking PyPI and GitHub release provenance. This is artifact
integrity evidence, not empirical result validation.

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
