# Submission Freeze Local Public Proof Memo (2026-06-29)

Harnesses:

`python -m validation.reproduce_paper_numbers --profile smoke --stamp submission-freeze-smoke-20260629-cycle9`

`python -m validation.reproduce_paper_numbers --profile paper --stamp submission-freeze-paper-20260629-cycle9b`

Generated at: `2026-06-29T22:32:17.503163+00:00`

Harness commit under test:
`171b4a3bc78e3f9c81e27262354636569b798b77`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- Local manifests, stdout, and stderr artifacts remain under the ignored
  validation workspace and are not committed.
- This submission freeze local proof reruns the public synthetic and
  model-internal rows. It does not reproduce maintainer-local private-corpus
  calibration rows, does not claim an external submission, does not claim a DOI
  archive, and does not claim outside replication.

## Smoke Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 17.69 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 1.14 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 0.58 | Synthetic interval-coverage harness health |
| `likelihood-sensitivity` | pass | 2.75 | Likelihood perturbation harness health |
| `layer-ablation` | pass | 1.22 | Synthetic Bayesian and graph-layer ablation harness health |

## Full Public Proof Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 15.96 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 65.44 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 179.98 | Paper-sized synthetic interval-coverage sweep under the CAL8 likelihood band |
| `likelihood-sensitivity` | pass | 1010.15 | Paper-sized likelihood perturbation sweep over 4,000 synthetic domains |
| `layer-ablation` | pass | 376.56 | Paper-sized synthetic Bayesian and graph-layer ablations |

## Ancillary Local Gates

| Gate | Status |
|---|---:|
| Claim audit | pass |
| Figure drift | pass |
| Validation hygiene | pass |
| Text hygiene | pass |
| Local CI mirror | pass, 3727 passed, 5 skipped, 4 deselected, 86.64 percent coverage |
| Local release readiness | pass |

## Interpretation

The submission freeze local proof has a passing public smoke run, a passing full
public proof run, a passing claim-map audit, a passing figure drift check,
passing validation hygiene, passing text hygiene, a passing full local gate, and
passing local release readiness.

The public proof rows cover suppression monotonicity and planted-evidence
perturbation measurement, differential verification, synthetic interval
coverage, likelihood sensitivity, and layer ablations. The planted evidence
boundary remains a synthetic model-internal perturbation result, not attacker
prevalence, exploitability, or a real-world false-positive rate.

The interval result remains model-internal perturbation coverage, not
ground-truth frequentist coverage. The layer-ablation rows remain synthetic
layer-contribution checks under the model assumptions, not real-world validity
claims.

Private-corpus calibration rows, public-list calibration reruns without a frozen
list, and posture distributions that require a caller-supplied domain list remain
out of this memo by design.
