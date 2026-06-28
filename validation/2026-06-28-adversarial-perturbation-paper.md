# Adversarial Perturbation Public Proof Memo (2026-06-28)

Harness:
`python -m validation.reproduce_paper_numbers --profile paper --stamp adversarial-perturbation-paper-20260628`

Generated at: `2026-06-28T15:52:31.547314+00:00`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- The local manifest, stdout, and stderr artifacts remain under the ignored
  local validation workspace and are not committed.
- This is a full public proof run after the adversarial add/remove
  perturbation harness change. It regenerates the public synthetic and
  model-internal rows, not the maintainer-local private-corpus calibration
  rows.

## Aggregate Results

| Step | Status | Seconds | Public claim covered |
|---|---:|---:|---|
| `adversarial-properties` | pass | 16.28 | Evidence-removal guarantee and planted evidence boundary over the shipped network |
| `differential-verification` | pass | 44.12 | Variable elimination against the full-joint reference |
| `interval-coverage` | pass | 119.23 | Paper-sized synthetic interval-coverage sweep under the CAL8 likelihood band |
| `likelihood-sensitivity` | pass | 880.48 | Paper-sized likelihood perturbation sweep over 4,000 synthetic domains |
| `layer-ablation` | pass | 375.83 | Paper-sized synthetic Bayesian and graph-layer ablations |

## Interpretation

The paper profile proves that the public reproduction bundle runs end to end
without private corpora, paid services, or default network access after the
adversarial add/remove perturbation harness change.

The adversarial-property step reported zero positive-indicator violations, zero
declarative-absence violations, and zero suppression monotonicity or bound
violations. Under the shipped network, hiding fired evidence only moves a claim
toward the all-absent floor.

The same step also measured the planted evidence boundary as a synthetic
model-internal perturbation, not attacker prevalence, exploitability, or a
real-world false-positive rate. Across 8 reported nodes, the harness evaluated
774 paired add/remove cases and found 211 cases where adding a single evidence
unit moved the posterior across the 0.5 decision boundary. The maximum planted
posterior reached `1.0000` in the synthetic contexts. This is intentionally
framed as a boundary condition: a passive inference engine can measure
evidence-consistent movement, but it cannot determine whether a newly visible
public signal is truthful operational configuration or planted evidence.

The differential-verification step checked 2,972 configurations against the
naive full-joint reference, with zero failures and worst per-node gap
`4.95e-05`.

The interval-coverage step reported model-conditional coverage `1.0` for every
Bayesian node at the CAL8 `delta=0.20` band. Across all reported deltas, the
minimum model-conditional coverage was `0.9985`, on the declarative mail-policy
node at `delta=0.30`. This is model-internal perturbation coverage, not
ground-truth frequentist coverage.

The likelihood-sensitivity step reported worst-case `dECE <= 0.020` and
decision flips no higher than `1.3%` under the configured plus-or-minus
20 percent likelihood perturbations.

The layer-ablation step used 20,000 synthetic worlds. In the fired regime, the
full posterior had lower Brier loss than the `any_fired` baseline on every node
with fired evidence. The graph-layer experiment kept Louvain adjusted Rand
index at `1.0` across the bridging-noise grid while connected components
collapsed under shared-noise certificates. These are synthetic layer-contribution
checks under the model assumptions, not real-world validity claims.

Private-corpus calibration rows, public-list calibration reruns without a frozen
list, and posture distributions that require a caller-supplied domain list remain
out of this memo by design.
