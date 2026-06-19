# Public Paper Reproduction Smoke Memo (2026-06-19)

Harness:
`python -m validation.reproduce_paper_numbers --profile smoke --stamp roadmap-aggregate-smoke-20260619`

Generated at: `2026-06-19T13:35:20.127742+00:00`

Private corpora read: no.

Network required by default: no.

External spend: 0 USD.

## Disclosure Controls

- Source data is synthetic or model-internal only.
- No apex domains, organization names, tenant IDs, per-domain JSON, raw row
  excerpts, or screenshots are included.
- The local manifest, stdout, and stderr artifacts remain under the ignored
  local validation workspace and are not committed.
- This is a smoke run for harness health. It is not a replacement for the
  paper-sized runs or maintainer-local private-corpus calibration memos.

## Aggregate Results

| Step | Status | Seconds | Smoke-covered claim |
|---|---:|---:|---|
| `adversarial-properties` | pass | 6.69 | Suppression monotonicity proof obligations over the shipped network |
| `differential-verification` | pass | 1.03 | Fast tricky-node variable-elimination sweep against the full-joint reference |
| `interval-coverage` | pass | 0.50 | Small synthetic interval-coverage sweep at `delta=0.20`, `worlds=1`, `samples=20` |
| `likelihood-sensitivity` | pass | 2.36 | Small likelihood-sensitivity sweep with `samples=50`, `trials=1` |
| `layer-ablation` | pass | 1.28 | Small Bayesian-only layer-ablation sweep with `samples=50` |

## Interpretation

The smoke profile proves that the public reproduction bundle still runs end to
end without private corpora or paid services. It covers the paper draft's public
evidence rows for suppression monotonicity, differential verification, synthetic
interval coverage, likelihood sensitivity, and layer ablations.

The interval-coverage smoke row reported coverage `1.0` on every Bayesian node
at the CAL8 `delta=0.20` band, with `fired_coverage=1.0` on every node that had
fired bindings in the smoke sample. That is a harness-health result on a tiny
synthetic sample, not an empirical calibration claim.

The layer-ablation smoke row used 50 synthetic worlds. In the fired regime, the
full posterior had lower Brier loss than the `any_fired` baseline on 7 of the 8
nodes with fired evidence in this small run. This checks that the machinery is
exercising the same comparison as the paper-sized ablation, not that the smoke
sample should be quoted as a headline result.

Private-corpus calibration rows, public-list calibration reruns without a frozen
list, and posture distributions that require a caller-supplied domain list remain
out of this memo by design.
