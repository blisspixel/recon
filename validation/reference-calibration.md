# Email-policy score comparison with DMARC

Current interpretation reviewed 2026-07-10. Historical aggregate measurements
are unchanged.

Harness: `validation/reference_calibration.py`. Pure-logic tests:
`tests/test_reference_calibration.py`. Statistical interpretation:
[docs/statistical-assurance.md](../docs/statistical-assurance.md).

## Question

`email_security_policy_enforcing` combines DMARC, strict SPF, and MTA-STS
evidence under the committed Bayesian model. An observed DMARC channel supplies
a binary reference: `reject` or `quarantine` is 1, while `none` or a
successfully observed no-record result is 0. DNS or detector collection failures
remain unlabeled.

The harness compares the model score with that declaration and reports Brier,
log score, fixed-bin and tie-preserving ECE, reliability cells, and threshold
agreement. Bootstrap and Wilson ranges are naive iid row diagnostics with no
coverage interpretation for the selected cohort. The full-score comparison is **overlapping corroboration**, not
independent calibration, because the DMARC unit is also the model's dominant
input.

The harness also masks the entire `dmarc_policy` dependency unit and evaluates
the strict-SPF plus MTA-STS residual against DMARC. That predictor and label are
disjoint inside recon. The residual comparison tests whether those other public
signals predict the DMARC declaration on this corpus. It does not test whether a
receiver actually enforces policy. Predictor-disjoint does not mean the
observations or selected domains are independent, and the pooled metrics are
descriptive for the evaluated corpus rather than population estimates.

## Why the uncertainty band is not scored against a binary label

`interval_low` and `interval_high` bound a model probability display. Asking
whether that band contains a binary label is a category error. The real-record
comparison therefore evaluates point-score reliability and proper scores. The
separate perturbation experiment in `interval-coverage.md` evaluates finite
model-relative scenarios and is not empirical interval coverage.

## Data handling

The harness reads real apexes from an ignored maintainer corpus. It emits only
reviewed aggregates. No apex, tenant identifier, or per-domain row reaches
stdout or a tracked file. See
[data-handling-policy.md](../docs/data-handling-policy.md).

```text
python -m validation.reference_calibration validation/corpus-private/consolidated.txt
```

## Early aggregate runs

An n=378 sample with a published DMARC policy reported:

```text
base rate enforcing:   0.81
Brier:                 0.0079
ECE:                   0.0765
agreement rate:        1.000  naive-iid Wilson diagnostic range80 (0.996, 1.000)
reliability (posterior bin -> empirical enforcing rate):
  [0.00, 0.10)  rate 0.000  n 71
  [0.20, 0.30)  rate 0.000  n 1
  [0.80, 0.90)  rate 1.000  n 98
  [0.90, 1.00)  rate 1.000  n 208
```

A larger n=980 sample reported base rate 0.87, Brier 0.0069, fixed-bin
ECE 0.073, and agreement 1.000. The bimodal reliability table is expected when
the label-defining DMARC unit dominates the score. It does not independently
validate the other signals or the model parameters.

## Full-corpus refresh, 2026-06-28

The ignored 5,241-domain run contained 2,906 domains with a published DMARC
policy. This historical cohort was publisher-conditional and excluded
successfully observed no-record domains. Its values are preserved, but a new
run under the current label rule uses a broader cohort and is not directly
comparable without reconstructing the old selection rule.

Full score, including DMARC:

- fixed-bin ECE 0.0761;
- legacy equal-mass ECE 0.0651 with naive-iid row-bootstrap diagnostic range80
  `[0.0639, 0.0668]`;
- Brier 0.0077;
- log score 0.0769;
- threshold agreement 1.0;
- per-vertical fixed-bin ECE 0.065 to 0.098 across 22 verticals.

DMARC-masked residual:

- fixed-bin ECE 0.3747;
- legacy equal-mass ECE 0.3263 with naive-iid row-bootstrap diagnostic range80
  `[0.3177, 0.3349]`;
- Brier 0.2448;
- log score 0.6809;
- threshold agreement 0.1896;
- per-vertical fixed-bin ECE 0.26 to 0.50.

## Interpretation

The full score has low ECE against a declaration it substantially consumes.
That is useful wiring and overlap-aware corroboration, but the comparison is
close to definitional.

The predictor-disjoint residual is weak and poorly calibrated. Strict SPF plus
MTA-STS does not independently predict the DMARC declaration well on this
corpus. This is a valuable falsification result. It prevents promotion of the
full-score agreement into a clean empirical-calibration claim.

The result establishes neither actual receiver enforcement nor robustness to a
planted DMARC declaration. It does not generalize to hideable infrastructure
nodes. The next decision belongs to the predeclared product ablation in
`docs/roadmap.md`, not to further tuning of this model against the same label.

The recorded equal-mass values predate tie-preserving bin boundaries and may
split identical scores across bins. They remain historical numbers. Current
runs keep every distinct score in one reliability bin and need a fresh memo.
