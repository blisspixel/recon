# Reference calibration against the DMARC record (CAL3 / CAL4)

The roadmap's highest-value open assurance item: calibrate a recon
posterior against an external public reference, the one place the passive
setting allows it. Harness: `validation/reference_calibration.py`. Unit
tests for the pure logic: `tests/test_reference_calibration.py`. The
statistical-assurance dossier
([docs/statistical-assurance.md](../docs/statistical-assurance.md)) is
where this sits in the four-tier picture.

## What it does

`email_security_policy_enforcing` infers a probability that a domain's
email-authentication policy is enforcing. The authoritative definition
of "enforcing" is a public declaration anyone can read: a DMARC policy
of `reject` or `quarantine` (RFC 7489). So the DMARC record is its own
ground-truth reference, and the harness pairs, per domain, recon's policy
posterior with the binary reference label, then reports aggregate
calibration: Brier, ECE, a reliability table (posterior bin to empirical
enforcing rate), and the agreement rate with an 80% Wilson interval.

## Why this is calibration, not interval coverage

The reference label is binary, and a credible interval is for the
probability, so "does the 80% interval contain the label" is a category
mismatch. Calibration against the binary label (reliability / ECE /
Brier) is the measurable thing. Frequentist interval coverage in the
CAL3 sense needs a probability truth or repeated trials per evidence
pattern; the synthetic perturbation harness
(`validation/interval_coverage.py`, v2.1.15) supplies that. The two are
complementary: the synthetic harness proves the interval absorbs
parameter imprecision; this one proves the posterior agrees with an
authoritative external definition on real records.

## What it does and does not establish

The reference label comes from an authoritative external definition (the
published DMARC level), not from recon's own posterior, so this is
firmer than the near-tautological deterministic-vs-Bayesian consistency
check (tier 2 in the dossier). It is not the fully-independent ground
truth of an ideal study, because the node's own evidence includes the
DMARC signal, so the posterior and the reference overlap on input. What
it tests honestly: whether recon's combined multi-signal posterior (DMARC
plus strict SPF plus MTA-STS, under the node's definition) is calibrated
against the authoritative DMARC-only definition. The case it catches is
a domain whose DMARC is `p=none` but whose strict SPF or MTA-STS pushes
recon's posterior high; the reference marks that a miss.

## Running it (maintainer-local)

The harness reads real apex domains, so a run stays on the maintainer's
machine against the gitignored corpus and prints aggregates only. No
apex and no per-domain row reaches stdout or any committed file
([data-handling-policy.md](../docs/data-handling-policy.md)).

```
python -m validation.reference_calibration validation/corpus-private/consolidated.txt
```

Only the aggregate block (counts, base rate, Brier, ECE, reliability,
agreement with Wilson interval) is suitable to copy into a committed
memo; the per-domain pairing never leaves the process.

## Synthetic worked example (fabricated numbers)

A run over a fictional set, to show the shape of the output. These
numbers are invented for the format only; the real-run results are
recorded below once a current-version run completes.

```
Email-policy node calibrated against the DMARC record (n=420 with a published policy)
  base rate enforcing:   0.62
  Brier:                 0.10
  ECE:                   0.06
  agreement rate:        0.91  Wilson80 (0.89, 0.93)
  reliability (posterior bin -> empirical enforcing rate):
    [0.00, 0.10)  rate 0.04  n 70
    [0.50, 0.60)  rate 0.55  n 38
    [0.80, 0.90)  rate 0.86  n 120
```

Reading it: a low ECE and a reliability table whose empirical
enforcing-rate tracks the posterior bin would mean the policy posterior
is well-calibrated against the authoritative DMARC definition; a bin
where the posterior runs well above the empirical rate would localize an
over-weighting of the non-DMARC signals for the node to investigate
under the CPT-change discipline.

## Status

The harness and its unit tests ship now. The calibration run against the
corpus is maintainer-local and records its aggregate-only result in the
Results section above when complete; until then the dossier reports tier
4 as the open frontier for this node.
