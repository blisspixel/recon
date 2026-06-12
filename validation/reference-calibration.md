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

## Results (2026-06, aggregates only)

Two maintainer-local runs over the gitignored corpus, on two independent
samples. Only the aggregate block is recorded; no apex left the process.

Primary, current code, a random sample of the consolidated corpus
(n=378 carried a published DMARC policy):

```
base rate enforcing:   0.81
Brier:                 0.0079
ECE:                   0.0765
agreement rate:        1.000  Wilson80 (0.996, 1.000)
reliability (posterior bin -> empirical enforcing rate):
  [0.00, 0.10)  rate 0.000  n 71
  [0.20, 0.30)  rate 0.000  n 1
  [0.80, 0.90)  rate 1.000  n 98
  [0.90, 1.00)  rate 1.000  n 208
```

Cross-reference, a larger cached industry-curated run (n=980 with a
published policy): base rate 0.87, Brier 0.0069, ECE 0.073, agreement
1.000. The two independent samples agree closely, which is the
robustness signal worth more than either number alone.

Reading it honestly:

- The posterior distribution is bimodal (near 0 or near 0.9) on this corpus,
  because most domains either publish a clear enforcing DMARC policy or none.
  That is a corpus-composition artifact, not a property of the node: it does
  emit mid-range posteriors (roughly 0.27 to 0.53) on domains that publish
  strict SPF or MTA-STS without an enforcing DMARC, which is exactly the
  stratum a held-out residual calibration would populate. The interior bins
  [0.30, 0.80) are empty here, so the calibration is untested there. The
  empirical enforcing-rate matches the bin in every populated bin.
- The whole ECE (about 0.077) comes from the model being *under*-confident
  on enforcing domains: it reports 0.85 to 0.95 where the reference says
  100%. It never runs the other way (no bin where the posterior exceeds
  the empirical rate). Under-confidence is recon hedging down, which is the
  intended direction for a tool whose discipline is to not over-claim. The
  slight gap below 1.0 is the multi-signal combination: strict-SPF or
  MTA-STS absence pulls the posterior a little below DMARC-only certainty.
- The agreement rate is high partly because DMARC is also an *input* to
  the node, the documented overlap, so the reliability table and ECE are
  the informative figures here, not the agreement rate.

This is a partial tier-4 result for this one node, not a clean one. Because
DMARC is also the node's dominant input, the agreement is largely
definitional, and the honest tier-4 claim is only for the strict-SPF +
MTA-STS residual. The result also says nothing about whether the policy is
*enforced*, only that it is *declared*, and the declaration is forgeable at
zero cost (correlation.md 4.11, Pattern I). A held-out calibration that
removes the DMARC bindings and scores the residual against the DMARC label is
what would make the whole posterior tier 4. None of this generalizes to the
hideable nodes, where no external reference exists.

## The held-out residual (harness shipped; run pending)

The clean construction the section above asks for now ships in the same
harness: every run computes, beside the full posterior, a *held-out residual*
posterior with the `dmarc_policy` evidence unit masked as structurally
unobserved (`infer(..., masked_units=("dmarc_policy",))`, the
leave-one-unit-out primitive in `recon_tool/bayesian.py`, pinned by
`tests/test_bayesian_masked_units.py`). Masking matters because the policy
node is declarative: simply deleting the fired DMARC signal would let the
informative-absence rule read the domain as *disconfirmed* ("no DMARC
published"), contaminating the residual with the very record the label is
made from. The mask suppresses both directions, so the residual predictor
sees only the strict-SPF and MTA-STS channel and the DMARC record serves
purely as the label — predictor and label disjoint by construction.

Two things to expect from the run, so the numbers are read honestly:

- The residual predictor is weak by design (DMARC is the dominant input; the
  residual lives in roughly the 0.27 to 0.75 band, populating exactly the
  interior bins the full-posterior run left empty). The claim under test is
  its *calibration*, not its strength: in each residual-posterior bin, does
  the empirical enforcing rate match?
- The residual is invariant to the DMARC signal in either direction
  (unit-tested), so no leakage path from label to predictor remains inside
  the inference.

A maintainer-local run over the corpus fills in this section's numbers; the
output's second block ("Held-out residual") is the one to copy here,
aggregates only.

## Status

The harness, its unit tests, the full-posterior result above, and the
held-out residual mode all ship. The statistical-assurance dossier records
`email_security_policy_enforcing` as tier 4 for the strict-SPF + MTA-STS
residual and an agreement check for the DMARC-driven bulk, not tier 4 for
the whole posterior; the held-out residual *run* (the numbers for the
section above) is what would make the residual claim clean, and it is the
remaining step, together with the optional per-vertical stratification
(does the calibration hold across industries), for which the `by-vertical/`
corpus lists are the input (`--stratify-dir` now reports full and held-out
blocks per stratum).
