# ADR-0002: Treat missing evidence as adversarially missing (MNAR / LR=1)

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); formalized in correlation.md §4.3

## Context

Under passive collection (ADR-0001) the subject controls most of the evidence: a
hardened organization publishes fewer indicators, and that suppression is *not
random* - it correlates with the very security maturity we're estimating. A
naive model reads "no signal" as "technology absent" and becomes confidently
wrong about exactly the hardened targets that matter most. This is
missing-not-at-random (MNAR) in the adversarial sense, which standard
calibration assumptions exclude.

## Decision

For *hideable* nodes, a non-fired binding contributes a **likelihood ratio of 1**
(absence of evidence is treated as no evidence, never as evidence of absence), so
the credible interval **widens** on hardened targets instead of collapsing to a
false verdict. The exception is *declarative* public-record nodes (DMARC/SPF/
MTA-STS), where absence is genuine and informative, conditioned per
evidence-group (CAL14). The guarantee is robustness to evidence *removal*, not
*addition* - a planted decoy record can still mislead, and we say so.

## Consequences

- A proved, machine-checked suppression-monotonicity property: hiding signals can
  only move a claim toward "we cannot tell," never to a confident false positive.
- A measured honesty cost: on benign-missing data the hideable nodes pay a
  bounded Brier penalty a naive detector doesn't - accepted deliberately.
- Validation must tier by whether an external reference label exists; "calibrated"
  is reserved for nodes where it does (CAL1/CAL13). This shapes the whole
  assurance and paper story.
