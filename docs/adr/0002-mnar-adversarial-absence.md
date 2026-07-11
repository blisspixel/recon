# ADR-0002: Ignore non-fired hideable bindings (`LR=1` policy)

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); corrected 2026-07-10; formalized in
  correlation.md section 3.3

## Context

Under passive collection (ADR-0001) the subject controls most of the evidence: a
hardened organization can publish fewer indicators, and that suppression is
not random with respect to the infrastructure state being inferred. A
naive model reads "no signal" as "technology absent" and becomes confidently
wrong about exactly the hardened targets that matter most. This is
missing-not-at-random (MNAR) in the adversarial sense, which standard
calibration assumptions exclude. MNAR alone does not derive a unique likelihood
ratio or point posterior. Without an observation model, the claim is generally
partially identified.

## Decision

For *hideable* nodes, a non-fired binding contributes a **likelihood ratio of 1**
(absence of evidence is treated as no evidence, never as evidence of absence).
This is a conservative implementation policy, not a consequence of MNAR. The
exception is a reviewed *declarative* public-record node, where successful
observation of a defined absence can be informative. Source failure remains
unobserved. The policy covers evidence removal, not addition; a planted decoy
record can still mislead.

## Consequences

- Under the proposition's fixed local assumptions, deleting positive factors
  cannot raise local presence odds. It does not guarantee movement toward 0.5,
  a wider uncertainty band, or a globally non-confident result through the DAG.
- The self-generated benign-missing experiment records a Brier cost under its
  own observation model. It is not a real-world bound.
- Future work should compute explicit removal and planting envelopes over
  provenance classes instead of treating `LR=1` as a Manski bound or complete
  adversarial solution.
