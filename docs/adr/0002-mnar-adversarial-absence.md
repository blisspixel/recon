# ADR-0002: Ignore non-fired hideable bindings (`LR=1` policy)

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); corrected 2026-07-13; formalized in
  correlation.md section 3.3 and bounded by ADR-0011

## Context

Under the credential-free public-metadata collection boundary in ADR-0011, a
domain operator can choose not to publish many hideable indicators. The
publication mechanism can depend on deployment choices, disclosure policy, and
other unobserved state, so independent missingness is not justified. Calling
this adversarial missing-not-at-random (MNAR) records a plausible design
condition, not an empirically established relationship between missingness and
security maturity. The specific exchangeability and feature-independent-noise
assumptions used by reviewed conformal and noisy-label methods do not resolve
this condition. MNAR itself does not derive a unique likelihood ratio or point
posterior. Without an identified observation model, the claim is generally only
partially identified.

## Decision

For *hideable* nodes, a non-fired binding contributes a **likelihood ratio of 1**
(absence of evidence is treated as no evidence, never as evidence of absence).
This is a conservative implementation policy, not a consequence of MNAR. The
exception is a reviewed *declarative* public-record node, where successful
observation of a defined absence can be informative. Source failure remains
unobserved. The policy covers evidence removal, not addition; a planted decoy
record can still mislead.

ADR-0001 records the original passive-only intent. ADR-0011 is the current
collection-boundary decision: DNS traffic can be visible externally, MTA-STS is
the one default target-owned HTTP request, and Google CSE and BIMI certificate
requests are explicit opt-in direct probes. Those collection details do not
change the hideable-binding decision here.

## Consequences

- Under the proposition's fixed local assumptions, deleting positive factors
  cannot raise local presence odds. It does not guarantee movement toward 0.5,
  a wider uncertainty band, or a globally non-confident result through the DAG.
- The self-generated benign-missing experiment records a Brier cost under its
  own observation model. It is not a real-world bound.
- Future work should compute explicit removal and planting envelopes over
  provenance classes instead of treating `LR=1` as a Manski bound or complete
  adversarial solution.
