# ADR-0004: A small hand-specified Bayesian network; no numpy/ML

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); see correlation.md

## Context

The fusion layer turns evidence into high-level claims with uncertainty. The
options ranged from a learned model (trained weights, bundled ML) to a tensor
backend (numpy/scipy) to a small, hand-specified discrete network. Learned
weights and bundled models would breach the no-shipped-baselines invariant
(ADR-0001) and make the reasoning unauditable; a tensor backend would add a heavy
dependency for a problem that doesn't need it.

## Decision

We will use a **small, hand-specified discrete Bayesian network** (nine binary
nodes) with **exact variable-elimination inference in pure Python — no numpy,
scipy, or ML**. CPT values are directionally-accurate, corpus-grounded estimates
documented in a priors ledger, with the credible interval carrying the residual
uncertainty; they are not learned and not precise to many decimals.

## Consequences

- Every conclusion is auditable by hand and reachable through the evidence DAG;
  the network is small enough to verify exhaustively (differential verification
  against the full joint, 512 states).
- No heavy dependency; the dependency floor (no numpy/pandas/scipy/ML in core)
  holds.
- Accuracy is bounded by hand-specification, mitigated by the maintainer
  validation loop (re-grounding priors) and the honest-uncertainty stance
  (ADR-0002) rather than by training.
