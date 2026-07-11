# ADR-0004: A small manually encoded Bayesian network; no runtime ML

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); see correlation.md

## Context

The fusion layer turns evidence into high-level claims with uncertainty. The
options ranged from a runtime-trained model (bundled ML) to a tensor backend
(numpy/scipy) to a small, manually encoded discrete network. Opaque runtime
weights and bundled models would breach the no-shipped-baselines invariant
(ADR-0001) and make the reasoning unauditable; a tensor backend would add a heavy
dependency for a problem that doesn't need it.

## Decision

We will use a **small, manually encoded discrete Bayesian network** (nine binary
nodes) with **exact variable-elimination inference in pure Python - no numpy,
scipy, or runtime-trained model**. CPT and likelihood values are reviewed model
assumptions documented in committed data. Some were hand-elicited and some were
manually regrounded from a June 2026 development corpus. They are not
independently validated for most claims or precise to many decimals. The
post-inference uncertainty band is an evidence-strength display; it does not
carry parameter uncertainty.

## Consequences

- Every conclusion is auditable and reachable through the evidence DAG. Each
  inference query is cross-checked by enumerating the full 512-state latent
  joint; the committed harness tests a structured evidence sweep, not the full
  global evidence power set.
- No heavy dependency; the dependency floor (no numpy/pandas/scipy/ML in core)
  holds.
- Real-world validity is limited by manual specification and development-corpus
  reuse. The maintainer
  validation loop and ADR-0002 test selected behavior, but neither replaces a
  training-disjoint, predictor-input-disjoint external evaluation. The roadmap's predeclared ablation
  decides whether this layer remains primary.
