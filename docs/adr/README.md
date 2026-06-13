# Architecture Decision Records

Each ADR captures one architecturally significant, hard-to-reverse decision —
its context, the decision, and its consequences — so the *why* outlives anyone's
memory (and an AI assistant can read the rationale instead of re-deriving or
violating it). Format is Nygard's five sections; see
[`0000-template.md`](0000-template.md).

Rules:

- **One decision per record**, numbered `NNNN-kebab-title.md`.
- **Accepted ADRs are immutable.** Don't edit a decision after acceptance —
  supersede it with a new ADR and mark the old one `Superseded by ADR-NNNN`.
- **Only for significant / hard-to-reverse decisions** (invariants, contracts,
  cross-cutting design). Routine choices don't need one.

These records are the durable backbone of [engineering-practices.md](../engineering-practices.md);
deeper rationale for several lives in [correlation.md](../correlation.md),
[roadmap.md](../roadmap.md), and [stability.md](../stability.md).

| ADR | Decision |
|---|---|
| [0001](0001-passive-zero-credential.md) | Strictly passive, zero-credential collection |
| [0002](0002-mnar-adversarial-absence.md) | Treat missing evidence as adversarially missing (MNAR / LR=1) |
| [0003](0003-v2-schema-lock.md) | Lock the v2.0 JSON/MCP output contract |
| [0004](0004-small-handspecified-bayes-no-numpy.md) | A small hand-specified Bayesian network; no numpy/ML |
| [0005](0005-flat-package-layout.md) | Keep flat package layout (not src-layout) |
