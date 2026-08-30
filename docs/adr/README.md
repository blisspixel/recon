# Architecture Decision Records

Each ADR captures one architecturally significant, hard-to-reverse decision:
its context, the decision, and its consequences, so the *why* outlives anyone's
memory (and an AI assistant can read the rationale instead of re-deriving or
violating it). Format is Nygard's five sections; see
[`0000-template.md`](0000-template.md).

Rules:

- **One decision per record**, numbered `NNNN-kebab-title.md`.
- **Accepted ADRs are immutable.** Don't edit a decision after acceptance;
  supersede it with a new ADR and mark the old one `Superseded by ADR-NNNN`.
- **Only for significant / hard-to-reverse decisions** (invariants, contracts,
  cross-cutting design). Routine choices don't need one.

These records are the durable backbone of [engineering-practices.md](../engineering-practices.md);
deeper rationale for several lives in [correlation.md](../correlation.md),
[roadmap.md](../roadmap.md), and [stability.md](../stability.md).

| ADR | Decision |
|---|---|
| [0001](0001-passive-zero-credential.md) | Strictly passive, zero-credential collection, superseded by ADR-0011 |
| [0002](0002-mnar-adversarial-absence.md) | Ignore non-fired hideable bindings (`LR=1` policy) |
| [0003](0003-v2-schema-lock.md) | Lock the v2.0 JSON/MCP output contract |
| [0004](0004-small-handspecified-bayes-no-numpy.md) | A small manually encoded Bayesian network; no runtime ML |
| [0005](0005-flat-package-layout.md) | Keep flat package layout (not src-layout), superseded by ADR-0006 |
| [0006](0006-src-package-layout.md) | Adopt src package layout |
| [0007](0007-surface-inventory-discovery-context.md) | Keep surface inventory as discovery context |
| [0008](0008-interface-package-locality.md) | Move interface layers to local packages |
| [0009](0009-mcp-2026-readiness.md) | Prepare for MCP 2026-07-28 without premature protocol forking |
| [0010](0010-evidence-gated-native-acceleration.md) | Keep the default runtime pure Python and evidence-gate any optional native accelerator |
| [0011](0011-public-metadata-collection-boundary.md) | Define the public-metadata collection boundary and target-visible interactions |
| [0012](0012-default-view-evidence-role-visibility.md) | Split evidence-role visibility between the default and detailed views |
| [0013](0013-fusion-non-promotion-and-v3-transition.md) | Apply fusion non-promotion through a compatible v2 transition and flip the implicit default only at v3 |
| [0014](0014-caller-owned-capsules-and-okf-deferral.md) | Use caller-owned JSON observation capsules and defer OKF until a named consumer justifies an additive projection |
| [0015](0015-role-split-vendor-claims-in-the-default-view.md) | Split a mail vendor and a differing identity vendor into roled rows instead of one unroled Provider row |
| [0016](0016-plain-emits-the-panel-record.md) | Make `--plain` the panel linearised, with the complete record behind `--plain --full` |
| [0017](0017-one-briefing-in-every-shape.md) | Render one shared briefing on every human surface and gate it with a cross-surface parity matrix |
| [0018](0018-namespace-review-bundle-v1.md) | Define one bounded, caller-owned single-namespace review artifact with explicit collection validity and lineage |
