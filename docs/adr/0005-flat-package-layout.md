# ADR-0005: Keep flat package layout (not src-layout)

- **Status:** Accepted
- **Date:** 2026-06-13

## Context

Current best-practice for *new* Python packages is src-layout
(`src/<pkg>/`), which forces tests to run against the installed package and
prevents accidental imports of the working tree. recon uses flat layout
(`recon_tool/` at the repo root). The question is whether to migrate.

## Decision

We will **keep the flat layout**. recon is an established package with a stable,
locked import path (`recon_tool`, ADR-0003) and a large test suite already
running against it; the benefits src-layout would add are largely covered by our
CI installing the package and running the full gate, while a migration would
churn every import, every test path, packaging config, and tooling scopes for
little real gain. Flat layout remains acceptable for established projects.

## Consequences

- No churn to imports, packaging, or the locked schema tooling.
- We accept the small residual risk src-layout removes (accidental working-tree
  imports), mitigated by CI running against the built/installed package.
- Should the package ever be restructured for another reason, revisit this
  decision rather than treating flat layout as permanent.
