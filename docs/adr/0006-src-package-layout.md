# ADR-0006: Adopt src package layout

- **Status:** Accepted
- **Date:** 2026-06-16
- **Supersedes:** ADR-0005

## Context

ADR-0005 kept the flat package layout because the project was already stable
and the migration cost did not justify itself at that point. The 2026-06
reference-grade repository pass changed that tradeoff: path-coupled tooling was
already being reviewed, and the package could move in one atomic change while
preserving the public import path and verifying wheel parity.

The published package name and import name remain `recon_tool`; only the source
tree location changed from `recon_tool/` at the repository root to
`src/recon_tool/`.

## Decision

We will keep `src/recon_tool/` as the package source layout. Tooling, docs, and
tests that point at source files should use `src/recon_tool/`; import examples
and consumer-facing APIs should continue to use `recon_tool`.

## Consequences

- Hatchling builds the package from `src/recon_tool/`.
- Pyright, ruff, fingerprint validation, traceability checks, mutation tests,
  and file-size gates use `src/recon_tool/` when they need source paths.
- Repo-root import shadowing is structurally harder, and local gates stay closer
  to installed-package behavior.
- ADR-0005 is superseded. Any future package-layout change needs a new ADR and a
  migration plan that preserves the public `recon_tool` import path unless a
  major release deliberately breaks it.
