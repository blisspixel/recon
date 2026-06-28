# ADR-0007: Keep surface inventory as discovery context

- **Status:** Accepted
- **Date:** 2026-06-26

## Context

recon now publishes `docs/surface-inventory.json`, `docs/cli-surface.md`, and
the `recon://surface-inventory` MCP resource. They are generated, packaged,
no-network discovery aids that summarize local CLI commands, MCP tools and
resources, JSON Schema pointers, agent integration files, and maintainer-loop
context.

The current standards direction supports machine-readable discovery. MCP tools
and resources carry names, descriptions, schemas, annotations, and MIME types;
the May 2026 MCP release-candidate direction strengthens tool schemas around
JSON Schema 2020-12. OpenAPI's interface-description model makes the same broad
point for HTTP APIs: a machine-readable description is valuable because a
consumer can discover capabilities without source access. JSON Schema 2020-12 is
also the current JSON Schema dialect for validation and documentation.

That does not make every generated description a stable product contract. The
surface inventory intentionally aggregates stable surfaces and non-contractual
maintainer context: `docs/.agent/PROGRESS-LOG.md`, `docs/.agent/SKILLS.md`, agent guidance, local
client-config templates, and derived approval guidance. Freezing that whole
aggregate as a v2.3 contract would make internal maintainer context harder to
improve and would force compatibility obligations before an external consumer
has a real need.

## Decision

Do not promote `docs/surface-inventory.json` or `recon://surface-inventory` to a
v2.3 stable surface now.

Keep the inventory patch-level, generated, drift-gated, packaged, and
non-contractual. It remains discovery context for agents and maintainer tools.
Stable contracts stay where they already are: the CLI behavior, the v2.0 JSON
Schema, and the documented MCP tool/resource semantics.

Promotion to a minor-version stable surface requires all of the following:

- A concrete external consumer that needs fields beyond best-effort discovery.
- A named schema/version for the smallest useful subset, not the entire
  maintainer-context aggregate.
- A compatibility policy that says which fields are stable and how additive
  changes work.
- Contract tests against that subset, including generated docs and packaged MCP
  resource output.
- Migration notes in the changelog, stability docs, and roadmap.

## Consequences

- Agents still get a current local map of recon's capabilities without network
  calls or repository-file access.
- Maintainers can evolve generated guidance, local client templates, and loop
  context without creating a breaking API change.
- A future 2.3 promotion remains available, but only after a consumer proves the
  stable subset and compatibility cost.
