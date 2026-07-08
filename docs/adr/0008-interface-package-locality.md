# ADR-0008: Move Interface Layers To Local Packages

- **Status:** Accepted
- **Date:** 2026-07-08

## Context

The current runtime architecture has strong domain boundaries in the resolver,
source collectors, fingerprint catalog, signal engine, Bayesian inference,
posture analysis, validation harnesses, cache, and committed data files. The
weaker boundary is the interface layer. Earlier god-file decomposition reduced
single-file size, but left conceptually related implementation modules as flat
top-level siblings:

- `cli.py` plus `cli_*` modules.
- `formatter.py` plus `formatter_*` modules.
- `server.py`, `server_*`, `mcp_*`, and client doctor modules.

The local code graph built on 2026-07-08 recorded no import cycles, but it also
showed high blast radius around the interface facades:

- `recon_tool.formatter` is imported by dozens of scanned modules and remains
  the largest source module.
- `recon_tool.cli` is the console-script entry point and is imported broadly by
  CLI tests and generated-surface tooling.
- `recon_tool.server` is the public MCP facade and re-exports tool functions and
  runtime seams used by tests.

The problem is not file count by itself. The problem is locality. A maintainer
should be able to open `cli/`, `formatter/`, or `server/` and understand that
interface concern locally, without scanning prefix-named siblings across the
top-level package.

## Decision

Move interface implementation modules into packages:

- `recon_tool.cli` becomes the CLI package and remains the console-script import
  surface for `recon_tool.cli:run`.
- `recon_tool.formatter` becomes the formatter package and remains the public
  rendering and serialization import surface.
- `recon_tool.server` becomes the MCP server package and remains the public MCP
  facade.

The migration preserves stable behavior and import compatibility. Existing
public imports from `recon_tool.cli`, `recon_tool.formatter`, and
`recon_tool.server` must keep working through package `__init__.py` exports.
Old sibling implementation paths may remain as tiny compatibility shims only
when tests or documented usage prove the path is relied on directly.

## Consequences

- The top-level package becomes easier to scan because interface implementation
  details live under local packages instead of prefix conventions.
- File moves are behavior-preserving. CLI behavior, MCP behavior, JSON schema,
  generated CLI surface, and generated surface inventory must remain stable.
- The migration must be phased: formatter first, server second, CLI third.
- `models.py` and schema work are explicitly out of scope for this migration.
  `models.py` has the widest import blast radius and should not be combined
  with interface package movement.
- Architecture guards should reject new top-level `cli_*`, `formatter_*`,
  `server_*`, or `mcp_*` implementation modules after the migration, except for
  explicitly allowed compatibility shims.
- File-size ratchets should tighten after moves rather than bless moved debt.

## Verification

Each phase must pass the full local gate:

```bash
uv run python scripts/check.py
```

Each phase must also preserve:

- No import cycles in the refreshed local code graph.
- Stable public import surfaces.
- Stable generated schema.
- Stable generated CLI and surface inventory outputs, except source-location
  metadata if a guard explicitly includes it.
- Text hygiene and release-readiness rules.

