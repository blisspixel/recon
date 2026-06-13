# ADR-0003: Lock the v2.0 JSON/MCP output contract

- **Status:** Accepted
- **Date:** 2025 (backfilled 2026-06-13); see stability.md, migration-v2.md

## Context

recon's `--json` / MCP output is consumed by scripts and LLM agents. Without a
stable contract, every internal refactor risks silently breaking consumers, and
agents can't rely on field shapes. The pre-2.0 schema-hardening (SH1–SH9) was
done specifically so the shape could be frozen without foreseeable need for a
breaking change.

## Decision

We will treat the v2.0 top-level JSON shape (and the MCP tool/resource surface)
as a **locked, stable contract**: changes are **additive only** within 2.x
(consumers ignore unknown fields), and any breaking change requires a major bump
with the deprecation window the stability policy mandates. `schema_version` is
emitted; both `recon-schema.json` copies are kept byte-identical and machine-
checked.

## Consequences

- Consumers and agents can depend on the output; additive evolution is safe.
- Genuinely contract-changing improvements (e.g. migrating MCP tools to
  `structuredContent`/`outputSchema`, or a default pagination envelope) are
  deliberately deferred to a version-noted pass rather than slipped in — even
  when individually attractive.
- A new top-level field touches a fixed set of serialization sites (cache, JSON,
  MCP, both schema copies, schema.md); that fan-out is the cost of the guarantee.
