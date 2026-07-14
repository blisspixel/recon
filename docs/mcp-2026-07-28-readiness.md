# MCP 2026-07-28 Readiness Plan

Status: candidate compatibility matrix complete; final adoption gate pending
Review date: 2026-07-13

The Model Context Protocol 2026-07-28 release candidate was published on
2026-05-21, with the final specification scheduled for 2026-07-28. It is a
breaking protocol release. The official Python SDK `2.0.0b1` shipped on
2026-06-30 with draft-2026 support, so the compatibility-spike trigger is now
met. recon completed the isolated candidate characterization without
publishing a prerelease dependency or implementing unused surface area.

Sources:

- [MCP 2026-07-28 release candidate blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP draft specification](https://modelcontextprotocol.io/specification/draft)
- [MCP draft changelog](https://modelcontextprotocol.io/specification/draft/changelog)
- [MCP draft caching specification](https://modelcontextprotocol.io/specification/draft/server/utilities/caching)
- [MCP Python SDK 2.0.0b1 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0b1)
- [MCP Python SDK v2 migration guide](https://py.sdk.modelcontextprotocol.io/v2/migration/)
- [MCP Python SDK release history](https://pypi.org/project/mcp/)

## Current recon Posture

recon exposes MCP as a local stdio server through one SDK compatibility
boundary:

- Server instance: `src/recon_tool/server/app.py`
- Stdio entrypoint and safety guard: `src/recon_tool/server/__init__.py`
- Client diagnostics: `src/recon_tool/mcp_client/doctor.py`
- Structured-output contract tests: `tests/test_mcp_structured_output.py`
- Live doctor tests: `tests/test_mcp_doctor.py`

The declared dependency range is `mcp>=1.28.1,<2`, and the lock resolves to
stable v1.28.1. The live doctor uses that SDK's
`ClientSession.initialize()` and `tools/list` flow. Candidate SDK v2.0.0b1
instead uses `server/discover`, `MCPServer`, `mcp_types`, snake-case Python
attributes, wire aliases, and worker threads for synchronous handlers. The
same server registration and domain logic now passes on both generations.

recon does not currently operate a remote Streamable HTTP MCP server, does not
implement MCP OAuth flows, and does not use Roots, Sampling, or MCP Logging.
Those facts materially reduce the immediate blast radius.

## Dated Compatibility Result

The isolated working-tree matrix completed on 2026-07-13. It exported the
locked production runtime constraints, replaced only the exact MCP pin, and
installed the editable working tree into a separate environment under the
gitignored `.agent/` workspace. Package installation used the configured
package index; all recon probes after installation were local and network-free.

| Exact SDK | Result | Discovery | Sync handler execution | Disposition |
|---|---|---|---|---|
| 1.0.0 | incompatible | unavailable | unavailable | Unsupported. It exposes neither server API recon requires, so the former dependency floor was not truthful. |
| 1.28.1 | pass | `initialize` | event-loop thread | Production floor and rollback line. Sixteen required checks passed; three v2-only checks were not applicable. |
| 2.0.0b1 | pass | `server/discover` | AnyIO worker thread | Candidate-compatible only. Nineteen checks passed; production remains below v2. |

Both passing rows proved the same deterministic inventory of 22 tools, five
resources, zero resource templates, and one `domain_report` prompt. The matrix
validated 44 input and output schema documents as JSON Schema 2020-12 with no
external output references, representative structured success and `ToolError`
results, all five resource reads, catalog reload concurrency, real stdio
framing, `domain_report` prompt rendering, and the live doctor. Under v2, 14
cacheable results carried valid
`ttlMs`, `cacheScope`, and `resultType` metadata, and both tested tool results
carried `resultType=complete`.

The production decision is therefore `mcp>=1.28.1,<2`. The v2 compatibility
boundary explicitly configures all six cacheable methods with the conservative
`ttlMs=0`, `cacheScope=private` policy. This means immediately stale and scoped
to one authorization context. It avoids claiming reusable freshness for
catalogs that can change through session reload or local configuration. A
longer TTL requires separate freshness evidence.

Reproduce both supported rows with:

```bash
uv run python scripts/check_mcp_compatibility.py --sdk-version 1.0.0 --sdk-version 1.28.1 --sdk-version 2.0.0b1 --require-compatible 1.28.1 --require-compatible 2.0.0b1
```

This is a candidate compatibility result, not a claim of compatibility with an
unpublished final specification or stable v2 SDK.

## RC Changes That Matter to recon

### High Relevance

- Protocol session removal and the new stateless request model.
- Removal of `initialize` / `initialized`, replaced by per-request `_meta` and
  `server/discover`.
- `resultType` requirements on results, depending on how the Python SDK
  exposes them through FastMCP.
- Mandatory `ttlMs` and `cacheScope` hints on every complete
  `server/discover`, tool list, prompt list, resource list, resource-template
  list, and resource-read result. SDK `2.0.0b1` exposes cache-hint support.
- Full JSON Schema 2020-12 for tool schemas, with external `$ref` and
  validation-boundary requirements.
- Deterministic tool, prompt, and resource listing. recon already tries to be
  deterministic; this should become an explicit test where SDK support allows.
- OpenTelemetry trace context names in `_meta`, if the SDK exposes request
  metadata to stdio servers.

### Medium Relevance

- Extensions framework. recon should advertise or implement no extension until
  a concrete MCP client and user workflow need it.
- Tasks extension. Potentially useful for long-running batch analysis later,
  but current recon lookups are bounded, synchronous tool calls from the
  client's perspective.
- MCP Apps. Useful only if recon grows an interactive UI surface, which is not
  on the current roadmap.

### Low or No Current Relevance

- Remote HTTP routing headers such as `Mcp-Method` and `Mcp-Name`. These
  matter if recon ships a remote Streamable HTTP server.
- OAuth and Dynamic Client Registration hardening. Important for MCP clients
  and remote servers, but recon's current stdio server has no OAuth surface.
- HTTP+SSE migration. recon does not ship that transport.

## Decisions

1. Keep the local stdio server as the supported MCP surface.
2. Do not implement remote Streamable HTTP, OAuth, Apps, or Tasks for this
   readiness track.
3. Keep the exact-pinned v1.28.1 and v2.0.0b1 compatibility matrix blocking in
   CI, then repeat it for the final specification and stable v2 SDK.
4. Keep production on stable v1 and `<2` until the final specification and
   stable v2 SDK pass every compatibility and release gate.
5. Build compatibility around the doctor, tool/resource discovery, schemas,
   wire aliases, and worker-thread behavior using observed SDK behavior rather
   than a speculative adapter.
6. Preserve raw structured access while adding compact agent output only for
   high-volume tools where it reduces context cost.

This decision is recorded in [ADR-0009](adr/0009-mcp-2026-readiness.md).

## Implementation Plan

### Phase 0: Stable-v1 Safety Rails

Status: complete and maintained. Production remains on stable v1; the
dependency floor is corrected to the first fully characterized release.

- Keep this readiness plan linked from the roadmap and MCP docs.
- Keep `recon mcp doctor` truthful about the currently installed SDK behavior.
- Keep tests pinning structured output, tool annotations, and server
  instructions.
- Record non-goals so future work does not add remote auth, Apps, or Tasks by
  accident.

Exit criteria:

- Roadmap links this plan.
- ADR-0009 records the decision.
- Documentation hygiene passes.

### Phase 1: Isolated SDK Compatibility Matrix

Status: complete for exact SDKs 1.28.1 and 2.0.0b1 on 2026-07-13.

Work:

- Keep a clean compatibility environment exact-pinned to `mcp==2.0.0b1`.
  Production metadata and the lock stay on stable v1.
- Keep server import, stdio startup, doctor, representative tool calls,
  resource reads, errors, schemas, structured output, and deterministic order
  green against stable v1.28.1 and v2 beta.
- Preserve the proven migration boundary for `FastMCP` to `MCPServer`,
  `mcp.types` to `mcp_types`, `ToolError`, `ToolAnnotations`, snake-case Python
  attributes, `discover()`, and wire serialization aliases.
- Verify tool, resource, prompt, and resource-read metadata objects for
  `ttlMs`, `cacheScope`, `resultType`, and 2026 schema changes.
- Keep synchronous resource handlers, shared catalogs, and caches covered under
  the v2 worker-thread execution model.
- Keep `src/recon_tool/mcp_client/doctor.py` capability-aware:
  - current SDK path: `initialize` followed by `tools/list`
  - 2026 SDK path: `server/discover` or the Python SDK helper that wraps it
- Keep error messages version-aware so a user sees which protocol path failed.
- Enforce the proven `>=1.28.1` floor and reject unsupported older releases.
- Keep `docs/mcp.md` aligned with matrix evidence.

Exit criteria:

- A dated matrix records pass, fail, migration action, and rollback pin for
  each compatibility surface.
- `recon mcp doctor` and representative client calls pass against both tested
  generations, or the matrix names the smallest required migration.
- Tests cover the legacy and 2026 discovery paths where one codebase can
  support them honestly.
- No production runtime change is made for unsupported or prerelease-only SDK
  behavior.

### Phase 2: Schema, Cache, and Compact Output

Status: candidate schema and cache requirements characterized; final stable-v2
adoption remains pending.

Trigger: Phase 1 records a viable compatibility path. The candidate SDK already
exposes cache-hint support; lack of an integration point is a compatibility
failure to resolve, not a reason to omit mandatory wire behavior.

Work:

- Verify every structured data tool still advertises an `outputSchema`.
- Add a schema guard that rejects external `$ref` use in tool output schemas.
- Add a bounded schema-depth or schema-size check if generated schema growth
  becomes measurable.
- Validate each declared tool schema and returned structured result with an
  independent JSON Schema 2020-12 validator. Do not rely on `format` as
  application-boundary semantic validation.
- Keep explicit non-negative `ttlMs` plus an accurate `cacheScope` for every
  complete cacheable operation recon exposes, including
  `server/discover`, `tools/list`, `resources/list`,
  `resources/templates/list`, and `resources/read`. Record the disposition of
  `prompts/list`; recon registers the `domain_report` prompt.
- Retain `ttlMs=0`, `cacheScope=private` until per-surface freshness and session
  mutation semantics justify a longer duration.
- Add compact detail modes for high-volume agent tools only where raw output
  remains available.

Exit criteria:

- Structured-output tests pass against the updated SDK.
- Compact outputs include omitted counts and deterministic ordering.
- Raw structured output remains backward compatible.
- Every complete cacheable response carries valid hints, including every
  resource read and each list or discovery page.
- Docs identify which tools are compact and how to request raw output.

### Phase 3: Remote Transport Only If Product Scope Changes

Trigger: a named consumer needs recon as a remote MCP server rather than a
local stdio server.

Work:

- Write a new ADR before code changes.
- Define deployment model, auth model, rate-limit model, telemetry boundary,
  and tenant data-handling boundary.
- Implement Streamable HTTP requirements, including protocol version,
  `Mcp-Method`, `Mcp-Name`, and header/body consistency tests.
- Implement OAuth or client identity handling only if the deployment requires
  it.

Exit criteria:

- Remote deployment threat model exists.
- Auth and rate-limit tests exist.
- Stdio behavior remains supported.

## Test Plan

During the beta compatibility matrix, add or adjust tests for:

- Doctor discovery path selection.
- Deterministic tool and resource ordering.
- Structured output schemas under JSON Schema 2020-12.
- No external `$ref` in tool output schemas.
- Required cache metadata on discovery, tool-list, resource-list,
  resource-template-list, and resource-read results, plus an explicit
  prompts-list disposition.
- Legacy and candidate SDK import, discovery, serialization, and worker-thread
  behavior.
- Declared dependency-floor coverage or an evidence-backed floor increase.
- Deprecated-feature absence: no Roots, Sampling, MCP Logging, or HTTP+SSE
  transport use.
- Compact-output caps, omitted counts, and raw-output preservation.

## Documentation Plan

- `docs/mcp.md`: describe the protocol version the current doctor validates.
- `docs/roadmap.md`: keep this readiness track listed under near-term
  hardening.
- `docs/adr/0009-mcp-2026-readiness.md`: record why recon keeps stable v1 in
  production until the final specification and stable v2 SDK pass the full
  gate, while preserving stdio as the supported MCP surface.
- `CHANGELOG.md`: mention the compatibility result when code, dependency
  metadata, or user-facing behavior changes.

## Non-Goals

- Do not ship a second MCP server implementation just to chase the RC.
- Do not add remote HTTP or OAuth support without a named consumer.
- Do not adopt MCP Apps or Tasks until there is a concrete workflow and client
  support.
- Do not remove existing stdio support.
- Do not weaken the passive-collection invariant or broaden target interaction
  beyond the documented DNS, default MTA-STS, and opt-in CSE/BIMI boundaries.

## Final Readiness Gate

Before claiming recon is compatible with the final MCP 2026-07-28 release:

- Local tests pass.
- `uv run python scripts/check.py` passes.
- `recon mcp doctor` passes against the stable SDK that advertises the final
  2026-07-28 protocol.
- The stable-v1 rollback pin and tested dependency floor are documented.
- Every complete cacheable result recon exposes carries valid `ttlMs` and
  `cacheScope` hints under the 2026 protocol.
- MCP docs name the supported protocol behavior accurately.
- The candidate matrix is rerun against the final specification and stable SDK,
  with any delta documented before the production dependency changes.
