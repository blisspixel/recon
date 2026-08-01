# MCP 2026-07-28 Readiness Plan

Status: adopted. Production serves MCP 2026-07-28 on the v2 SDK; 1.28.1
remains the rollback pin and stays blocking in the compatibility matrix
Review date: 2026-07-28

The Model Context Protocol 2026-07-28 specification and official Python SDK
`2.0.0` were published on 2026-07-28. This is a breaking protocol release.
recon first completed the isolated final characterization without widening the
production dependency or implementing unused surface area, then adopted v2
after the 2026-07-31 production review. The earlier candidate result remains
documented below as migration history.

Sources:

- [MCP 2026-07-28 release candidate blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP current documentation](https://modelcontextprotocol.io/docs/getting-started/intro)
- [MCP Python SDK 2.0.0 release](https://pypi.org/project/mcp/2.0.0/)
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

The declared production dependency is `mcp>=2.0.0,<3`, and the lock resolves to
stable v2.0.0. Stable v2 uses `server/discover`, `MCPServer`, `mcp_types`,
snake-case Python attributes, wire aliases, and worker threads for synchronous
handlers. Exact v1.28.1 remains the tested rollback pin and uses
`ClientSession.initialize()` plus `tools/list`. The same server registration
and domain logic pass on both generations.

recon does not currently operate a remote Streamable HTTP MCP server, does not
implement MCP OAuth flows, and does not use Roots, Sampling, or MCP Logging.
Those facts materially reduce the immediate blast radius.

## Dated Compatibility Results

The candidate isolated working-tree matrix completed on 2026-07-13. The final
stable matrix completed on 2026-07-28. Each run exported the
locked production runtime constraints, replaced only the exact MCP pin, and
installed the editable working tree into a separate environment under the
gitignored `.agent/` workspace. Package installation used the configured
package index; all recon probes after installation were local and network-free.

| Exact SDK | Result | Discovery | Sync handler execution | Disposition |
|---|---|---|---|---|
| 1.0.0 | incompatible | unavailable | unavailable | Unsupported. It exposes neither server API recon requires, so the former dependency floor was not truthful. |
| 1.28.1 | pass | `initialize` | event-loop thread | Tested rollback line. Seventeen checks pass; seven v2-only checks are correctly not applicable. |
| 2.0.0b1 | pass | `server/discover` | AnyIO worker thread | Historical candidate checkpoint from 2026-07-13. |
| 2.0.0 | pass | `server/discover` | AnyIO worker thread | Production line adopted 2026-07-31. All 24 compatibility checks pass. |

The passing rows proved the same deterministic inventory of 22 tools, five
resources, zero resource templates, and one `domain_report` prompt. The matrix
validated 44 input and output schema documents as JSON Schema 2020-12 with no
external output references, representative structured success and `ToolError`
results, all five resource reads, catalog reload concurrency, real stdio
framing, `domain_report` prompt rendering, and the live doctor. Under v2, 14
cacheable results carried valid
`ttlMs`, `cacheScope`, and `resultType` metadata, and both tested tool results
carried `resultType=complete`.

The production decision is `mcp>=2.0.0,<3`, with exact v1.28.1 retained as the
rollback pin. The v2 compatibility
boundary explicitly configures all six cacheable methods with the conservative
`ttlMs=0`, `cacheScope=private` policy. This means immediately stale and scoped
to one authorization context. It avoids claiming reusable freshness for
catalogs that can change through process-wide reload or local configuration. A
longer TTL requires separate freshness evidence.

Reproduce both supported rows with:

```bash
uv run python scripts/check_mcp_compatibility.py --sdk-version 1.0.0 --sdk-version 1.28.1 --sdk-version 2.0.0 --require-compatible 1.28.1 --require-compatible 2.0.0
```

The matrix itself is compatibility evidence. The later adoption review below
is the production dependency decision.

## RC Changes That Matter to recon

### High Relevance

- Protocol session removal and the new stateless request model.
- Removal of `initialize` / `initialized`, replaced by per-request `_meta` and
  `server/discover`.
- `resultType` requirements on results, depending on how the Python SDK
  exposes them through FastMCP.
- Mandatory `ttlMs` and `cacheScope` hints on every complete
  `server/discover`, tool list, prompt list, resource list, resource-template
  list, and resource-read result. SDK `2.0.0` exposes cache-hint support.
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
3. Keep the exact-pinned stable v1.28.1 and v2.0.0 compatibility matrix
   blocking in CI.
4. Run production on stable v2 after the adoption gate; retain exact v1.28.1 as
   the blocking rollback row.
5. Build compatibility around the doctor, tool/resource discovery, schemas,
   wire aliases, and worker-thread behavior using observed SDK behavior rather
   than a speculative adapter.
6. Preserve raw structured access while adding compact agent output only for
   high-volume tools where it reduces context cost.

This decision is recorded in [ADR-0009](adr/0009-mcp-2026-readiness.md).

## Adoption Review, 2026-07-31

A first adoption review ran the production pin at `mcp>=2.0.0,<3` end to end
against the real specification rather than against release notes. Recording it
here so the next review starts from evidence instead of repeating the work.

What held up. The stdio server ran clean on v2: `recon mcp doctor` reported
protocol `2026-07-28`, all 22 tools and 5 resources registered in the same
deterministic order, and the compatibility gate passed every check on both
1.28.1 and 2.0.0. Five wire-level probes were added to that gate so the modern
requirements rest on recon's own evidence: dual-era `initialize` serving,
`-32602` for a request missing the required `_meta` envelope, `-32022` with the
supported-version list for an unsupported version, `-32602` rather than the
retired `-32002` for an unknown resource, and a `server/discover` payload
carrying instructions and server identity. No SDK nonconformance was found.

What blocked adoption, and how it was cleared. `build_remote_application`
refused any SDK family but v1, so moving the pin would have disabled the
optional remote adapter rather than degraded it. The adapter has since been
ported and the guard removed. Two differences had to move into `sdk_compat`:
the read-only allow-list read `annotations.readOnlyHint`, which does not exist
as an attribute on v2, so every tool looked non-read-only and the remote
surface would have come up empty; and the transport options moved from a
mutable `settings` object to keyword arguments on `streamable_http_app`.

Adoption landed on 2026-07-31. Both compatibility rows stay blocking: 24 of 24
checks pass on 2.0.0, and 17 pass with 7 correctly reported not-applicable on
1.28.1.

Two defects the review found and fixed under the v1 pin, because both are
era-independent:

- The doctor read server identity from a top-level `serverInfo` field. This
  revision moves it into `_meta` under `io.modelcontextprotocol/serverInfo`, so
  the doctor printed a bare `?` for a server that was identifying itself
  correctly. It now accepts both locations.
- recon set no application version, so a v2 server advertised
  `version: ""` and a client could not tell which recon it was connected to.

One trap worth recording for whoever does the migration. The two generations
spell tool annotations differently: v1 declares `readOnlyHint` as the field,
while v2 declares `read_only_hint` with `readOnlyHint` as an alias. Passing the
snake_case spelling to v1 does not raise. Pydantic stores it as an unrelated
extra attribute and leaves the real hint unset, so a mechanical rename would
have silently dropped every tool annotation on the rollback pin. Only the
camelCase spelling is read by both, and it is now produced in one place by
`sdk_compat.tool_annotations` instead of at each of the 22 registrations.

Cache hints stay at `ttlMs=0`, which is conformant. `reload_data` and ephemeral
injection can change what the cacheable methods return at any point in a
process's life, so a positive TTL would let a client serve a catalog recon knows
is stale. Raising it is a measured optimization, not a default.

## Implementation Plan

### Phase 0: Stable-v1 Safety Rails

Status: complete and maintained. Production runs on stable v2; exact v1.28.1
remains the first fully characterized rollback release.

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

Status: complete for exact stable SDKs 1.28.1 and 2.0.0 on 2026-07-28.

Work:

- Keep clean compatibility environments exact-pinned to `mcp==1.28.1` and
  `mcp==2.0.0` without mutating production metadata or the active lock.
- Keep server import, stdio startup, doctor, representative tool calls,
  resource reads, errors, schemas, structured output, and deterministic order
  green against stable v1.28.1 and stable v2.0.0.
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

Status: complete; final stable-v2 schema and cache requirements are
characterized and production adoption landed on 2026-07-31.

Trigger: Phase 1 records a viable compatibility path. The stable SDK
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
- Retain `ttlMs=0`, `cacheScope=private` until per-surface freshness and
  process-mutation semantics justify a longer duration.
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

The compatibility matrix covers tests for:

- Doctor discovery path selection.
- Deterministic tool and resource ordering.
- Structured output schemas under JSON Schema 2020-12.
- No external `$ref` in tool output schemas.
- Required cache metadata on discovery, tool-list, resource-list,
  resource-template-list, and resource-read results, plus an explicit
  prompts-list disposition.
- Legacy and stable-v2 SDK import, discovery, serialization, and worker-thread
  behavior.
- Declared dependency-floor coverage or an evidence-backed floor increase.
- Deprecated-feature absence: no Roots, Sampling, MCP Logging, or HTTP+SSE
  transport use.
- Compact-output caps, omitted counts, and raw-output preservation.

## Documentation Plan

- `docs/mcp.md`: describe the protocol version the current doctor validates.
- `docs/roadmap.md`: keep this readiness track listed under near-term
  hardening.
- `docs/adr/0009-mcp-2026-readiness.md`: preserve stdio as the supported MCP
  surface, record the v2 adoption, and retain v1.28.1 as the rollback pin.
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

Status: compatibility gate passed on 2026-07-28 and production adoption passed
on 2026-07-31. Before any future major dependency change:

- Local tests pass.
- `uv run python scripts/check.py` passes.
- `recon mcp doctor` passes against the stable SDK that advertises the final
  2026-07-28 protocol.
- The stable-v1 rollback pin and tested dependency floor are documented.
- Every complete cacheable result recon exposes carries valid `ttlMs` and
  `cacheScope` hints under the 2026 protocol.
- MCP docs name the supported protocol behavior accurately.
- The exact stable v1.28.1 and v2.0.0 matrix remains blocking in CI, with any
  future delta documented before the production dependency changes.
