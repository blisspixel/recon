# MCP 2026-07-28 Readiness Plan

Status: active readiness plan
Review date: 2026-07-09

The Model Context Protocol 2026-07-28 release candidate was published on
2026-05-21, with the final specification scheduled for 2026-07-28. It is a
breaking protocol release. recon should get ahead of it without implementing
unstable or unused surface area.

Sources:

- [MCP 2026-07-28 release candidate blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP draft specification](https://modelcontextprotocol.io/specification/draft)
- [MCP draft changelog](https://modelcontextprotocol.io/specification/draft/changelog)

## Current recon Posture

recon currently exposes MCP as a local stdio FastMCP server:

- Server instance: `src/recon_tool/server/app.py`
- Stdio entrypoint and safety guard: `src/recon_tool/server/__init__.py`
- Client diagnostics: `src/recon_tool/mcp_client/doctor.py`
- Structured-output contract tests: `tests/test_mcp_structured_output.py`
- Live doctor tests: `tests/test_mcp_doctor.py`

The current dependency range is `mcp>=1.0,<2`. The live doctor uses the
currently installed Python SDK's `ClientSession.initialize()` and `tools/list`
flow. This is correct for the installed SDK, but the 2026-07-28 release
candidate removes the `initialize` / `initialized` handshake at the protocol
level and introduces `server/discover`.

recon does not currently operate a remote Streamable HTTP MCP server, does not
implement MCP OAuth flows, and does not use Roots, Sampling, or MCP Logging.
Those facts materially reduce the immediate blast radius.

## RC Changes That Matter to recon

### High Relevance

- Protocol session removal and the new stateless request model.
- Removal of `initialize` / `initialized`, replaced by per-request `_meta` and
  `server/discover`.
- `resultType` requirements on results, depending on how the Python SDK
  exposes them through FastMCP.
- `ttlMs` and `cacheScope` on list and resource-read results, if exposed by
  the SDK.
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
3. Wait for official Python SDK support before changing runtime protocol code.
4. Build compatibility around the doctor, tool/resource discovery, and schema
   checks as soon as the SDK exposes the 2026-07-28 behavior.
5. Preserve raw structured access while adding compact agent output only for
   high-volume tools where it reduces context cost.

This decision is recorded in [ADR-0009](adr/0009-mcp-2026-readiness.md).

## Implementation Plan

### Phase 0: Ready Now

No dependency bump. No runtime protocol change.

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

### Phase 1: SDK Compatibility Branch

Trigger: the Python MCP SDK publishes support for the 2026-07-28 final spec or
a release-candidate build that exposes the relevant server APIs.

Work:

- Create a branch dedicated to SDK compatibility.
- Try the SDK update without widening unrelated dependencies.
- Inspect FastMCP's `list_tools`, `list_resources`, and resource-read metadata
  objects for `ttlMs`, `cacheScope`, `resultType`, and 2026 schema changes.
- Update `src/recon_tool/mcp_client/doctor.py` so the live check can use the
  installed SDK's supported discovery path:
  - current SDK path: `initialize` followed by `tools/list`
  - 2026 SDK path: `server/discover` or the Python SDK helper that wraps it
- Keep error messages version-aware so a user sees which protocol path failed.
- Update `docs/mcp.md` only after the code path is proven.

Exit criteria:

- `recon mcp doctor` passes against the updated SDK.
- `tests/test_mcp_doctor.py` covers both the legacy and 2026 discovery names
  where practical, or conditionally asserts the installed SDK's supported path.
- No runtime change is made for unsupported SDK behavior.

### Phase 2: Schema, Cache, and Compact Output

Trigger: Phase 1 passes locally and FastMCP exposes enough metadata hooks.

Work:

- Verify every structured data tool still advertises an `outputSchema`.
- Add a schema guard that rejects external `$ref` use in tool output schemas.
- Add a bounded schema-depth or schema-size check if generated schema growth
  becomes measurable.
- If the SDK exposes cache metadata, set conservative list/resource cache
  values for deterministic no-network surfaces:
  - fingerprints
  - signals
  - profiles
  - schema
  - surface inventory
- Add compact detail modes for high-volume agent tools only where raw output
  remains available.

Exit criteria:

- Structured-output tests pass against the updated SDK.
- Compact outputs include omitted counts and deterministic ordering.
- Raw structured output remains backward compatible.
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

When SDK support lands, add or adjust tests for:

- Doctor discovery path selection.
- Deterministic tool and resource ordering.
- Structured output schemas under JSON Schema 2020-12.
- No external `$ref` in tool output schemas.
- Cache metadata on list/resource results if SDK exposes it.
- Deprecated-feature absence: no Roots, Sampling, MCP Logging, or HTTP+SSE
  transport use.
- Compact-output caps, omitted counts, and raw-output preservation.

## Documentation Plan

- `docs/mcp.md`: describe the protocol version the current doctor validates.
- `docs/roadmap.md`: keep this readiness track listed under near-term
  hardening.
- `docs/adr/0009-mcp-2026-readiness.md`: record why recon waits for SDK
  support and preserves stdio as the supported MCP surface.
- `CHANGELOG.md`: mention only when code or user-facing docs change in a
  release.

## Non-Goals

- Do not ship a second MCP server implementation just to chase the RC.
- Do not add remote HTTP or OAuth support without a named consumer.
- Do not adopt MCP Apps or Tasks until there is a concrete workflow and client
  support.
- Do not remove existing stdio support.
- Do not weaken the passive-only invariant or broaden target interaction.

## Final Readiness Gate

Before claiming recon is compatible with MCP 2026-07-28:

- Local tests pass.
- `uv run python scripts/check.py` passes.
- `recon mcp doctor` passes against an SDK that advertises 2026-07-28 support.
- MCP docs name the supported protocol behavior accurately.
- The roadmap no longer describes the work as pending.
