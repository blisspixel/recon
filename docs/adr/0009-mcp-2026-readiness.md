# ADR-0009: Prepare for MCP 2026-07-28 Without Premature Protocol Forking

## Status

Accepted

## Context

The MCP 2026-07-28 release candidate is a breaking protocol revision. The
release candidate removes protocol sessions and the `initialize` /
`initialized` handshake, introduces `server/discover`, changes result and list
metadata expectations, moves more capability into extensions, deprecates
Roots, Sampling, and MCP Logging, and expands tool schemas to full JSON Schema
2020-12.

recon exposes MCP as a local stdio server. It does not run a
remote Streamable HTTP MCP deployment, does not implement MCP OAuth, and does
not use Roots, Sampling, MCP Logging, Apps, Tasks, or HTTP+SSE. The risk is
therefore not that recon needs a new production transport immediately. The
risk is that a future Python SDK update changes the discovery, schema, result,
or metadata behavior that `recon mcp doctor`, MCP documentation, and structured
output tests currently pin.

## Decision

recon will keep local stdio as its supported MCP surface and will not implement
a parallel 2026-07-28 protocol stack. One narrow import and serialization
boundary may adapt the same registration and domain logic to supported SDK
generations.

Readiness work will focus on:

- Maintaining a version-aware MCP doctor.
- Preserving structured output schema tests.
- Checking deterministic tool and resource discovery.
- Adding compact agent output only for high-volume tools where raw output stays
  available.
- Avoiding deprecated Roots, Sampling, MCP Logging, and HTTP+SSE features.
- Treating remote HTTP, OAuth, Apps, and Tasks as separate future decisions
  that require a named consumer and a new ADR.

The execution plan lives in
[../mcp-2026-07-28-readiness.md](../mcp-2026-07-28-readiness.md).

## Consequences

Positive consequences:

- recon can retest final SDK behavior without a server rewrite.
- The current stable stdio MCP integration remains supported.
- The project avoids speculative transport, auth, UI, or task-scheduler code.
- Compatibility risk is concentrated in the doctor, discovery, and schema
  tests, where failures are visible.

Negative consequences:

- recon will not be an early independent implementation of the 2026-07-28 MCP
  protocol.
- Production v2 adoption cannot complete until the final specification and a
  stable v2 SDK are published and pass the full gate.
- Remote MCP consumers still need a separate design before recon can serve
  them.

## Alternatives Considered

### Implement a second MCP protocol path now

Rejected. It would duplicate SDK behavior, raise maintenance cost, and risk
shipping a pre-final interpretation of the release candidate.

### Add remote Streamable HTTP support now

Rejected. recon has no current remote-server product requirement, and remote
MCP would require a separate threat model for auth, rate limits, telemetry,
tenant data handling, and deployment operations.

### Ignore the release candidate until final

Rejected. The release candidate changes discovery, result metadata, schemas,
and deprecations in areas recon already tests and documents. Planning now keeps
the eventual SDK migration small and deliberate.

## Validation

The decision is enforced by:

- `tests/test_mcp_doctor.py`
- `tests/test_mcp_structured_output.py`
- `tests/test_mcp_tool_annotations.py`
- `tests/test_mcp_compatibility.py`
- `tests/test_server_instructions.py`
- `scripts/check_mcp_compatibility.py`
- the readiness gate in [../mcp-2026-07-28-readiness.md](../mcp-2026-07-28-readiness.md)

The exact v1.28.1 and v2.0.0b1 matrix met the candidate validation target on
2026-07-13. The final adoption target remains:

- `recon mcp doctor` passes with the updated discovery path.
- Structured tools still advertise output schemas.
- Deprecated features remain absent.
- Full repository checks pass before any compatibility claim is made.
