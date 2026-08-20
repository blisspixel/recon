# v2.15 Agent-Portability Evaluation Declaration

Status: frozen on 2026-08-14; contract prerequisite passed protected main;
portable candidate implemented and offline-validated; representative-client
collection not yet complete. The first maintainer-local preflight stopped before
collection. A second network-free preflight passed on 2026-08-20 with recon
2.17.4 and all three required clients, while starting zero sessions and making
zero network requests.

The candidate's version is not itself a frozen value. The portable candidate is
generated from the runtime sources, so its version tracks the package and moves
with any release; the fail-closed generator already rejects a candidate whose
version disagrees with `pyproject.toml`. What is frozen is the contract digest
`403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe`, the
standards snapshot, the client and task frame, the paired variants, the
measures, the privacy boundary, the promotion thresholds, and the stop rules.
The runtime gate is unchanged and states a relationship rather than a number:
the recon that launches each client must be the exact candidate under
evaluation. Record the observed version at collection time.

This is the preregistration for the representative-client evaluation. Its
round id and title stay `v2.15` because a preregistration's identity must not
move once frozen. The release milestone that will carry the result was
renumbered to v2.16 when unrelated default-view work shipped as v2.15; that is
a scheduling change and alters no frozen term.
It freezes the question, standards snapshot, client and task frame, paired
variants, measures, privacy boundary, promotion thresholds, and stop rules
before the portable candidate was implemented or a client session was
collected.
The authoritative machine-readable artifact is
[`agent-portability-evaluation-contract.json`](agent-portability-evaluation-contract.json).
Run its network-free validator with:

```bash
uv run python -m validation.agent_portability_contract
```

The expected digest is
`403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe`.

## Question and boundary

The primary question is whether a schema-pinned Agent Plugins package can
preserve recon's task behavior and native-client reliability across a declared
representative frame. A secondary question is whether actual client-visible
model context justifies a smaller discovery profile.

Packaging and discovery cost are separate axes. Both paired package variants
retain the complete 22-tool MCP surface. The evaluation does not change the
stable CLI, versioned JSON, MCP wire behavior, observation-capsule schema,
cache, or import surface. The tracked candidate is not installed by the PyPI
runtime wheel and does not make an Agent Plugins compatibility or conformance
claim.

## Frozen standards snapshot

The standards were checked against their official sources on 2026-08-14.
Exact response-byte and source-revision commitments make later draft movement
visible instead of silently changing the evaluation basis.

| Basis | Frozen value |
|---|---|
| Agent Plugins | v1.0.0, Status: Working Draft, source revision [bd383552095128f6effe895b9257cfd580a6d179](https://github.com/agentplugins/agent-plugins-spec/commit/bd383552095128f6effe895b9257cfd580a6d179) |
| Plugin schema | [canonical v1.0.0 schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json), 1,805 bytes, SHA-256 `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883` |
| MCP schema | [canonical v1.0.0 schema](https://agent-plugins.org/schemas/1.0.0/mcp.schema.json), 3,408 bytes, SHA-256 `6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb` |
| Agent Skills | [official specification](https://agentskills.io/specification), source revision [69ef37e9424c0a7ea9dd2293b559e43ec8176379](https://github.com/agentskills/agentskills/commit/69ef37e9424c0a7ea9dd2293b559e43ec8176379) |

The table preserves the at-freeze standards state. On 2026-08-20, Agent
Plugins v1.0.0 reports Status: Published, and both canonical schema endpoints
remain byte-identical to the frozen copies above. That external status change
does not alter the contract digest, client frame, measures, or thresholds.
The official compatible-client list has also expanded since the freeze. The
preregistered three-client frame remains fixed for this round; broader client
coverage would require a new contract rather than silently extending this one.

The frozen Agent Skills field set is `name`, `description`, `license`,
`compatibility`, `metadata`, and `allowed-tools`. The specification marks
`allowed-tools` experimental. Permissions and user experience remain
client-controlled, so no safety or portability result may depend on a client
honoring that field.

## Client selection

The selection rule is the exact intersection, at freeze time, of:

1. clients in the official
   [Agent Plugins compatible-client list](https://agent-plugins.org/compatible-clients)
   that declare both Agent Skills and MCP stdio support; and
2. clients for which recon ships a native scaffold.

That rule yields this required frame:

| Client | Native control scaffold | Run-version rule |
|---|---|---|
| Visual Studio Code | `agents/vscode/mcp.json` | Record the exact client version at collection time |
| Cursor | `agents/cursor/mcp.json` | Record the exact client version at collection time |
| Kiro | `agents/kiro/mcp.json` | Record the exact client version at collection time |

This is a purposive compatibility frame, not a market-share sample and not a
claim about every Agent Plugins client. A missing required client is not
silently substituted or dropped. It triggers the portable-promotion stop rule.

## Task and variant frame

Five fixed tasks cover the ordinary and bounded-specialist workflows that the
current surface must preserve:

| Task | Required starting tool | Essential success condition |
|---|---|---|
| Single-domain summary | `lookup_tenant` | Hedged observations with confidence and degraded-source state |
| Explanation and provenance | `lookup_tenant` with explanation output | Evidence lineage summarized without hidden reasoning |
| Posture gaps | `find_hardening_gaps` | Neutral review candidates, not vulnerability claims |
| Posture comparison | `compare_postures` | Evidence differences without an overall-security ranking |
| Bounded catalog absence | `get_fingerprints` | Exhaust the bounded local catalog path before an absence statement |

All domain prompts use IANA-reserved `.invalid` names. The catalog task uses a
synthetic service name and makes no target lookup.

Each task is run once per client against both frozen variants:

| Variant | Packaging | MCP surface |
|---|---|---|
| `native-control` | Existing client-native scaffold and native skills | Complete 22 tools |
| `portable-full` | Candidate pinned to Agent Plugins v1.0.0 and the frozen Agent Skills snapshot | Complete 22 tools |

The frame therefore contains 15 paired comparisons and 30 sessions. A smaller
surface is not a third paired variant. It remains deferred unless the separate
surface-profile gate is satisfied.

## Measures and failure cases

The blocking task measures are task success, unsupported-claim count, correct
tool selection, and complete install, discovery, launch, handshake, update,
and failure-case behavior. Round trips, discovery bytes, result bytes,
client-visible model-context bytes when instrumented, and failure-recovery
quality are diagnostics.

Serialized MCP discovery bytes are not model-context evidence. The existing
69.2 percent serialized reduction for a hypothetical seven-tool listing is a
useful size diagnostic only. It cannot support a discovery-profile decision
unless representative clients expose the actual model-visible context.

The required negative-path cases are:

| Case | Required behavior |
|---|---|
| Unsupported specification version | Clear rejection with the working native configuration unchanged |
| Invalid skill | Identify the invalid component and prevent false install or conformance success |
| Invalid MCP server entry | Reject before launch and preserve unrelated configuration |
| MCP handshake failure | Actionable failure with no silent fallback or state loss |
| Update-state preservation | Update recon-owned fields while retaining unrelated and hand-curated client state |

## Frozen decisions and stop rules

Portable packaging may be promoted only when all of these are true:

- the pinned plugin, MCP, and Agent Skills validations pass;
- all three required clients pass the declared install-through-failure matrix;
- there are zero task-success regressions;
- there are zero portable-only unsupported claims; and
- no task adds more than one round trip.

Any public wording remains qualified: "validated against the pinned Agent
Plugins v1.0.0 Working Draft snapshot" on the named clients. It must not become
an unqualified compatibility or conformance claim. Because v1.0.0 is now
Published, any result must also state that the pinned schema bytes match the
Published canonical schemas and that client behavior, not schema status, is
what the paired evaluation measures.

A smaller discovery profile may be considered only when at least two
instrumented representative clients show at least a 30 percent reduction in
actual client-visible model context, with zero task-success regression, zero
unsupported claims, and direct specialist access preserved. Otherwise the
decision is `defer` and the complete surface remains the default.

Stop rather than reinterpret the frame when a required client, task, schema,
launch, update, failure-recovery, privacy, or measurement gate is unavailable
or fails. A new question, threshold, client replacement, task, or variant
requires a dated amendment before further collection.

## Privacy and disclosure

Client session records stay under the ignored
`validation/agent-portability-local/` directory. No credential is allowed.
Transcripts and hidden reasoning are neither public artifacts nor acceptable
inputs to a public result. Public output is limited to the frozen contract, an
aggregate decision memo, the exact client-version matrix, and schema and
failure-case results. It contains no real target and no session-level prompt or
response.

## Execution order

1. Complete: merge this frozen contract, validator, tests, and documentation
   through the ordinary protected-main gate.
2. Complete: build the portable candidate without changing stable runtime
   surfaces.
3. Complete: validate the candidate offline against the byte-pinned schemas,
   exact package layout, launch contract, and portable skill rules.
4. Complete: run the network-free, private preflight with an explicit recon
   executable path, then record exact client versions. The first local preflight
   applied the frozen stop rules. The 2026-08-20 rerun passed with the matching
   runtime and all three required clients.
5. Next: declare the selected client models and hard cost ceiling, then execute
   the paired and negative-path frame without changing its rules.
6. Publish only disclosure-safe aggregate evidence and apply the frozen
   promote-or-defer decisions.

The disclosure-safe preflight results are
[`../validation/2026-08-14-agent-portability-preflight.md`](../validation/2026-08-14-agent-portability-preflight.md)
and
[`../validation/2026-08-20-agent-portability-preflight.md`](../validation/2026-08-20-agent-portability-preflight.md).

Agent Plugins remains a packaging evaluation, not an MCP protocol change.
Open Knowledge Format v0.2 remains separately deferred by
[ADR-0014](adr/0014-caller-owned-capsules-and-okf-deferral.md) until a named
consumer justifies the lifecycle, trust, freshness, and privacy mapping. This
round neither creates an OKF export nor replaces recon's authoritative
versioned JSON and caller-owned observation capsules.
