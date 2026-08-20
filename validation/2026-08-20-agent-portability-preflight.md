# v2.15 Agent-Portability Local Preflight Rerun

Status: ready for representative-client collection on 2026-08-20.

## Scope

This is a disclosure-safe summary of one maintainer-local, network-free
preflight rerun. It checks whether the frozen v2.15 frame can start on that
machine. It is not an Agent Plugins compatibility result, a client conformance
result, or evidence about installations outside this environment.

The full preflight report remains under the ignored
`validation/agent-portability-local/` workspace. Executable paths are omitted.
No prompt, response, transcript, hidden reasoning, credential, real target, or
per-session record appears here.

## Bound Inputs

| Input | Value |
|---|---|
| Frozen contract digest | `403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe` |
| Candidate version | `2.17.4` |
| Candidate package digest | `e81a7570478e95ee6d118e7d2fea3009d4956aa9e70f55a89b0a6a803df98b63` |
| Preflight implementation digest | `d428a99fc1845eddbb3948297734d96174e4d81a75f7a9923a0eead8c40c21a2` |
| Private preflight report digest | `8ae8de2ad52d3d38cecfb38b549339b03ab55d45e110968a1065403325b15f44` |
| Recorded at | `2026-08-20T16:27:39.516669Z` |

The frozen contract and schema-pinned candidate passed their network-free
validators before executable probing. The candidate was current against its
generated native sources. The canonical Agent Plugins v1.0.0 schema endpoints
were separately checked on 2026-08-20 and remained byte-identical to the frozen
copies. Version 1.0.0 now reports Status: Published. The contract preserves the
at-freeze Working Draft status as historical evidence.

## Result

| Required surface | Observed version | Preflight state |
|---|---:|---|
| recon executable selected for client launch | `2.17.4` | ready: exact candidate version |
| Visual Studio Code | `1.132.0` | ready: executable and exact version observed |
| Cursor | `3.16.29` | ready: executable and exact version observed |
| Kiro | `1.0.309` | ready: executable and exact version observed |

`ready_for_collection` is `true`. Sessions started: 0. Network requests: 0.
No native-versus-portable task, installation, discovery, launch, handshake,
update, or negative-path result was collected.

## Disposition

The runtime and required-client stop conditions recorded in the 2026-08-14
preflight are cleared for this environment. This authorizes the frozen paired
collection to start, but establishes no client compatibility or conformance.

Before collection, declare the exact model used by each client and a hard total
cost ceiling. Do not begin a session whose marginal cost cannot be bounded. Run
all 30 frozen sessions only if the complete frame fits that ceiling; otherwise
defer without shrinking, substituting, or selectively sampling the frame.
