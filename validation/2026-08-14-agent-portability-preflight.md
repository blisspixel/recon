# v2.15 Agent-Portability Local Preflight

Status: stopped before representative-client collection on 2026-08-14.

## Scope

This is a disclosure-safe summary of one maintainer-local, network-free
preflight. It checks whether the frozen v2.15 frame can start on that machine.
It is not an Agent Plugins compatibility result, a client conformance result,
or evidence about installations outside this environment.

The full preflight report remains under the ignored
`validation/agent-portability-local/` workspace. Executable paths are omitted.
No prompt, response, transcript, hidden reasoning, credential, real target, or
per-session record appears here.

## Bound inputs

| Input | Value |
|---|---|
| Frozen contract digest | `403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe` |
| Candidate version | `2.14.0` |
| Candidate package digest | `ebbadcdb8d2965558b8836cd8a89cf0d994ed8020fa7a435920e609954baa8b7` |
| Preflight implementation digest | `e424ec0a9e27e2ee422b63c5fe983a556ee65e78f98cf50adf4e45b59daef1cf` |
| Private preflight report digest | `b0ab3db1932db421945eee6cee6428109d056c63fa1a4c86409d63dcf3d91eed` |
| Recorded at | `2026-08-14T09:35:29.002544Z` |

The frozen contract and schema-pinned candidate passed their network-free
validators before executable probing. The candidate was current against its
generated native sources.

## Result

| Required surface | Observed version | Preflight state |
|---|---:|---|
| recon executable selected for client launch | `2.6.3` | stopped: expected candidate version `2.14.0` |
| Visual Studio Code | `1.66.1` | executable and exact version observed |
| Cursor | not observed | stopped: required client unavailable |
| Kiro | `0.12.263` | executable and exact version observed |

The frozen stop rules therefore apply:

- `runtime-version-mismatch`;
- `required-client-cursor-missing`.

`ready_for_collection` is `false`. Sessions started: 0. Network requests: 0.
No native-versus-portable task, installation, discovery, launch, handshake,
update, or negative-path result was collected.

## Disposition

Do not reinterpret the two-client subset as the frozen frame and do not promote
the portable candidate. Before collection, make all three declared clients
available, select the exact recon executable those desktop clients resolve,
and rerun the preflight to a new exclusive private output. A passing preflight
only authorizes collection; it does not itself establish compatibility.

Run the preparer with an explicit runtime path. A bare `recon` under `uv run`
is unsafe for this purpose because the temporary project environment can take
precedence over the executable visible to desktop clients:

```bash
uv run python -m validation.prepare_agent_portability_evaluation \
  --runtime-command /absolute/path/resolved-by-the-clients/recon \
  --output validation/agent-portability-local/<unique-run>/preflight.json
```

The command refuses to replace an existing report, keeps output under the
ignored private root, prints no executable path, starts no client session, and
makes no network request.
