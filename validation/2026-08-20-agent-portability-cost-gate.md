# Agent-Portability Model and Cost Gate

Status: deferred before collection on 2026-08-20 under the frozen stop rules.
Zero model sessions started. External spend: $0.

## Scope

This is a disclosure-safe cost and execution-gate result for the frozen v2.15
representative-client evaluation. It is not a client compatibility result, a
conformance result, or a sampled substitute for the required 30-session frame.
No prompt, response, transcript, hidden reasoning, credential, real target, or
per-session record appears here.

## Bound readiness inputs

| Input | Value |
|---|---|
| Frozen contract digest | `403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe` |
| Candidate version | `2.17.5` |
| Candidate package digest | `9cbc988480779e789da16ba9af308a45f2dcfa932f43aefa374b58f1d0300842` |
| Preflight implementation digest | `d428a99fc1845eddbb3948297734d96174e4d81a75f7a9923a0eead8c40c21a2` |
| Private preflight report digest | `29e155adcacd0449f8f45195cf504aed9101390ab51c088995bc97f8ed0e037d` |
| Visual Studio Code | `1.132.0`, ready |
| Cursor | `3.16.29`, ready |
| Kiro | `1.0.309`, ready |
| recon runtime | `2.17.5`, exact candidate version |

The network-free preflight reported `ready_for_collection: true`, zero
sessions, and zero network requests. This cleared executable and version
readiness only. It did not clear model billing or session-control gates.

## Declared model and envelope

GPT-5.6 Luna is the selected model for every required client if collection
resumes. Using one named model avoids a model-choice confound across the paired
native and portable variants. Current first-party pricing material lists Luna
for all three clients:

| Client | Current published basis | Planned external-charge sublimit |
|---|---|---:|
| Visual Studio Code with GitHub Copilot | [GitHub Copilot models and pricing](https://docs.github.com/en/copilot/reference/copilot-billing/models-and-pricing): $0.20 per million input tokens, $0.02 cached input, $0.25 cache write, $1.20 output. | $1.50 |
| Cursor | [Cursor models and pricing](https://cursor.com/docs/models-and-pricing): $0.20 per million input tokens, $0.02 cache read, $0.25 cache write, $1.20 output. Plan-specific platform treatment can still apply. | $1.50 |
| Kiro | [Kiro models](https://kiro.dev/docs/models/): 0.1x credit multiplier. [Kiro pricing](https://kiro.dev/pricing/) lists add-on credits at $0.04 per credit on eligible paid plans. | $2.00 |

The hard total external-charge ceiling is $5 across the complete evaluation for
this workday. Included plan allowance may reduce the external charge, but it is
not counted as proof of a hard stop. The complete 30-session frame must fit the
ceiling. No client, task, or variant may be removed, sampled, or substituted to
make it fit.

## Stop decision

Collection did not begin for two independent reasons:

1. The signed-in GitHub, Cursor, and Kiro usage dashboards and their active
   overage or hard-stop settings could not be verified through the available
   browser-control channel. Published rates alone do not prove that a shared
   $5 ceiling is enforceable across three accounts.
2. The environment exposes the three required desktop launchers, but no
   supported `copilot`, `cursor-agent`, or `kiro-cli` command and no
   reproducible desktop-session driver. The frozen frame requires real client
   install, discovery, launch, handshake, update, failure recovery, and task
   behavior. Replacing those clients with another CLI would violate the
   preregistration.

Actual client-visible model context is also unavailable on at least two
instrumented clients, so the separate smaller-surface decision remains
`defer` and the complete 22-tool surface remains the default.

## Resume gate

Resume only when all of the following are true at the same time:

1. Each signed-in client shows GPT-5.6 Luna as available.
2. Account-level controls or an equivalent fail-closed mechanism prove the
   $1.50, $1.50, and $2.00 sublimits, with a $5 aggregate stop.
3. A reproducible control path can run and record the exact VS Code, Cursor,
   and Kiro desktop behaviors without exposing transcripts or hidden reasoning.
4. The v2.17.5 candidate and runtime still match, or the preflight is rerun for
   the then-current candidate before any session.

Until then, portable promotion and the discovery-profile decision remain
deferred. No compatibility or conformance wording is authorized.
