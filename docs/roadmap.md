# Roadmap

This file is forward-looking. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md); release mechanics belong in
[release-process.md](release-process.md).

## What's next (short version)

recon is in a deepen-not-expand phase: the engine, schema, and assurance track
are all locked and shipped, so there is no headline feature in flight. The
remaining work makes what exists more trustworthy rather than larger, which is
why the version number now climbs slowly and deliberately. The committed
post-2.0 assurance track is **complete**; what is left is operator-paced or
standing, in dependency order:

1. **Calibration corpus passes** (maintainer-local, aggregate-only,
   patch-level). *Done (2026-06):* the core runs landed against the private
   corpus (aggregates in
   `validation/2026-06-23-full-corpus-calibration.md`), calibrating the
   email-policy and M365-tenancy nodes against authoritative external labels:
   strong but DMARC-anchored for the policy node, the clean DMARC-disjoint
   residual *disconfirmed* (ECE 0.373), and a strong channel-split tenancy
   corroboration (ECE 0.048). They do not upgrade the 80% intervals to
   frequentist coverage; that stays a separate, unclaimed property. The optional
   C3 CT-enabled full-corpus pass remains.
2. **Fingerprint and motif triage loop** (maintainer-local, optional, reviewed).
   *Why:* keeps the catalog growing from observed gaps, not invented entries.
   Stays patch-level unless it adds a stable surface; catalog changes still get
   human review. The 2026-06-25 pass tightened candidate filtering so sample
   terminals and chain hops are checked against existing patterns, then promoted
   public-source-backed surfaces for UltraDNS Web Forwarding via
   `crs.ultradns.net` and Squarespace managed subdomains via
   `ext-sq.squarespace.com`. The remaining private aggregate candidates are held
   for later review because they are target-owned, generic platform internals,
   unclear, deprecated, or not yet backed by stable public vendor docs.
3. **Surface-inventory promotion decision.** *Why:* `surface-inventory.json` is
   already generated and drift-gated as discovery context. It only graduates to
   a 2.3 *stable surface* if a concrete consumer needs machine-readable fields
   beyond best-effort local discovery; until then it stays patch-level.
4. **arXiv write-up** (aspirational, off the critical path). *Why:* packages the
   existing rigor for an outside reader within the no-real-data publication rule.

Anything that would force a minor bump (2.3) waits for a coherent new *stable
surface*; a major bump (3.0) is reserved for an unavoidable breaking change that
does not currently exist. The permanently out-of-scope boundary (active
scanning, paid APIs, credentialed access, hosted service, remote MCP) is not
version-gated; see [Intentionally Out Of Scope](#intentionally-out-of-scope).
Full detail and sequencing live in
[Build order for the remaining work](#build-order-for-the-remaining-work) and
[Version milestones and build order](#version-milestones-and-build-order) below.

> **Before adding a rule or an agentic behavior, read
> [agentic-balance.md](agentic-balance.md).** recon's observe-infer-report core
> is rules-based by invariant; agent judgment belongs outside it (the MCP
> consumer, maintainer loops). Most of our self-inflicted wounds were brittle
> rules that should have been principled rules, not rules that should have been
> agentic. That doc is the standing decision guide and the catalog of
> brittle-rule smells; keep it current as the boundary moves.

> **Status (2026-06):** v2.2.14 is the current release (boundary-aware hostname
> matching for Google identity routing and IdP display names, plus Exchange
> Online DKIM attribution by hostname suffix; shipped 2026-06-26 to PyPI).
> v2.2.13 was the prior release (the profile `signal_boost` /
> `exclude_signals` fix so `--profile` reweighting fires against posture
> observations instead of inert signal-name keys, the SPF multi-record
> include-count fix, the schema source-map `--json` audit, and the Windows
> text-hygiene local/CI parity fix; shipped 2026-06-26 to PyPI). v2.2.12
> (2026-06-25) was the release before that (safe MCP launch guidance, README license
> wording cleanup, private validation-output root guards, maintainer-loop
> side-effect and resume boundaries, and the v2.2.11 scorer, DMARC rua
> report-size, delta exit-code, delta signal-diffing, validator, CT-cache, and
> SPF-parse determinism fixes). The v2.2 line delivered the evidence-semantics diagnostics (per-node
> entropy reduction, exact leave-one-unit-out counterfactuals, graph partition
> stability), the MCP tool-output contract revision (navigable
> `structuredContent` + per-tool `outputSchema` + `isError` across the eighteen
> data tools, aligned to MCP 2025-11-25), the 2026 CLI-ergonomics pass, and OSC 8
> hyperlinks. The v2.0 schema lock, the v2.1 cohort summary
> (`recon batch --summary`), and the v2.1.x through v2.2.9 hardening, security,
> and assurance work have all shipped; per-release detail is in
> [CHANGELOG.md](../CHANGELOG.md) and upgrade notes in
> [migration-v2.md](migration-v2.md).
>
> **Unreleased on `main` (toward the next patch):** no committed user-facing
> runtime changes after v2.2.14; the bundled Homebrew formula pins the
> published 2.2.14 sdist and sha256.
>
> **Boundary-unaware-substring hardening shipped in v2.2.14:** IdP-name
> extraction matches vendor hosts by hostname suffix, Google identity redirect
> routing parses the final URL host before deciding whether the flow left
> Google, and Exchange Online DKIM attribution matches `onmicrosoft.com` /
> `protection.outlook.com` by suffix (validated aggregate-only against the
> corpus, memo `validation/2026-06-26-onmicrosoft-suffix-match.md`). The other
> vendor-host substring checks (`outlook.com`, `google.com`, and the SRV-based
> Microsoft patterns) were validated against the same corpus evidence, showed
> zero non-suffix matches, and are left unchanged per the mirror-not-fitter
> discipline.
>
> **Post-2.0 assurance track, in priority order:** the first three are done.
> Differential verification of the inference core shipped in v2.1.7; the 2026-06
> fault-injection sweep closed four confirmed ingestion-boundary gaps (v2.1.8 made
> the CSE/BIMI direct probes opt-in so the default is passive; v2.1.9 added a gzip
> decompression-bomb guard, deeply-nested-JSON handling in the cache and CT
> providers, and a CT-graph entry-count bound); and the hostile-input fuzz CI gate
> plus per-parser resource-bound tests shipped in v2.1.10, with the residual
> per-parser bounds and the OIDC/Azure region cap in v2.1.11. Reproducible builds
> (SOURCE_DATE_EPOCH, CI-gated) and sigstore-signed PyPI attestations shipped in
> v2.1.12 (see [supply-chain.md](supply-chain.md)), the auditable assurance case
> and operational contract in v2.1.13, and the PV2 maintainer-validation loop with
> a committed, CI-gated inference drift gate in v2.1.14 (see
> [maintainer-validation.md](maintainer-validation.md)). The credible-interval
> perturbation-coverage gate shipped in v2.1.15
> (`validation/interval_coverage.py`, gated by
> `tests/test_interval_coverage.py`, memo in
> `validation/interval-coverage.md`), and the mutation gate in v2.1.16
> (cosmic-ray over the inference core, blocking in
> `.github/workflows/mutation.yml`; the corrected baseline, the
> equivalent-mutant classification, and the honest score floor are in
> `validation/mutation-gate.md`, which also records why v2.1.16's first
> reported kill score was a wrong-interpreter artifact). The traceability matrix
> shipped in v2.1.17 (`docs/traceability-matrix.md`, machine-checked by
> `scripts/check_traceability.py` and gated by `tests/test_traceability.py`),
> which completes the committed post-2.0 assurance track. v2.1.18 was UX and docs
> polish (the services-panel label-collision fix, the rotating-spinner variety,
> and the aspirational arXiv-paper roadmap item below). Since v2.1.18 the
> docs-and-validation track has closed most of what remained: the
> suppression-monotonicity proposition is now formalized in `correlation.md`
> section 4.3 and machine-checked by `validation/adversarial_properties.py` (the
> one formal result, that hiding evidence can only move a claim toward its
> all-absent baseline, never to a confident false positive by hiding); the
> CAL3/CAL4 reference-calibration run landed (`email_security_policy_enforcing`
> full-posterior calibration strong but DMARC-anchored, the clean residual
> disconfirmed by the 2026-06 full-corpus run); and the data-handling
> policy and statistical-assurance dossier docs shipped. The calibration
> harness set is now complete: the conformal-coverage complement
> (`validation/conformal_coverage.py`), the leave-one-unit-out inference
> primitive (`infer(..., masked_units=...)`) with the held-out residual mode in
> the reference calibration, and the tenancy corroboration harness
> (`validation/tenancy_reference_calibration.py`; M365 two-class via the
> channel split, GWS honestly one-sided) all ship with unit-tested pure logic.
> The evidence-semantics diagnostics (the 2.2 surface) were the headline of
> v2.2.0, shipped 2026-06-13 alongside the MCP structured-output contract
> revision and OSC 8 hyperlinks.
>
> **Post-2.2.0, the god-file decomposition track ran as the active engineering
> work and is now complete** (see the dedicated section below): `formatter.py` is
> down from 4413 to ~2160 lines across five extracted modules (`formatter_exposure`,
> `formatter_classify`, `formatter_classify_tables`, `formatter_markdown`,
> `formatter_serialize`); `cli.py` is down from 3941 to ~2830 with its four
> Typer sub-apps split into sibling modules; and the two modules just over the
> cap are now under it — `exposure.py` (1130 → 983, result dataclasses to
> `exposure_models.py`) and `merger.py` (1131 → 958, slug tables to
> `merger_tables.py`). `sources/dns.py` is now fully decomposed and under the
> cap (2524 → 840) across four extracted leaves — `dns_tables` (static catalogs
> + pure parsers), `dns_base` (resolver primitives + `DetectionCtx`),
> `dns_email` (SPF/MX/DKIM/DMARC/BIMI/MTA-STS detectors), and `dns_infra`
> (M365/GWS CNAME, NS/CNAME/hosting/CAA/SRV, CT fallback) — leaving `dns.py`
> as the `DNSSource` orchestrator plus its surface-classification pipeline.
> `bayesian.py` is likewise decomposed and under the cap (1411 → 926): the
> result dataclasses moved to `bayesian_models.py` and the YAML loaders to
> `bayesian_loader.py`, leaving the inference engine in place so the
> mutation-gated surface stays byte-identical. `server.py` is likewise
> decomposed and under the cap (2859 → 406) via the app-sharing variant: the
> shared FastMCP instance and resolve seam moved to `server_app.py`, the runtime
> state to `server_runtime.py`, and the MCP tools into per-domain modules
> (`server_ephemeral`, `server_lookup`, `server_posture`, `server_graph`,
> `server_introspection`), all registering on the shared instance. And `cli.py`
> is decomposed and under the cap (2800 → 702): its command-implementation
> helper families moved to `cli_lookup` / `cli_batch` / `cli_doctor`, with the
> Typer app and the thin `@app.command` wrappers staying in `cli.py` (the
> helpers use `get_console()` rather than module state, so a plain leaf split and
> an assignment facade sufficed, no app-sharing needed). **The planned god-file
> decomposition track is now complete:** every module the 2026 metrics pass
> flagged has been split and is under the 1000-line cap, except `formatter.py`
> (~2160), whose remaining cohesive Rich panel core is deliberately kept whole
> and ratchet-capped rather than fragmented. Every split was
> golden-byte-identical and CI-gated by the file-size ratchet.
>
> What is otherwise open is operator-paced or standing: maintainer loops that run
> existing validation gates and propose reviewed changes, the maintainer-local runs of the
> calibration harnesses (held-out residual, tenancy corroboration, per-vertical
> stratification, conformal pass - collection now, not construction), the C3
> CT-enabled corpus pass, and the arXiv write-up. This file is the plan from
> here.

## Version milestones and build order

recon is past its expansion phase. v1.0 set the stability contract and v2.0
locked the schema; the project is now in a deepen-not-expand phase, so the
version number is meant to climb slowly and deliberately. This section is the
single statement of what each milestone means and the order the remaining work
runs in. The per-release detail is in [CHANGELOG.md](../CHANGELOG.md); the semver
rules are in [release-process.md](release-process.md#version-numbering).

### What each milestone meant, and means

- **0.x (done).** Pre-contract. Breaking changes were allowed within minors while
  the core took shape (passive collection, the fingerprint catalogue, the panel).
- **1.0 (done).** The stability commitment. The CLI surface and the v1.0 JSON
  contract became stable surfaces ([stability.md](stability.md)); semver is
  enforced from here.
- **1.x (done).** Additive growth: graph correlation (1.8), the Bayesian fusion
  layer (1.9, experimental at first), and the long 1.9.x hardening run that drove
  the engine and catalogue to the v2.0 bar.
- **2.0 (done).** The schema lock and maturity capstone. Promoted the fusion
  surfaces from experimental to stable, flipped `--fusion` default-on, and locked
  the v2.0 JSON contract. Deliberately a mechanical ceremony over already-proven
  work, not a feature event.
- **2.1.x (shipped, through 2.1.18).** The post-2.0 assurance and thin-feature
  line: the cohort summary (PV1), then the assurance track (differential
  verification, the inference drift gate, the interval-coverage and mutation
  gates, the traceability matrix), plus UX polish. Everything additive, off the
  locked v2.0 schema.

### Where the next numbers sit

- **2.2 (shipped 2026-06-13).** A minor bump is earned by a coherent new
  *stable surface*, not by internal hardening, which stays patch-level. v2.2.0
  carried two surfaces: the evidence-semantics diagnostics (per-node entropy
  reduction, exact leave-one-unit-out counterfactuals, graph partition
  stability, as additive JSON / MCP fields) and the MCP tool-output contract
  revision (navigable `structuredContent` + per-tool `outputSchema` + `isError`
  across the data tools; see [mcp.md](mcp.md)). The 2026 CLI-ergonomics pass and
  OSC 8 hyperlinks rode along.
- **2.2.1 through 2.2.9 (shipped through 2026-06-20).** Patch-level UX,
  maintainability, docs, and assurance hardening: input is normalized to the
  registrable apex via the Public Suffix List with an `--exact` opt-out,
  `recon update` is surfaced in the docs, the god-file decomposition track is
  complete, the release / installer / dependency / source-layout docs drift and
  HTTP non-global IP guard fixes have shipped, and the public assurance
  proving-test backlog is closed. No locked JSON shape changed.
- **2.2.x (active patch line).** The next work is ordered by dependency, not by
  calendar estimate. Current `main` now has the local release-readiness
  preflight, the Scorecard-facing supply-chain posture pass, the
  pinned-workflow supply-chain pass, the maintainer-local calibration bundle
  runner, validation-runner path-containment hardening, the calibration
  corpus-shape preflight, the generated surface-inventory drift gate, the
  generated maintainer context-packet inventory, and PR-scoped ClusterFuzzLite
  parser-boundary fuzzing. Current `main` also has incremental schema drift
  guards that tie model-backed JSON Schema `$defs` to their dataclass fields and
  trace every top-level schema property to a `TenantInfo` field or explicit
  formatter/mode source while the full schema-generation backlog remains open,
  a PLR size-rule ratchet prevents new function-size debt while existing
  violations are paid down, and the default branch lockfile has been updated to
  `msgpack` 1.2.1 for GHSA-6v7p-g79w-8964 in the dev-audit stack. The
  MCP dependency path has likewise been updated to `pydantic-settings` 2.14.2
  for GHSA-4xgf-cpjx-pc3j. The ClusterFuzzLite build now also uses hash-pinned
  runtime requirements plus source-path loading, closing the remaining local
  Pinned-Dependencies warning from the Scorecard scan, and the local CI mirror
  and CI validation job now check that `.clusterfuzzlite/requirements.txt` still
  matches the frozen runtime export from `uv.lock`. Added-line text hygiene is
  now likewise checked locally and in CI for attribution markers, em dashes, and
  pictographic symbols. The current lockfile also folds in the grouped
  dependency-currency update: `mcp` 1.28.0,
  `publicsuffixlist` 1.0.2.20260615, and the latest dev toolchain patch line,
  with a Pyright 1.1.410 socket-address type fix in the HTTP SSRF guard. Current
  `main` also aligns MCP setup guidance and diagnostics with the installer
  fallback: `doctor --mcp` emits the same sys.path-stripping Python launcher
  that `recon mcp install` writes when `recon` is not on PATH, and
  `doctor --client` warns on hand-written `python -m recon_tool.server` client
  configs. The remaining order is private-corpus
  calibration runs, aggregate-only validation memos, optional reviewed
  maintainer loops around those deterministic gates, and the decision whether
  the derived inventory ever becomes a stable surface. These are
  patch-level unless they add a new stable user or agent-consumed surface. None
  of this makes AI a requirement for using recon.
- **2.3+ (reserved for a real surface).** The next minor waits for a coherent
  named surface. The only current candidate that plausibly earns one is an
  agent-consumable surface inventory: a generated CLI/MCP/schema manifest or
  comparable agent-context bundle that removes drift between README examples,
  MCP docs, CLI help, and skills. If it is only documentation, it stays
  patch-level. If it becomes a stable command or committed machine-readable
  contract, it can be 2.3. An OKF-compatible bundle is considered only as a
  packaging shape for recon's own docs/runbooks, not as a recon findings export
  and not while OKF remains a draft spec without a concrete recon consumer.
- **3.0 (intentionally deferred, possibly never).** A major bump is forced only by
  an unavoidable *breaking* change to a stable surface, with the deprecation
  window the stability policy requires. The pre-2.0 schema-hardening (SH1 to SH9)
  was done specifically so no foreseeable change needs one, so there is no planned
  3.0; it is reserved for a breaking necessity that does not currently exist. The
  project does not invent a 3.0 to look like it is progressing.
- **Intentionally never (permanent, not version-gated).** These are out of the box
  by design, not deferred to some future major: active scanning, paid APIs,
  credentialed access, learned weights or bundled ML, bundled ASN / GeoIP, a
  persistent aggregate store, user-code plugins, remote / HTTP MCP transport, and
  a hosted service. They will not appear in 3.0 or 4.0 either; they are the
  boundary that makes recon what it is (see [Intentionally Out Of
  Scope](#intentionally-out-of-scope)).

The honest reading: a slowing version number here is a sign of a settled shape,
not stagnation. The work that remains deepens trust in what exists rather than
enlarging the surface.

### Build order for the remaining work

The v2.2.0 assurance and diagnostics items (the CAL3/CAL4 reference calibration,
the statistical-assurance dossier, and the evidence-semantics diagnostics) have
shipped; their detail is kept in [Assurance and trust hardening](#assurance-and-trust-hardening-the-post-20-north-star)
and the `validation/` memos for rationale. The god-file decomposition track also
shipped in v2.2.1. Before any item below, run the local maintainer preflight:
`uv run python scripts/release_readiness.py --allow-dirty` during edits,
`uv run python scripts/check.py` before commit, and
`uv run python scripts/release_readiness.py --remote` after pushing `main`.
What remains is dependency-ordered work with no calendar estimates:

1. **Calibration corpus runs** (maintainer-local, aggregate-only, patch-level).
   The harnesses are built and unit-tested, and
   `validation/run_calibration_bundle.py` now runs the gitignored corpus to
   aggregate JSON and feeds `validation/render_calibration_memo.py`, the
   publication boundary. The bundle now performs a no-network corpus preflight
   first: the consolidated corpus must meet `--min-cell`, at least one
   per-stratum file must meet `--min-cell`, and dry runs report eligible versus
   suppressed strata before any live resolution starts. *Done 2026-06:* the
   reference (with held-out residual), tenancy corroboration, per-vertical
   stratification (`--stratify-dir`), and conformal harnesses ran against the
   corpus at concurrency 2; the aggregate memo is committed at
   `validation/2026-06-23-full-corpus-calibration.md`, with the honest reading
   folded into `validation/reference-calibration.md` and
   [statistical-assurance.md](statistical-assurance.md). The one remaining
   calibration pass is the C3 CT-enabled full-corpus run. The committed memo must
   follow
   [data-handling-policy.md](data-handling-policy.md): no apexes, no
   organization names, no tenant IDs, no per-domain output, and no published
   stratum below 10 domains. *Design:* [statistical-assurance.md](statistical-assurance.md),
   `validation/reference-calibration.md`, and [related-work.md](related-work.md).
2. **Fingerprint and motif triage loop** (maintainer-local, optional, reviewed
   proposals, patch-level unless it adds a stable surface). Use existing
   scan/gap outputs to propose catalog or motif changes with vendor references,
   before/after aggregate deltas, sparse-result wording, and regression tests.
   The loop can prepare YAML and test patches, but catalog changes still require
   human review under [agentic-balance.md](agentic-balance.md).
3. **Surface-inventory promotion decision** (possible 2.3 surface, not needed
   for normal use). `docs/surface-inventory.json` is now generated from the CLI,
   MCP registry, JSON schema, agent guidance, and maintainer-loop context
   packet, and CI checks it for drift. `recon://surface-inventory` now exposes
   the same generated snapshot as a local no-network MCP resource for agents
   that cannot read repository files.
   Keep it patch-level while it remains derived discovery context. Promote it to
   a 2.3 contract only if a concrete consumer needs stable machine-readable
   fields beyond best-effort local discovery.
4. **The arXiv write-up** (packaging; aspirational, off the critical path).
   Assemble the existing rigor for an outside reader, plus the few additional
   experiments already designed into the harnesses above, within the no-real-data
   publication rule. *Design:* [paper-outline.md](paper-outline.md),
   [related-work.md](related-work.md), the [Research write-up](#research-write-up-aspirational-an-arxiv-paper)
   section below, and the constraints in
   [data-handling-policy.md](data-handling-policy.md).

Decided not to do now:

- **Branch protection.** This would improve Scorecard but changes how the
  single-maintainer `main` flow works. Keep the local readiness gate plus remote
  CI verification as the current guardrail unless the repo starts taking regular
  external PRs.
- **Attach separate signature files to GitHub releases.** Done 2026-06-19 for
  future releases: the release workflow now gates PyPI and GitHub Release
  publication on successful build-provenance attestation, exports the signed
  attestation bundles as `recon-tool-<version>.intoto.jsonl`, and attaches that
  provenance asset to the GitHub Release. As of the 2026-06-19 Scorecard API
  result, `Signed-Releases` is still 0 because the recent already-published
  releases do not contain a Scorecard-recognized provenance asset.
- **Scorecard-recognized fuzzing integration.** Done 2026-06-19 with a real
  ClusterFuzzLite + Atheris target for local parser, normalization, cache
  deserialization, and formatter-serialization boundaries. This is PR-scoped,
  read-only, SHA-pinned, and bounded; do not add batch fuzzing or storage repos
  until crash triage volume justifies the extra moving parts.

Research and consider:

- Whether the derived surface inventory should remain a committed drift guard,
  become an MCP resource, or gain a CLI command once a concrete consumer exists.
- A derived docs bundle for maintainer runbooks if the same context is being
  copied into multiple agents. OKF remains only a packaging candidate, not a
  recon findings export.
- Done 2026-06-19: added `docs/maintainer-loop-runbook.md`, a compact
  maintainer-loop contract for CI triage, private calibration, and fingerprint
  proposal loops. It requires an ignored state file, deterministic gates, stop
  conditions, spend tracking, and maintainer review for semantic changes.
- Done 2026-06-19: added `scripts/diff_coverage.py` as an advisory maintainer
  signal. It reads Coverage.py JSON plus a unified diff, reports changed-line
  coverage for executable Python lines, can fail under an optional threshold,
  and treats documentation-only diffs as a successful no-op. It is deliberately
  outside the blocking gate.

Standing, maintainer-paced, off this critical path: the PV2 validation routine
(live), the mutation gate (live), and corpus-driven catalogue growth (local,
aggregate-only). These run continuously and do not gate the sequence above.

### Agent loops and OKF disposition (2026-06 external review)

The current agentic-AI tooling discussion is useful for recon only where it
reinforces the boundary in [agentic-balance.md](agentic-balance.md): agents may
orchestrate work around recon, but recon's observe-infer-report core remains
deterministic. The relevant external shape is now well documented by the agent
platforms themselves: Codex describes the agent loop as a harness that prepares
context, lets the model request tool calls, observes tool results, and repeats
until the model returns a final message
([OpenAI, "Unrolling the Codex agent loop"](https://openai.com/index/unrolling-the-codex-agent-loop/));
Claude Code describes the same evaluate/tool/observe cycle and exposes routines
for scheduled, API-triggered, and GitHub-triggered runs
([Claude Code agent loop](https://code.claude.com/docs/en/agent-sdk/agent-loop),
[Claude Code routines](https://code.claude.com/docs/en/routines)). Google OKF is
also relevant as a file-based agent-context convention: markdown files with YAML
frontmatter, cross-links, optional indexes, and optional logs
([Google Cloud OKF intro](https://cloud.google.com/blog/products/data-analytics/how-the-open-knowledge-format-can-improve-data-sharing),
[OKF v0.1 spec](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)).

Disposition for recon:

| Pattern | Applies to recon | Boundary |
|---|---|---|
| Goal-driven agent loops | Yes, for release readiness, CI triage, private-corpus calibration orchestration, and fingerprint proposal drafts | Use them only when the task repeats, success is verified by an automated gate, cost is bounded, and the loop can read logs and run the same local tools a maintainer would. It does not silently mutate CPTs, fingerprints, schema, releases, or distribution artifacts. |
| Manager/worker or subagent loops | Yes, for read-heavy review: docs drift, test-log triage, schema checks, and catalog candidate review | Parallel agents summarize evidence back to one reviewed decision. Avoid parallel write-heavy code edits. |
| Self-critique/eval loops | Yes, when the verifier is deterministic or separately reviewable: `scripts/check.py`, schema drift tests, coverage, mutation gate, no-real-data review, aggregate-only validation memos | The agent may critique output; deterministic gates decide whether the repo is clean. Human review decides semantic changes. |
| Security-rule selection | Yes, for maintainer-loop planning and review | Keep a short always-on checklist for every code pass (secrets, untrusted input, shell/file boundaries, private-data handling, supply chain, and MCP side effects), then add changed-area checks based on the touched subsystem. The checklist informs review and tests; it does not become runtime behavior or a new dependency. |
| Persistent memory | Limited | Use committed docs, validation baselines, and git history. Do not add a persistent aggregate scan database or target-memory store. |
| OKF-style knowledge bundles | Maybe, as an agent-readable packaging pattern for recon's own runbooks, invariants, schemas, and surface inventory | Do not export target findings as OKF. Do not duplicate docs into a second source of truth unless a generator and drift gate make it derived. |
| Scheduled hosted operation | No, inside recon | Scheduling belongs to Codex, Claude Code, GitHub Actions, cron, or the operator's environment. recon stays a local CLI/library/MCP server. |

The near-term implementation is therefore not "make recon agentic." It is:
publish optional maintainer/developer runbooks in the repo for the people who
want them, give those loops explicit stop conditions and gates, and keep the
installed user path exactly what it is today: local CLI, library, JSON, and MCP
surfaces that require no AI assistant. For security work, the practical shape is
an explicit review plan: start with the always-on checklist, select subsystem
checks only for the files actually touched, then prove the result with the
smallest deterministic gate that covers the changed boundary before running the
full local gate.

The minimum viable maintainer-loop contract now lives in
[maintainer-loop-runbook.md](maintainer-loop-runbook.md): one context packet, one
ignored state file, one deterministic gate, and one explicit stop condition. The
gate is the point. Without it, the loop is just an expensive reminder to review
the work by hand.

## Pre-2.0 hardening (shipped) and the road past v2.0

The pre-2.0 hardening below shipped with the v2.0 lock; the v1.9.x track detail
is in [CHANGELOG.md](../CHANGELOG.md), kept here only for the rationale. The
forward plan, the post-2.0 assurance north star, the backlog, and the invariants
follow it.

The engineering-elevation series (v1.9.27 to v1.9.37: py.typed, the 3.12
floor, branch coverage, `deal` contracts, build provenance, the stateful
and 3.14t test work, PEP 735, the C901 gate) is shipped. Before the v2.0
lock, the project is in a deliberate hardening phase: v2.0 is gated behind
making the engine and catalog demonstrably solid, not behind docs currency
alone. The scoping confirmed the eventual lock is small (EXPERIMENTAL
labels are already gone, `correlation.md` is most of the way to the polish
bar, the v2.0 corpus-run file is populated), so the value now is in depth,
not ceremony.

**What 2.0 delivers, and why the small ceremony is the point.** The 2.0
*event* is mechanical by design: a schema lock, a doc snapshot, the `--fusion`
default flip, and a tag, with no new feature work invented at the lock moment.
That is deliberate, not modest. Every capability ships and is validated in a
1.9.x patch first, so the lock is small precisely because the substance is
already done and proven. What 2.0 *delivers* is the capstone where that
accumulated excellence becomes a stable contract:

- a fingerprint catalog that is comprehensive and high-precision across the
  5,000+ company corpus, with the gap report driven to a low residual, not just
  the top-tier-vendor spot checks that cleared early;
- a Bayesian layer whose every node is calibrated and stable across the full
  corpus, the credible intervals behaving as designed on sparse and hardened
  targets, validated by complete (CT-enabled) calibration runs rather than
  snapshots;
- a JSON / MCP schema locked as a real v2.0 contract, with the promoted fields
  documented as stable;
- reference docs (notably `correlation.md`) at the polish bar;
- and zero EXPERIMENTAL labels anywhere.

So the "mechanical lock event" language elsewhere in this file describes the
*ceremony*, not the *ambition*. By the time it fires, recon is meant to be
excellent everywhere because the corpus-driven depth above made it so, and the
small tag step is the proof that nothing was rushed to get there.

Five tracks run as a sequence of focused, CI-green 1.9.x patches:

- **Complexity decomposition.** Decompose the functions carrying
  `# noqa: C901` (the gate from v1.9.37 already holds new code), removing
  each marker as its function drops under 15. Golden-output
  characterization tests for the renderers came first
  (`tests/test_golden_renders.py`, fictional brands only); with that net in
  place the whole of `formatter.py` is decomposed and carries no marker as of
  v1.9.52, the ~940-line `render_tenant_panel` and the markdown renderer
  included, output held byte-identical throughout. The remaining markers are
  the behaviour-heavy functions (`_lookup`, `merge_results`, `_batch`, and a
  tail of validators / loaders), which want characterization coverage of their
  own before they are split.
- **Test and validation rigor.** `deal` contracts on the boundary
  validators (third pass after the inference core and matchers); a
  Hypothesis stateful machine for the cache lifecycle; deterministic
  fault-injection at the source boundary (malformed / truncated payloads,
  timeouts, partial provider failures) asserting hedged output and
  `degraded_sources` hold; branch coverage driven up toward the
  `server.py` target.
- **Catalog growth.** Public vendor-doc-sourced `cname_target`
  fingerprints via the `CONTRIBUTING.md` methodology, plus corpus-mined
  candidates from `validation/scan.py` over private-corpus subsets
  (respecting CT rate limits and the `--ct-retry-from` multi-session
  workflow). Per-domain output stays gitignored; only aggregate counts
  reach committed memos, and committed examples use the fictional brands.
- **Robustness and security.** Adversarial bug-hunt of the ingestion and
  parse paths (DNS, CT, BIMI VMC, identity endpoints), input edge cases
  (IDN / punycode, malformed, oversized, truncated), and another
  security-audit round folded into `docs/security-audit-resolutions.md`.
- **CLI and agent quality-of-life.** Polish the consumer surface, separate
  from the internal complexity work. The capability is already broad (the
  `lookup` / `batch` / `delta` / `discover` / `doctor` / `cache` /
  `fingerprints` / `signals` / `mcp` command tree, `--explain` / `--full` /
  `--json` / `--exposure` / `--gaps` / `--profile` / `--chain`, an exit-code
  contract, and roughly two dozen MCP tools), so the gap is discoverability and
  small ergonomics rather than missing features. Concrete items, each its own
  small patch:
    - *Exit-code reference.* The contract exists (`0` success, `2` validation,
      `3` no-data, `4` internal) but is documented only in scattered spots
      (`schema.md`, `security.md`); pull it into one reference block for
      scripters, and name every literal as a constant in `cli.py`.
    - *Shell completion currency.* Typer ships `--install-completion` /
      `--show-completion` automatically; decide deliberately whether to
      document it or disable it, rather than leave it present but invisible.
    - *`batch` stdin.* Support `cat domains.txt | recon batch -` if not
      already present, the natural piping ergonomic for batch input.
    - *`autoApprove` guidance.* Document which MCP tools are read-only versus
      stateful so a consuming agent (and the README's manual-approval advice)
      can reason about what is safe to auto-approve.
    - *Schema-discovery surface.* An MCP tool or `recon://` read-only resource
      that returns the JSON schema and its version, so an agent can
      self-describe without an external fetch.
    - *Data-not-instructions demarcation.* Already tracked in Known gaps: mark
      recon's returned DNS / CT / BIMI strings as untrusted observed content so
      a consuming agent treats them as data, not instructions. It belongs to
      this track as the highest-value agent-facing item.
    - *Small consistency items.* `_SUBCOMMANDS` omits the real `discover`
      command (harmless today, since the set only gates dotted first args, but
      worth aligning). None of these add engine surface; they make what already
      ships easier to consume, which is squarely the "exceptionally well before
      2.0" goal a consumer actually notices.

### Remaining work to v2.0 (the execution queue)

> **All shipped (historical).** Everything in this subsection and the v2.0 lock
> ceremony below was completed; v2.0.0, the v2.1.x line, and the v2.2.0 surface
> release have all shipped (see the status header at the top of this file for
> the current release). The detail
> is kept for the rationale and the per-item disposition; the forward plan is the
> post-2.0 assurance track above and the feature candidates below. Per-release
> detail lives in [CHANGELOG.md](../CHANGELOG.md).

This subsection is the single source of truth for what is left before the v2.0
lock. The five tracks above describe the shape of the work; the queue below
turns it into an ordered, checkable list so "what ships next" is never
ambiguous. Each row is one coherent 1.9.x patch under the no-bundling
discipline (one story per patch, version bump last, local gate matched to CI).
Rows marked *corpus-driven* run against the gitignored ~5,200-domain validation
corpus (`validation/corpus-private/`) and the network, rather than from the public
tree alone. That corpus is intentionally kept out of git for cleanliness, respect
for the organizations in it, and security / legal hygiene, **not** because the
work is secret or done elsewhere. The scans run locally with the tooling already
in the repo (`validation/scan.py` to resolve, `validation/find_gaps.py` to rank
unclassified termini, the calibration / stability harness for the Bayesian
layer), and rigorous validation against that base is a core part of the pre-2.0
"exceptionally well done" bar. The only constraint is a commit filter: aggregate
counts, vetted patterns, fictional-brand examples, and calibration metrics are
committed; real apexes and per-domain findings stay in the gitignored paths.
Small ad-hoc random lists are fine for quick iteration on a specific change; the
full corpus is what gives the broad coverage and calibration confidence. Every
other row is code or docs work that ships on its own.

The order is the recommended sequencing: cheapest-and-clearest first
(consumer-facing polish and pure decomposition), then the rigor and
robustness layers, then the corpus-driven depth, and finally the mechanical
lock. Numbers are queue positions, not version numbers; each row claims the
next free `v1.9.x` when it ships.

**Order of operations to the lock.** Track E is done. The remaining doable work
runs in this order, each step one or more 1.9.x patches:

0. **Tooling foundation.** Done: `release.py`'s `_INIT_VERSION_RE` matches the
   refactored `__init__.py` (only `_FALLBACK_VERSION` is a literal now) and the
   `scripts/` C901s are cleared, so the release gate is sound.
1. **Finish complexity decomposition (Track A) to zero markers.** Done in
   v1.9.72 to v1.9.76. The behaviour-heavy tail was the last of it: A6 the `cli`
   set (`signals_show` + `_doctor` in v1.9.72, `_lookup` in v1.9.73, `_batch` in
   v1.9.74), A7 `merge_results` (v1.9.75), and A8 the `server` pair (v1.9.76),
   each with characterization coverage added first. Zero `# noqa: C901` markers
   remain and the cap holds the whole tree.
2. **Test and validation rigor (Track B).** Done in v1.9.77 to v1.9.80: `deal`
   contracts on `validator.py` (B1), the cache-lifecycle stateful machine (B2),
   source-boundary fault injection (B3), and the server-tool coverage lift that
   took `server.py` to ~75% (B4).
3. **Robustness and security (Track D).** D1 done in v1.9.81: a fresh adversarial
   ingestion audit closed round six (output-sink control stripping for
   source-derived service strings and the DMARC `p=` value), folded into
   `docs/security-audit-resolutions.md`.
4. **Catalog growth (Track C).** C1 shipped (v1.9.82 to v1.9.86, vendor-sourced
   `cname_target` fingerprints from local live-analysis batches, 808 to 829
   entries, fictional-brand examples only). C2 corpus-mined gap-fill is underway:
   a full 5,241-domain `validation/scan.py` run plus `validation/find_gaps.py` and
   `triage_candidates` drove three verified batches (v1.9.87 to v1.9.89, 13
   vendors, 829 to 841 entries; trail in `validation/v1.9.87-c2-corpus-batch.md`).
   The triage confirmed most high-count residual termini are org-internal GSLB /
   load-balancers that by design never become fingerprints; the named third-party
   residual is now closed, leaving only the low-frequency long tail. Aggregate
   counts and vetted patterns reach the repo; real apexes do not.
5. **Bayesian full-corpus calibration (Track C, C3),** with the legitimacy
   refinements below applied so the numbers are defensible, not just
   self-consistent. Run over the final catalog: per-node metrics,
   deterministic-vs-Bayesian *consistency*, interval coverage, sparse-case
   behavior. Aggregate metrics only.
6. **Docs currency (pre-lock).** Bring the release-notes draft current (F1),
   promote `correlation.md` to the polished reference (G3, incl. the
   independence-bias and ground-truth caveats below), and refresh the
   validation-summary with the fresh baseline (F2).

The corpus runs are network-heavy. The DNS / identity-endpoint pass runs at low
batch concurrency (a concurrency-16 pass blew the 120s per-domain budget on
~84% of domains via resolver saturation; concurrency 5 holds the error rate near
4%). CT is separate and self-throttles to a process-wide cap of 2 with an AIMD
limiter + circuit breaker, so a CT-enabled pass is small-subset / multi-session
(`--ct-retry-from`) and reported as partial. The nine Bayesian nodes are fed by
DNS / identity, not CT, so the no-CT pass calibrates the layer fully; CT only
feeds the separate `infrastructure_clusters` and cert lexical surfaces. Only the
v2.0 lock ceremony itself (G1 schema lock, G2 `--fusion` default-on, G4
changelog-move + tag) stays out of this sequence.

#### Calibration legitimacy refinements (Track C-cal)

A 2026-06 methodology review flagged that the current numbers measure
*self-consistency*, not calibration against ground truth, and over-claim when
they call it "calibration." A second review of the theory (`correlation.md`)
against the first full-corpus pass added CAL10 to CAL13 and sharpened CAL1 /
CAL7 / CAL9: the consistency number is near-tautological under the
virtual-evidence construction (so it cannot falsify the CPT values), the
correlated-binding multiplication makes the layer over-confident on
richly-instrumented targets even as the absence rule keeps it conservative on
hidden ones, and the information-recovery north-star is now measurable
(entropy reduction). These refinements make the Bayesian-validation story
defensible without overstating it. Each is its own small patch; they gate the
C3 calibration claims and the `correlation.md` polish (G3).

**Shipped so far (2026-06):** CAL1, CAL2, CAL5, CAL7, CAL10 landed in the
v1.9.61 to v1.9.71 calibration work. CAL13 (evidence-responsive framing in
`correlation.md` section 4.4) and CAL8 shipped 2026-06-04; CAL8 is a new
`validation/likelihood_sensitivity.py` harness (cleaner than overloading
`threshold_sensitivity.py`, which sweeps trigger thresholds) with worst-case
dECE <= 0.032 and decision flips <= 1.3% under a +/-20% perturbation, artifact
in `validation/cal8-likelihood-sensitivity.md`. CAL3 / CAL4 are reframed around
authoritative public records (DMARC / SPF / MTA-STS records as their own truth;
M365 / GWS tenancy via the providers' own endpoints) plus an optional, external,
anonymized case-study sanity check (`validation/2026-06-04-case-study-spot-check.md`,
first sample: 7 of 7 positive detections corroborated, 0 false positives), rather
than a fabricated hand-labeled corpus. **CAL14 design note:** the email-policy
node's `dmarc_reject` and `dmarc_quarantine` bindings are mutually exclusive, so a
correct absence-conditioning rule must operate per evidence-group with new
absence-likelihood parameters (each a claim under the CPT-change discipline), not
per independent non-fired binding; it is the heaviest remaining change and ships
with the maintainer in the loop on those modeling choices. (CAL14 shipped as the
`missingness: declarative` model with `group_absence`; the design memo is
`validation/cal14-missingness-design.md`.) Since then: the CAL3/CAL4
reference-calibration run landed (the email-policy node at tier 4 for the
residual); CAL11 shipped as the 2.2 `partition_stability` field (Louvain
seed-sweep consensus as mean pairwise ARI); and CAL9's harness half shipped
(`calibration_summary` now leads with the proper log-score beside Brier/ECE —
the reliability-diagram-and-sparse-cohort memo discipline applies at the next
corpus run). CAL6 (the stratified corpus run) landed 2026-06 across all 22
verticals (`validation/2026-06-23-full-corpus-calibration.md`). Remaining open:
the measurement half of CAL12 (the elicitation ledger is now written —
`bayesian-cpt-discipline.md`, "The priors ledger" — with the unrecorded
corpus rates marked as the open cells the next full-corpus pass fills).

| # | Refinement | Acceptance |
|---|---|---|
| CAL1 | Reframe consistency vs calibration (and show why) | Everywhere (analyzer headers, `correlation.md`, validation memos), the deterministic-vs-Bayesian number is named *consistency / agreement*, not *calibration*, with an explicit note that both layers share the same evidence. State the mechanism: under the virtual-evidence construction a high non-sparse posterior requires a fired positive binding, which is itself a deterministic detection, so the consistency number tests the inference plumbing, not the CPT / likelihood values. Only CAL3 interval coverage can falsify the values. Proxy-label Brier / ECE are labeled as proxy-label, not ground-truth. |
| CAL2 | Uncertainty on every metric | The agreement rate carries a Wilson / Rule-of-Three CI (report the upper bound on disagreement, e.g. ~3/n); Brier / ECE carry bootstrap CIs. No bare "100%". |
| CAL3 | Empirical interval coverage | The load-bearing claim (80% credible intervals) is tested: empirical coverage of the 80% interval against ground truth is computed and reported. |
| CAL4 | Ground-truth subset | A hand-labeled set of ~50-100 domains with independently-known answers (verified M365 / GWS tenants, known Okta orgs) lives gitignored; real calibration + CAL3 coverage are computed against it, aggregates only. |
| CAL5 | Split coverage from calibration | The per-node verdict separates firing count (coverage / power) from Brier / ECE (calibration). `okta_idp` is reported as well-calibrated-but-low-coverage, not a flat "fail"; the `>= 10` firing gate is a coverage note, not a calibration verdict. |
| CAL6 | Stratified sampling | Calibration draws a random / stratified sample (by cloud vendor / vertical / region, using `by-vertical/` and `by-region/`) and reports per stratum; the full 5,241 run is used so low-coverage nodes (okta_idp) clear the firing gate on volume. |
| CAL7 | Correlated-binding overconfidence | `correlation.md` documents that co-firing bindings (e.g. `microsoft365` + `entra-id` + `exchange-online`, three views of one fact) are multiplied as if conditionally independent, which compounds the likelihood ratio and narrows the interval more than the evidence warrants. Combined with the `LR=1` absence rule this gives an asymmetric failure: conservative on hidden targets, over-confident on richly-instrumented ones. Mitigation: a noisy-OR / single evidence-cluster factor over co-firing slugs or an explicit down-weight, plus an interval-width-vs-evidence-count diagnostic that surfaces the over-confidence (which the mean-agreement metric cannot see). |
| CAL8 | Sensitivity analysis per release | `threshold_sensitivity.py` runs a +/-20% likelihood perturbation each calibration pass and shows the posteriors / agreement are stable; the result is an aggregate artifact. |
| CAL9 | Reliability diagrams + proper scoring lead; do not drop the hard cases | The validation memo leads with reliability diagrams, the posterior histogram, and the log-score (a proper scoring rule); ECE is demoted to a secondary diagnostic with its binning scheme stated, and the memo notes that ECE looks low partly because the posterior distribution is bimodal (few mid-range points). The headline consistency number excludes sparse observations today; report the sparse cohort separately rather than silently dropping the cases where the model's real uncertainty lives. |
| CAL10 | Entropy-reduction (information-recovery) metric | Operationalize the mutual-information north-star that `correlation.md` currently disclaims as intent: report the per-domain posterior entropy reduction (H(prior) - H(posterior), in nats) distribution each calibration pass. A first full-corpus pass measured median ~0.85 nats (Q3 ~1.23). This is the concrete "information recovered" number the framing wants. |
| CAL11 | Graph partition stability, not a lone modularity score | The graph layer (Louvain / CPM) reports a partition stability / consensus measure across seeds and resolution, not a single modularity Q; `correlation.md` cites the resolution-limit (Fortunato-Barthelemy 2007) and degeneracy (Good et al. 2010) literature where CPM is introduced, since CT co-occurrence graphs are typically small and sparse. |
| CAL12 | Ground priors in observed base rates | Node priors are documented against observed corpus base rates and the elicitation is written down. The first full-corpus pass showed mismatches (e.g. `m365_tenant` prior 0.30 vs high-confidence in ~60% of domains, `aws_hosting` 0.40 vs ~28%). Strong likelihoods wash this out for the point estimate, but the prior is load-bearing for the sparse-case posterior and the interval, which is the field we say matters most. |
| CAL13 | "Evidence-responsive" not "calibrated" | Until CAL3 frequentist coverage exists, the 80% credible intervals are described as *evidence-responsive* (they widen on sparse evidence, a monotonicity property), not *calibrated* (a coverage statement in the Dawid sense). The word "calibrated" is reserved for what CAL3 demonstrates. |
| CAL14 | Node-dependent missingness (MAR vs MNAR) | The blanket asymmetric / LR=1 absence rule is right for hideable infrastructure (m365, okta), but wrong for public-declaration signals whose absence is genuine, not adversarially hidden (DMARC / SPF / MTA-STS policy). The 2026-06 synthetic calibration showed `email_security_policy_enforcing` at conditional ECE ~0.31 (the [0.85] reliability bin realizing 0.166) precisely because the model could not use the absence of the strong DMARC signals as disconfirmation. A `spf_strict` down-weight (v1.9.71, conceptual) took it to ~0.28; the real fix is per-node MAR / symmetric conditioning for public-declaration nodes. A prototype confirmed the direction (the no-signal baseline correctly drops toward 0). It is a core-invariant change that ripples into n_eff / sparse (absence is evidence, so a no-signal MAR node should not be flagged sparse) and the criterion-(a) stability test (reframe from "every binding raises the posterior above the all-absent baseline" to "toggling a binding raises the posterior"), so it ships as its own fully-validated patch, not bundled. v2.0 should gate on the *max* per-node conditional ECE, not the mean. |

#### External-review candidate items (2026-06)

A 2026-06 external review of the correlation engine surfaced four additive items
worth scheduling. The rest of that review either restated already-shipped work
(the evidence-group correction in v1.9.70, the CAL1 to CAL14 calibration track)
or conflicted with the zero-dependency / passive-only invariants and is not
adopted. None of the four are scheduled yet; each would be its own future patch.

| # | Item | Track | Notes |
|---|---|---|---|
| EXT1 | CT-edge temporal decay | C (graph) | Down-weight CT-derived edges by certificate age (`w = e^(-lambda * delta_t)`) before community detection, so legacy-infrastructure edges do not bridge distinct infrastructure epochs. Additive, no new dependency. |
| EXT2 | SAN-count edge weighting | C (graph) | Penalise edges from large shared-CDN certificates (`|SAN| > tau`): a 2-SAN cert is a strong ownership link, a 150-SAN edge cert is noise. Pairs with EXT1 and the CAL11 partition-stability work. |
| EXT3 | Counterfactual explanations | B / explainability | "If DMARC reject were absent, the policy posterior would drop from X to Y." Cheap given the exact-inference engine (re-run with one binding flipped); extends `--explain-dag`. The per-node LLR attribution it also asks for already exists (`NodeEvidence.llr` / `influence_pct`). |
| EXT4 | PROV-O / JSON-LD provenance export | E / agent QoL | A `--prov` flag emitting the evidence DAG as W3C PROV-O rather than the bespoke `explanation_dag` JSON. Optional polish, not a v2.0 gate. |

Explicitly *not* adopted from that review, with reasons: HPD-from-PMF (the claim
nodes are binary, so each posterior is a single probability, not a multi-state
mass function to take an HPD over); a scipy / numpy tensor inference backend
(breaches the no-numpy invariant, and the nine-node network is deliberately
small); an external empirical-Bayes prior source such as Censys / Rapid7 Sonar
(breaches zero-paid-API / no-bundled-DB; the own-corpus version is CAL12); a
historical-DNS `StateTransition` signal (recon has no historical-DNS source
under its invariants, only live resolution plus `delta` and cross-source
conflict provenance); matplotlib calibration SVGs (heavy dependency; the
calibration artifacts live as `validation/` memos); and a code-plugin node
system (data-only YAML overlays only, per the no-user-code invariant).

#### The concept that orders this plan

recon does one thing: report what the public channel can defensibly reveal about
a domain, with provenance and honest uncertainty. The invariants follow from that
single idea rather than from a feature list. No credentials and no active
scanning, because private and active observation are out of scope. No committed
company data, because examples teach the method, not targets. No shipped baselines
and no persistent aggregate store, because recon is a reducer over what it
observes, not an intelligence database. A small, inspectable Bayesian layer,
because the uncertainty exists to discipline claims, not to decorate them.

So the post-2.0 work is ordered concept-first: make what exists more trustworthy
before adding anything, and let any new candidate earn its place by passing back
through the concept. The cohort work is the clearest case: it is the same
uncertainty discipline applied across a caller-owned set, "across this
caller-supplied cohort, what did the public channel reveal, how observable was it,
and how uncertain are we", never "what does this industry use". Hold the concept
and the build order below stays simple.

#### Post-2.0 release sequence

This is the original post-2.0 sequencing note, kept for the rationale. The
current, consolidated version plan and build order live in [Version milestones
and build order](#version-milestones-and-build-order) at the top of this file;
prefer that section, which is kept current. What this note described has all
shipped:

- **2.0.x: trust hardening.** The assurance work, differential verification of
  the inference core first. The product is trust, not surface area. *Shipped
  across the 2.1.x assurance track.*
- **2.1: aggregate state, thin and doc-first, in two stages.** 2.1a shipped the
  methodology doc (`docs/aggregate-state.md`), a synthetic fixture, and a local
  reducer script, with no change to core. 2.1b shipped the thinnest core surface:
  `recon batch --summary` (with `--json`), one cohort at a time, carrying its own
  `cohort_summary` record type and `schema_version` 2.1, with no persistent
  store, no industry taxonomy or baselines in core, and the observability
  denominators in the output. See PV1.
- **2.2 or later: maintainer validation loop formalized.** *Shipped earlier than
  planned, in v2.1.14:* PV2's committable core (the inference drift gate) plus the
  documented tiered loop, with the corpus-free tiers now wired to a weekly
  `/schedule` routine (see [maintainer-validation.md](maintainer-validation.md)).

Everything past the lock is additive and off the v2.0 schema; the lock stays
clean. The assurance items are not on the critical path of the feature
candidates; they come first.

#### Assurance and trust hardening (the post-2.0 north star)

The product is trust, not surface area. The priority after the v2.0 lock is to
make what exists more resilient and verifiable, not to make recon bigger. These are
quality tracks: none adds a user-facing feature, none touches the locked schema,
each is a small gated patch in the 2.0.x / 2.x line, and each deepens something
recon already leans on. They sit above the feature candidates on purpose.

Resilient (survives any input or failure):
- A fault-injection sweep across every external boundary (DNS, CT, the
  identity-discovery endpoints, certificate parsing) ran in 2026-06 and was
  adversarially verified: the four confirmed gaps shipped in v2.1.9 and the seven
  it rejected as already-guarded are recorded in
  `docs/security-audit-resolutions.md`. Builds on the existing source-boundary
  fault injection and the cache-lifecycle stateful machine. *Residual:* organize
  the per-boundary coverage as one explicit parametrized (boundary x failure-mode)
  matrix rather than topic-by-topic test files.
- Proven resource bounds on every parser: hostile-input fuzzing is promoted from
  a sweep to a dedicated CI gate (the `hostile_input` marker and the
  `hostile-input-fuzz` job, v2.1.10), with per-parser oversized-input bound
  assertions. *Residual:* the `_MAX_SUBDOMAIN_TXT_MATCH_LEN` and
  `_MAX_CNAME_MATCH_LEN` caps still want their own bound-assertion tests, and the
  OIDC / Azure `region` field wants a source-level length cap (today only the
  merger scrubs it).

Defensive (cannot be exploited or fooled):
- A written threat model with a traceability matrix (every threat to its
  mitigation to the test that proves it), on top of the six security-audit rounds.
- A second static-analysis lane in CI (taint analysis on the input-to-output
  paths) alongside the existing ruff-S and bandit.
- An adversarial-robustness corpus: can a domain owner manipulate public
  observables to make recon confidently wrong? The MNAR hardening is the start;
  this makes the predicted sparse and widened-interval behavior a standing
  asserted suite, not just a catalogued failure mode.

Adaptive (stays correct as the world drifts):
- PV2 (the maintainer-validation loop) shipped its committable core in v2.1.14: a
  deterministic inference drift gate (`validation/drift_check.py` +
  `inference_baseline.json`, CI-gated by `tests/test_drift_check.py`) that fails
  when the network's CPT-implied marginals move beyond a band without an
  acknowledged baseline update, plus the documented tiered loop
  (`docs/maintainer-validation.md`). The corpus firing-rate re-grounding tier
  stays maintainer-local against the gitignored corpus; wiring the agent to run
  the loop on a `/schedule` routine is the remaining operator step.
- A coverage check on the credible intervals, even a proxy-label or case-study
  version, framed exactly as honestly as CAL1 requires (consistency and
  evidence-responsiveness, never claimed ground-truth calibration). *Shipped in
  v2.1.15* as perturbation coverage: `validation/interval_coverage.py` builds
  synthetic worlds whose evidence likelihoods sit anywhere in the CAL8 +/-20%
  band, takes the truth from the independent full-joint reference (never the
  engine), and measures how often the shipped 80% interval contains the
  correct-world conditional; `tests/test_interval_coverage.py` gates the
  nominal-80% floor (measured at or above 0.999), the delta=0 consistency row,
  and a falsifiability case proving the check can still fail. Memo with the
  full sweep and the MAR diagnostic: `validation/interval-coverage.md`.

Trusted (the artifact and the answer are both verifiable):
- Differential verification of the inference core: brute-force enumeration over
  the full joint (nine binary nodes, 512 states) cross-checked against variable
  elimination for every evidence configuration (3^9, about 19.7k, all
  enumerable), with an independent reference implementation so it verifies the
  factor construction (declarative conditioning, grouped evidence, virtual
  evidence), not just the elimination step. Turns "tested" into "exhaustively
  verified for this network." Shipped: `validation/differential_verification.py`
  carries the independent full-joint reference and sweeps the enumerable
  none/one/all cross product (~2.9k configs) plus an exhaustive per-node subset
  sweep over the grouped and declarative nodes; variable elimination matched
  naive enumeration on every node of every configuration (worst gap ~5e-5, the
  engine's 4-decimal posterior rounding). `tests/test_bayesian_differential.py`
  anchors the reference to hand-computed marginals and runs a fast subset in CI.
- Reproducible builds bit-for-bit and sigstore-signed releases shipped in v2.1.12
  (SOURCE_DATE_EPOCH pinned at release time and gated in ci.yml; PEP 740 PyPI
  attestations on top of the existing GitHub build-provenance attestation and
  CycloneDX SBOM; see docs/supply-chain.md). The full SLSA L3 generator workflow
  stays deferred as disproportionate for a passive single-maintainer tool.
- A cross-platform and cross-Python determinism gate so the same input yields
  byte-identical output on every matrix cell.
- Mutation testing promoted to a gate with a score floor, and a
  requirements-and-invariants traceability matrix so every promise maps to the
  test that keeps it. *The mutation half shipped in v2.1.16 and was corrected
  afterward:* cosmic-ray over `recon_tool/bayesian.py`, a kill-set proven green
  before scoring, equivalent-by-construction operators filtered, and a blocking
  88%-kill (12%-survival) floor. The first reported "all killed" was a
  wrong-interpreter artifact the CI baseline step caught; the corrected
  authoritative sweep measured 91.4% kill (123 survivors of 1,431, residual
  classified equivalent), and that honest baseline plus the survivor
  classification is the standing record
  (`.github/workflows/mutation.yml`, `validation/mutation-gate.md`).
  *The traceability half shipped in v2.1.17:* `docs/traceability-matrix.md`
  maps the box invariants, the operational-contract bounds, the output
  contract, and the inference trust chain to the test that keeps each one,
  and `scripts/check_traceability.py` (gated by `tests/test_traceability.py`)
  resolves every backticked reference there and in `assurance-case.md`
  against the AST of the current tree, so a renamed test breaks CI instead
  of orphaning a doc row.

Priority order, highest trust-per-effort first. **Done:** differential
verification of the inference core (v2.1.7); the fault-injection sweep and its
four fixes (v2.1.9) plus the hostile-input fuzz gate (v2.1.10); the "Resilient"
residuals, the source-level `region` cap, and the boundary-by-mode matrix
(v2.1.11); and reproducible builds plus sigstore-signed PyPI attestations
(v2.1.12); the auditable assurance case + operational contract (v2.1.13); the
PV2 inference drift gate + maintainer-validation loop (v2.1.14); the
credible-interval perturbation-coverage gate (v2.1.15); mutation-as-a-gate
(v2.1.16); and the traceability matrix (v2.1.17). **The committed track is
complete.** What remains is operator-paced or standing: the CAL3/CAL4
reference-calibration run and the C3 CT-enabled corpus pass (corpus-driven,
maintainer-local), the data-handling policy and statistical-assurance dossier
docs, and the evidence-semantics diagnostics candidates. None of these is on
the critical path of the feature candidates below.

Each item ships with acceptance criteria, checkable gates rather than "improved
tests," and where it produces a durable artifact it ships a doc so the trust is
inspectable rather than asserted. Shipped: the engineering threat model
(`docs/security.md`), the assurance case mapping each promise to its mechanism,
its test, and its residual risk (`docs/assurance-case.md`), the operational
contract (`docs/operational-contract.md`: timeouts, caps, exit codes, cache and
partial-result semantics, determinism), and the supply-chain / release-integrity
doc (`docs/supply-chain.md`), and the data-handling policy
(`docs/data-handling-policy.md`: what may and may not enter the public repo,
down to comments and fixtures, each rule mapped to its enforcing mechanism), and
the statistical-assurance dossier (`docs/statistical-assurance.md`: each claim
placed at the highest of four evidence tiers, observed / consistency /
evidence-responsive / empirical coverage, with the tier-4 gap stated). This is a
standing track across the 2.x line, not a single release, and it adds no
discovery surface.

Kept proportionate to what recon is. The exhaustive differential cross-check, over
a few thousand enumerable states, is the right level of formal verification here;
full TLA+ or Lean machine proofs, recurring paid third-party reviews, and
long-term-support branches are recorded as aspirational, not committed, because
for a passive tool they cost more than they return. The principle holds inside
this track too: deepen what exists rather than keep adding.

Evidence-semantics diagnostics (candidates, not features). Several reviews
converged on enriching the evidence model rather than enlarging it: per-node
entropy reduction (how much the channel narrowed the prior), exact
leave-one-evidence-group-out counterfactual influence, framed as evidence
counterfactuals over the model and never causal claims about the world (the
nine-node joint makes it cheap), the evidence-group capping already tracked as CAL7, and graph
partition stability across seeds. These are additive `--explain` and JSON
diagnostics that leave the default panel unchanged and feed the
statistical-assurance dossier, and the monotonicity and missingness behaviors
become property tests in the differential-verification harness. Deferred as
disproportionate for a nine-node passive model: compiling the network to
sum-product or arithmetic circuits (exact variable elimination is already
instant, and the differential cross-check depends on the small joint), a credal
or imprecise-Dirichlet inference mode, and any baseline-relative anomaly scoring.

First pass landed in v2.1.1: a four-round adversarial bug-hunt of the
cohort-summary surface (two rounds were independent subagent passes) plus a
security review of the network, ReDoS, and resource/path/deserialization surfaces.
The SSRF/network and resource/path/deserialization reviews came back clean; the
fixes were a ReDoS-guard bypass (nested quantified groups such as `((a+))+`) and
output sanitization (`render_error` and the batch progress line), each with a
regression test. v2.1.2 added a full output-injection sweep across the render
paths and closed four more sanitization gaps (`render_warning`, verbose conflict
annotations, the `delta` error sinks, and markdown autodiscover domains). v2.1.3
took a deeper pass over the engine internals (Bayesian inference, merge / resolve
/ cache, graph / CT), fixing a Louvain determinism bug, a related-domain
enrichment correctness bug, and several cache and validation robustness gaps; the
inference math and the schema contract were re-confirmed clean. v2.1.4 closed an
external agentic-review batch: a cache symlink vector introduced by the v2.1.3
atomic write, cname_target substring overmatch, an IDNA2003 lossy mapping, and a
client-doctor terminal-escape sink, each with a regression test. v2.1.5 added a
self-driven five-area bug-hunt (fifteen fixes: markup injection on `--verbose`,
several control-character scrub gaps that bypassed the central merger scrub, a
non-capturing-group ReDoS gap, a CT-scan resource bound, and `merge_conflicts`
lost on the cache round-trip). v2.1.6 resolved the four held inference-layer
items: the `spf_strict` `-all` substring match is fixed to a token match (the one
behavior change); the `compute_slug_posteriors` "alpha double-count" was a
misleading comment, not a defect (the code matches the documented
`alpha_prior + weight` model, so posteriors are unchanged); a load-time warning
now flags declarative nodes whose grouped bindings lack a `group_absence` entry;
and the signed `entropy_reduction` is documented rather than clamped. The
differential verification of the inference core landed in v2.1.7 (the independent
full-joint reference in `validation/differential_verification.py` cross-checking
variable elimination across the enumerable evidence sweep). v2.1.8 then made the
Google CSE and BIMI VMC direct probes opt-in (`--direct-probes`) so a default
lookup stays passive, and added an `analyze_posture` profile guard. The 2026-06
fault-injection sweep closed four confirmed ingestion-boundary gaps in v2.1.9 (a
gzip decompression-bomb guard via identity-encoding plus a compressed-response
refusal, deeply-nested-JSON `RecursionError` handling in the cache and CT
providers, and a CT-graph entry-count bound), and the hostile-input fuzz CI gate
plus per-parser bound assertions shipped in v2.1.10. Signed and reproducible
builds with SLSA remain ahead.

#### Post-2.0 feature candidates (maintainer)

Ideas that fit the passive-primitive brand but are deliberately held until after
the v2.0 schema lock, since the lock adds no new surface by design. Each would be
its own post-2.0 patch, and each sits below the assurance work above in priority.
Every candidate earns its place against a trust budget: does it keep collection
passive-only, keep provenance intact, avoid any persistent cross-domain state, and
improve reliability or operator clarity, and what failure mode does it add? A
candidate that does not improve trust or clarity waits.

| # | Item | Track | Notes |
|---|---|---|---|
| PV1 | Local cohort summary over recon output | E / agent QoL | Local, caller-owned statistical analysis over a batch, built as a reducer that consumes recon's `--json` / `--ndjson` rather than as core logic, so core recon stays frozen and stateless. The caller owns the domain set and any grouping (by industry, portfolio, vendor set, location, or arbitrary type); those grouping files stay local and gitignored, never committed. The reducer emits aggregate-only views: provider / cloud / CDN / email-posture mix, concentration (entropy or HHI), and the Bayesian-claim prevalences. The honest-statistics discipline (refined from a 2026-06 review): observability-adjusted prevalence reported as three numbers (observed rate on the observable denominator, conservative lower bound over the whole cohort, observability fraction) so MNAR absence is encoded correctly; aggregate posterior mass plus a separate high-confidence (non-sparse, posterior > 0.8) share; hierarchical partial pooling of group rates only when the caller's batch has multiple strata, pooling toward the caller's own global across those strata and never a shipped baseline (a single cohort uses a Wilson interval, since there is nothing to pool toward); compositional treatment of mixes (entropy / divergence / log-ratios, not independent percent columns); weighted log-odds with a Dirichlet prior (the Fightin' Words method) for distinctive-slug ranking that shrinks unstable rare counts; Benjamini-Hochberg FDR control and paired permutation tests for any multi-cohort comparison; small-cell suppression (suppress counts of 1 to 10, caution below about 30); and ecological-fallacy discipline in the wording ("within this cohort tagged X, among observable signals, we saw Y", never "industry X does Y"). Guardrails: no persistent aggregated store (compute-and-forget; the SQLite / DuckDB hard-no holds, and with nothing persisted no differential privacy is needed); recon ships no curated lists and no industry baselines; humble naming ("cohort summary", not authoritative "industry insights"). The committed artifact is a methodology doc (`docs/aggregate-state.md`) with the metric definitions, the honesty rules, and a fully synthetic (Contoso-style) worked example with fabricated numbers; the real grouped numbers stay in gitignored local runs. Build and validate locally heading toward 2.1; if it proves out, the only thing upstreamed into core is the thinnest `recon batch --summary`, one cohort at a time, no grouping logic. v2.1 candidate, off the v2.0 schema. (Explicitly rejected, including ideas that keep resurfacing under "keep recon recon" cover: a persistent local learning store; accumulated or shipped industry baselines (including per-industry centroids in `verticals.yaml`, which is a fingerprint catalog, not a baseline store); Mahalanobis or Z-score anomaly scoring against shipped baselines; putting aggregate state into core (a top-level schema field, a core MCP tool, or a core `--aggregate` flag) instead of a downstream reducer; "industry benchmarking" or "industry intelligence" framing; inferring hidden or unobserved services from industry priors, which overclaims past the passive channel; and K-means / Markov / clustering / differential privacy over stored scans. The dependency floor holds: no pandas, numpy, scipy, matplotlib, or persistent store in core; a local sidecar may use heavier tools. All of these break the compute-and-forget, no-baseline, passive-only, defensive-only invariants.) |
| PV2 | Agentic maintainer-validation loop | maintainer ops | A periodic, maintainer-side validation loop, run by an agent rather than by hand, that keeps the Bayesian CPT numbers and the catalog honest as the world drifts. Premise: the priors and likelihoods are directionally-accurate, corpus-grounded estimates, not values precise to many decimals, and they are not meant to be; the credible interval already carries the residual uncertainty, so the right discipline is "grounded this release, re-checked next," not false precision. The loop: (1) a fresh corpus scan (`scan.py`), (2) re-ground the base rates from it, (3) the synthetic calibration and likelihood-sensitivity (CAL8) harnesses, (4) the external case-study spot-check, (5) a drift comparison against the previous release that an agent reads and, if a number moved materially, opens an issue or proposes a CPT-update PR with the reasoning (under the CPT-change discipline, with the maintainer approving any semantic change). Tiered by data sensitivity: the synthetic harnesses run anywhere with no data, the spot-check needs only public web plus recon, and the corpus re-grounding stays local on the maintainer's machine because the corpus is gitignored, aggregate-only output. Maintainer-facing, never something an end-user runs, and a natural fit for the existing agent surface (the MCP server, `agents/` scaffolding, and a `/schedule`-style routine). Not a v2.0 gate. |

#### Research write-up (aspirational): an arXiv paper

A standing, aspirational deliverable, not a release gate and not on the critical
path of any version. The assurance track has accumulated most of the substance a
paper would need (the formal missing-data treatment in `correlation.md`, the
calibration harnesses, the differential verification, the interval-coverage and
mutation gates), so the work is mostly packaging the existing rigor for an
outside reader, plus the few additional experiments below. It is recorded here so
the experiments are designed into the validation harnesses rather than
retrofitted.

**The contribution, stated honestly.** The claim is not a new algorithm; variable
elimination, Louvain, and Beta-style credible intervals are textbook. The claim
is a *combination* that is uncommon in the passive-recon literature: a
zero-credential, strictly-passive external-surface tool that preserves full
provenance (every conclusion reachable through the evidence DAG), pairs
deterministic graph correlation over certificate-transparency co-occurrence with
a small auditable Bayesian network, and treats missing evidence as
*adversarially* missing (the MNAR / `LR = 1` absence rule, grounded in m-graphs
and Manski partial identification) so the credible interval widens on hardened
targets instead of collapsing to a false verdict. The honest-evaluation posture
is itself part of the contribution: the paper would be unusually explicit about
what it does and does not validate (the near-tautological consistency check, the
synthetic-versus-real distinction, perturbation coverage framed as model-internal
rather than ground-truth, per CAL1 and CAL13), which is rarer in the area than it
should be.

**Positioning, and the one validate-differently implication (2026-06 review).**
A pass over the maintainer's research library placed recon inside the label-free
calibration conversation and surfaced one change worth making before
building more, both captured in [related-work.md](related-work.md). The
positioning: recon occupies the corner that the label-free estimators and the
conformal-under-noise methods each exclude. Confidence-based performance
estimation assumes the calibration recon declines to assert for hideable nodes
and offers nothing under shift; noise-aware conformal prediction assumes the
missingness is independent of the input, while recon's is feature-dependent and
adversarial by construction. The honest answer recon already gives (structural
guarantees that hold under hiding, calibration only where a self-defining
reference exists) is the principle-compliance methodology that the epistemic-
uncertainty-calibration line argues for. The implication worth acting on: recon's
nodes tier by whether an external reference label exists, and that tier decides
the guarantee. Provider-attested M365 tenancy and the public-declaration
email-policy node admit calibration and, newly, a distribution-free conformal
coverage check (Google tenancy is one-sided — the channel has no authoritative
negative — so it carries a recall check, not a calibration); the hideable nodes
carry only the structural guarantees. The conformal complement is a small
validation-only harness (a quantile of sorted nonconformity scores, no new
dependency, maintainer-local, aggregates only), shipped as
`validation/conformal_coverage.py` with its falsifiability split, unit-tested
in `tests/test_conformal_coverage.py`. Nothing else in the
review changed the build or validate plan; it sharpened the framing.

**Working title candidates** (humble, descriptive): "Calibrated, Provenance-Aware
Passive Inference for External Attack-Surface Management"; "Evidence-Responsive
Uncertainty for Zero-Credential Infrastructure Fingerprinting". Primary category
cs.CR; secondary stat.ML for the inference framing or cs.SE for the
artifact/engineering angle. Independent submission, no affiliation needed.

**The data-publication constraint is a first-class design problem, not an
afterthought.** The repository invariants (no real company data, ever; the corpus
stays gitignored; committed examples use the Microsoft fictional brands) mean the
empirical section cannot print the targets. The paper turns that into a
methodological feature: every empirical claim is reproducible against *public
references* anyone can re-query (DMARC / SPF / MTA-STS records as their own truth;
the Microsoft and Google identity endpoints for tenancy) plus the fully synthetic
calibration harnesses, so the results are checkable without the private corpus.
Only aggregate, posture-stratified statistics, synthetic reproductions, and the
public-reference calibration are published; the per-domain corpus never appears.
This is the same discipline PV1 and the maintainer-validation loop already
follow.

**Additional experiments to design in** (each maps to a harness that exists or is
a small extension; none crosses an invariant):

- *Ablations on the layers.* Quantify what the graph layer and the Bayesian layer
  add over single-source slug matching: drop each and measure the change in
  recovered structure on the synthetic corpus and the public-reference set. This is
  the clearest way to show the combination earns its complexity.
- *Public-reference coverage* (the CAL3 / CAL4 work already on the assurance track):
  empirical interval coverage and calibration against the authoritative records,
  reported with uncertainty (Wilson / bootstrap), never as a bare percentage.
- *Posture stratification.* Aggregate behaviour across hardening postures
  (edge-proxied, privacy-focused, financial, government-adjacent) using the
  failure-mode catalogue in `correlation.md` 4.10 to 4.11, reported as
  distributions, not exemplars.
- *Information recovered.* The per-domain entropy-reduction distribution (CAL10)
  across postures, as the operational reading of "what the public channel still
  leaks" after hardening.
- *Figures.* An architecture diagram, the nine-node network as a clean DAG,
  reliability diagrams with the posterior histogram, and an
  interval-width-versus-evidence-count plot that surfaces the documented
  correlated-binding over-confidence (CAL7). Colour-blind-safe palettes.

**What is already paper-ready** (no new work): the formal model and its
references; the calibration-legitimacy framing (CAL1 to CAL14); the
differential-verification, interval-coverage, and mutation evidence; the
operational contract and assurance case; and the artifact itself, since the repo
is reproducible (bit-for-bit builds, signed releases, a locked JSON schema, the
test and gate suite). The honest framing is that recon is "most of the way there"
on substance; the remaining effort is the additional experiments above and the
writing, which is itself bounded by the no-real-data rule.

**Explicitly out of scope for the paper**, because the tool's invariants forbid
them and the paper must describe the tool as it is: any internet-wide active scan,
any learned-weight or trained-model component, any released target list or
deanonymizable corpus, and any claim of ground-truth calibration the passive
channel cannot support. A paper that respects those limits is the only kind this
project can honestly publish.

**Track E - CLI and agent quality-of-life.** Complete. The seven items (exit-code
reference, `_SUBCOMMANDS` consistency, `batch` stdin, shell-completion docs,
`autoApprove` guidance, the `recon://schema` discovery resource, and the
data-not-instructions demarcation) shipped in v1.9.55 to v1.9.60; see the
CHANGELOG for the per-patch detail.

**CLI best-practices pass (2026).** A grade against the 2026 CLI-first rubric
(clig.dev, 12-factor CLI, MCP 2025-11, XDG, NO_COLOR, WCAG) drove a two-tier
ergonomics pass, recorded in the v2.2.0 CHANGELOG section. *Tier 1 (shipped):*
stdout/stderr discipline (diagnostics + spinners off stdout), `-h`/`-V` aliases,
a clean crash/SIGINT handler, `--color`/`--no-color`, and a `cache clear --all`
guard. *Tier 2 (shipped):* XDG base-dir support via `recon_tool.paths`
(back-compat preserved), `--plain` linear/screen-reader output, and additive
`limit`/`offset` pagination on `get_fingerprints`. *Deliberately deferred —
contract-sensitive, want a dedicated version-noted pass, not a rushed change:*
(a) migrating the MCP tools from JSON-string returns to `structuredContent` +
per-tool `outputSchema` and `isError` flagging (changes the locked,
agent-consumed wire shape and the text representation; additive in principle but
deserves a deliberate contract revision); (b) a default pagination *envelope*
(`{total, offset, next, items}`) on the list tools (changes the bare-array
shape); (c) terminal-width detection replacing the fixed 80/120 widths (the
golden-render tests pin width, so this needs the tests reworked to force width
explicitly first); and (d) grapheme/East-Asian-width column padding in the
catalog-listing tables (today `len()`-based; low impact since the content is
ASCII slugs/categories). None is on any release's critical path.

**MCP structured-output revision (Phase 1 shipped 2026-06-13).** Closes deferred
item (a). All eighteen data tools now return Python objects, so FastMCP emits
navigable `structuredContent` with a per-tool `outputSchema` plus the back-compat
serialized-JSON text block; failures raise `ToolError`, surfaced as `isError`
tool results. Narrative tools (`lookup_tenant`, `chain_lookup`, `reload_data`,
`explain_dag`) stay text by design. Posture tools share a `_resolve_single_for_tool`
helper that raises on every failure path. Pinned by
`tests/test_mcp_structured_output.py`; contract documented in `mcp.md`. Deferred
items (b) pagination envelope, (c) terminal-width, (d) grapheme width, and the
precise-typed-schema Phase 2 (TypedDict/Pydantic `outputSchema`s) remain open.
Phase 2 has started with low-risk MCP surfaces:
`get_fingerprints` now advertises a `FingerprintSummary` item schema and
`get_signals` advertises `SignalSummary` plus nested `SignalMetadataSummary`.
`explain_signal` now advertises static-definition and domain-evaluation variants
with `SignalTriggerConditions` and `SignalEvidenceSummary`. The simple
ephemeral-fingerprint session tools now advertise
`EphemeralInjectionResult`, `EphemeralFingerprintSummary`, and
`EphemeralClearResult`. The graph data tools now advertise
`VerificationTokenClusterResult`, `InfrastructureClusterEnvelope`, and
`GraphExportEnvelope`. The compact agent-facing posture helpers now advertise
`HypothesisAssessmentResult` and `HardeningSimulationResult`. `get_posteriors`
now advertises `PosteriorBlockResult`, `PosteriorNodeSummary`, and
`UnitCounterfactualSummary`. The exposure report tools now advertise
`ExposureAssessmentResult`, `GapReportResult`, and `PostureComparisonResult`
with nested evidence and posture record definitions.
`discover_fingerprint_candidates` now advertises `FingerprintCandidate` plus
nested `FingerprintCandidateSample`. `analyze_posture` now advertises its list,
profiled, explained, and profiled-explained result variants.
`reevaluate_domain` now advertises its full cache-only lookup record as
`LookupResult`, with nested definitions for the formatter payload. The precise
TypedDict schema pass is complete for data-returning MCP tools; narrative tools
remain text by design.
The design record that drove it, kept for rationale:

A mid-2026 research pass (cited best-practices report) plus a code investigation
turned deferred item (a) into a ready-to-execute plan. Findings:

- *Spec currency.* The current stable MCP revision is **2025-11-25** (recon's
  citation is correct). A **2026-07-28** revision exists only as a release
  candidate, is explicitly not final, and carries breaking changes, so the
  revision targets 2025-11-25 and does not chase the RC items
  (`structuredContent` as any JSON value, full 2020-12 composition,
  `tools/list` `ttlMs`/`cacheScope`).
- *FastMCP 1.27 mechanics (verified empirically).* A typed return value
  auto-generates `outputSchema`, populates `structuredContent`, AND emits a
  serialized-JSON text block for back-compat. A `-> str` return (every recon
  tool today) wraps as `structuredContent = {"result": "<string>"}`, so the
  JSON-returning tools currently emit their JSON as a double-encoded string
  blob, not navigable data. A raised exception is wrapped as `ToolError` and the
  low-level server converts it to an `isError: true` tool result, which is the
  spec-correct category for execution and input-validation errors.
- *Phase 1 change.* Pure-data tools return the object instead of
  `json_mod.dumps(obj)` (`-> dict`/`-> list[dict[str, Any]]`); error `return`
  paths become `raise ToolError(...)` so `isError` is set and the model can
  self-correct; permissive `outputSchema` (`additionalProperties: true`) is
  acceptable, with precise TypedDict/Pydantic models a later phase. Dual-format
  and narrative tools (e.g. `lookup_tenant` text) stay `-> str`.
- *Why one coherent PR, not tool-by-tool.* It is all-or-nothing for contract
  consistency: a half-migrated server gives some tools navigable
  `structuredContent` + correct `isError` and leaves most as string blobs with
  `isError` always false, which is more confusing than the status quo. The blast
  radius is real: each return-type change ripples into the direct-call tests
  that do `json.loads(await tool())` and flips the error tests to
  `pytest.raises(ToolError)`. The three introspection tools alone touch ~40 test
  sites across `test_explain_integration.py`, `test_mcp_introspection.py`, and
  `test_server_agentic.py`; all 22 tools span more. Update `mcp.md`; the locked
  CLI `--json` v2.0 schema is a separate surface and stays untouched.

Verified-already-correct in the same pass (no change needed): the
`NO_COLOR`/`TERM=dumb` contract (recon delegates to Rich 15, which honors the
present-and-non-empty rule and yields no color system on `TERM=dumb`; pinned by
`tests/test_formatter.py::TestColorSuppressionContract`), and deterministic
`tools/list` ordering (FastMCP preserves decorator-registration order). OSC 8
terminal hyperlinks for printed URLs (vendor-doc links, crash-log path), with a
plain-text fallback off a TTY, remain an available polish item (Rich supports
them natively).

**Module decomposition (god-file split) — complete (2026-06-14), ratcheted.** A 2026 metrics
pass found several modules far over the ~1000-line convention: `formatter.py`
(4413), `cli.py` (3941), `server.py` (3114), `sources/dns.py` (2524),
`bayesian.py` (1411), `merger.py` (1131), `exposure.py` (1130). Track A
decomposed *functions* (the C901 cap) but never *files*. `scripts/check_file_size.py`
now baselines these as ceilings that may only shrink (CI-gated), so they cannot
regrow and new modules cap at 1000 lines. The work is to split each into a
cohesive subpackage while preserving the public import path and keeping the
golden/snapshot tests byte-identical.

All seven flagged modules are now decomposed: the two in the 1000-1130 band,
`sources/dns.py`, `bayesian.py`, `server.py`, and `cli.py` are under the cap,
and `formatter.py` is reduced to its cohesive panel core (~2160, kept whole by
design). The decomposition track below is complete; each entry is marked Done
with the approach taken, kept as the record of how the splits were sequenced and
what was learned:

1. `formatter.py` → split by render concern. **Done (4413 → ~2160, five
   modules):** exposure/gaps rendering → `formatter_exposure.py`; the shared
   service-classification layer → `formatter_classify.py` (logic) plus
   `formatter_classify_tables.py` (the ~880-line slug/vendor/keyword data dicts);
   the markdown report renderer → `formatter_markdown.py`; and the non-Rich data
   serializers (the json-dict / json / plain / CSV layer, including the shared
   `format_tenant_dict`) → `formatter_serialize.py`. `formatter` re-exports every
   moved public name and aliases the historical `_NAME`s, so the import/test
   surface is byte-identical. What remains in `formatter.py` is the cohesive Rich
   panel core (`render_tenant_panel` and the secondary panels), now ratchet-capped.
   **Two learned constraints, recorded so the cli/server/dns splits reuse them:**
   (a) *extract the shared layer first* — the renderers all depend on the
   classification layer, so a renderer-first extraction was reverted until
   classify came out; (b) *cross-module names must be public* — pyright-strict
   flags cross-module underscore access as `reportPrivateUsage` (the `tests/`
   executionEnvironment relaxes it, production does not), so a moved module
   exposes public names and the origin module aliases them back to `_NAME`. Where
   a module exceeds the 1000-line cap on its own (the classification data dicts),
   split the data tables from the logic.
2. `cli.py` → split each self-contained Typer sub-app into a sibling module that
   defines and exports the sub-app; `cli.py` imports it and keeps the
   `app.add_typer(...)` registration (no package conversion, no circular import,
   since the sub-app pulls nothing from `cli.py` and its commands use inline
   imports). **Done for the sub-apps (3941 → ~2830):** `cache` → `cli_cache.py`,
   `mcp` → `cli_mcp.py`, `signals` → `cli_signals.py` (with its signal-render
   helpers), and `fingerprints` → `cli_fingerprints.py`. The one shared helper a
   sibling needed (`_fmt_exc`, used across ~20 sites) moved to `cli_shared.py`
   first so the sibling could import it without a cycle. **Done for the command
   core too (2800 → 702):** the `@app.command` functions turned out to be thin
   wrappers delegating to helper families, so the app-sharing variant was not
   needed after all. The `_lookup_*` / `_batch_*` / `_doctor_*` implementation
   helpers moved to `cli_lookup` / `cli_batch` / `cli_doctor` (plain leaves, since
   they call `get_console()` rather than touch module state); `cli.py` keeps the
   Typer `app`, the thin commands, and the sub-app registration, and references
   the orchestrators through an assignment facade so no call site is qualified.
   The white-box tests that reach into the batch reader and the status spinner
   point at the impl modules, including the `_MAX_BATCH_*` and
   `_STATUS_ROTATE_SECONDS` monkeypatch targets.
3. `exposure.py` → **Done (1130 → 983):** the frozen result-type family
   (`EvidenceReference` / `EmailPosture` / `IdentityPosture` / `ExposureAssessment`
   / `GapReport` / `PostureComparison` and kin) split to `exposure_models.py`, a
   pure data-vs-logic seam; `exposure` re-exports every name. Clean single lift
   because the dataclasses are pure and already public.
4. `merger.py` → **Done (1131 → 958):** the gateway/provider slug sets and the
   slug-humanizing name maps split to `merger_tables.py`; `merger` re-exports each
   under its historical `_NAME` so internal callers and `test_email_topology.py`
   are unchanged. Same data-table lift as `formatter_classify_tables`.
5. `bayesian.py` → **Done (1411 → 926):** the models-first variant as planned.
   The `_Node` / `_Evidence` (publicized to `Node` / `Evidence`) and the result
   dataclasses moved to `bayesian_models.py`; the YAML loaders, parsers, topology
   validation, and prior-override application moved to `bayesian_loader.py`
   (importing the dataclasses, one-directional). The inference engine and the
   `TenantInfo` adapters stayed in `bayesian.py`, moved byte-identically, so the
   cosmic-ray mutation surface (the inference core) is unchanged and its 12%
   floor holds; `bayesian.py` re-exports every name (aliasing `Evidence` / `Node`
   back to `_Evidence` / `_Node`), so the import path and the differential /
   drift / contract harnesses are unchanged. The loaders and dataclasses keep
   their unit-test coverage but sit outside the inference-core mutation surface by
   design (see `validation/mutation-gate.md`).
6. `server.py` → **Done (2859 → 406, app-sharing variant):** the shared FastMCP
   instance, server instructions, and the validate/cache/rate-limit/resolve seam
   moved to `server_app.py`; the in-process runtime state (TTL cache, rate
   limiter, structured logging) to `server_runtime.py`; and the MCP tools grouped
   by domain into `server_ephemeral`, `server_lookup`, `server_posture`,
   `server_graph`, and `server_introspection` (the last also holds the four
   catalog resources). Each tool module imports `mcp` from `server_app` and
   registers on it; `server.py` imports them for the registration side-effect,
   keeps the prompt and the `main()` entry point, and re-exports every tool plus
   the runtime facade for the test surface. The one new lesson over the dns split:
   every resolve call (helpers and the inline tool resolutions) routes through
   `server_app.resolve_tenant` so the network seam is patchable from one place,
   and the resolve/cache monkeypatch targets retarget to `server_app` /
   `server_runtime` accordingly.
7. `sources/dns.py` → **Done (2524 → 840, four leaves):** the static catalogs +
   pure parsers → `dns_tables.py`; the resolver primitives + `DetectionCtx` →
   `dns_base.py` (the `safe_resolve` seam tests monkeypatch, so detectors call it
   qualified and patches live in one place); the email-channel detectors →
   `dns_email.py`; and the infra/hosting/CT detectors → `dns_infra.py`. `dns.py`
   keeps the `DNSSource` orchestrator and its surface-classification pipeline and
   re-exports each moved `detect_*` under its `_NAME`. Reused the formatter
   constraints (extract the shared leaf first; cross-module names public) and
   added one: the resolver/provider/fingerprint-getter monkeypatch seam moves
   with the code, so test patches retarget to the defining module.

Each split is its own commit: move code, re-export from the original path so
imports and the locked surface are unchanged, run the full gate + golden tests,
then lower the ratchet baseline via `scripts/check_file_size.py --update`.
Sequenced highest-value-and-cleanest-seam first; none changes behavior or the
v2.0 contract. Standards and rationale: [engineering-practices.md](engineering-practices.md),
[adr/](adr/).

**Track A - Complexity decomposition.** Complete as of v1.9.76. Zero
`# noqa: C901` markers remain in `recon_tool/`, so the mccabe cap of 15 from
v1.9.37 now holds the whole tree, not just new code. The full sweep (formatter,
posture / insights core, the validator/loader tail, `validation_runner`,
`sources/dns`, `cert_providers`, `explain_insights`, and the behaviour-heavy
tail below) is in the CHANGELOG.

| # | Story | Status | Acceptance |
|---|---|---|---|
| A6 | `cli` behaviour-heavy set | done (v1.9.72-v1.9.74) | `signals_show` + `_doctor` (v1.9.72), `_lookup` (v1.9.73), `_batch` (v1.9.74), each characterized then decomposed under the cap. A new `tests/test_signals_show_cli.py` covers the previously-untested `signals show`. |
| A7 | `merger.merge_results` (64) | done (v1.9.75) | Decomposed under the cap via single-purpose helpers; the merge property tests stayed green. |
| A8 | `server` tool pair | done (v1.9.76) | `lookup_tenant` (text rendering to `_lookup_tenant_text`) and `simulate_hardening` (fix-parsing to `_simulate_fixes`) decomposed; server / exposure / GWS tests green. |

**Track B - Test and validation rigor:**

| # | Story | Status | Acceptance |
|---|---|---|---|
| B1 | `deal` contracts on boundary validators | done (v1.9.77) | Third `deal` pass: `@deal.post` on `strip_control_chars` (no-control-chars) and `validate_domain` (normalized-domain), named predicates with fire-on-violation tests in `test_contracts.py`; no-ops under `-O`. |
| B2 | Cache-lifecycle stateful machine | done (v1.9.78) | `tests/test_cache_stateful.py`: a Hypothesis `RuleBasedStateMachine` drives write / unknown-fields / corrupt / stale / clear / clear-all over a valid+invalid domain pool and reconciles disk against a model each step (load-known / ignore-unknown / skip-malformed / TTL-evict / traversal-safe). |
| B3 | Source-boundary fault injection | done (v1.9.79) | `tests/test_source_fault_injection.py`: a `_FaultySource` drives raise / hang / error / degraded / good modes through `_safe_lookup` and `resolve_tenant`, asserting exception hygiene, degraded surfacing, hedged output, all-fail, and timeout; one case isolates a malformed OIDC payload end to end. |
| B4 | Branch coverage toward `server.py` | done (v1.9.80) | `tests/test_server_bayesian_tools.py` covers `get_posteriors`, `explain_dag`, and `cluster_verification_tokens`, lifting `server.py` to ~75%. The global 82% branch gate is left unratcheted to avoid flaky failures on unrelated dips. |

**Track D - Robustness and security:**

| # | Story | Status | Acceptance |
|---|---|---|---|
| D1 | Ingestion adversarial bug-hunt | open | A fresh adversarial pass over the DNS / CT / BIMI VMC / identity-endpoint parse paths plus input edge cases (IDN / punycode, malformed, oversized, truncated); any finding fixed and folded into `docs/security-audit-resolutions.md` as a new round. |
| D2 | Operator-paced scanner pass | operator-paced | Any Codex / external scanner pass between now and the tag adds to the closure trail if it surfaces anything new. |

**Track C - Catalog growth** (the corpus-driven depth that is the real v2.0
gate; see "The pre-2.0 build plan" below for the empirical bar):

| # | Story | Status | Acceptance |
|---|---|---|---|
| C1 | Vendor-doc-sourced `cname_target` additions | done (v1.9.82-v1.9.86) | High-precision `cname_target` rules sourced from public vendor docs via the `CONTRIBUTING.md` methodology (21 rules, 808 to 829 entries). Committed examples use the fictional brands. |
| C2 | Full-corpus fingerprint mining | third-party residual closed (v1.9.87-v1.9.89) | `validation/scan.py` over the gitignored corpus plus `validation/find_gaps.py` and `/recon-fingerprint-triage`, merging vetted rules so the gap report reaches a low residual. Three verified batches shipped (v1.9.87 to v1.9.89, 13 vendors, 829 to 841 entries; trail in `validation/v1.9.87-c2-corpus-batch.md`). The named third-party residual is closed; the remaining high-count termini are org-internal GSLB / load-balancers that are not catalogued by design. Run locally; aggregate counts and vetted patterns reach the repo, real apexes do not. |
| C3 | CT-enabled full-corpus calibration | corpus-driven (local) | A complete (CT-enabled) full-corpus Bayesian calibration run so `infrastructure_clusters` and the region / shard `lexical_observations` are exercised on real input; per-node Brier / ECE, deterministic-vs-Bayesian agreement, sparse-case interval coverage, and the CAL10 entropy-reduction numbers tabulated, extending the release trend. Run locally; only aggregate metrics reach the repo. |

**v2.0 docs currency** (ships as one or two patches once the tracks above
settle, before the lock):

| # | Story | Status | Acceptance |
|---|---|---|---|
| F1 | Release-notes draft brought current | done | `validation/v2.0-release-notes-draft.md` extended through v1.9.95: the release-range table now covers the C2 corpus mining (v1.9.87-v1.9.89), CAL14 (v1.9.90), and the schema hardening (v1.9.91-v1.9.95); the schema-lock section describes the SH reshapes and the experimental-to-stable promotion note is corrected for the slug_confidences reshape. |
| F2 | Validation-summary refresh | docs done; C3 re-run remaining | `validation/v2.0-validation-summary.md` refreshed through v1.9.95: a post-v1.9.14 section covers the CAL track, CAL14 (synthetic conditional ECE about 0.31 to about 0.03), catalog C1/C2, the spot-check, and SH1-SH9; the stale corpus-gate and disposition-carried-unchanged claims are corrected. The CT-enabled full-corpus re-run (C3) that exercises the cert surfaces and reflects CAL14 on real input is the remaining corpus-driven step; the nine DNS/identity-fed nodes are already calibrated by the existing passes. |

**Pre-2.0 schema hardening (gates G1). SHIPPED v1.9.91 to v1.9.95.** A four-lens
pre-lock review of `docs/recon-schema.json` (API-design, Bayesian,
downstream-consumer, and long-term-maintainer perspectives, 2026-06-05) found a
finite set of field shapes that were cheap to fix before the lock but would have
needed a major (3.0) bump with a deprecation window to fix after. All nine items
shipped in five risk-ascending patches: v1.9.91 (SH1 descriptions, SH3 CT
loosening, SH4 cloud_instance enum drop), v1.9.92 (SH2 slug_confidences object
map, SH5 wildcard_sibling_clusters objects), v1.9.93 (SH6 fusion_enabled flag),
v1.9.94 (SH7 record_type / schema_version discriminator, SH8 error_kind), and
v1.9.95 (SH9 the include-ecosystem always-wrapper behavior fix). The two CS-panel
decisions resolved to the object map (SH2) and yes to the discriminator (SH7).
The bulk of the schema reviewed clean (the named-object `$defs`,
`posterior_observations`, `DeltaReport`, the nullable cert / BIMI objects,
`NodeConflict.magnitude`) and was left untouched. With the track done, G1 now
applies the lock to a surface with no known regret. The rows below are the
original plan, kept for the per-item detail; the schema-vs-emitter drift test
(`tests/test_json_schema_file.py`) and the batch-record contract test gate the
locked surface.

| # | Story | Decision | Acceptance |
|---|---|---|---|
| SH1 | Schema-description reconciliations | resolved | Reconcile the contradictory `partial` description (the JSON's "core sources only, not CT-only degradation" definition wins; fix `schema.md`); update the `sparse` / `n_eff` descriptions so they survive CAL14 (a declarative node can be confidently-absent: low posterior, narrow interval, `sparse=false`); tighten the credible-interval description to the CAL13 "evidence-responsive, not frequentist coverage" framing. Verify the maintainer-flagged `detection_scores` schema-vs-model shape (map vs pairs) and fix if drifted. Descriptions only, no field-shape change. |
| SH2 | `slug_confidences` to object map | resolved (CS panel): object map `{slug: posterior}` | Reshape the v2.0-new `slug_confidences` from a positional `[slug, posterior]` tuple to an object map `{slug: posterior}`, matching its structural twin `detection_scores` (the other slug-keyed scalar map) rather than the node-keyed `posterior_observations`. The panel split 2-1 for array-of-objects, but slug_confidences is slug-keyed with a scalar value (a map), the repo's own consumer already rebuilds it into a dict, and both shapes are equally 3.0-safe (a future per-slug interval is an additive sibling map either way), so the map is the more consistent permanent shape. Update the emitter, the cache round-trip, the schema, the tests. |
| SH3 | CT telemetry out of `required` | resolved | Remove `ct_provider_used`, `ct_cache_age_days`, `ct_attempt_outcome` from the root `required` list (keep emitting them as optional properties) so the CT pipeline can be restructured later without a 3.0. Pure loosening; the schema-contract required set updates. |
| SH4 | `cloud_instance` enum drop | resolved: drop enum, keep name | Drop the closed host enum on `cloud_instance` (Microsoft controls those values and adds sovereign clouds); keep type `string\|null` and document the known values. Keep the field name (a rename would break v1.x consumers for a cosmetic gain; not worth it). Same treatment for `tenant_region_sub_scope` only if a value gap appears. |
| SH5 | `wildcard_sibling_clusters` to objects | resolved | Reshape from a bare `list[list[string]]` to an array of `{names: [...]}` objects (room for the generating wildcard SAN / issuer later), matching the adjacent `CertBurst`. Experimental v1.7+ field; changes before the lock. |
| SH6 | `fusion_enabled` flag | resolved: add the flag | Add a required top-level `fusion_enabled: bool` so a consumer can tell `slug_confidences: []` / `posterior_observations: []` meaning "fusion off" from "fusion ran, found none". Keep both arrays `required` (2.0 flips `--fusion` default-on, so they are normally populated; the flag only disambiguates `--no-fusion`). `surface_attributions` is not fusion-gated and needs no change. |
| SH7 | Record discriminator | resolved (CS panel): yes | Add a required `schema_version` ("2.0") to the single-domain root and a `record_type` discriminator (`lookup` / `batch_result` / `delta` / `error`) to each object-shaped mode, so consumers (especially an agent handed a bare payload) do not discriminate by accidental key-disjointness. A required discriminator cannot be added cleanly after the lock (an agent cannot depend on an optional field); `record_type` is a field you would never drop, so "required forever" costs nothing, and `schema_version` is the only in-band 2.x->3.0 signal a detached payload carries. The cache reader defaults both fields on read for pre-2.0 entries (the same graceful-degradation pattern used for posterior_observations). |
| SH8 | `BatchErrorRecord` machine-readable kind | resolved | Add an `error_kind` enum (`validation` / `lookup` / `timeout`, extensible) to `BatchErrorRecord` and bless the "a success record never carries a top-level `error` key" guarantee in the contract, so a SIEM routes on a code not free-text and the cheap discriminator is stable. The error record is `additionalProperties: false`, so the slot must exist before the lock. |
| SH9 | `--include-ecosystem` always-wrapper | resolved | When `--include-ecosystem` is set, always emit the `BatchResult` wrapper (errors under `domains`, `ecosystem_hyperedges: []`) instead of falling back to a bare array when no domain resolved, so the top-level type does not flip on an all-failed batch. The one behavior change; gated by the batch-output tests. |

Two decisions want explicit sign-off before they ship: the `slug_confidences`
object form (SH2: array-of-objects recommended, vs an object-map) and whether to
add the `record_type` / `schema_version` discriminator (SH7). The rest are
clear-cut. Once SH1 to SH9 are green, G1 applies the lock to a surface with no
known regret.

**v2.0 lock ceremony** (operator-paced; mechanical, runs only after every row
above is green; Outstanding item 5):

| # | Story | Status | Acceptance |
|---|---|---|---|
| G1 | Schema lock | done (2.0.0) | `docs/recon-schema.json` (both copies) bumped from "Stable v1.0 contract" to "Stable v2.0 contract", additive-within-2.x; README, the formatter comments, and the contract-test docstring updated; `recon doctor` first line reads "v2.0 stable schema" (version-driven). EXPERIMENTAL labels were already zero in user-facing surfaces (stripped in v1.9.11). |
| G2 | `--fusion` default-on | done (2.0.0); panel speak-up done (2.0.1) | Fusion runs on every lookup; `--json` always emits the posteriors; `fusion_enabled` disambiguates; `--no-fusion` (new) opts out; `--fusion` is a now-default no-op. v2.0.1 added the panel "speak up": posterior-backed confidence dots (the weakest claimed node's interval position relative to the threshold), a dimmed plain-language clause when a claimed node is thin or contested, and the per-node intervals under `--verbose`. Without posteriors the panel is byte-identical to v1.x. See the v2.0.1 panel-disclosure design note below. |
| G3 | `correlation.md` promotion | done | Promoted from living draft to the polished reference: the header framing updated, the node-dependent-missingness section (4.3) rewritten to the shipped CAL14 reality (declarative email-policy node, the n_eff / stability ripples handled, corpus-grounded numbers, ECE about 0.31 to about 0.03). The four required sections are present (defense-correlation mapping 4a, prior-art 4b, dependency-floor manifesto 4c, failure-mode catalog 4.10); the CAL13 evidence-responsive framing and the ground-truth / independence-bias caveats are in place. No math removed. |
| G4 | Changelog move + tag | done (2.0.0 commit); tag pending operator | `CHANGELOG.md` carries the `## [2.0.0]` entry summarizing the lock; `docs/migration-v2.md` finalized (draft banner removed); version bumped to 2.0.0. The `v2.0.0` tag is the one remaining operator action (it publishes to PyPI), held for explicit go. |

Schema-contract polish (the original Outstanding item 1) shipped in v1.9.26 and
is not in the queue. The original v1.9.4 to v1.9.11 numbered sequence (now in
[roadmap-history.md](roadmap-history.md)) is historical: every one of those
versions shipped, and the current framing is these five tracks plus the lock
ceremony, not that sequence.

### The pre-2.0 build plan: corpus-driven validation depth

2.0 is the "polished and excellent everywhere" release, so before the schema
locks the engine and catalog have to be demonstrably excellent rather than
merely present, and that bar is set empirically against the private corpus of
5,000+ companies, not asserted. The rest of the 1.9.x build series is, at its
core, about exhausting what that corpus can teach before the lock. Two threads
run in parallel, each as its own focused 1.9.x patches:

- **Fingerprint and pattern excellence.** Keep mining the full corpus with
  `validation/scan.py` (the 4-5k+ domain library) and the
  `/recon-fingerprint-triage` flow, merging vetted `cname_target` and other
  rules so the catalog (841 entries today, up from 808 via the v1.9.82 to v1.9.86
  live-analysis batches and the v1.9.87 to v1.9.89 corpus-mining batches) closes its
  residual coverage gaps and every high-value detection is precision-checked
  against real observations. The goal at lock time is a catalog that is
  comprehensive and high-precision across the whole corpus, with the
  fingerprint-gap report driven to a low residual, rather than resting on the
  top-tier-vendor spot checks that cleared early. This is the "Catalog growth"
  track above, run to completion rather than opportunistically.
- **Thorough Bayesian-layer validation.** Run complete full-corpus calibration
  passes, not spot checks: per-node Brier / ECE, deterministic-versus-Bayesian
  agreement, and credible-interval coverage on sparse-evidence cases, repeated
  across the release trend so the calibration claims stay falsifiable over time
  rather than at one moment. The broadest run so far (2026-05-26) had 13,939 of
  13,939 high-confidence posteriors agree with the deterministic pipeline, zero
  cross-source conflicts across 5,236 successful domains, and all 9 nodes inside
  the v1.9.5 stability gates (Brier <= 0.05, ECE <= 0.19). Before lock we want a
  CT-enabled full-corpus re-run so the cert-fed signals
  (`infrastructure_clusters`, the region / shard `lexical_observations`) are
  exercised on real input too, plus confirmation that the trend holds across the
  rest of the hardening series, not just at one snapshot.

All of this stays aggregate-only: no apex names or per-domain output is
committed (the corpus lives in gitignored paths), so what reaches the repo is
counts and calibration metrics, not the underlying data. This corpus-driven
depth is what "demonstrably solid" means above, and it, not docs currency or
ceremony, is the real gate. 2.0 is revisited only once it holds; the items
below are the mechanical lock ceremony that follows it.

**Outstanding before v2.0:** *(refined 2026-05-26 after the v1.9.24
mega-batch; the v1.9.24 entry above absorbed items 1 and the
fingerprint / engine work that originally would have been split
across multiple patches.)*

The work below ships as 1.9.x patches following the no-bundling
discipline; v2.0 itself stays the mechanical lock event with no
new work. Recommended sequencing is at the end.

1. **Schema-contract polish.** *(SHIPPED in v1.9.26. Chose option (a):
   document the error-record shape and add an explicit pure-Python
   allowance rather than change runtime output. A fourth gap surfaced
   while grounding the work and was fixed in the same patch: the
   `BatchResult` `$def` claimed batch JSON always wraps under `domains`,
   but the default `recon batch --json` emits a bare array. See
   `validation/v1.9.26-schema-contract.md`.)* Three items the pre-lock
   audit surfaced in `docs/recon-schema.json` and the way real output
   relates to it:

   - The schema description currently reads "Stable v1.0 contract
     for `recon <domain> --json` output", but batch NDJSON output
     (`recon batch ... --ndjson`) also emits records, including
     input-validation error records of shape `{domain, error}`
     that do not match the single-domain contract. The schema
     must explicitly state its scope (single-domain success
     output) and either (a) document the batch error-record shape
     separately or (b) emit the full skeleton on input-validation
     failures.
   - Fields `domain` and `error` appear in batch error records
     but are not declared in the schema's `properties`. Either
     declare them with conditional semantics or document the
     omission with intent.
   - Fields `explanation_dag` and `unclassified_cname_chains` are
     in the schema but conditionally emitted (only with
     `--explain-dag` / `--include-unclassified`). Document the
     conditional emission explicitly so consumers do not infer
     "always present".

   *Acceptance:* a sample batch NDJSON over the private corpus
   validates against the schema using a single deterministic rule
   set (success records pass the full shape; error records are
   handled by an explicit allowance), and a re-read of the schema
   prose answers "what shape can I expect from each output mode"
   without ambiguity.

2. **Release-notes draft brought current.** `validation/v2.0-
   release-notes-draft.md` was staged in v1.9.14 prep and covers
   v1.9.3 through v1.9.14 only. The releases since (v1.9.15
   through whatever the last 1.9.x is at lock time) must be added
   so the eventual v2.0 CHANGELOG entry captures the full pre-2.0
   work. The post-v1.9.14 work includes audit rounds 1-5 (DNS
   leak, CT / BIMI ingestion, MCP / CLI / output injection, DoS /
   resource, detector exception isolation), the cname_target
   fingerprint expansion (v1.9.22), the broader corpus-
   discovery batch (v1.9.23, 113 new fingerprints), and the
   v1.9.24 mega-batch (216 catalog entries plus shadow-handling
   consistency across substring matchers and the cname-regex
   matcher fix).

   *Acceptance:* the draft's release table covers every tag from
   v1.9.3 through the lock-time 1.9.x, each row linked to its
   shipping patch and validation memo; the security closure table
   reflects rounds 1-5 in addition to the original 2026-05 cycle.

3. **Validation-summary refresh with the full-corpus baseline.**
   `validation/v2.0-validation-summary.md` was published in
   v1.9.14 prep. A full-corpus Bayesian calibration run on
   2026-05-26 produced the broadest result the project has:
   13,939 of 13,939 high-confidence posteriors agree with the
   deterministic pipeline (100%), zero cross-source conflicts
   across 5,236 successful domains, and all 9 nodes pass the
   v1.9.5 stability gates with Brier <= 0.05 and ECE <= 0.19.
   The summary should incorporate this run as the v2.0 lock-time
   baseline rather than the v1.9.14 snapshot, so the document a
   v2.0 consumer reads is the freshest evidence the engine
   improved. A CT-enabled re-run is also wanted before lock so
   `infrastructure_clusters` and the region / shard kinds of
   `lexical_observations` are exercised on real input rather than
   recorded as "no data" (the no-CT run skips the cert layer that
   feeds both signals).

   *Acceptance:* the summary's trend table extends through the
   2026-05-26 full-corpus run with CT enabled; per-node stability
   metrics on the full corpus are tabulated; the historical
   v1.9.14 baseline remains as the prior reference point.

4. **Codex security scans (operator-paced).** Continuing the
   trail that closed in v1.9.4 / v1.9.9 / v1.9.13 / v1.9.14 plus
   rounds 1-5; `docs/security-audit-resolutions.md` records the
   closure trail. Any additional scanner pass between now and the
   v2.0 tag adds to that trail if it surfaces anything new.

5. **Mechanical lock ceremony (v2.0.0 itself).** Once items 1-4
   are addressed:

   - Bump `docs/recon-schema.json` description from "v1.0
     contract" to "v2.0 contract"; strip EXPERIMENTAL language
     from the promoted-field descriptions per the schema-lock
     disposition table.
   - Flip `--fusion` to default-on with the clean-panel
     disclosure rule (see "v2.0 design decision" section below).
   - Promote `correlation.md` from living draft to polished
     reference, with the four sections the snapshot requires
     (defense / correlation mapping, prior-art comparison,
     dependency-floor manifesto, failure-mode catalog).
   - Move `validation/v2.0-release-notes-draft.md` body into
     `CHANGELOG.md` under `## [2.0.0] - <date>`; delete the
     draft file.
   - Run `scripts/release.py`.

**Recommended sequencing.** Items 1 through 3 ship as 1.9.x
patches, one per coherent story. The actual order kept diverging from the
original plan because standing work claimed the next number: **v1.9.25**
took the operator-paced CT-resilience + catalog story, sliding the
schema-contract polish to v1.9.26; **v1.9.27** took the MCP-onboarding
story; and the **engineering-elevation series** (the adopted slice of the
2026-05 standards review, see Engineering quality posture) then claimed
v1.9.28 onward, sliding the docs-currency work further down the line.

- ~~**v1.9.25** lands the schema-contract polish (item 1).~~ Shipped
  instead as **v1.9.26** (v1.9.25 was the CT-pipeline-resilience patch).
- **v1.9.27** lands MCP-onboarding UX and folds in the standards review.
  Standing work, not a numbered item.
- **Engineering-elevation series** (standing work) runs as a sequence of
  focused patches, each its own story: **v1.9.28** shipped `py.typed` +
  the 3.14 matrix; the next patches raise the floor to `>=3.12` (later
  relaxed back to `>=3.11` in v1.9.43), add the
  quality gates (branch coverage + the complexity refactor), adopt `deal`
  Design-by-Contract, migrate to PEP 735, and add the provenance step.
  Details and per-item rationale are in the Known gaps list.
- **v2.0 docs currency** (original items 2 and 3): bring the release-notes
  draft current and refresh the validation summary. Ships as one patch
  once the elevation series settles, before the lock.
- Item 4 runs in parallel on the operator's schedule and folds
  into the closure trail as it lands.
- **v2.0.0** is item 5, the mechanical ceremony, after the docs-currency
  patch is in `main` and any pending scanner pass has settled.

Current theme: treat correlation as inference
over a graph of strictly public observables (DNS, CT, identity-discovery
endpoints), keep every output hedged with full provenance, and let live
validation against a private corpus drive what ships next.

## What recon is

recon is the **passive-DNS primitive**: given an apex domain, return hedged
observations about the organization's public technology stack and identity
posture using public DNS, certificate transparency, and unauthenticated
identity-discovery endpoints.

It is designed to be consumed by other tools - active scanners, company
research enrichers, GTM systems, agent workflows - not to become those tools.
Humility over completeness is the product line: if a feature would make sparse
evidence sound more certain than it is, it does not belong here.

It is also meant to be useful to security teams, compliance analysts, vendor
due-diligence practitioners, IT architects, and AI-agent workflows that need
clean, provenance-rich public-signal visibility. The right mental model is a
composable building block, not a standalone source of truth.

## What recon can and can't do against a hardened target

Honest framing: a disciplined paranoid setup - wildcard certs everywhere,
short-lived rotation, multi-hop randomized proxy chains, decoy noise, minimal
public DNS, hardened IdP metadata - will always produce sparse, low-confidence
output. That is physics, not a bug. The "obscurity is not security" critique
cuts both ways: a defender can choose to publish very little, and recon will
report very little.

What we can do better is make the residual signal go further. Wildcard certs
still leak sibling SAN sets within the same issuance batch. Short-lived certs
still land in CT logs with timestamps. Randomized CNAME chains still expose
recurring proxy motifs and intermediate-vendor markers. Multi-hop chains have
structure even when individual hops look bespoke. Treating the noisy
remainder as an inference problem - graph structure, temporal proximity,
chain motif libraries, vertical baselines - recovers usable defensive
intelligence that single-hop fingerprinting misses, while staying inside the
invariants.

Progress shows up as **multi-signal correlation depth**: `--explain`
outputs whose evidence DAG references more than one source per
high-confidence slug. The metric is tracked per release against the private
corpus (see Success Metrics) and is the lens we use to ask "did the new
correlation work do something single-source detection could not?". The
**Build plan** below lists the concrete extensions, each gated by the same
live-validation discipline.

See [correlation.md](correlation.md) for the formal latent-variable model
$G = (V, E, \Theta)$, the mutual-information objective, and the detailed
mapping of each planned extension (v1.7 through v1.9) to hardened-target
signal recovery.

## Current Fingerprint Library Assessment

Built-in fingerprints live in nine categorized YAML files under
`recon_tool/data/fingerprints/`: `ai.yaml`, `crm-marketing.yaml`,
`data-analytics.yaml`, `email.yaml`, `infrastructure.yaml`,
`productivity.yaml`, `security.yaml`, `surface.yaml`
(per-subdomain CNAME-target classification, added in v1.5), and
`verticals.yaml`.

**Current totals** *(as of v1.9.89)*:

- 841 fingerprint entries (808 at v1.9.53, plus 21 cname_target rules from the
  v1.9.82 to v1.9.86 live-analysis batches and 13 vendors from the v1.9.87 to
  v1.9.89 C2 corpus-mining batches).
- All slugs map to a defender-visible category in `formatter.py`.
- Zero cross-file slug-name collisions (verified by `tests/test_fingerprint_expansion.py`).

**Coverage outlook.** v1.9.3.9 closed the largest cloud-vendor coverage
blindspot (GCP / Azure non-O365 / Oracle / IBM / Alibaba / SaaS-PaaS /
SSE-SASE) via vendor-doc-sourced fingerprints. Empirical validation
against a stratified sample of known-rich-stack public companies
(Stripe, Shopify, Slack, Atlassian, Datadog, HashiCorp; gitignored
private corpus) showed **zero unclassified CNAME chain termini** on
these targets - the catalog is comprehensive for top-tier enterprise
vendors. Residual coverage gaps live in lesser-known regional clouds
(Yandex, OVH, Kakao), SAP / Oracle SaaS apps beyond Fusion, and the
long-tail SSE/SASE vendors (iboss, Versa, Aryaka).

**What remains.** The metadata richness pass is the largest pending
catalog-quality item - see Track B below. Description and reference
coverage targets (≥ 80% / ≥ 25%) before v2.0; the vendor-doc-sourced
methodology codified in `CONTRIBUTING.md` advances reference coverage
on every new `cname_target` rule shipped under it.

**Detection-gap honesty.** Coverage is bounded by passive DNS
fundamentally: server-side API consumption, internal workloads, data
pipelines, and ML jobs that call cloud APIs from existing
infrastructure never surface in DNS records on the queried apex.
recon will not, and architecturally cannot, see these. The
[Backlog](#backlog-after-v20) carries the framing-side fixes that
make this limit visible to operators rather than hiding it.

## Invariants

- **Passive only.** No active scanning, port probes, zone transfers, or target
  TLS handshakes.
- **Zero credentials, zero API keys, zero paid APIs.** Every data source must
  be reachable without an account.
- **No bundled ML models, embeddings, ASN data, GeoIP data, or local aggregate
  intelligence database.**
- **No user-code plugin system.** Custom fingerprints, signals, and profiles
  are data files only.
- **Hedged output.** Sparse evidence stays qualified. Dense evidence can be
  firmer, but never absolute.
- **Neutral language.** Observable facts only. No offensive guidance, takeover
  hints, maturity verdicts, or timeline narratives.

Anything new must fit inside this box.

## Priority Order

Correctness → reliability → explainability → composability → new features.

Post-1.0, hardening existing behavior beats adding new surface. Data-file
growth is welcome; engine growth needs stronger justification.

## Engineering quality posture

Standing engineering practices - type checking, lint gates, test
coverage, dependency audit, trusted-publisher releases, structured
logging, schema versioning, property-based fuzzing - are the floor
this roadmap assumes. They are documented in `CONTRIBUTING.md` and
exercised by CI; the v1.9.x and v2.0 plans below build on top of
them.

A few patterns are distinctive enough to call out:

- **Strict-positive likelihoods, no degenerate factors.** The
  Bayesian schema rejects `{0, 1}` likelihoods because one
  mis-fingerprint would otherwise pin a node permanently.
- **Cache-poisoning resilience.** Cache loaders skip malformed
  entries instead of crashing.
- **Property-based testing where invariants exist.** Hypothesis
  generates random valid networks and evidence sets to surface
  edge cases unit tests miss.
- **Pure-Python dependency floor.** No numpy, no scipy, no
  probabilistic-programming framework, no C-extension of our own
  choosing. `pip install recon-tool` pulls roughly eight runtime
  packages. Two deliberate additions have been made. v1.9.31: `deal`
  (pure-Python Design-by-Contract), adopted from the 2026-05 standards
  review; it is a no-op in production under `-O`, so it adds an import,
  not runtime cost. 2026-06-13: `publicsuffixlist`, for registrable-apex
  input reduction (a naive last-two-labels rule mishandles ccTLDs). It was
  chosen over `tldextract` precisely to hold this floor: it is pure-Python
  with *zero required transitive dependencies* (tldextract drags in
  `requests` + three more), and bundles a self-updating Public Suffix List.
  It is recon's first MPL-2.0 dependency (recorded in `THIRD-PARTY-NOTICES.md`);
  MPL-2.0 is file-level copyleft and does not affect recon's MIT license,
  since the package is consumed unmodified. Dependency-hygiene note: the apex
  reduction is only as fresh as the pinned `publicsuffixlist` version, so PSL
  currency rides the normal dependency-bump cadence (the package self-updates
  its list per dated release); it is not a security boundary — `to_apex` falls
  back to the validated host on any unknown suffix. The floor stays a hard
  constraint otherwise: `cryptography` and `pydantic-core` are the only compiled
  pieces in the tree, and both arrive transitively through `mcp` rather
  than by our choice.

### The trust bar: toward high-assurance use (the vision — grill into this)

> Status: **vision, not committed scope.** This is the guiding vision to
> interrogate deliberately later, not a queued milestone. The ambition: recon
> should be trustworthy enough that a high-assurance consumer — pick your
> safety-critical, audit-heavy, "show me why I should believe this" operator —
> could adopt it without a leap of faith. The bar for a *passive, probabilistic*
> tool is specific and worth stating plainly so we can hold ourselves to it.

For a tool that infers rather than observes, "trusted" does not mean "always
right" — that is impossible from the passive channel. It means **never
confidently wrong, always auditable, always reproducible, and honest about its
own uncertainty.** Concretely, the threads to grill into, hardest-lever first:

1. **Empirical calibration against ground truth (the load-bearing gap).** Today
   the credible intervals are *evidence-responsive* but not *empirically
   calibrated* — we say so in the README and `correlation.md`. High-assurance
   means a documented, reproducible calibration story: a maintained
   ground-truth corpus (verified tenants/IdPs), measured coverage (does the 80%
   interval contain truth ~80% of the time, per stratum), conformal guarantees
   where they apply, and a published reliability diagram per node. Until an 80%
   interval *demonstrably* means 80%, every other trust property is built on
   sand. See `statistical-assurance.md`, `interval-coverage.md`, and the CAL\*
   track below — this is where the real work is.
2. **Reproducible analysis, not just reproducible builds.** We already ship
   byte-identical wheels. Extend that to the *analysis*: pin the PSL and
   fingerprint/signal catalog snapshots into each result's provenance, and build
   a record-replay harness so a captured DNS/CT/identity-endpoint snapshot
   re-runs to an identical verdict months later. A claim you cannot reproduce is
   a claim you cannot audit.
3. **End-to-end provenance on every field.** The evidence DAG is strong; the bar
   is that *every* emitted field traces to (raw observation → rule → catalog
   version → model version) such that an auditor can re-derive it offline. Tie
   outputs to the exact catalog/engine versions that produced them.
4. **Adversarial robustness with a written threat model.** No public source can
   crash, hang, or mislead the engine. We already bound hostile inputs
   (`strip_control_chars`, length caps, CNAME-chain validation); high-assurance
   means a documented threat model, a fuzz corpus in CI, and metamorphic tests
   that assert the absent-evidence discipline holds under hostile sparsity.
5. **Formal-ish verification of the inference core.** Push past `deal` contracts
   + Hypothesis: a full-joint reference oracle for the Bayesian core (partly
   planned below), high mutation-testing thresholds on the engine, and invariant
   proofs for the load-bearing rules (strict-positive likelihoods, LR=1 absence,
   no degenerate factors).
6. **Supply chain to SLSA L3.** Currently deferred (see `supply-chain.md`) as
   more than a single-maintainer passive tool warrants — but it is explicitly on
   *this* bar. Reproducible + attested + provenance-pinned dependencies, the
   whole chain verifiable from two independent roots.
7. **A complete, maintained assurance case.** `assurance-case.md` exists; the bar
   is a living GSN-style argument where every top-level trust claim is decomposed
   to evidence that CI keeps green, so "why should I trust this" has a single,
   current, verifiable answer rather than a scatter of docs.
8. **Uncertainty legibility as a first-class output.** The deepest trust property
   for an inference tool: it must make over-trust *hard*. Quantified confidence,
   explicit "the channel cannot see this" rather than a confident-wrong point
   estimate, and the `sparse`/ceiling signals surfaced everywhere a consumer (or
   an agent) might otherwise over-read. This is the [[recon-as-agent-verifier-primitive]]
   thesis taken to its conclusion.

When we return to this: rank by *trust delivered per unit of complexity added*,
and refuse anything that breaks the Invariants box above. The first three items
(calibration, reproducible analysis, per-field provenance) are almost certainly
the highest-leverage and should be grilled first.

### External standards review (2026-05)

Two general-purpose Python-standards briefs were reviewed against this
project (a first pass, then a sharper revision that argued a pure-Python
-first, formally-contracted, supply-chain-hardened posture). Most of the
combined ask is already in place (uv + lockfile, grouped Dependabot,
pre-commit with ruff / pyright / actionlint, pyright strict, pytest +
coverage + Hypothesis, pip-audit in CI and release, SBOM, gitleaks, OIDC
trusted-publisher). The items worth adopting are folded into Known gaps
below. This sub-section records the decisions, both the adoptions that
reverse an earlier call and the declines, so the reasoning is durable.

Adopted from the review:

- **Raise the Python floor to `>=3.12`.** The first brief asked for a
  3.14-only baseline, which we declined as hostile to downstream
  consumers. The revision made the better argument: floor at 3.12, dev
  and static-analysis baseline at 3.14, matrix 3.12 / 3.13 / 3.14. 3.10
  reaches EOL on 2026-10-31 and 3.11 on 2027-10, so 3.12 buys upstream
  security coverage through 2028 and lets the core use post-3.11 syntax
  and typing. This is a deliberate floor raise (it drops 3.10 and 3.11),
  tracked in Known gaps; v1.9.28 already added 3.14 to the matrix under
  the old `>=3.10` floor, so the raise removes the two oldest rows rather
  than adds work. *Update: shipped in v1.9.29, then reversed in v1.9.43.
  On review, no runtime dependency needed 3.12 (networkx set the practical
  floor at 3.11) and the only 3.12-only code was three PEP 695 `type`
  aliases, since rewritten as `TypeAlias`; for a building-block library the
  reach of supporting 3.11 while it still gets security fixes outweighed the
  cosmetic syntax. The floor is now `>=3.11` with the dev / static-analysis
  baseline still at 3.14. See the v1.9.43 row.*
- **Design-by-Contract via `deal`.** Pure-Python, so it clears the
  no-C-extensions bar, and a no-op in production under `-O`. Adopted as a
  real track on the highest-value surfaces (Bayesian fusion and the
  engine matchers) where preconditions and postconditions catch errors
  that types alone do not. This grows the runtime floor by one import, a
  cost accepted for the verifiability gain. Tracked in Known gaps.
- **Build-provenance attestation plus hash-pinned audit requirements.**
  GitHub-native `actions/attest-build-provenance` (cheap, did not exist
  when SLSA was first deferred) and `--require-hashes` on the exported
  audit requirements. Full SLSA L3 and Sigstore in-toto signing stay
  aspirational, not this cycle. Tracked in Known gaps.

Declined, with the reason:

- **Pydantic at every boundary plus structlog as runtime deps** -
  declined. This would break the pure-Python dependency-floor invariant
  above for little gain. Pydantic already rides in transitively via
  `mcp`, so the MCP layer can lean on it without taking a new floor, but
  the CLI and core keep their hand-rolled boundary validation
  (`validator.py`, `strict_mode.py`, `schema_contract.py`,
  `defusedxml`), which already follows "parse, don't validate" via frozen
  dataclasses. `deal` covers the contract half the brief wanted from
  Pydantic without the heavier dependency. The hedged, provenance-rich
  output is recon's observability story; a structured-logging framework
  is sized for long-running services, not a stdio tool.
- **mypy strict on top of pyright** - declined as redundant. pyright
  strict already gates CI. Astral's `ty` may be worth a spike once it
  reaches 1.0; it is in preview, so not now.
- **Blanket 95% branch coverage** - declined in favor of a measured
  raise (see Known gaps); branch coverage measured at 83% today, so the
  honest gate sits near there, not at a flat 95% that buys execution
  rather than test quality.
- **Literal Power-of-10 rules** (two asserts per public function,
  50-line cap, line-length 100) - adapted rather than adopted. The
  intent, simple statically-analyzable control flow and bounded
  resources, is already a project value (resource caps, bounded
  clustering, rate limits). We encode the measurable part as a ruff
  complexity cap with a worst-offender refactor (see Known gaps) and keep
  the deliberate 120 line length.
- **Trivy and a Dockerfile** - not applicable. recon ships as a stdio
  CLI and library on PyPI, not a container image, so there is no image to
  scan. If a container is ever published, Trivy folds in then.
- **Central Copier template plus reusable workflows across a repo
  portfolio** - out of scope for this roadmap. recon can serve as a
  reference for that later, but the multi-repo machinery is not recon's
  concern.

### AI-security review (2026-05)

A separate AI-systems security brief (adversarial-ML threat models;
poisoning / evasion / extraction / inference attacks; differential
privacy; secure enclaves; model watermarking; confidential computing;
SecMLOps) was reviewed. Almost all of it is out of scope here for a
structural reason: recon trains no model and serves no model. The Bayesian
layer is hand-authored YAML, not learned weights (the no-learned-weights
invariant); there is no training data, no fine-tuning loop, no inference
endpoint, and nothing multi-modal. So model poisoning, extraction,
inversion, membership inference, DP-SGD, enclaves, adversarial training,
and certified robustness do not apply, since there is no model to poison,
steal, or invert.

The part that does apply is the agentic surface, and it already has an
explicit threat model. recon is consumed by AI agents over MCP and is a
conduit of untrusted external strings (DNS TXT records, CT SAN names, BIMI
metadata, identity-endpoint responses) into an LLM's context. `SECURITY.md`
documents the MCP threat model (the agent is assumed adversarial; prompt
injection, tool poisoning, and parameter tampering are assumed), the
v1.9.18 to v1.9.21 audit rounds closed the output-injection surface (ANSI
/ newline / markdown sanitization, SSRF, ReDoS, resource caps), and the
v1.9.32 build-provenance attestation extends integrity to the bundled
fingerprint and signal data, which is recon's only "data supply chain".
The one genuinely new forward item is carried in Known gaps below.

### Known gaps

The list of things a security-focused project ideally has but we
do not yet ship. Listed publicly so an evaluator can see what we
know is missing rather than only what we know is present:

- ~~No SBOM attached to releases.~~ **Shipped in v1.9.3.1** -
  CycloneDX SBOM (`recon-tool-<version>.cdx.json`) attached to
  every GitHub Release as an artifact, generated by the release
  workflow from the same locked dependency set the audit gate
  validates.
- ~~No SECURITY.md / vulnerability disclosure policy.~~ **Shipped
  pre-v1.9.3.1** - see `SECURITY.md` for scope, response SLA,
  reporting channel, and the MCP-specific threat model.
- ~~No secrets-scanning in CI.~~ **Shipped in v1.9.3.1** -
  gitleaks runs on every PR, every push to main, and on a weekly
  scheduled scan against the historical branch tree. Read-only
  workflow permissions; failures are non-bypassable.
- ~~No forward-compat cache test.~~ **Shipped in v1.9.3.1** -
  `tests/test_cache_forward_compat.py` pins the implicit "ignore
  unknown fields, load known fields cleanly" contract that the
  reader has always honoured but never tested.
- ~~No `py.typed` marker (PEP 561).~~ **Shipped in v1.9.28** -
  `recon_tool/py.typed` added and verified present in the built wheel,
  so a downstream consumer's type checker now picks up recon's inline
  types. The `Typing :: Typed` classifier is no longer a false promise.
- ~~Python 3.14 not in the support matrix.~~ **Shipped in v1.9.28** -
  3.14 added to the `ci.yml` test matrix (Ubuntu, Windows, macOS) and a
  `Programming Language :: Python :: 3.14` classifier added. recon
  imports and passes its suites on CPython 3.14.5.
- ~~**Raise the Python floor to `>=3.12`** (engineering-elevation series).~~
  **Shipped in v1.9.29, then reversed in v1.9.43.** The raise dropped 3.10 and
  3.11, set the matrix to 3.12 / 3.13 / 3.14, and moved `ruff target-version` /
  `pyright pythonVersion` to 3.12, with the dev toolchain pinned at 3.14. On
  later review the 3.11 drop was reverted: no runtime dependency needs 3.12
  (networkx sets the practical floor at 3.11) and the only 3.12-only code was
  three PEP 695 `type` aliases (now `TypeAlias`), so for a building-block
  library the reach of supporting 3.11 while it still gets security fixes won
  out. The floor is now `>=3.11`; 3.10 stays dropped (EOL 2026-10-31); the dev /
  static-analysis baseline stays at 3.14. Both moves shipped as their own
  patches so the changelog shows exactly when the floor moved each way.
- **Adopt Design-by-Contract via `deal`** (engineering-elevation series).
  *First pass shipped in v1.9.31*: `deal` added as a runtime dependency
  (disabled in production via `deal.disable()` when not `__debug__`, so
  zero cost for installed users), with `@deal.post` contracts on the
  inference math in `bayesian.py` (factor entries are probabilities;
  evidence factors are strictly positive, encoding the no-degenerate
  invariant; marginals stay in `[0, 1]`; credible intervals are ordered
  within `[0, 1]`). `tests/test_contracts.py` proves the contracts fire
  on violation and are no-ops under `-O`. *Second pass shipped in v1.9.35*:
  contracts on the fingerprint engine, `filter_shadowed_matches` (no
  shadowed pair survives, the no-double-count invariant) and
  `evaluate_pattern` (match count stays within `[0, corpus_size]`), with
  matching predicate tests. Still open as a smaller follow-up: contracts
  on the boundary validators in `validator.py`. The dependency-floor note
  above reflects the deliberate addition.
- ~~Branch coverage is not enforced and the gate sits at 80% line
  coverage.~~ **Shipped in v1.9.30** - `--cov-branch` enabled in the CI
  matrix, the release test job, and the local gate (`scripts/release.py`,
  `CONTRIBUTING.md`). Branch coverage measured at 82.95%, so the gate
  moves from 80% line to 82% branch, a stricter metric at a higher number
  rather than the flat 95% the brief asked for. `server.py` (around 71%
  line) stays the named under-covered target for follow-up tests.
- Complexity gate enabled, refactoring incremental. **Gate live in
  v1.9.37**: ruff `C901` at `max-complexity=15` is now enforced, so new
  code must come in under 15. The functions over the cap at enable time
  carry an explicit `# noqa: C901` and are being decomposed in batches;
  each refactor removes its marker, ratcheting the debt down. This is the
  honest brownfield order: hold the line for new code first, then work the
  backlog. Progress: `tenant_info_from_dict` (v1.9.40) and then the entire
  `formatter.py` (v1.9.45 to v1.9.52, behind the golden-output net) are done,
  including the worst offender `render_tenant_panel` (96 to under 15); then
  `insights._email_security_insights` (v1.9.53), `posture._validate_and_build_rule`
  (v1.9.54), the validator/loader tail (`_validate_fingerprint`,
  `_validate_motif`, `_validate_and_build_signal`, `load_network`) in v1.9.61 to
  v1.9.64, the `validation_runner` pair (v1.9.65), the `cert_providers` queries
  (v1.9.66), the `sources/dns` detectors (v1.9.67 to v1.9.68), and
  `explain_insights` (v1.9.69). 7 markers remain. The remaining monsters are the
  behaviour-heavy functions (`_lookup` at 77, `merge_results` at 64, `_batch` at
  60, the two `cli` doctor / signals-show commands, and the `server` tool pair);
  these take characterization coverage of their own before they are split, since
  they are not pure renderers the golden snapshots can pin.
  Each refactor preserves behavior and is verified against the suite. The
  `PLR` refactor family (too-many-branches / statements / returns / args,
  ~107 hits) is deferred to a later pass so the gate stays focused on
  cyclomatic complexity first. Keep the deliberate 120 line length.
- Deterministic fault-injection / chaos tests at the network boundary.
  recon already carries retry, an adaptive rate limiter, a per-provider
  circuit breaker, and `degraded_sources` handling, and the existing
  resilience suites (`test_ct_pipeline_resilience.py`,
  `test_properties_resilience.py`, `test_fallback_chain.py`) plus the new
  stateful machine (v1.9.33) cover much of the failure surface. Open as a
  deeper follow-up: a dedicated layer injecting malformed and truncated
  provider payloads at the source boundary and asserting the hedged output
  and exception hygiene hold.
- ~~No Hypothesis *stateful* testing.~~ **Shipped in v1.9.33** -
  `tests/test_rate_limit_stateful.py` drives the `AdaptiveRateLimiter` +
  circuit breaker with arbitrary outcome sequences (a
  `RuleBasedStateMachine`) and asserts the interval bounds, a
  model-tracked consecutive-failure counter, bounded cooldown, and the
  open-breaker-implies-threshold invariant after every step. The cache
  state machine is a candidate for the same treatment later.
- ~~Free-threaded 3.14t not exercised.~~ **Shipped in v1.9.33** - an
  Ubuntu `3.14t` matrix entry, marked experimental and `continue-on-error`
  so it surfaces a dependency without a `cp314t` wheel without failing CI.
  recon is asyncio-based with no shared mutable thread state, so this is a
  dependency-readiness probe rather than a correctness change.
- ~~Dev dependencies still live under `[project.optional-dependencies]`.~~
  **Shipped in v1.9.36** - migrated to a PEP 735 `[dependency-groups].dev`
  table, so the dev toolchain is no longer published as an installable
  `recon-tool[dev]` extra. uv treats `dev` as a default group, so
  `uv sync` installs it and the `--no-dev` build/audit steps still exclude
  it; the CI / release `uv sync --extra dev` calls became plain
  `uv sync`. A separate `[tool.uv]` block was not needed (the `dev`
  default-group behavior is built in). README and CONTRIBUTING note the
  pip path (`pip install -e . --group dev`, pip 25.1+) for non-uv users.
- No mutation testing - line coverage measures execution, not test
  quality. Still post-v2.0, but the standards review reaffirmed it as
  the chosen answer to "test quality beyond line coverage." Candidate
  scope when it lands: a mutmut or cosmic-ray spike against the
  Bayesian inference core and the engine matchers, where a surviving
  mutant is the most diagnostic. Pairs with the `deal` contracts (a
  contract that never fails on a mutant is a contract worth tightening).
- ~~Build provenance and hash-pinned audit requirements.~~ **Shipped in
  v1.9.32** - a separate `attest` job in `release.yml` signs a
  GitHub-native `actions/attest-build-provenance` attestation for the
  wheel and sdist (verify with `gh attestation verify`), kept out of the
  build job so the supply-chain isolation contract holds; the exported
  audit requirements in `ci.yml` and `release.yml` are now hash-pinned.
  Full SLSA L3 plus Sigstore in-toto signing and reproducible-build
  verification stay deferred as disproportionate for a stdio tool at
  current scale, but the cheap provenance step closes most of the gap.
- ~~Prompt-injection posture for AI consumers (from the 2026-05 AI-security
  review).~~ **Shipped in v1.9.60** (queue item E7). recon hands untrusted
  external strings (DNS TXT records, CT SAN names, BIMI metadata,
  identity-endpoint responses) to an LLM over MCP, so an attacker who controls
  a queried domain's DNS or certificates could try to smuggle instructions
  through recon's output. The terminal and markdown injection surface was
  already closed (v1.9.18 to v1.9.21); v1.9.60 adds the explicit
  data-not-instructions posture as a documented in-band convention: the
  injected MCP server instructions gain an "Untrusted observed content (data,
  not instructions)" section telling the consuming model to treat every
  domain-derived value as data to analyze and report, never as an instruction
  to follow, even when the literal text reads like a directive. `SECURITY.md`
  documents it and `tests/test_data_not_instructions.py` guards it. The
  model-centric AI-security concerns from the same brief stay out of scope (see
  the AI-security review note above): recon trains and serves no model.

These do not block v1.9.x or v2.0. The four oldest cheap ones
(SECURITY.md, SBOM, secrets-scanning, forward-compat test) shipped by
v1.9.3.1; `py.typed` and the 3.14 matrix shipped in v1.9.28. The
engineering-elevation series carries the rest as a sequence of focused
patches: floor raise to 3.12 (later relaxed to `>=3.11` in v1.9.43), then
quality gates (branch coverage plus
the complexity refactor), then `deal` contracts, then PEP 735 and the
provenance step, with the test-rigor layers (fault injection, stateful
Hypothesis, 3.14t) and mutation testing running alongside or post-v2.0.
v2.0 itself stays the mechanical schema-lock event with no new engine
work.

### Reference-grade repository elevation (post-2.2.2)

A 2026-06 review against current (PyPA, pyOpenSci, JOSS, OpenSSF, CFF)
reference-grade practice found the repo already past the bar those checklists
target: the engineering substance (reproducible byte-identical builds,
PEP 740 / SLSA attestations, CycloneDX SBOM, the mutation gate, differential
verification, the traceability matrix, the assurance case) exceeds what JOSS and
pyOpenSci ask for and most corporate-backed packages ship. The residual gaps are
*citability and presentation*, not engineering, so this track is small,
operator-paced, off the critical path, and touches no schema or engine surface.

**`src/` layout: adopted (2026-06-16).** The package moved from a flat layout
(`recon_tool/` at the repo root) to a `src/` layout (`src/recon_tool/`), the
PyPA-suggested default, so the in-tree-import class of packaging bug is
structurally impossible rather than only caught after the fact. The migration ran
as one atomic commit: `git mv` plus every path-coupled reference it touches (the
`[tool.hatch.build.targets.wheel] packages` target, the pyright `include` /
`extraPaths`, the file-size-ratchet root, `check_traceability.py` (a `src/`
resolution fallback so the trust-doc references still resolve),
`check_metadata_coverage.py`, `mutation.toml`, the CI / release / mutation
workflows, the pre-commit pyright and fingerprint filters, and the handful of
tests that read package source by path). The import name `recon_tool` stayed
stable for consumers, while coverage gates now target `--cov=src/recon_tool` so
local and CI coverage measure the moved source tree. Verified non-functional:
the built wheel is byte-for-byte identical to the pre-move wheel (same sha256),
so the published 2.2.2 artifact is unchanged and no release was triggered, and
the full gate stays green.

The elevation items, ranked by value over effort, each its own small patch.
**Status (2026-06-16):** items 1 (partial), 3, and 4 shipped this pass; the
remaining open work is the Zenodo DOI (a one-time maintainer toggle), the
`preferred-citation` block (pending the paper), and item 2.

1. **`CITATION.cff` (+ a Zenodo concept DOI on releases).** Highest leverage and
   the precondition for the planned arXiv paper to cite its own software cleanly:
   GitHub renders a "Cite this repository" button and BibTeX export, and the
   GitHub to Zenodo linkage mints a versioned DOI under a stable concept DOI per
   release. Seed `CITATION.cff` now (author, title, version, repo); add the
   `preferred-citation` block when the paper lands. Pairs with
   [paper-outline.md](paper-outline.md).
2. **A one-command "reproduce the paper's numbers" entry point.** Shipped for the
   public, no-private-data rows: `python -m validation.reproduce_paper_numbers`
   runs the synthetic/proof bundle and writes a local manifest plus summary under
   `validation/local/`, with safe run-stamp validation for local artifact
   directories. The private-corpus and public-list calibration reruns remain
   separate until there is a frozen, publishable identifier list or a
   maintainer-local aggregate memo.
3. **Surface the assurance stack on the README front door.** The
   provenance / SBOM / mutation / reproducibility work is currently buried in
   `docs/`; a short "Assurance" section with an OpenSSF Scorecard badge (which
   scores high here at near-zero new work), the DOI badge, and a four-line summary
   linking [assurance-case.md](assurance-case.md) makes the first-impression match
   the actual rigor.
4. **`.editorconfig`.** Editor-layer settings (indent, final newline, charset)
   that complement rather than duplicate ruff; cheap, and its absence is the one
   "not quite finished" tell a sharp reviewer notices.

Deferred, not skipped: a rendered docs site (mkdocs-material entered maintenance
mode in early 2026 with its successor still stabilizing, and the markdown `docs/`
are already reviewer-legible) revisited once the paper is out and there is an
external-user reason. Explicitly out of scope, for the same deepen-not-expand and
solo-maintainer reasons as the rest of this file: an `src/` migration (above),
generated API reference docs (recon is a CLI / MCP server, not an imported
library; the MCP tool schema is the real API surface and is already documented),
a `FUNDING` file, and the OpenSSF Best-Practices *Gold* badge (it structurally
requires multiple maintainers; target passing / silver).

## Success Metrics (Post-1.0)

These are directional measures, not product OKRs:

- **Multi-signal correlation depth** - north-star metric. Share of
  `--explain` outputs whose evidence DAG references more than one source
  per high-confidence slug. The lens for "did the new correlation work
  do something single-source detection could not?". Tracked per release
  against the private corpus; explained in detail in
  [correlation.md](correlation.md).
- Share of high-value multi-detection fingerprints with an explicit
  `keep_any`, `match_mode: all`, or `tighten_patterns` decision backed by
  validation notes.
- Detection metadata coverage: descriptions, public references where available,
  and deliberate non-default weights.
- Quality of sparse-result explanations in live validation summaries, especially
  links to known passive-observation ceilings.
- Stability of JSON and MCP consumption examples against the documented schema.
- Sustainable community fingerprint PRs that pass schema, specificity, and
  validation gates without maintainer guesswork.
- For experimental Bayesian or community-detection output: average posterior
  entropy reduction (or modularity score) per domain on the private corpus,
  tracked across releases. Trend matters more than absolute number.

## Build plan and shipped-release history

The per-release build detail (the v1.7 to v2.1.0 numbered sequences, the v2.0
maturity disposition table, and the v2.1 mining sketch) lives in
[roadmap-history.md](roadmap-history.md) so this file stays forward-looking. The
authoritative shipped record is [CHANGELOG.md](../CHANGELOG.md); the forward plan
is the [version milestones and build order](#version-milestones-and-build-order)
above plus the [backlog](#backlog-after-v20) below.

### Backlog (after v2.0)

Items that are real but speculative enough to not commit a slot in the
plan above. Each remains gated by the same invariants and validation
discipline.

**Detection-gap framing & enumeration breadth** *(added 2026-05-11
following empirical validation pass against rich-stack public
companies):*

- **Passive-DNS ceiling phrasing in the panel.** When the default
  panel lists few services on a domain that public knowledge suggests
  uses many, surface a one-line acknowledgement: "Passive DNS surfaces
  X public services; server-side API consumption, internal workloads,
  and SaaS without DNS verification are not observable from public
  DNS alone." Prevents "absence of finding = service not present"
  reading. The architectural Category-1 limit becomes visible without
  needing the operator to know the invariants. Backlog because the
  trigger heuristic ("when does the panel hint at the ceiling?") is
  policy and deserves explicit design.
- **Subdomain enumeration breadth.** Today's related-domain discovery
  is CT-driven + a fixed common-prefix probe. A customer with
  `data-pipeline.example.com → GCP` whose subdomain doesn't appear in
  CT and isn't a common prefix is invisible. Expand: pull SAN sets
  from ALL observed apex certs (not just the queried apex), longer
  common-prefix wordlist (security, ops, internal, ml, ai, data,
  etc.), and a CT search by org name when one is available from a
  prior lookup. None violates passive-only. Backlog because the
  optimal wordlist + CT-query plan needs corpus-driven calibration.
- **Stratified-corpus validation as standing practice.** Single
  private corpus has bias; stratified samples (known GCP-customer set,
  known Azure-customer set, etc.) surface the bias by design. Process
  change in `validation/` - not code. Backlog because the per-cloud
  10-domain reference sets need curation; vendor case-studies are the
  starting input.
- **Cloud-provider rollup at the apex level.** When subdomains span
  multiple clouds (apex on Cloudflare, subdomains across AWS + Fastly
  + Stripe), the v1.9.3.10 "Subdomain" line shows counts. A natural
  extension is a top-of-panel `Multi-cloud` indicator: "5 cloud
  providers observed across the surface". Backlog because the
  threshold for "multi-cloud" is policy.

**Additive feature candidates** *(moved from the former
"v1.9.x optional feature additions" section when the roadmap
restructured to a flat sequence; any of these may be promoted into
a post-v2.0 v2.x.y patch when there's a falsifiable defensive case):*

- **BIMI VMC legal-name clustering** - pairs with the v1.8
  hypergraph view; demonstrates real multi-brand identification on
  a private corpus.
- **MCP delta helper** - `recon_delta(domain_or_json_a,
  domain_or_json_b)` MCP tool. Compares supplied or cached JSON
  only; no hidden network. Optional `include_fusion` flag surfaces
  v1.9 posterior shifts alongside the deterministic diff.
- **Portfolio / self-audit batch mode** - `recon batch --self-audit`
  aggregating vertical-baseline hits, anomaly rules, correlation-
  depth distribution, and gateway / sovereignty consistency across
  many domains in one summary. A lightweight agent-side precursor
  ships today in `AGENTS.md` / `SKILL.md` under the
  "Family-of-companies / portfolio rollup" workflow - agents
  synthesize the rollup from per-domain JSON returned by
  `recon batch --json --include-ecosystem`. Promoting to Python
  gives deterministic, testable output emitted as schema fields;
  worth doing once the agent-side rollup has validated the report
  shape on a private corpus. Operator-supplied apex list in both
  versions; recon never infers the corporate-family relationship.
- **Non-MCP graph exports** - Mermaid diagram output for the v1.8
  cluster graph, plus CSV exports for relationship metadata and
  chain motifs.
- **Per-node `n_eff_multiplier` in `bayesian_network.yaml`** -
  schema-additive field that scales effective sample size on a
  per-node basis. Lets weak-calibration nodes widen their credible
  intervals without globally widening every node. May be promoted
  into a pre-v2.0 patch if v1.9.4 hardened-adversarial findings +
  the existing sensitivity test surface nodes whose interval shape
  only makes sense with per-node scaling.
- **Per-binding conflict penalty (localize the global `n_eff`
  conflict deduction).** Today's loaded `conflict_n_eff_penalty`
  value in `bayesian_network.yaml` applies globally: any cross-source conflict in the merged
  `TenantInfo` widens every node's credible interval, not only the
  nodes whose bindings overlap the conflicting field. The behavior
  is conservative (never under-reports uncertainty) but coarser
  than ideal - a conflict over `display_name` should not widen the
  posterior on `aws_hosting`. The localized form would thread per-
  node conflict overlap so the penalty only fires on nodes whose
  evidence set actually depends on the conflicted field, sharpening
  the layer's output on messy real-world inputs without weakening
  the calibration guarantee. The limitation is already called out
  in `docs/correlation.md` (§ "We acknowledge two open issues") so
  the design rationale and acceptance shape are already documented;
  the missing piece is the implementation plus a falsifiable
  regression test that the global-penalty behavior is preserved as
  the conservative floor when the per-binding analysis returns no
  overlap. Candidate for v2.1 alongside the operator-driven catalog
  growth if a corpus run surfaces nodes whose widening is dominated
  by unrelated conflicts; otherwise v2.2.
- **Corpus-driven Hypothesis tests** - extend
  `tests/test_bayesian_hypothesis.py` with property tests over real
  corpus output. Strengthens the test floor.
- **Hawkes-kernel CT burst classification** - fit a one-parameter
  exponential-decay kernel to each cluster's CT timestamps and
  classify `automated_renewal` vs `manual_deployment`. Surface as
  `cert_summary.deployment_bursts[].kernel_class`.
- **Asynchronous Label Propagation fallback for `infra_graph`** -
  pure-Python LPA replaces the connected-components fallback above
  the 500-node Louvain cap, keeping community structure visible on
  10k+-node graphs.
- **Explicit ignorance mass (epistemic vs aleatoric)** - Dempster-
  Shafer-style mass on the "don't know" state, computed from the
  ratio of unbound to bound evidence nodes for that posterior;
  surfaces in `--explain-dag` as a third quantity alongside
  posterior and interval.
- **Noisy-OR / noisy-AND CPT gates** - schema-additive
  `gate: noisy_or | noisy_and | custom` on multi-parent CPTs in
  `bayesian_network.yaml`. Compact and human-reviewable as the
  network grows beyond ~10 nodes.
- **Public `Factor` / `Node` / `Evidence` API surface plus
  canonical-textbook-example test.** Today the variable-elimination
  primitives in `recon_tool/bayesian.py` (`_Factor` as
  `dict[Assignment, float]`, `_multiply`, `_sum_out`,
  `_query_marginal`) are correct and idiomatic but private; the
  underscored types leak through some public type hints. Promote
  them to a documented public surface with `__all__` discipline
  and add `tests/test_bayesian_ve.py` reproducing the canonical
  Burglary-Earthquake-Alarm joint and marginals from Koller &
  Friedman (2009), *Probabilistic Graphical Models*, Table 9.1
  / §9.3. Lets the project cite "exact inference verified against
  a canonical reference" as a hard claim rather than a docstring
  assertion. Schema-additive; no behavior change.
- **Sensitivity-analysis tooling for CPT entries.**
  `scripts/sensitivity_analysis.py` runs N Monte-Carlo
  perturbations (default ±10% uniform) over every CPT entry and
  every prior in `bayesian_network.yaml`, reports per-node
  posterior-shift histograms and max entropy change, and flags
  fragile edges where small CPT changes produce disproportionate
  posterior swings. Optional `--bayesian-sensitivity` CLI flag
  surfaces the analysis on-demand; runs in under a second at the
  current 9-node scale. Pairs with the v1.9.6 CPT-change
  discipline: tells a contributor *which* edges are worth
  questioning before they consider tuning, and gives the reviewer
  a falsifiable basis to accept or reject a proposed CPT change.
- **Mutual-information surface in `--explain-dag`.**
  `BayesianNetwork.mutual_info(node: str, evidence: EvidenceSet)
  -> float` computes the exact information-theoretic reduction
  $I(\text{node}; O)$ contributed by each piece of observed
  evidence, derived from the joint via variable elimination.
  Feasible at the current 9-node scale (the joint has at most
  $2^9 = 512$ assignments). Surfaces in `--explain-dag` JSON as
  a per-evidence `mutual_information` field alongside the existing
  LLR contributions. Pure information-theoretic derivation, not
  parameter learning, so it stays inside the invariants.
- **`bayesian.py` calibration constants moved to YAML (done
  2026-06-19).** `bayesian_network.yaml` now carries a top-level
  `calibration:` block for `min_n_eff`, `evidence_n_eff_contrib`,
  and `conflict_n_eff_penalty`. The loader defaults older test
  fixtures to the same values, and inference reads the loaded
  settings from `BayesianNetwork.calibration`. This keeps interval
  tuning reviewable as data rather than inference-code edits.
- **Scaling exact inference past treewidth handling: compile to
  tractable probabilistic circuits (post-v2.0 candidate).** The
  current variable-elimination engine handles the 9-node v1.9.3+
  topology comfortably (treewidth $w = 3$, time complexity
  $O(n \cdot d^{w+1}) \approx 144$ operations per query). If a
  future schema change drives the network past roughly 20 nodes
  or treewidth above 5, the principled engineering refactor is
  to compile the Bayesian network into a **tractable probabilistic
  circuit** (Sum-Product Network, arithmetic circuit, or
  Probabilistic Sentential Decision Diagram). The unified
  modern treatment is
  [Choi, Vergari, and Van den Broeck 2020, "Probabilistic Circuits:
  A Unifying Framework for Tractable Probabilistic Models" (JMLR
  submission / UCLA Tech Report)](http://starai.cs.ucla.edu/papers/ProbCirc20.pdf).
  Once compiled, exact marginal inference takes $O(|C|)$ time in
  the size of the circuit, **bypassing the treewidth bottleneck
  of variable elimination entirely**.

  An adjacent compilation path,
  [Darwiche 2020, "An Advance on Variable Elimination with
  Applications to Tensor-Based Computation"](https://arxiv.org/abs/2002.09320),
  maps functional-CPT BNs to dense tensor-graph operations
  (reshape, transpose, MATMUL) exploitable via SIMD. Both
  approaches are post-v2.0 candidates; the right one depends on
  which compilation cost the network actually hits first.

  Explicit constraints either way:
  - **Not a path to `pgmpy`, `pomegranate`, or any
    probabilistic-programming runtime.** Those cross the
    pure-Python dependency floor. The compilation target stays
    inside pure Python (or pure-Python plus a small numerical
    backend without the heavyweight inference framework).
  - **Not a path to learned parameters.** CPTs stay
    human-authored YAML data files; the compilation is a
    build-time transform from committed data files to efficient
    runtime factor or circuit representations.

  Worth doing only if the network actually outgrows the current
  inference path. The right trigger is "we want to add a node
  whose CPT shape pushes treewidth past 5", not "this paper is
  interesting." Until that trigger fires the current engine is
  the right engine.

  **This is an architectural pivot, not a backend swap.** The
  current variable-elimination engine processes evidence
  dynamically at query time. Tractable probabilistic circuits
  require a compilation phase that runs whenever the topology
  or any CPT parameter changes:

  - **Build-time compilation pipeline.** Recon would need a
    deterministic compiler that maps
    `recon_tool/data/bayesian_network.yaml` to a circuit
    representation, plus a packaging step that ships the
    compiled circuit alongside the YAML in the wheel. The CI
    pipeline grows a compile-and-verify step that ensures the
    committed circuit is byte-identical to a fresh compile of
    the committed YAML.
  - **Per-evidence-set re-evaluation cost.** Circuit inference
    is $O(|C|)$ in circuit edge count for a given evidence set;
    different evidence sets traverse different sub-circuits.
    Recon would need to verify that the empirical evidence
    distribution from real domains does not pathologically miss
    cached circuit paths, which would erode the $O(|C|)$
    benefit.
  - **Stacking Generalized Bayesian Inference or IDM on
    compiled circuits is an open research problem.** The
    correlation.md §4.4 framework adopts Generalized Bayes
    for the conflict-penalty term and notes IDM as the
    second-order-uncertainty upgrade path. Both modifications
    are straightforward to apply post-hoc to a VE marginal
    posterior. Applying them to a compiled circuit requires
    deciding *where* in the compilation pipeline the
    loss-calibrated update or interval-valued parameter enters,
    and the literature does not have a settled answer. Adopting
    circuits without resolving this question would lock recon
    into either a calibration regression (drop GBI / IDM) or a
    research project (invent the integration).

  The conclusion: a future move to tractable circuits is a
  fundamental architectural pivot that requires its own
  milestone, not a drop-in optimisation. Keep the current
  engine until the treewidth trigger fires *and* the
  compilation pipeline plus calibration-integration story are
  designed.

- **CPM-based modularity for the graph-correlation layer
  (post-v2.0 candidate).** The current §4.5 Louvain implementation
  maximises standard modularity, which has a proven resolution
  limit ([Fortunato and Barthélemy 2007](https://doi.org/10.1073/pnas.0605965104)):
  communities smaller than $\sqrt{2m}$ edges cannot be detected
  reliably. The principled refinement is the Constant Potts
  Model (CPM) objective from
  [Traag, Waltman, and van Eck 2019](https://doi.org/10.1038/s41598-019-41695-z),
  which replaces the global-edge-weight null model with a tunable
  resolution parameter $\gamma$. CPM is implementable in pure
  Python over `networkx`; does not require the `leidenalg` C
  extension. Surface as `--graph-resolution <gamma>` with a sane
  default tuned against the v1.8 ecosystem corpus. Justified
  whenever the global-CT-ecosystem density on a target apex
  makes the small-community resolution failure a real defect on
  measured data (currently a theoretical concern; v2.0+ corpus
  runs would confirm or refute).

- **Aggregated calibration report HTML
  (`scripts/calibration_report.py` plus
  `docs/calibration_report.html`).** Consolidates the per-release
  calibration narratives (`validation/v1.9-validation-summary.md`,
  `validation/v1.9.4-calibration.md`,
  `validation/v1.9.5-stability.md`,
  `validation/v1.9.6-stability-update.md`, and future analogues)
  into a single readable HTML artifact: headline metrics per
  release, per-node trend tables, sparse-rate histograms, and the
  Brier / log-score / ECE diagnostics from each report. CI
  regenerates on each release tag. Decoration on top of existing
  validation work; ships nothing new mathematically. Useful as
  the citable single-page artifact when sharing recon's
  calibration story externally (the validation `.md` files are
  the source of truth; the HTML is the rollup).

- **Generate `docs/recon-schema.json` from code rather than
  maintaining it manually.** The schema currently lives as a
  hand-maintained JSON file; drift between code and schema is a
  recurring failure mode. The current guard covers top-level formatter output,
  required-field symmetry, internal `$defs` references, model-backed nested
  `$defs` field names, and a top-level source map from schema properties to
  `TenantInfo` fields or explicit formatter/mode sources. The source-map guard
  can also emit JSON for local review. The remaining step is a
  `scripts/generate_schema.py` that derives the schema from the `TenantInfo`
  dataclass plus field metadata, then runs in CI to verify the generated schema
  matches the committed one.
  Stays inside the pure-Python floor (the generator runs over Python typing
  introspection, no JSON-Schema framework required). Pairs with the v2.0
  schema-stability test that fails any committed schema change without a major
  version bump.

**Pre-existing backlog:**

- CT organization-name search (opt-in, exact-match only).
- Wayback Machine temporal enrichment (new public network surface; opt-in).
- Deeper hardening simulation UX (high overreach risk).
- Anomaly detection on issuer-mix changes over time.
- Per-domain inference cache for batch-mode reruns.
- **`--mine-motifs` mode for `run_fingerprint_mining` (v2.2+).**
  Specialised runner mode that proposes new entries for
  `motifs.yaml` (or a sibling `community_motifs.yaml`) by
  clustering recurring chain patterns inside Louvain communities.
  Output includes representative samples and projected
  multi-signal depth gain on the corpus. Same dry-run + human-
  triage discipline as v2.1 mining; never auto-edits the catalog.
  Worth doing only if v2.1 corpus runs show that
  community-scoped motif candidates consistently outscore single-
  domain motif candidates on the north-star metric. The feature
  is additive on top of v2.1's `clue_source: "graph_community"`
  branch and reuses the same projection pipeline.
- **Imprecise Dirichlet Model (Walley 1991) for CPT entries.**
  Replace point-CPT values with intervals derived from
  bounded-prior Dirichlet samples. Yields second-order
  uncertainty on the parameters themselves rather than only on
  the posterior. The lightweight v1.9.x optional ("explicit
  ignorance mass") ships the user-facing epistemic-vs-aleatoric
  distinction first; this entry is the deeper refactor that
  would replace point-CPTs entirely once the lightweight
  version proves operators actually consume the ignorance
  signal. Cited in `correlation.md` §4.4 as prior art.

  **This is not a drop-in refactor of `bayesian.py`.** Adopting
  IDM converts the Bayesian network into a **Credal Network**
  (a Bayesian network whose CPTs are interval-valued). Exact
  inference on credal networks is **NP-hard even on trees**
  (treewidth $w = 1$); the standard reference is
  [de Cooman, Hermans, Antonucci, and Zaffalon 2010,
  "Epistemic irrelevance in credal nets" (Int. J. Approximate
  Reasoning)](https://doi.org/10.1016/j.ijar.2010.07.005). The
  practical adoption paths are:

  1. **Accept approximate credal inference.** Use algorithms
     like 2U / GL2P, or the k-reduction technique benchmarked
     in [CREPO (Antonucci et al. 2021)](https://arxiv.org/abs/2105.04158),
     trading exactness for tractability. The pure-Python
     dependency floor admits this but adds substantial
     algorithmic complexity to `bayesian.py`.
  2. **Stick with the post-hoc $n_{\mathrm{eff}}$ widening.**
     The correlation.md §4.4 framework now justifies the
     current heuristic as a tractable approximation of
     Generalized Bayesian Inference (Bissiri, Holmes, and
     Walker 2016) with an engineered conflict-penalty loss
     plus a moment-matching Beta wrap. This is formally
     coherent for any bounded loss; it is "not IDM" but it is
     not unprincipled either.

  Path 2 is the current state and the default. Path 1 is worth
  the cost only if v2.0+ corpus runs show that marginal-only
  interval widening systematically misses calibration
  pathologies that interval-valued CPTs would catch. Until that
  evidence materialises, the current engine is the right
  engine, and the IDM citation in correlation.md is honest
  prior-art acknowledgement rather than a deferred refactor
  commitment.
- **Operator-tuned likelihoods as committed data files.** Allow
  operators to supply per-node likelihood overrides via
  `~/.recon/likelihoods.yaml` analogous to the existing priors
  override. Crosses into v1.9.6's "no automated CPT fitting"
  invariant only if a script auto-derives the file; manual
  operator-side tuning with explicit reasoning is fine. Decide
  the discipline before shipping.
- **Cross-vertical generalization study.** The v1.9.0 corpus
  skews enterprise. A future calibration pass on
  consumer-facing / niche-SaaS targets would tell us whether the
  network's prior assumptions transfer; ECE on that subset is
  the metric.
- **CLI surface inventory for downstream skill and agent authors.** Status:
  `docs/surface-inventory.json` now carries the machine-readable local CLI, MCP,
  JSON-schema, and agent-integration map, and `docs/cli-surface.md` now carries
  the generated human-readable command and flag reference.
  `recon://surface-inventory` exposes the same generated inventory to MCP
  clients as local discovery context. `scripts/check.py` drift-checks both
  generated files.
  1. Done 2026-06-19: `scripts/summarize_cli_surface_changes.py`
     compares generated surface inventories and emits the
     changelog-ready "Tool surface changes" one-liner for user-visible
     CLI commands and flags. Release docs now require a
     `### Tool Surface Changes` entry per release.
  2. Done 2026-06-19: `docs/cli-surface.md` is generated from
     the live Typer command tree and lists every flag and
     subcommand in one place, suitable for skill files or AI
     agent prompts.
  3. Done 2026-06-19: `recon://surface-inventory` serves the packaged generated
     inventory to MCP clients, including MCP resource metadata, without adding a
     network call or a stable field-level contract.

  Explicitly out of scope for this entry: Claude-skill-
  specific or agent-behavior guidance in the repo. That
  layer lives in the per-client skill files under `agents/`
  (and the portable `AGENTS.md` at the repo root). The
  recon repo's job here is to be the source of truth for
  the tool's surface, machine-readable; the skill's job is
  to translate that surface into agent behavior.

## Good First Roadmap Items

Narrow, useful, aligned with the product shape. Each one is a single PR
with a corpus-delta or audit note. None of these block a release; they
are picked up alongside the build plan above.

- Done 2026-06-19: convert the CrowdStrike TXT fingerprint to
  `match_mode: all`, with same-record TXT bookkeeping, before/after audit
  evidence, and fictional-domain regressions in
  `validation/2026-06-19-crowdstrike-match-mode.md`.
- Done 2026-06-19: added a high-confidence Supabase `cname_target`
  fingerprint from the official custom-domain docs, with classifier coverage
  and a validation memo explaining why the generic ACME TXT challenge is not
  catalogued as vendor-specific evidence.
- Done 2026-06-19: enrich 5 verification-token fingerprints with official
  public references, and update the advisory metadata richness audit to
  recognize binding-signal scope language without changing detection patterns.
- Done 2026-06-19: improve sparse-result guidance for unclassified CNAME chain
  termini, clarifying that a reached but unmatched terminus is a fingerprint
  proposal queue, not a vendor claim.
- Done 2026-06-19: add a weak-area note for custom DKIM selector false
  negatives, clarifying that `No DKIM observed` means no match at probed
  selectors rather than proof DKIM is absent.
- Done 2026-06-19: add schema/docs examples that make existing JSON modes
  easier to consume in automation (`docs/automation-examples.md`, with snippet
  tests).
- Done 2026-06-19: improve MCP resource consumption examples for
  `recon://fingerprints`, `recon://signals`, `recon://profiles`,
  `recon://schema`, and `recon://surface-inventory` without adding network
  behavior.
- Done 2026-06-19: add cache edge tests for URL-to-apex cache keys,
  top-level-only `cache_clear_all()` deletion, and the batch-only
  `shared_verification_tokens` non-persistence contract.
- Done 2026-06-19: added `tm_to_azurefd_to_msedge` to the built-in
  `motifs.yaml`, describing the complete Traffic Manager to Azure Front Door to
  Microsoft Edge CNAME chain, with a public candidate-chain delta in
  `validation/2026-06-19-msedge-triad-motif.md`.
- Done 2026-06-19: add high-value-target profile baseline expectations for
  `Identity` and `Security & Compliance`, with tests confirming the absence
  observations stay hedged and suppress when those categories are observed.
- Done 2026-06-19: add a small aggregate-only public smoke memo from
  `validation.reproduce_paper_numbers --profile smoke`, with hygiene tests and
  no real apexes, tenant IDs, or per-domain output.

## Opportunistic Refactoring

The god-file decomposition track is complete. `formatter.py` remains the only
deliberately-large module because its Rich panel core is cohesive and
ratchet-capped. Future refactors should happen only when a feature, bug fix, or
test gap opens a real boundary; do not create a standalone refactor milestone
without behavioral payoff.

## Intentionally Out Of Scope

**Hard no:** active scanning, paid APIs, credentialed access, bundled ML or
embedding weights, bundled ASN/GeoIP datasets, aggregate local databases,
user-code plugins, remote/HTTP MCP transport. The Bayesian and graph
extensions stay inside the box because they ship as data-file CPTs and
algorithms over already-collected observables - never as learned weights or
imported intelligence.

**Statistical methods we deliberately don't use.** External reviews regularly
propose techniques that would cross the invariants. Listed once here so
contributors can see what's off-limits and why, without re-litigating each
proposal:

- *Automated parameter-fitting pipelines* (EM, Snorkel,
  weak-supervision, gradient descent on CPT entries, or any
  `scripts/learn_cpts.py`-style script that auto-emits CPT values
  into committed YAML). Output is opaque in the sense that
  matters: a reader of the committed YAML cannot reconstruct what
  observed counts produced what posterior values without re-running
  the pipeline. This is the "no learned weights" invariant in its
  specific form. v1.9.6 codifies the discipline; the v1.9.6
  refinement distinguishes this from *transparent Bayesian
  Dirichlet posterior updates* (allowed, with publication
  discipline), which are exact probability theory rather than
  opaque automation. The bright line is auditability from
  committed artifacts: an automated pipeline that writes CPT
  values without publishing the prior, the counts, and the
  derivation is banned; a manual Bayesian update with all three
  published in the YAML comment and a validation report is
  acceptable.
- *ML structure learning that auto-applies* (PC algorithm or FCI run as part
  of a build pipeline). Constraint-based causal-discovery output as an
  *operator-facing proposal tool* - a human reads the candidate edges and
  decides whether to add them to YAML - is acceptable; the auto-apply step
  is what crosses the invariant.
- *Cross-organization hierarchical models that share evidence between domains
  the operator did not look up together.* Crosses "no aggregate local
  intelligence database." Within-batch sharing (e.g. v1.8 ecosystem
  hypergraph) is fine because the operator chose the batch; persistent
  cross-run state is not.
- *Bundled scientific-Python stack* (numpy, scipy, pandas, scikit-learn,
  pgmpy, pomegranate, PyMC, Stan, Pyro). Crosses the pure-Python dependency
  floor. Pure-Python implementations of specific techniques are fine when
  the technique is genuinely worth it (e.g. LPA, Hawkes-kernel fitting via
  closed-form MLE).
- *Loopy belief propagation, MCMC, particle filtering as the default
  inference engine.* Variable elimination is exact and fast at current
  network size; the ~20-25-node ceiling is a known scaling boundary, not a
  bug. Approximate inference imports complexity that current scale doesn't
  justify.
- *Tractable-circuit compilation* (SPNs, arithmetic circuits) as a v1.x
  upgrade. Real technique, real scaling story - but solves a problem we
  don't yet have. Noted as a known option for post-v2.0 if the CPT space
  grows past what VE handles.
- *Replacing rule-based signals with a single unified PGM.* Misreads the
  layering: slugs are the evidence layer, the Bayesian network is the
  inference layer, signals are the *presentation* layer (operator-facing
  views over slug evidence). Each abstraction is intentionally addressable
  on its own - collapsing them into one model would lose the audit surface
  the project's defensive posture depends on. See
  [correlation.md § Vocabulary](correlation.md#12-vocabulary).
- *LLM-driven coherence-graph construction in the inference path*
  ([Huntsman 2025](https://arxiv.org/abs/2509.18520)). Uses
  large language models to build weighted coherence graphs from
  propositions, then runs max-cut over the graph. A real
  technique with a real published cybersecurity-application
  story, but recon's invariant is that the inference path is
  deterministic and auditable end-to-end. LLMs are valid as
  *consumers* of recon output (the MCP integration explicitly
  supports that) and as *catalog-construction aids* (a human
  reviews LLM-suggested fingerprints before they enter
  `data/fingerprints/`). LLMs in the inference path itself
  would erase the audit surface; reject.
- *Adversarial risk analysis influence diagrams for
  defender-attacker games* ([Wang and Neil 2021](https://arxiv.org/abs/2106.00471)).
  Hybrid Bayesian networks with utility nodes, backward
  induction for optimal defenses, dynamic observation updates.
  Different problem: ARA computes optimal *responses* against
  modelled attackers; recon reports *what the public channel
  reveals* without modelling adversaries. Adopting ARA would
  force a threat-model commitment recon deliberately avoids,
  and would push the tool from "describe observable structure"
  into "prescribe defensive action", which is downstream of
  recon by design.
- *Belief propagation seeded by external reputation labels*
  ([cGraph, Daluwatta et al. 2022](https://arxiv.org/abs/2202.07883)).
  Uses VirusTotal labels and Alexa rankings as seeds, then
  propagates maliciousness scores over a passive-DNS graph.
  Architecturally parallel to recon's §4.5 graph layer but
  produces maliciousness *verdicts* recon explicitly does not
  produce (no shared reputation database, no external label
  feed, no operator-judgment claim). See
  [correlation.md §3.5](correlation.md#35-ct-co-occurrence-graph--louvain-community-detection)
  for the explicit scope boundary.
- *Workload-aware materialization of junction trees*
  ([Kanagal and Deshpande 2010 / 2110.03475](https://arxiv.org/abs/2110.03475)).
  Query-specific precomputation of shortcut potentials for
  probabilistic-database workloads. Premature optimization at
  9 nodes where inference runs in under a millisecond. Worth
  reconsidering only if the network grows past tens of nodes
  *and* recon develops a query-specific workload pattern; both
  conditions are speculative.
- *Region-based / hybrid exact-Gibbs / recursive-conditioning
  approximations*
  ([Yedidia et al. 2005; Hugin 1302.4968; Darwiche 2001](https://arxiv.org/abs/1302.4968)).
  All speculative for the current scale. The current pure-VE
  engine is exact, fast, and small. Listed here so a reviewer
  who suggests one of these techniques sees the project's
  considered rejection rather than re-litigating.

**Not this tool:** company research, firmographic enrichment, news/funding
feeds, hiring signals, GTM briefings, contact data, maturity scores, HTML
dashboards, TUI, REPL, daemon mode, scheduled monitoring, STIX/Maltego/MISP
exports, Prometheus metrics, Docker image, PDF reports.

**Distribution we don't ship:** static binaries (PyInstaller / shiv /
PEX), self-contained installers, and OS-native packages (.deb / .rpm /
MSI). recon ships as a Python wheel on PyPI, with a lightweight Homebrew formula
that installs from PyPI into an isolated virtualenv. Static-binary and native
package distribution add signing, notarization, per-OS verification, and
reproducible-build overhead disproportionate to the audience size. Operators who
need a containerized recon can run it under `uv run` or any ephemeral Python
sandbox; we do not gain from owning that distribution surface.

Use `--json` (or `--ndjson` for big batches) as the integration surface. If
you need rendered graphs, reports, SIEM ingestion, or company research, pipe
recon output into a tool built for that job.

## Design Choices That Stay

- No confident "maturity" or "zero-trust" verdicts on sparse data.
- No generic subdomain service-name matching such as `grafana.*` or `n8n.*`.
- No ownership or acquisition verdicts from shared tokens or branding.
- No posture or insights layer may trigger a new network call.
- Delta mode reports raw changes; users decide what story, if any, those
  changes imply.
- Correlation extensions describe **observed structure**, not ownership.
  "Co-issued within 60s" is observable; "same owner" is not. Cluster output
  surfaces modularity scores and edge evidence, never verdicts. Bayesian
  layer surfaces credible intervals and the CPT that produced them, never
  point scores without provenance.
- **The `EXPERIMENTAL` label on the `--fusion` Bayesian surface
  is held through v1.9.x and dropped at v2.0 by design.** This is
  a release-engineering posture, not a calibration claim. The
  v1.9.4 hardened-adversarial corpus, v1.9.5 per-node stability
  dispositions, and v1.9.6 topology refinement have all done
  their validation work; the label persists because v2.0 is the
  release that commits to the wire-format and per-field
  stability story, and that is the right moment to drop the
  label, not earlier. External reviewers will sometimes flag
  the label as stale and recommend renaming it to "SHIPPED" or
  "calibration-gated" or similar in v1.9.x. The label stays
  until v2.0 cuts. The `correlation.md` §4.8 header carries a
  "Label vs. status" paragraph that explains the distinction;
  that paragraph is the right place for an interested reader to
  understand the current validation state.

## Implementation discipline for new correlation work

Any item promoted from "Ideas Worth Prototyping" into shipped behavior must:

1. Land first as a YAML schema extension (signals, fingerprints, motifs, or
   a new sibling file). Engine code grows only when the data file alone
   cannot express the rule.
2. Carry a live-corpus before/after delta in the PR description, run on
   the private validation corpus with the discovery loop tooling
   (`validation/scan.py`, `find_gaps.py`, `triage_candidates.py`).
3. Document the sparse-result behavior - when this rule does NOT fire and
   why - alongside the positive case. Output language must remain hedged
   under sparse evidence even when the new feature surfaces nothing.
4. Update `docs/recon-schema.json` and the schema drift test if the JSON
   shape changes. Mark experimental fields explicitly; the v1.0 contract
   stays narrow and stable.
5. Stay deterministic when possible. Where probabilistic output is
   appropriate (Bayesian layer), gate behind an existing flag, mark
   EXPERIMENTAL, and never destabilize the default panel.
