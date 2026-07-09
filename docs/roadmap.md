# Roadmap

This file is the current plan and scope boundary. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md). Release mechanics belong in
[release-process.md](release-process.md). Historical release planning lives in
[roadmap-history.md](roadmap-history.md).

> **Status:** v2.3.6 is current. recon is feature-complete for the current
> roadmap: the CLI, JSON schema, MCP server, validation guards, release path,
> generated schema guard, and generated surface inventory guard are shipped.
> Remaining work hardens the project, sharpens documentation, and improves
> validation evidence without expanding the runtime surface. The final public
> claim audit for the current paper package is complete; future wording,
> package, or validation changes rerun it.
> The current step-back audit is [strategic-gap-audit.md](strategic-gap-audit.md).

## What Is Next

The next work is dependency-ordered:

1. **Harden and refine the current system.**
   - Why first: the roadmap is not waiting on a runtime expansion. The main
     value now is making recon easier to review, harder to misuse, and more
     explicit about what its passive observations can and cannot support.
   - Current state: validation guards, public reproduction commands, citation
     metadata checks, generated-artifact checks, and release readiness are in
     place. The maintainer is continuing theory and correlation work, but new
     evidence should refine the existing recon system conservatively rather
     than create features by default.
   - Current plan: keep docs readable for casual users, keep dependencies,
     supply-chain checks, and OpenSSF posture current, keep the public
     reproduction path passing, improve interface-layer locality, and make
     small correctness or clarity refinements when validation runs expose them.
     The current step-back audit in
     [strategic-gap-audit.md](strategic-gap-audit.md) keeps process, research,
     release, archive, and data-governance gaps separated from runtime work.
     The current engineering refinement plan is
     [engineering-refinement-plan.md](engineering-refinement-plan.md), which
     scopes MCP readiness, compact agent output, async/blocking audit,
     target-poisoning fixtures, and conditional fingerprint-expression work.
   - Current near-term refinements (all passive, within-invariant, no runtime
     expansion):
     1. RFC 9989 (DMARCbis) alignment. Effective-enforcement gating on the
        DMARC `pct=` coverage tag has shipped: a monitoring-only `pct=0` or a
        partial rollout no longer counts as full enforcement in the
        `email_security_policy_enforcing` signal, and the `pct=` tag that RFC
        9989 removes stays parsed for RFC 7489 backward compatibility. The RFC
        9989 `np=` (non-existent subdomain policy) and `t=` (testing) tags are
        now parsed internally, and `t=y` steps the effective policy down one
        level for scoring and Bayesian signal generation.
        Current decision: keep `dmarc_testing` and `dmarc_np` internal for this
        pass. Exposing them as stable `--json` and MCP output fields remains a
        separate 2.3 minor-release decision under the
        [ADR-0003](adr/0003-v2-schema-lock.md) schema lock, handled with the
        full schema-lock discipline (schema regen, `schema.md`, schema tests,
        drift and CPT-discipline notes), not an ad hoc edit.
     2. Provider and protocol drift early warning. The live-endpoint
        integration suite is deselected from ordinary CI because it uses real
        public network endpoints, but upstream provider changes still need a
        visible signal. A scheduled and manually runnable provider-drift
        workflow now runs the passive live integration smoke suite against
        public reserved-domain fixtures, while the gitignored
        `tests/validation/fixtures/` path remains available for maintainer-local
        golden acceptance sets that cannot be published.
     3. MCP 2026-07-28 readiness. The MCP release candidate published on
        2026-05-21 targets a final specification on 2026-07-28 and contains
        breaking protocol changes. recon's current MCP surface is local stdio
        through FastMCP, so the correct near-term response is not a speculative
        remote transport or OAuth implementation. The plan is to keep stdio as
        the supported surface, wait for official Python SDK support, and be
        ready to update `recon mcp doctor`, discovery tests, structured-output
        schema guards, deterministic tool/resource listing checks, and compact
        high-volume agent outputs as soon as the SDK exposes the final
        behavior. Details live in
        [mcp-2026-07-28-readiness.md](mcp-2026-07-28-readiness.md), with the
        decision in
        [ADR-0009](adr/0009-mcp-2026-readiness.md).
     4. Interface-layer debt reduction. recon's core domain boundaries
        are healthy: source collectors, resolver, merger, fingerprint catalog,
        signals, Bayesian inference, posture analysis, and validation harnesses
        each have coherent reasons to change. ADR-0008 moved the
        user-interface implementation behind local packages:
        `recon_tool.cli`, `recon_tool.formatter`, `recon_tool.server`, and
        `recon_tool.mcp_client`. Historical top-level prefix modules now remain
        only as bounded compatibility shims. `scripts/check_interface_layout.py`
        guards against new top-level `cli_*`, `formatter_*`, `server_*`,
        `mcp_*`, or `client_doctor` implementation files.

        Compatibility discipline stays active: preserve `recon_tool.cli`,
        `recon_tool.formatter`, and `recon_tool.server` as public import
        surfaces; keep stable CLI, MCP, and JSON behavior unchanged; do not mix
        this work with `models.py` or schema refactors. The completed migration
        record below remains as an audit checklist for future locality work.
        v2.3.6 added the next interface cleanup: the Typer lookup command now
        translates raw flags into `LookupOptions` at the boundary, while
        `cli.lookup.lookup` receives `domain` plus that one typed options value.
        Future lookup-mode work should extend the grouped options model and its
        validation tests instead of widening orchestration signatures.
     5. Targeted refinement work from the architecture review. Do the parts
        that reduce risk without overbuilding: compact MCP output for
        high-volume tools, a measured async/blocking audit, more target-side
        poisoning fixtures, and ADRs for cross-cutting invariants. Keep a
        fingerprint expression grammar conditional on measured matcher pressure
        or a real need for multi-observable boolean rules. The scoped plan is
        [engineering-refinement-plan.md](engineering-refinement-plan.md).
   - Acceptance: every refinement preserves the project invariants, keeps
     examples fictional or synthetic, and publishes only public, synthetic, or
     aggregate-only evidence. Feedback on gaps, wording, and false positives is
     welcome.

2. **Treat the closed certificate-transparency validation cohort as context,
   not active expansion.**
   - Why next: the main calibration bundle already ran in June 2026, and the
     remaining certificate-transparency validation branch was bounded to
     aggregate, maintainer-local evidence.
   - Current state: the private validation cohort has seven bounded sessions
     documented in
     [validation/2026-06-26-c3-ct-partial.md](../validation/2026-06-26-c3-ct-partial.md).
     The aggregate summary covers retry accounting, provider limits, candidate
     triage, and publication controls. It does not claim complete
     certificate-transparency coverage.
   - Current plan: do not run more live public certificate-transparency retries
     by default. Resume only if a new concrete consumer, provider path, or
     disclosure-safe validation question changes the value calculation.
   - Acceptance: publish only aggregate counts and disclosure-reviewed memos.
     No apexes, organization names, tenant IDs, or per-domain rows leave the
     maintainer machine.

3. **Run fingerprint and motif triage only as a reviewed proposal path.**
   - Why next: catalog growth should come from observed public DNS or stable
     vendor documentation, not invented patterns.
   - Current state: the June 2026 pass promoted public-source-backed UltraDNS
     Web Forwarding, Squarespace managed-subdomain, Descope custom-domain, and
     Infobip email-tracking surface rules. A 2026-07 corpus gap pass added the
     Marketo `mktoapps.com` landing-page backend and the Edgecast/Edgio
     `zetacdn.net` CDN domain (both additional infrastructure for vendors
     already in the catalog, public-source-backed and regression-tested). It
     also surfaced further candidates (Shopify edge, iCIMS, Outbrain,
     Brandwatch, Uptime.com, ngrok, Blockscout, Fortinet) that stay pending
     public-documentation verification before promotion.
   - Acceptance: every promoted rule has scoped language, a public reference or
     aggregate validation basis, regression tests, and conservative sparse-result
     wording.

4. **Keep generated discovery artifacts non-contractual unless a real consumer
   needs a stable subset.**
   - Why next: agent and maintainer discovery context is useful, but a stable
     compatibility promise should exist only for a named consumer.
   - Current state: ADR-0007 keeps `docs/surface-inventory.json`,
     `docs/cli-surface.md`, and `recon://surface-inventory` as generated drift
     guards and discovery context.
   - Acceptance for promotion: a concrete external consumer, the smallest useful
     subset, a compatibility policy, contract tests, and migration notes.

5. **Prepare the external write-up without changing runtime behavior.**
   - Why next: the assurance, validation, and correlation work is now strong
     enough to package for outside review.
   - Current state: this is the active next work. The plan lives in
     [external-writeup-plan.md](external-writeup-plan.md). The paper outline and
     draft exist, the public reproduction bundle exists, the initial claim map
     lives in [paper-claim-map.md](paper-claim-map.md), the public reviewer
     command path lives in [artifact-review.md](artifact-review.md), the
     [public label snapshot decision](public-label-snapshot-decision.md) closes
     public-list sampling as a robustness check rather than a population-rate
     path, the certificate-transparency validation cohort is closed as
     aggregate-only evidence, the
     [M365 tenancy decision](m365-tenancy-decision.md) keeps that result named
     as corroboration rather than calibration,
     [2026-06-29-scorecard-gate-claim-audit.md](../validation/2026-06-29-scorecard-gate-claim-audit.md)
     records the current final public claim audit refresh, and release
     readiness now guards citation metadata. The final submission gate is
     documented in [submission-freeze-checklist.md](submission-freeze-checklist.md),
     and the latest local submission-freeze public proof record is
     [2026-06-30-submission-freeze-local-proof.md](../validation/2026-06-30-submission-freeze-local-proof.md).
     The archive and DOI stop rules are documented in
     [archive-readiness.md](archive-readiness.md), and the
     outside public-artifact rerun path is documented in
     [replication-runbook.md](replication-runbook.md).
   - Acceptance: cite only public or synthetic artifacts and aggregate-only
   validation memos. Public-list numbers remain robustness checks rather than
   population rates. M365 tenancy evidence stays named as corroboration for
   this submission because no passive independent instrument was adopted. Do
   not claim frequentist coverage for the 80 percent intervals. Rerun the
   final claim audit after any draft, package, or claim-map change. Do not add
   runtime behavior while packaging the artifact.

## Interface Package-Locality Migration Record

This hardening refactor reduces cognitive load in the interface layers while
preserving the stable CLI, MCP, JSON, and import surfaces. ADR-0008 records the
decision. The architecture guard is `scripts/check_interface_layout.py`.

### Baseline

The source layout already has strong domain boundaries in the resolver,
sources, fingerprint catalog, signals, Bayesian inference, posture analysis,
validation harnesses, cache, and data files. The weaker locality is at the
top-level package namespace:

- CLI implementation: 9 top-level modules, about 4.2k lines.
- Formatter implementation: 7 top-level modules, about 4.7k lines.
- MCP and client support implementation: 11 top-level modules, about 5.0k
  lines.
- `formatter.py`, `cli.py`, and `server.py` are public import surfaces as well
  as implementation entry points, so they have a wide test and consumer blast
  radius.
- No import cycles are known in the current interface-layer graph. The package
  migration must preserve that property.

The observed problem was not the number of files by itself. The problem was
that the earlier god-file decomposition left conceptually related
implementation modules as flat prefix-based siblings (`cli_*`, `formatter_*`,
`server_*`, `mcp_*`) instead of local packages with clear public surfaces.

### Non-Goals

- No stable CLI behavior change.
- No stable MCP tool, resource, prompt, or JSON-RPC behavior change.
- No stable JSON schema change.
- No inference, scoring, fingerprint, signal, source, cache, or model redesign.
- No `models.py` package split in this pass. Its import blast radius is too
  high to combine with interface package movement.
- No new dependency and no generated runtime code.
- No attempt to lower line counts by merging unrelated modules or by creating
  tiny files for every helper.

### Current Package Map

Formatter:

```text
recon_tool/formatter/
  __init__.py          public re-export surface
  panel.py             Rich panel rendering and console helpers
  serialize.py         JSON, plain text, CSV, and dict serializers
  markdown.py          markdown report rendering
  exposure.py          exposure and gap rendering
  classify.py          service classification logic
  classify_tables.py   classification tables
  layout.py            wrapping and compact-layout helpers
```

MCP server:

```text
recon_tool/server/
  __init__.py          public MCP facade and compatibility exports
  app.py               shared FastMCP app and resolve-or-cache seam
  runtime.py           in-process cache, rate limiter, structured logging
  lookup.py            lookup tool
  posture.py           posture, exposure, gaps, compare, hypothesis, simulate
  graph.py             chain lookup and graph tools
  introspection.py     resources, catalog tools, reload, diagnostics
  ephemeral.py         ephemeral fingerprint session tools
```

CLI:

```text
recon_tool/cli/
  __init__.py          Typer app, command registration, run entry point
  lookup.py            lookup and discover command implementation
  batch.py             batch command implementation and emitters
  doctor.py            doctor commands
  cache.py             cache sub-app
  fingerprints.py      fingerprint sub-app
  signals.py           signal sub-app
  mcp.py               CLI wrapper for MCP start, install, and doctor
  shared.py            shared command validation and error helpers
```

MCP client support may move separately:

```text
recon_tool/mcp_client/
  install.py           client config installer
  doctor.py            end-to-end MCP self-check
  client_doctor.py     client-side config validation
```

### Phase 0: Decision And Safety Rails

Status: complete.

1. ADR-0008 records package locality and names the compatibility surfaces:
   `recon_tool.cli`, `recon_tool.formatter`, and `recon_tool.server`.
2. The command, schema, and MCP surface are guarded by:
   `uv run python scripts/generate_cli_surface.py --check`,
   `uv run python scripts/generate_schema.py --check`, and the existing surface
   inventory guard through `uv run python scripts/check.py`.
3. The local code graph should be refreshed after package-locality work.
4. The migration handled Python's file-versus-package conflict:
   each public module that becomes a package must be moved atomically from
   `name.py` to `name/__init__.py`.
5. Old sibling modules remain as bounded compatibility shims where tests or
   documented imports prove consumers use the old sibling path.

Exit criteria: ADR accepted, graph refreshed, current gates green, and the
exact first package move selected.

### Phase 1: Formatter Package

Why first: `recon_tool.formatter` is the widest interface-layer dependency and
still contains the largest cohesive panel-rendering core.

Status: complete.

Planned steps:

1. `formatter.py` moved to `formatter/panel.py`; `formatter/__init__.py` is the
   public facade.
2. `formatter_serialize.py`, `formatter_markdown.py`,
   `formatter_exposure.py`, `formatter_classify.py`,
   `formatter_classify_tables.py`, and `formatter_layout.py` moved under the
   package.
3. Public imports from `recon_tool.formatter` are preserved, including
   historical aliases used by tests and validation scripts.
4. Serialization remains importable without panel callers importing old
   top-level implementation modules.
5. Email-security score calculation moved to core domain helper
   `email_security.py` and remains re-exported through formatter serialization.
6. Old formatter sibling paths are bounded compatibility shims.

Exit criteria: rendered golden tests unchanged, JSON serialization unchanged,
public formatter imports preserved, no new import cycle, file-size ratchet not
weakened, full local gate passes.

### Phase 2: MCP Server Package

Why second: the MCP tool groups already map cleanly to runtime submodules, and
`server.py` is mostly a registration and compatibility facade.

Status: complete.

Planned steps:

1. `server.py` moved to `server/__init__.py`.
2. `server_app.py`, `server_runtime.py`, `server_lookup.py`,
   `server_posture.py`, `server_graph.py`, `server_introspection.py`, and
   `server_ephemeral.py` moved under the package.
3. All imports served by `recon_tool.server` are preserved, including
   tool functions and test-visible runtime seams.
4. MCP client installer and doctor code moved to `recon_tool.mcp_client`, not
   the server runtime package.
5. `python -m recon_tool.server` is preserved through `server/__main__.py`.
6. Old server sibling paths are bounded compatibility shims.

Exit criteria: MCP unit and integration tests pass, `recon mcp doctor` path
still resolves, tool and resource inventory unchanged except source-location
metadata, no import cycle, full local gate passes.

### Phase 3: CLI Package

Why third: the CLI has broad command-surface tests and Typer registration order
matters, but its desired package shape is straightforward.

Status: complete.

Planned steps:

1. `cli.py` moved to `cli/__init__.py`.
2. `cli_lookup.py`, `cli_batch.py`, `cli_doctor.py`, `cli_cache.py`,
   `cli_fingerprints.py`, `cli_signals.py`, `cli_mcp.py`, and `cli_shared.py`
   moved under the package.
3. The console script target `recon_tool.cli:run` is preserved.
4. Historical imports used by tests and validation scripts are preserved,
   including
   `app`, `run`, exit codes, command helper re-exports, and command callback
   helpers.
5. Command registration stays explicit in one place so a maintainer can see the
   CLI shape without opening every command implementation file.
6. Old CLI sibling paths are bounded compatibility shims.

Exit criteria: CLI surface unchanged, help output and generated command docs
unchanged except source-location metadata if applicable, stdout and stderr
discipline preserved, no import cycle, full local gate passes.

### Phase 4: Ratchets And Cleanup

Status: complete for the initial migration.

1. `scripts/check_interface_layout.py` rejects new top-level implementation modules
   matching `cli_*`, `formatter_*`, `server_*`, or `mcp_*`.
2. Compatibility shims are allowed only when they are explicitly listed,
   small, and import-only.
3. The file-size ratchet follows the moved formatter panel baseline without
   raising the historical ceiling.
4. Docs that describe source paths, including engineering practices and
   any generated surface inventory references.
5. Remove temporary shims only after a compatibility policy says it is safe, or
   keep them permanently if the import path is treated as stable.

Exit criteria: architecture guard in CI, file-size baseline tightened, docs
match the new package layout, code graph refreshed, and full local gate passes.

### Review Checklist For Each Phase

- Does the change preserve `recon_tool.cli`, `recon_tool.formatter`, or
  `recon_tool.server` public imports?
- Does it reduce top-level namespace noise without hiding the feature flow?
- Does it move only one architectural layer?
- Does it avoid mixing behavior edits with file moves?
- Does it keep source-derived output, stdout and stderr behavior, and generated
  artifacts stable?
- Does the diff show old and new callables are equivalent through tests or
  import assertions?
- Does the code graph show no new cycles and no unexpected new high-blast
  dependency?

### Stop Conditions

Pause the migration and reassess if any phase:

- Changes generated CLI, MCP, or schema surfaces beyond source-location
  metadata.
- Requires weakening lint, type, coverage, mutation, schema, or generated
  artifact gates.
- Introduces an import cycle.
- Forces a `models.py` or schema redesign.
- Makes formatter serialization depend more heavily on Rich panel rendering.
- Makes MCP server startup write protocol-breaking bytes to stdout.

## Version Milestones

- **2.2.x active patch line.** Documentation, validation, correctness fixes,
  generated-artifact guards, corpus-run tooling, and catalog refinements. Patch
  releases must not add a new stable runtime surface.
- **2.3 reserved.** The only plausible current candidate is a stable subset of
  the generated surface inventory. ADR-0007 blocks promotion until a concrete
  external consumer needs compatibility guarantees.
- **3.0 reserved.** A major release happens only for an unavoidable breaking
  change to a stable surface after the required deprecation path. No such change
  is planned.

## Backlog After v2.0

These items are not in the critical path. They become active only when they have
a clear consumer, validation plan, and invariant-safe design:

- CT organization-name search, opt-in and exact-match only.
- Wayback Machine temporal enrichment, opt-in and treated as a new public
  network surface.
- Deeper hardening simulation UX, only if it stays neutral and evidence-bound.
- Anomaly detection on issuer-mix changes over time.
- Per-domain inference cache for batch-mode reruns.
- `--mine-motifs` for maintainer-local motif proposals, dry-run first and
  human-reviewed.
- Imprecise Dirichlet or credal-network work, only if corpus evidence shows the
  current interval widening misses material calibration pathologies.
- Operator-tuned likelihood files, manual and local only.
- Cross-vertical generalization study on a disclosed, aggregate-safe corpus.

## Invariants

These are the hard boundaries. A proposal that violates one is out of scope even
if it is technically feasible:

- Passive collection only.
- Zero credentials, zero API keys, zero paid APIs.
- No active scanning, port scanning, brute-forcing, exploit checks, or
  target-service enumeration.
- No hosted service, daemon, scheduler, remote MCP transport, or shared
  monitoring backend.
- No bundled ML weights, embeddings, ASN data, GeoIP data, reputation feeds, or
  aggregate intelligence database.
- No user-code plugin system. Extensibility is data-file based.
- No learned weights in the runtime inference path. Fingerprints, signals,
  motifs, profiles, and CPTs must be inspectable committed data.
- Output stays hedged, neutral, provenance-backed, and never a security maturity
  verdict.
- Public artifacts never contain real apexes, organization names, tenant IDs,
  per-domain findings, or unsuppressed small strata.
- Agent judgment may consume recon output, but it cannot sit inside the
  deterministic observe-infer-report core.

## Intentionally Out Of Scope

Hard no:

- Active scanning or vulnerability assessment.
- Credentialed inventory.
- Company financials, news, hiring signals, firmographics, contacts, or
  marketing intelligence.
- Persistent aggregate databases.
- Docker image ownership, static binaries, native OS packages, HTML dashboards,
  PDF reports, TUI, REPL, or hosted API.
- STIX, MISP, Maltego, Prometheus, Excel, or SIEM-native exporters inside recon.

Use `--json` or `--ndjson` as the integration surface and pipe output into a
tool built for that job.

## Success Metrics (Post-1.0)

Success means:

- The stable CLI, MCP, and JSON surfaces stay backward compatible within the
  SemVer policy.
- The local gate and CI stay green, with branch coverage above the configured
  floor.
- The schema, CLI surface reference, and surface inventory never drift from
  code.
- Corpus validation produces aggregate-only memos with disclosure controls.
- New detections reduce real observed gaps without broadening false positives.
- Sparse outputs remain explicit about what the public channel cannot resolve.
- The assurance case and traceability matrix keep every major promise tied to
  code and tests.

## Implementation Discipline For New Correlation Work

Any item promoted from idea to shipped behavior must:

1. Land as data first when possible: fingerprints, signals, motifs, profiles, or
   CPT YAML.
2. Add engine code only when the data file cannot express the rule.
3. Include before-and-after validation, aggregate-only when a real corpus is
   involved.
4. Document both the positive case and the sparse or false-negative case.
5. Keep output hedged and provenance-backed.
6. Update `docs/recon-schema.json`, [schema.md](schema.md), and schema tests if
   the JSON shape changes.
7. Avoid stable surface changes unless the version plan, compatibility story,
   and tests are explicit.
8. Pass the full local gate before push:

```bash
uv run python scripts/check.py
```

## Design Choices That Stay

- Absence is no evidence unless the missing record is a public declaration that
  has defined disconfirming semantics.
- Delta mode reports changes. It does not invent a cause.
- Batch relationship signals are operator-scoped observations, not ownership
  claims.
- Graph clusters describe observed co-issuance or co-membership, not business
  relationships.
- The Bayesian layer reports credible intervals over a small, inspectable
  network. It does not learn from users or remote telemetry.
- Surface inventory files are generated discovery context unless ADR-0007's
  promotion gate is satisfied.
