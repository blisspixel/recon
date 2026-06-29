# Roadmap

This file is the current plan and scope boundary. Shipped work belongs in
[CHANGELOG.md](../CHANGELOG.md). Release mechanics belong in
[release-process.md](release-process.md). Historical release planning lives in
[roadmap-history.md](roadmap-history.md).

> **Status:** v2.2.16 is current. recon is feature-complete for the current
> roadmap: the CLI, JSON schema, MCP server, validation guards, release path,
> generated schema guard, and generated surface inventory guard are shipped.
> Remaining work hardens the project, sharpens documentation, and improves
> validation evidence without expanding the runtime surface. The final public
> claim audit for the current paper package is complete; future wording,
> package, or validation changes rerun it.

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
     reproduction path passing, and make small correctness or clarity
     refinements when validation runs expose them.
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
     Infobip email-tracking surface rules. Session F produced no new candidate,
     so there is no active public-source-backed catalog task.
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
     [2026-06-29-final-claim-audit-refresh.md](../validation/2026-06-29-final-claim-audit-refresh.md)
     records the current final public claim audit refresh, and release
     readiness now guards citation metadata.
   - Acceptance: cite only public or synthetic artifacts and aggregate-only
   validation memos. Public-list numbers remain robustness checks rather than
   population rates. M365 tenancy evidence stays named as corroboration for
   this submission because no passive independent instrument was adopted. Do
   not claim frequentist coverage for the 80 percent intervals. Rerun the
   final claim audit after any draft, package, or claim-map change. Do not add
   runtime behavior while packaging the artifact.

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
