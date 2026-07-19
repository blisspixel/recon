# Roadmap

The canonical roadmap lives in [docs/roadmap.md](docs/roadmap.md).

Current status: recon v2.6.6 has a stable, production-ready baseline. The CLI,
JSON schema, local stdio MCP server, bounded collectors, generated-artifact
guards, validation gates, and release path are shipped. Recent shipped work
improves first-run help and error recovery, removes rejected MCP values from
logs,
aligns public issue intake with the no-target-data policy, corrects the package
surface description, requires verification dates on new fingerprint
detections, groups batch help by task, redacts unexpected batch exception
details, reports cache deletion failures, exposes payload-free result and CT
cache metadata, hardens diagnostic rendering, discloses doctor connectivity,
keeps narrow help complete, adds all-source failure recovery, executes the
sealed wheel before publication, and treats closed output pipes as normal
control flow. Shipped polish also makes catalog search bounded and
field-associated, preserves every same-slug fingerprint record in `show`,
aligns CLI and MCP category matching, keeps signal summary projections
consistent, emits plain redirected gate logs, and makes partial-release reruns
stop on named preconditions before mutation. Shipped maintenance also
bounds default cache payload inspection with exact completeness counts, exposes
and clears interrupted-write residue, separates fingerprint corpus errors from
misses under bounded input, rejects empty catalog filters, preserves ranked
signal hierarchy, and keeps welcome descriptions associated at 80 columns.
The shipped MCP diagnostics pass makes static registry failures exit non-zero,
exercises every canonical local JSON resource through live stdio, preserves the
failed protocol phase, and documents the three-part server and client check.
The active product work is evidence-semantic integrity and a
reproducible product-quality baseline. The
isolated MCP v1.28.1
and v2.0.0b1 matrix passed on 2026-07-13, with production remaining on stable v1
and the final v2 adoption gate still pending. Measured latency, catalog quality,
agent context cost, provenance, and interface-hotspot work follow in dependency
order. Retained batch output now uses a fixed worker pool instead of one task
per input; summary shaping and cross-domain correlation remain measured
follow-up work. The first bounded internal claim contract now evaluates the exact apex
DMARC `p=reject` observation and drives the opt-in cohort schema 2.2 DMARC
denominator while schema 2.1 remains the default.

Shipped maintenance also refuses HTTP destinations whose hostname or DNS
result cannot be validated, confines default MCP logging to the running server,
bounds fatal MCP stderr, keeps doctor checks useful across ordinary HTTP
request failures, labels CT cache overview freshness, and completes narrow root
and welcome help. Release-shaped builds now select exact uv and a hash-locked
backend graph, reconstruct the wheel from the new sdist, and reject any sealed
artifact set other than one tag-matching wheel and sdist.
Publication now waits for exact PyPI-to-sealed byte parity before GitHub assets
can be created or replaced, and documents the recoverable partial-publication
state if parity fails after PyPI accepts immutable files. Remote readiness
validates the completed SBOM, exported provenance bundle, exact signer workflow,
source tag and commit digest, and cross-channel digests. Reviewed installer
helpers bind installation to their release version
and preserve one existing package-manager owner; consumer verification now has
complete fail-closed POSIX and PowerShell paths. Shipped release hardening also
reuses one bounded exact PyPI metadata validator, includes the completed SBOM in
GitHub provenance, and rejects unsafe existing-release state before recovery
can replace assets. The operator recovery block itself now uses strict Bash
mode, named failures, and a visible pre-mutation success checkpoint. One
  digest-bound v2.6.3 historical exception preserves the
  published distribution-only bundle while still requiring SBOM validation;
  future releases fail if SBOM provenance is absent. Enforcing dependency
  audits resolve the installed auditor under Python isolated mode, and the
  later SBOM job treats every nonzero audit status as fatal.

Pull requests targeting `main` run CodeQL before merge, every push to `main`
updates exact default-branch analysis, and scheduled and manual scans remain
available. Remote readiness keeps the other required code-owned Scorecard
controls at `10` and uses the observed SAST floor
of `7` while the public sample still contains pre-policy pull requests. The
SAST requirement returns to `10` only after the public API reports supported
SAST checks for every sampled merged pull request; historical checks are not
backfilled to improve the metric.

The catalog-quality track uses deduplicated private rounds with distinct rank,
regional, vertical, vendor-seed, or drift questions. It must account for every
bounded record path as measured, partial, unavailable, or unmeasured before
claiming broad coverage. The opt-in typed reducer now covers all current catalog
paths; its detailed queues and manifests remain private. Target identities,
target-owned records, and per-domain rows stay off GitHub. Within validation,
only generic provider patterns, reserved synthetic fixtures, and
disclosure-safe aggregates are public. Current validation generators are
deterministic, their tracked outputs must match source, and the local and
release gates reject identity-bearing JSON,
NDJSON, CSV, candidate-rejection rows, and detailed run artifacts.
Current prose, CLI and help examples, agent guidance, structured samples,
snapshots, schemas, and tests use reserved synthetic identities. The local and
release gates reject the retired fictional target vocabulary across tracked and
nonignored-untracked text candidates without changing provider definitions or
generic ACME protocol references. Release source distributions explicitly
exclude ignored agent work and private validation paths, and an artifact test
plants an ignored sentinel before inspecting the built archive.
The first frozen convenience-sample baseline, provider-supported promotion
gate, and unseen vertical holdout are complete. Independent rank, regional,
vendor-seed, and drift rounds remain before any broad catalog-coverage claim.

The canonical dependency order, acceptance evidence, stop rules, current
high-trust code-graph summary, invariants, and explicit non-goals are in
[docs/roadmap.md](docs/roadmap.md). The implementation plan is
[docs/engineering-refinement-plan.md](docs/engineering-refinement-plan.md).
The measured source, test, compatibility, and facade cleanup plan is
[docs/structural-maintainability.md](docs/structural-maintainability.md).
The time-bound MCP plan is
[docs/mcp-2026-07-28-readiness.md](docs/mcp-2026-07-28-readiness.md), with the
decision in
[docs/adr/0009-mcp-2026-readiness.md](docs/adr/0009-mcp-2026-readiness.md).
The performance-language boundary is governed by
[docs/adr/0010-evidence-gated-native-acceleration.md](docs/adr/0010-evidence-gated-native-acceleration.md).
The current step-back audit is
[docs/strategic-gap-audit.md](docs/strategic-gap-audit.md).

Publication, OpenSSF process, independent replication, and archive work remain
separate maintainer tracks. Their final submission gate is
[docs/submission-freeze-checklist.md](docs/submission-freeze-checklist.md); they
do not outrank output truthfulness, measured utility, or compatibility work.

The most recent completed historical public claim audit is recorded in
[validation/2026-06-29-scorecard-gate-claim-audit.md](validation/2026-06-29-scorecard-gate-claim-audit.md).
The current paper and artifact package is unfrozen after subsequent wording,
package, validation, and release changes. Maintainers must rerun that gate
before external submission or submission packaging. The most recent completed
historical local submission-freeze proof is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).
