# Roadmap

The canonical roadmap lives in [docs/roadmap.md](docs/roadmap.md).

Current status: recon v2.6.3 has a stable, production-ready baseline. The CLI,
JSON schema, local stdio MCP server, bounded collectors, generated-artifact
guards, validation gates, and release path are shipped. Unreleased work improves
first-run help and error recovery, removes rejected MCP values from logs,
aligns public issue intake with the no-target-data policy, corrects the package
surface description, requires verification dates on new fingerprint
detections, groups batch help by task, redacts unexpected batch exception
details, reports cache deletion failures, exposes payload-free result and CT
cache metadata, hardens diagnostic rendering, discloses doctor connectivity,
and treats closed output pipes as normal control flow. The active product work is
evidence-semantic integrity and a reproducible product-quality baseline. The
isolated MCP v1.28.1
and v2.0.0b1 matrix passed on 2026-07-13, with production remaining on stable v1
and the final v2 adoption gate still pending. Measured latency, catalog quality,
agent context cost, provenance, and interface-hotspot work follow in dependency
order. Retained batch output now uses a fixed worker pool instead of one task
per input; summary shaping and cross-domain correlation remain measured
follow-up work. The first bounded internal claim contract now evaluates the exact apex
DMARC `p=reject` observation and drives the opt-in cohort schema 2.2 DMARC
denominator while schema 2.1 remains the default.

The catalog-quality track uses deduplicated private rounds with distinct rank,
regional, vertical, vendor-seed, or drift questions. It must account for every
bounded record path as measured, partial, unavailable, or unmeasured before
claiming broad coverage. The opt-in typed reducer now covers all current catalog
paths; its detailed queues and manifests remain private. Target identities,
target-owned records, and per-domain rows stay off GitHub; only generic provider
patterns, fictional fixtures, and disclosure-safe aggregates are public.
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
