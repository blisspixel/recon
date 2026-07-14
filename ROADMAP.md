# Roadmap

The canonical roadmap lives in [docs/roadmap.md](docs/roadmap.md).

Current status: recon v2.6.3 has a stable, production-ready baseline. The CLI,
JSON schema, local stdio MCP server, bounded collectors, generated-artifact
guards, validation gates, and release path are shipped. The active product work
is evidence-semantic integrity and a reproducible product-quality baseline. The
isolated MCP v1.28.1 and v2.0.0b1 matrix passed on 2026-07-13, with production
remaining on stable v1 and the final v2 adoption gate still pending. Measured
latency, catalog quality,
agent context cost, provenance, and interface-hotspot work follow in dependency
order. Retained batch output now uses a fixed worker pool instead of one task
per input; summary shaping and cross-domain correlation remain measured
follow-up work. The first bounded internal claim contract now evaluates the exact apex
DMARC `p=reject` observation and drives the opt-in cohort schema 2.2 DMARC
denominator while schema 2.1 remains the default.

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
