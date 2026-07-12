# Roadmap

The canonical roadmap lives in [docs/roadmap.md](docs/roadmap.md).

Current status: recon v2.4.0 has a stable, production-ready baseline. The CLI,
JSON schema, local stdio MCP server, bounded collectors, generated-artifact
guards, validation gates, and release path are shipped. The active product work
is evidence-semantic integrity, an isolated MCP v2 beta compatibility matrix,
and a reproducible product-quality baseline. Measured latency, catalog quality,
agent context cost, provenance, and interface-hotspot work follow in dependency
order.

The canonical dependency order, acceptance evidence, stop rules, current
high-trust code-graph summary, invariants, and explicit non-goals are in
[docs/roadmap.md](docs/roadmap.md). The implementation plan is
[docs/engineering-refinement-plan.md](docs/engineering-refinement-plan.md).
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

The final public claim audit refresh for the current paper package is recorded
in
[validation/2026-06-29-scorecard-gate-claim-audit.md](validation/2026-06-29-scorecard-gate-claim-audit.md).
Future wording, package, or validation changes rerun that gate before
submission or release packaging. The latest local submission-freeze public proof
record is
[validation/2026-06-30-submission-freeze-local-proof.md](validation/2026-06-30-submission-freeze-local-proof.md).
