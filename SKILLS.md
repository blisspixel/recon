# Maintainer Loop Skills

This is a local agent learning artifact for this repository. It records reusable
operating rules for future cycles and must not override `AGENTS.md`,
`CONTRIBUTING.md`, or `docs/agentic-balance.md`.

## recon Operating Rules

- Treat `docs/agentic-balance.md` as the boundary document for any rule or
  agentic workflow.
- Keep agentic work outside the observe-infer-report core.
- Prefer deterministic gates over prose review.
- Do not add stable public surfaces without a concrete consumer and a
  compatibility story.
- When the private corpus is unavailable, support the calibration path with
  public-tree docs, guards, tests, or runbooks rather than inventing unrelated
  runtime features.
- Treat publishable validation memos as a disclosure boundary: target-looking
  strings can appear as values, keys, or free-form titles, so check all three.
- For paper or assurance reproducibility, add orchestration around existing
  harnesses rather than copying their logic. The orchestrator should capture
  commands, stdout, stderr, duration, success state, and what remains outside the
  public no-private-data path.
- When agent documentation mentions MCP approval, keep the stateful tool split
  explicit: ephemeral fingerprint mutation and data reload are session-local
  mutations even though most recon tools are read-only.
- When an agent only needs recon capability context, read MCP resources
  (`recon://fingerprints`, `recon://signals`, `recon://profiles`, or
  `recon://schema`) before any domain-analysis tool call.
- When a generated inventory is meant to help agents, include both machine
  surfaces and the guidance surfaces that teach clients how to call them. Pin
  the generated approval model to live MCP annotations, not copied prose.
- If MCP clients need the generated inventory but may not have repository-file
  access, expose the packaged snapshot as a local resource and keep it
  byte-identical to the docs copy with tests.
- For MCP precise-output-schema work, use `TypedDict` return annotations first
  on simple no-network or session-local tools and pin the advertised `$defs`
  through `mcp.list_tools()` before expanding to higher-blast-radius domain
  tools.
- For MCP typed envelopes, make every advertised required key present on every
  runtime branch. FastMCP may treat `TypedDict` optional keys as required, so
  prefer a small additive field over a schema that lies about skipped results.
- For MCP lookup-shaped schemas, do not rely on `NotRequired` to document
  branch-only keys. Either keep the key out of the advertised type or make the
  runtime branch emit an empty list/object so the schema stays truthful.
- For CLI surface docs, generate Markdown from the live Typer command tree and
  gate it in `scripts/check.py`; do not maintain command and flag tables by hand.
- For release notes about CLI command or flag changes, compare generated
  `docs/surface-inventory.json` files with
  `scripts/summarize_cli_surface_changes.py`; do not diff help output manually.
- For Scorecard work, prefer real controls that align with existing invariants.
  Do not add unpinned workflow dependencies or fake service integrations only to
  move the badge.
- For workflow-token posture, gate both the top-level default permissions and
  the named elevated job scopes. A workflow can need write or OIDC permissions,
  but that exception should be explicit and reviewed.
- For GitHub Actions checkout, set `persist-credentials: false` unless a job
  explicitly needs Git to reuse the workflow token. Prefer explicit `GH_TOKEN`
  environment use for GitHub CLI operations.
- For CI and release workflows, set explicit job-level `timeout-minutes` values
  and keep a structural test so new jobs cannot hang indefinitely by default.
- For Bayesian tuning knobs, prefer committed data in `bayesian_network.yaml`
  with loader defaults and invariant tests over module-level engine constants.
  Keep behavior unchanged at default values and update trust docs in the same
  cycle.
- For JSON-consumer examples, document every output shape with `record_type`
  routing, exit-code handling, and unknown-field tolerance. Keep examples backed
  by tests that parse snippets and compare against the schema or runtime
  classifier.
- For fingerprint metadata enrichment, change references, descriptions, and
  advisory audit heuristics only when they make provenance or scope clearer.
  Do not change detection patterns or confidence in the same pass unless the
  corpus evidence supports it.
- For weak-area docs, turn false-negative behavior into operator guidance:
  symptoms, why passive DNS cannot see more, and what to do without broadening
  fingerprints or adding network calls.
- For unclassified CNAME chains, keep the doc voice conservative: a reached
  unmatched terminus is a fingerprint proposal, not a vendor claim. Require
  public docs or repeated validation evidence plus negative tests before a rule.
- For profile baseline rules, use loaded fingerprint categories that actually
  suppress on current slugs, and test both the missing-category observation and
  the present-category suppression path.
- For committed validation memos, record only aggregate counts, rates, intervals,
  and harness status. Keep local manifests and per-step stdout under ignored
  scratch paths, and pin the memo with validation-hygiene tests.
- For maintainer-local validation runners, treat every operator-provided path
  segment as hostile. Validate names with a strict identifier regex and resolve
  final paths under the intended output root before writing artifacts.
- Keep validation-runner path safety centralized so public and private artifact
  writers share the same traversal and safe-stamp contract.
- For cache tests, pin the intended boundaries explicitly: normalized URL inputs
  use apex keys, clear-all touches only top-level JSON cache entries, and
  batch-only peer fields never survive per-domain cache round-trips.
- For `match_mode: all` on same-type TXT fingerprints, verify detector
  bookkeeping records every same-record match while preserving the historical
  first displayed service. Use fictional domains in validation notes.
- When vendor docs use both a vendor-specific CNAME target and a generic
  `_acme-challenge` TXT flow, fingerprint the vendor-specific CNAME and leave
  the ACME TXT out of the catalog unless the TXT value itself carries
  vendor-specific structure.
- For motif catalog growth, prefer complete ordered-chain motifs only when they
  add information beyond existing pairwise motifs. Record the before/after
  firing delta on fictional or aggregate-safe chain inputs.
- Track external spend explicitly. Default spend is 0 USD.
- Before closing a cycle, run the narrow relevant gate. Before claiming repo
  readiness, run `uv run python scripts/check.py`.
