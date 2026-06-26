# Progress Log

This file records maintainer-loop work performed in this checkout. It is a local
planning artifact and does not replace `CHANGELOG.md`. It keeps only the last
five active loop cycles; older completed milestones live in `CHANGELOG.md` and
repository history.

## 2026-06-26

Session: loop cycle 6, live documentation refresh. External spend 0 USD.

- Selected the docs refresh after user review feedback that the README needed a
  deep dive, clarification, and detail moved into the docs set.
- Used current documentation-architecture guidance: keep the README as a front
  door, split task guidance from reference and explanation, keep changelog
  entries human-readable, and preserve SemVer/status anchors.
- Rewrote `README.md` from 373 lines to 224 lines, keeping install, first
  lookup, common commands, JSON/MCP pointers, limitations, docs map, and
  development gates.
- Added `docs/getting-started.md` for install, update, uninstall, PATH notes,
  input normalization, output modes, batch, delta, MCP setup, and completion.
- Added `docs/how-it-works.md` for the plain-language source-to-slug-to-signal
  model, graph structure, Bayesian posteriors, provenance, caching, and
  non-inferences.
- Reorganized `docs/README.md` by reader need: orientation, how-to guides,
  reference, explanation and assurance, research, and contributing.
- Replaced the 2,771-line `docs/roadmap.md` with a 178-line current-plan and
  invariant document, preserving live anchors such as `#invariants`,
  `#intentionally-out-of-scope`, `#success-metrics-post-10`,
  `#backlog-after-v20`, and
  `#implementation-discipline-for-new-correlation-work`.
- Normalized tracked Markdown documentation, examples, agent guidance, and
  validation memos so they contain no em dashes, en dashes, pictographs, or
  literal AI-attribution phrases outside ignored private validation paths.
- Focused validation passed: text hygiene, markdown links, release-readiness
  README anchors, surface-inventory policy, automation docs, and generated
  surface checks.
- Final full local gate passed with `uv run python scripts/check.py`: 3,601
  passed, 6 skipped, 4 deselected, total coverage 86.61 percent. All gate
  stages passed.
- External spend: 0 USD.

Session: loop cycle 7, C3 CT retry hardening and bounded retry. External spend
0 USD.

- Ran the cycle-7 maintenance sub-goal against the C3 scan path: reviewed
  private artifact boundaries, retry/resume behavior, malformed streamed-tail
  handling, and validation hygiene before continuing the live CT track.
- Latest best-practice refresh for this task: keep long-running public-data
  workflows resumable and checkpointed, keep retries bounded by limiter state,
  and keep synthesized private inputs under explicitly private workspaces.
- Hardened `validation/scan.py --ct-retry-from`: prior run directories,
  `results.ndjson`, and legacy `results.json` are accepted; malformed streamed
  tails are skipped through a shared result-record iterator; retry domains are
  deduplicated; and synthesized retry corpora are written under the validated
  private output root.
- Added regression coverage for private retry-input path validation, private
  output placement, deduplication, malformed partial tails, and legacy JSON-array
  retry input.
- Ran a bounded maintainer-local C3 retry against degraded CT records from the
  first partial session. The retry corpus had 2,610 domains; the five-minute
  session finalized 109 valid retry records, with 1 live CT success, 1 rate
  limit, 105 breaker-open outcomes, 2 not-attempted outcomes, and 0 triage
  candidates. Private artifacts remain ignored under `validation/runs-private/`.
- Updated the aggregate public C3 memo, validation runbook, roadmap current
  state, changelog, current-state analysis, and quality rubric.
- Focused validation passed:
  `uv run python -m pytest tests/test_scan_ct_summary.py tests/test_maintainer_loop_runbook.py tests/test_agentic_balance_docs.py -q`
  with 20 passed. Focused ruff, text hygiene, validation hygiene, and
  `git check-ignore` checks passed.
- Fast local gate passed with `uv run python scripts/check.py --fast`.
- Final full local gate passed with `uv run python scripts/check.py`: 3,606
  passed, 5 skipped, 4 deselected, total coverage 86.63 percent. All gate
  stages passed.
- External spend: 0 USD.

Session: loop cycle 8, C3 CT session aggregation. External spend 0 USD.

- Selected aggregate session accounting because C3 is now explicitly
  multi-session and raw partial-record counts are not enough to know whether CT
  coverage is actually improving.
- Latest best-practice refresh for this task: resumable data-collection
  workflows need idempotent aggregation, provenance metadata, bounded retry
  accounting, and disclosure-safe summaries rather than row-level publication.
- Added `validation/summarize_ct_sessions.py`, an aggregate-only private-run
  summarizer. It accepts private run directories with `results.ndjson` or legacy
  `results.json`, streams partial NDJSON, skips malformed streamed tails,
  computes raw CT outcome counts, computes best CT outcome by unique domain, and
  validates that in-repo inputs and outputs stay under private validation roots.
- Added regression coverage for cross-session dedupe, best-outcome selection,
  malformed partial tails, legacy JSON-array input, private path rejection, and
  absence of target strings in rendered summary JSON.
- Ran the summarizer over the two current C3 private sessions. Aggregate result:
  2 sessions, 2,802 valid records, 2,769 records with domain fields, 2,647
  unique observed domains, 38 domains with usable CT data, 2,609 domains still
  degraded or unresolved for CT, and CT-data coverage ratio 0.014356. Private
  summary written to ignored `validation/runs-private/c3-ct-session-summary-20260626.json`.
- Updated the public C3 memo, validation runbook, roadmap current state,
  changelog, current-state analysis, quality rubric, and `SKILLS.md`.
- Focused validation passed:
  `uv run python -m pytest tests/test_ct_session_summary.py tests/test_markdown_links.py tests/test_release_readiness.py -q`
  with 19 passed. Focused ruff, text hygiene, validation hygiene, and diff
  checks passed.
- Final full local gate passed with `uv run python scripts/check.py`: 3,610
  passed, 5 skipped, 4 deselected, total coverage 86.61 percent. All gate
  stages passed.
- External spend: 0 USD.

Session: loop cycle 9, CT attempt-outcome accounting. External spend 0 USD.

- Selected CT outcome accounting because the C3 aggregate was dominated by
  breaker labels, while the current limiter state showed a more specific mixed
  provider condition: crt.sh breaker history plus CertSpotter live pacing.
- Latest best-practice refresh for this task: keep retries bounded by local
  limiter state, fail fast under provider stress, and use low-cardinality error
  labels that distinguish retryable live pacing from no-attempt breaker stops.
- Updated `ct_failure_outcome` so `breaker_open` is reserved for failed CT
  attempts where every failed provider was stopped by an open local breaker.
  Mixed provider failures now surface the live attempted failure cause, such as
  `live_rate_limited` or `live_other_failure`, while keeping the existing
  best-effort enum.
- Updated the model comments, packaged schema description, docs schema
  description, and operational contract to match the refined semantics.
- Added focused regression coverage for mixed breaker plus rate-limit, mixed
  breaker plus live error, and all-breaker outcomes.
- Ran a bounded maintainer-local retry against the degraded records from Retry
  Session A. The retry corpus had 106 domains; the 90-second session finalized
  34 valid records, with 1 live CT success and 33 live-rate-limited outcomes.
  The run produced zero `breaker_open` records, confirming the corrected
  accounting shape. Private artifacts remain ignored under
  `validation/runs-private/`.
- Rebuilt the private aggregate C3 summary across three sessions. Current
  aggregate state: 2,836 valid records, 2,803 records with domain fields, 2,647
  unique observed domains, 39 domains with usable CT data, 2,608 domains still
  degraded or unresolved for CT, and CT-data coverage ratio 0.014734.
- Updated the public C3 memo, roadmap current state, changelog, current-state
  analysis, quality rubric, operational contract, and `SKILLS.md`.

Session: loop cycle 10, bug-hunt and security-review round. External spend 0
USD.

- Confirmed prior pushed commit `8968f01` reached remote CI success before
  continuing.
- Ran a targeted review over the highest-risk surfaces: CT failure telemetry,
  disk cache path containment and atomic writes, validation-runner private path
  gates, HTTP SSRF/decompression-bomb controls, batch input bounds, and
  source-derived DNS target attribution.
- Fixed `classify_ct_failure` so direct or wrapped local `RateLimited`
  max-wait failures classify as `rate_limit`, while `circuit breaker open`
  remains a breaker outcome. Replaced brittle raw `429` substring
  classification with typed response-status inspection, so a non-429 error
  mentioning a numeric domain does not become a rate-limit outcome.
- Fixed Google Workspace DKIM CNAME attribution to match `google.com` by exact
  or dotted hostname suffix instead of raw substring.
- Fixed Microsoft 365, Teams, Intune, Office ProPlus, and Google Workspace
  module CNAME/SRV attribution to parse target hosts and match by suffix. SRV
  records now match against the final target field, and explicit unavailable
  targets (`.`) are ignored.
- Added focused regression tests for wrapped limiter failures, numeric-domain
  HTTP errors, Google DKIM lookalikes, M365/GWS CNAME lookalikes, Teams SRV
  interior labels, and unavailable SRV targets.
- Focused validation passed:
  `uv run pytest tests/test_dns_subdetectors.py tests/test_gws_features.py
  tests/test_sources/test_dns.py tests/test_cname_chain_validation.py
  tests/test_fallback_chain.py tests/test_ct_pipeline_resilience.py
  tests/test_markdown_links.py -q` with 251 passed. Focused ruff and pyright
  passed.
- Security and hygiene checks passed: text hygiene, validation hygiene, workflow
  pins, ClusterFuzzLite requirements drift, and `uv run pip-audit` with no known
  vulnerabilities.
- Final full local gate passed with `uv run python scripts/check.py`: 3,624
  passed, 6 skipped, 4 deselected, total coverage 86.71 percent. All gate
  stages passed.
- Cycle health: 5/5 | Simplicity: 5/5 | Est. spend: $0 | New skill distilled:
  DNS target suffix parsing
