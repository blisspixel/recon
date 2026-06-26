# Progress Log

This file records maintainer-loop work performed in this checkout. It is a local
planning artifact and does not replace `CHANGELOG.md`. It keeps only the last
five active loop cycles; older completed milestones live in `CHANGELOG.md` and
repository history.

## 2026-06-26

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

Session: loop cycle 11, C3 retry input security review. External spend 0 USD.

- Selected the C3 validation tooling because it is the top open roadmap item
  and the retry/finalize path handles private corpus artifacts.
- Reviewed `validation/scan.py`, `validation/summarize_ct_sessions.py`,
  `validation/run_path_safety.py`, and the batch input boundary for path
  containment, subprocess argument construction, partial NDJSON handling, and
  synthesized retry-corpus safety.
- Fixed `validation/scan.py --ct-retry-from` so prior `queried_domain` values
  are revalidated before they are written into a synthesized private retry
  corpus. Malformed, control-bearing, or newline-bearing values are skipped
  instead of becoming extra corpus lines.
- Rejected `--finalize-existing` combined with `--ct-retry-from`, because
  finalization is a no-network recovery mode and retry synthesis is a new
  network run plan.
- Added a reusable `SKILLS.md` rule for revalidating machine-output fields
  before turning them into line-oriented private validation corpora.
- Focused validation passed:
  `uv run pytest tests/test_scan_ct_summary.py tests/test_ct_session_summary.py
  tests/test_run_path_safety.py tests/test_markdown_links.py -q` with 37
  passed. Focused ruff, pyright, text hygiene, and validation hygiene passed.
- Final full local gate passed with `uv run python scripts/check.py`: 3,627
  passed, 5 skipped, 4 deselected, total coverage 86.69 percent. All gate
  stages passed.

Session: loop cycle 12, C3 Retry Session C and Descope surface promotion.
External spend 0 USD.

- Selected the top roadmap item again: continue C3 as bounded, aggregate-only
  CT sessions while reviewing private candidates only through public-source
  proposal rules.
- Checked persisted CT limiter snapshots, then ran a bounded retry against the
  33 CT-degraded records from Retry Session B:
  `uv run python validation/scan.py --corpus validation/corpus-private/consolidated.txt
  --ct-retry-from validation/runs-private/20260626-171647Z --ct
  --concurrency 1 --timeout 60 --max-runtime 240 --no-compare --label
  c3-ct-retry-c`.
- Retry Session C completed 33/33 records with 1 `live_success` and 32
  `live_rate_limited` outcomes. It produced one private triage candidate.
- Rebuilt the private aggregate summary across four sessions. Current aggregate
  state: 2,869 valid records, 2,836 records with domain fields, 2,647 unique
  observed domains, 40 domains with usable CT data, 2,607 domains still degraded
  or unresolved for CT, and CT-data coverage ratio 0.015111.
- Promoted a conservative Descope `cname_target` rule only after checking
  public Descope custom-domain documentation. Added both documented US and EU
  targets and negative boundary coverage for lookalike suffixes.
- Fixed the integration bug caught by the full local gate: the new `descope`
  slug now maps to the Identity panel category, participates in identity
  posture as Descope, and has regression coverage for both decisions.
- Ran the cycle-12 distill into `SKILLS.md`: private CNAME-target candidates
  require public vendor documentation plus negative boundary tests before public
  memo updates.
- Focused validation passed:
  `uv run pytest tests/test_surface_attribution.py tests/test_fingerprints.py
  tests/test_scan_ct_summary.py tests/test_ct_session_summary.py
  tests/test_markdown_links.py -q` with 90 passed,
  `uv run pytest tests/test_slug_category_invariant.py
  tests/test_surface_attribution.py tests/test_exposure.py -q` with 66 passed,
  and `scripts/validate_fingerprint.py` passed with 844 entries.
- Final full local gate passed with `uv run python scripts/check.py`: 3,630
  passed, 6 skipped, 4 deselected, total coverage 86.70 percent. All gate
  stages passed.

Session: loop cycle 13, documentation refresh and C3 next-plan clarification.
External spend 0 USD.

- Reviewed README, roadmap, docs index, validation runbooks, data-handling
  policy, operational contract, weak-areas guidance, and the validation scan
  and CT session summarizer code.
- Researched the current CT and documentation constraints from primary sources:
  RFC 9162, Let's Encrypt CT log documentation, the C2SP Static CT API, SSLMate
  Certificate Search API limits, NIST SP 800-188, Diataxis, Keep a Changelog,
  and Semantic Versioning.
- Added `docs/c3-ct-validation-plan.md` as the active plan for the next work:
  provider-health check, bounded Retry Session D, aggregate summary rebuild,
  public-source candidate triage, and a closure decision that treats public CT
  search limits as a real ceiling instead of waiting for full CT coverage.
- Updated README, docs index, roadmap, validation README, historical v2.0
  corpus runbook, maintainer-validation notes, limitations, how-it-works,
  weak-areas guidance, paper outline, changelog, current-state analysis,
  quality rubric, and `SKILLS.md` to point at the active C3 plan.
- Focused documentation validation passed:
  `uv run pytest tests/test_markdown_links.py tests/test_release_readiness.py -q`
  with 15 passed. Text hygiene, validation hygiene, generated surface
  inventory, generated CLI surface doc, and diff whitespace checks passed.
- Final full local gate passed with `uv run python scripts/check.py`: 3,631
  passed, 5 skipped, 4 deselected, total coverage 86.69 percent. All gate
  stages passed.

Session: loop cycle 14, C3 live retry closure and Infobip surface promotion.
External spend 0 USD.

- Re-opened the private aggregate summary and Session E candidate state. The
  six-session aggregate showed 2,932 valid records, 2,647 unique observed
  domains, 42 domains with usable CT data, and one candidate under the
  `email-messaging.com` host family.
- Researched the candidate against public Infobip email domain setup
  documentation and extended the existing `infobip` slug with a narrow
  `email-messaging.com` `cname_target` rule instead of creating a duplicate
  provider identity.
- Fixed the related taxonomy drift: `infobip` now maps to the Email panel
  category rather than the generic Business Apps fallback.
- Added focused tests for Infobip rule loading, regional tracking-host
  classification, lookalike suffix rejection, and Email panel categorization.
  Fingerprint validation passed with 844 entries.
- Ran final bounded Retry Session F against Session E's degraded tail. It
  finalized 15 of 28 records before the runtime cap, added 2 live CT successes,
  and produced zero candidates.
- Rebuilt the seven-session private aggregate summary. Current aggregate state:
  2,947 valid records, 2,909 records with domain fields, 2,647 unique observed
  domains, 44 domains with usable CT data, 2,603 domains still degraded or
  unresolved for CT, and CT-data coverage ratio 0.016623.
- Updated README, roadmap, C3 plan, validation memo, changelog, current-state
  analysis, and quality rubric to close C3 as a documented partial CT validation
  track after gates pass.
- Bug-hunt cleanup from the broad Pyright pass fixed legacy validation helper
  typing: JSON record aliases, synthetic fixture cache-version handling,
  TenantInfo snapshot rendering annotations, and DNS-only tenancy source-result
  typing.
- Final full local gate passed with `uv run python scripts/check.py`: 3,634
  passed, 5 skipped, 4 deselected, total coverage 86.70 percent. All gate
  stages passed.
