# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.9] - 2026-05-14

**v1.9.9 bridge milestone: detection-gap UX surfaces.** Three additions
to the default panel that make the architectural limits of passive DNS
collection visible without changing what data the tool collects. After
v1.9.9 the panel shows what it cannot see (the passive-DNS ceiling),
casts a wider net for what it can see (extended common-prefix
enumeration), and summarises the distribution (apex-level multi-cloud
rollup). No engine code changes ship; no JSON schema additions ship.

This is the v1.9.9 step of the v1.9.4 to v2.0 linear sequence in
`docs/roadmap.md`. The multi-apex CT SAN traversal mentioned alongside
the wordlist additions in the v1.9.9 roadmap section was deferred to
v1.9.9.1 so the cert-side breadth change can land with its own
validation pass; the three surfaces shipped here are panel-only and
self-contained.

### Added

- **Passive-DNS ceiling phrasing in the default panel.** When the panel
  is sparse on an apex that probably should not be, a one-line teaching
  footer renders under the Services block: "Passive DNS surfaces what
  publishes externally. Server-side API consumption, internal workloads,
  and SaaS without DNS verification do not appear in public DNS
  records." Operators and AI agents reading the panel now have an
  explicit cue against the absence-of-finding-equals-absence-of-service
  misread. Trigger heuristic is conservative on purpose: fires only when
  `info.services` is non-empty (a different surface owns failed runs),
  `info.domain_count >= 3` (the apex has multiple tenant domains, so
  sparse is genuinely surprising), categorized service families are
  fewer than 5, and CNAME-chain subdomain attributions are fewer than 5.
  Both halves of the sparse check must hold so a domain with short
  Services but many surface attributions does not gain a misleading
  footer. `--full` / `--domains` suppresses the line because those modes
  already carry the long surface section.
- **Apex-level multi-cloud rollup indicator.** When the canonicalized
  vendor count across apex slugs and surface attributions is at least
  two, a `Multi-cloud` row joins the key-facts block above Confidence:
  for example `Multi-cloud: 3 providers observed (AWS, Cloudflare,
  GCP)`. A single-vendor apex stays unannotated to avoid adding a
  vacuous row. Sibling slugs collapse: AWS Route 53 plus AWS CloudFront
  is one AWS vote, not two. Firebase rolls up under GCP because that
  matches how operators think about the Google cloud footprint at the
  rollup level. The per-slug Cloud row and per-subdomain Subdomain row
  continue to carry the full distribution; the rollup is the at-a-glance
  summary, not a replacement.
- **Cloud-vendor canonicalization map.** `_CLOUD_VENDOR_BY_SLUG` in
  `recon_tool/formatter.py` is the single source of truth that maps
  cloud-categorized fingerprint slugs to their vendor identity (AWS,
  Azure, GCP, Cloudflare, Fastly, Akamai, Vercel, Netlify, Oracle Cloud,
  IBM Cloud, Alibaba Cloud, and so on). Two public helpers,
  `canonical_cloud_vendor(slug)` and `count_cloud_vendors(apex_slugs,
  surface_slugs)`, sit on top of it so future panels and JSON paths can
  reuse the same canonicalization without duplicating the table inline.
  Slugs not in the map are not counted as cloud vendors, which is the
  right default for things like Slack or Auth0 (SaaS, not cloud
  infrastructure) and developer-platform slugs like Replit or Glitch.
- **Common-prefix wordlist breadth across four stack tiers.** The
  active-DNS probe in `recon_tool/sources/dns.py` and the CT
  high-signal sort in `recon_tool/sources/cert_providers.py` both gained
  the same eight prefixes covering tiers the prior wordlist ignored:
  data and analytics (`data`, `analytics`), AI and ML (`ai`, `ml`),
  operations and internal tooling (`internal`, `ops`, `tools`), and
  security (`security`). Each prefix maps to a recognised stack tier
  with vendor-product backing (Snowflake under `data`, Vertex AI under
  `ai`, internal portals under `internal`, SIEM consoles under
  `security`). The CT-side additions keep prioritization parity so a CT
  response surfacing `data.contoso.com` sorts to the top of the bounded
  output rather than falling off the cap.
- **`tests/test_formatter_ceiling.py`** (7 tests). Pins the trigger
  heuristic: fires on sparse-services + multi-domain apex; suppressed
  on single-domain apex, dense categorized services, many surface
  attributions, `--full` mode, and empty services. Phrasing tone is
  asserted to be teaching, not tool-blaming.
- **`tests/test_multi_cloud_rollup.py`** (16 tests). Pins both
  canonicalization (AWS family collapses to AWS, Firebase rolls under
  GCP, non-cloud slugs return None) and trigger discipline (fires on
  multi-vendor, suppressed on single-vendor and SaaS-only apex).
- **`tests/test_subdomain_enumeration_breadth.py`** (10 tests). Pins
  the new wordlist entries in both the active-probe tuple and the
  CT-prioritization tuple. A future refactor that compacts either
  cannot silently drop tier coverage without these tests flagging.
- **`tests/test_cloud_vendor_coverage.py`** (4 tests). Coverage-gap
  enforcement: every Cloud-categorized slug in ``_CATEGORY_BY_SLUG``
  must appear in either ``_CLOUD_VENDOR_BY_SLUG`` or
  ``_CLOUD_VENDOR_ROLLUP_EXCLUSIONS`` (a new explicit exclusion set
  for SaaS hosting, prototyping platforms, and long-tail specialty
  vendors). Map and exclusion set are disjoint and both stay
  consistent with the cloud category. The test caught one real
  inconsistency at introduction: ``aws-waf`` was incorrectly in the
  rollup map even though it is Security-categorized, not Cloud;
  removed.
- **`tests/test_formatter_ceiling_boundary.py`** (8 tests). Off-by-one
  cases that the surrounding fixture tests would miss: exact-threshold
  domain_count (3 fires, 2 suppresses), categorized count (4 fires, 5
  suppresses), surface attributions count (4 fires, 5 suppresses), and
  the AND-gate behaviour where density on one half is enough to
  suppress.
- **`tests/test_count_cloud_vendors_properties.py`** (5 Hypothesis
  property tests). Invariants that hold across the full input space:
  order independence on the apex stream, non-cloud-slug additions are
  no-ops, stream union semantics (apex + surface split equals
  concatenated stream), total count equals input length when all
  inputs are in the map, distinct vendor count is bounded above by
  the input slug count.
- **`tests/test_panel_render_snapshots.py`** (12 end-to-end render
  snapshot tests). Two reference TenantInfo fixtures (Contoso
  multi-cloud rich-stack, Northwind sparse-hardened) exercised through
  ``render_tenant_panel`` with structural asserts on which v1.9.9
  surfaces fire on which fixture, the layout invariant that
  Multi-cloud renders above Confidence in the key-facts block, and
  the ``--full``-mode suppression behaviour for the ceiling block.
- **``_CLOUD_VENDOR_ROLLUP_EXCLUSIONS`` in formatter.py**. New
  explicit exclusion set documenting which Cloud-categorized slugs
  intentionally do not appear in the rollup, with three rationale
  categories: SaaS hosting (WP Engine, Kinsta, Acquia, GitHub Pages,
  WordPress VIP), developer / prototyping platforms (Replit, Glitch),
  specialty CDN / DAM / hosting that operators would not list
  alongside AWS/Azure/GCP (Cloudinary, Azion, Section.io, MerlinCDN,
  Edgio, Lumen, Ionos, and others). Forces the rollup decision at PR
  time when a new cloud-categorized slug ships.
- **``category_for_slug`` public accessor in formatter.py**. Wraps
  `_CATEGORY_BY_SLUG` so callers outside the formatter (notably the
  v1.9.9 corpus aggregator) can estimate the panel's categorized
  count without re-running `_categorize_services` or reaching into
  the private lookup.
- **`validation/corpus_aggregator.py`**. Pure-function script
  that consumes a `recon batch --json` results file and emits
  anonymized aggregate statistics on Multi-cloud and ceiling
  firing rates. Reads gitignored private corpus runs; emits
  anonymized output safe to commit. The trigger logic mirrors the
  renderer's by design; the test file pins both implementations
  to the same fixtures so they cannot drift.

### Changed

- **`recon_tool/formatter.py`** gains `_CLOUD_VENDOR_BY_SLUG`,
  `_CLOUD_VENDOR_ROLLUP_EXCLUSIONS`, `canonical_cloud_vendor`, and
  `count_cloud_vendors`, plus the Multi-cloud field and the
  Passive-DNS ceiling block in `render_tenant_panel`. The
  categorized-service count threads through a small local helper
  variable so the ceiling check can reference it outside the services
  branch without `categorized` itself escaping scope.
- **AWS rollup family expanded.** Added `aws-nlb`, `aws-api-gateway`,
  `aws-app-runner`, `aws-global-accelerator` to the AWS family so the
  rollup catches them. Added `cloudflare-pages` to the Cloudflare
  family. Removed `aws-waf` (Security-categorized, not Cloud — the
  coverage-gap test caught this at introduction).
- **Standalone vendor coverage expanded** to include Heroku, VMware
  Cloud, Cloud.gov, Edgio, Lumen, F5 Distributed Cloud — each
  represents a cloud vendor an operator would name alongside AWS or
  Azure when describing a footprint at the rollup level.
- **`recon_tool/sources/dns.py`**'s `_COMMON_SUBDOMAIN_PREFIXES` grew
  from 38 to 46 entries; each new entry carries an inline comment naming
  the stack tier it represents and the vendor-product idiom that
  motivates including it.
- **`recon_tool/sources/cert_providers.py`**'s `HIGH_SIGNAL_PREFIXES`
  grew the same 8 prefixes so CT subdomain prioritization stays in
  parity with the active probe.

### Security

- **MCP fallback launch path closed on Python 3.10.** The
  `build_recon_block()` fallback (used when ``recon`` is not on
  PATH) previously persisted ``python -m recon_tool.server`` with
  ``PYTHONSAFEPATH=1``. On Python 3.10 the env var is a no-op, so a
  malicious workspace containing ``recon_tool/server.py`` could
  shadow the installed package and execute attacker code at module
  import time — before the runtime guard in ``server.py`` could
  fire. The v1.9.3.4 mitigation closed this for ``mcp_doctor``
  (which sets a safe tempdir cwd) but left the persisted
  installer block reliant on PYTHONSAFEPATH on 3.10.

  v1.9.9 closes this fully by switching the persisted form to
  ``python -c "<sys.path-stripping launcher>"``. The launcher runs
  ``sys.path[:] = [p for p in sys.path if p not in ('', '.')]``
  BEFORE any ``recon_tool`` import, removing the cwd-equivalent
  entry at the language level. This works on every supported
  Python version, including 3.10. PYTHONSAFEPATH=1 stays in the
  persisted env as belt-and-suspenders for 3.11+.

  New integration test
  ``test_v199_fallback_launcher_blocks_shadow_on_all_pythons``
  exercises the actual persisted launcher against a malicious
  shadow workspace and asserts the shadow does not execute.
  ``docs/security-audit-resolutions.md`` updated to reflect the
  v1.9.9 closure honestly (the v1.9.3.4 entry now distinguishes
  the doctor-path closure from the install-path partial mitigation
  that v1.9.9 completed).

### Fixed

- **`Data & Analytics` category KeyError in panel renderer.** The
  category was added to ``_CATEGORY_BY_SLUG`` in v1.9.3.9 (with the
  ``looker-studio`` slug) but never to ``_SERVICE_CATEGORIES_ORDER``.
  Any apex with the slug fired triggered ``KeyError`` at
  ``by_cat[cat].append(...)`` in ``_categorize_services`` and
  crashed the panel. Fixed by adding the category to the order
  tuple and adding a defensive bucket-creation guard so future
  category drift cannot crash the renderer (the new category will
  be missing from rendered output until added to the tuple, but
  the panel will not crash). Caught at first run by the new
  catalog-driven Hypothesis test
  ``test_catalog_driven_corpus.py::test_low_domain_count_never_fires_ceiling``.
- **Okta surface description used "strong"** (overclaim per the
  project's humble-tone discipline). Rephrased to "load-bearing"
  (`recon_tool/data/fingerprints/surface.yaml`). Caught at first
  run by the new suite-wide humble-tone enforcement test
  ``test_humble_tone_global.py``.
- **`aws-waf` was wrongly in the Multi-cloud rollup map** even
  though it is Security-categorized in `_CATEGORY_BY_SLUG`.
  Removed from `_CLOUD_VENDOR_BY_SLUG`. Caught by the
  coverage-gap test added during v1.9.9 development.

### Validation

- All 2496 tests pass (2 skipped, 4 deselected). v1.9.9 ships **182
  new tests across 23 new test files plus a corpus-aggregator
  script, a synthetic 19-fixture corpus generator, a render-
  snapshot report, a threshold-sensitivity analysis, an invariant
  audit, an agentic-UX runbook, a coverage-gap audit, and a
  performance baseline doc** covering falsifiable surfaces along
  seven orthogonal axes: trigger behaviour (fixture, boundary,
  property), test quality (mutation resistance with 6 named
  mutations + three-way differential agreement check), integration
  (CLI, cross-version cache, JSON shape), robustness (fuzz,
  adversarial, determinism, performance bounds), corpus validation
  (synthetic corpus + catalog-driven Hypothesis + aggregator),
  tone discipline (suite-wide humble-tone enforcement), and
  documentation (validation memo, test-quality manifesto,
  corpus-run report, threshold sensitivity, invariant audit,
  coverage-gap audit, performance baseline, agentic-UX runbook).

  The **catalog-driven Hypothesis test caught a real pre-existing
  bug**: ``looker-studio`` (added in v1.9.3.9 with category
  ``"Data & Analytics"``) was missing from
  ``_SERVICE_CATEGORIES_ORDER``, causing a ``KeyError`` in the
  panel renderer for any apex with the slug. Fixed by adding the
  missing category to the order tuple and adding a defensive
  bucket-creation guard in ``_categorize_services``. Test invariant
  pinned in ``test_cloud_vendor_coverage.py`` so future drift fails
  at PR time.

  The **suite-wide humble-tone test caught a real catalog
  violation**: the okta surface description used the word "strong"
  (overclaim per the project's discipline). Rephrased to
  "load-bearing".

  See `validation/v1.9.9-detection-gap-ux.md` for the per-file
  rationale and the explicit "what we test and what we honestly do
  not" section. See `validation/invariant_audit.md` for the
  distinct-invariant count (51) vs the test count (182), and the
  remediation plan for each "what we honestly do not test" item.
  Test files:
  1. Fixture behaviour on the ceiling trigger
     (`test_formatter_ceiling.py` — 7 tests).
  2. Fixture behaviour on the multi-cloud rollup, including
     canonicalization (`test_multi_cloud_rollup.py` — 16 tests).
  3. Wordlist extensions in both the active probe and the CT priority
     tuple (`test_subdomain_enumeration_breadth.py` — 10 tests).
  4. Coverage-gap enforcement on the rollup map versus
     `_CATEGORY_BY_SLUG`, with explicit exclusion-set discipline
     (`test_cloud_vendor_coverage.py` — 4 tests). Caught one real
     bug at introduction: `aws-waf` was wrongly in the rollup map.
  5. Off-by-one boundaries on the ceiling trigger's three numeric
     thresholds (`test_formatter_ceiling_boundary.py` — 8 tests).
  6. Hypothesis property invariants on `count_cloud_vendors`
     (`test_count_cloud_vendors_properties.py` — 5 tests).
  7. End-to-end render snapshots across two reference TenantInfo
     fixtures (`test_panel_render_snapshots.py` — 12 tests).
  8. Render-fuzz: arbitrary TenantInfo through
     `render_tenant_panel` must not raise
     (`test_render_fuzz.py` — 3 tests, 500 Hypothesis examples).
  9. v1.9.2 agentic-UX fixture compatibility under the v1.9.9
     panel (`test_agentic_ux_compatibility.py` — 7 tests).
  10. JSON-absence contract: v1.9.9 surfaces are panel-only
      (`test_panel_only_surfaces_json_absence.py` — 6 tests).
  11. Rendered-output sanity: no vendor duplication, no orphan
      punctuation, no overclaim words, bounded line length
      (`test_panel_output_sanity.py` — 7 tests).
  12. Wordlist hygiene: deduplication, lowercase, no whitespace,
      parity between active probe and CT priority tuples
      (`test_wordlist_sanity.py` — 8 tests).
  13. Corpus-aggregator script behaviour, mirroring the renderer's
      trigger logic on serialized TenantInfo dicts
      (`test_corpus_aggregator.py` — 11 tests).
  14. **Targeted mutation resistance** on the v1.9.9 helpers. Five
      named mutations (None-guard drop, unknown-slug leak, double
      count, comparator flip, threshold flip) confirmed caught by
      the existing test suite (`test_mutation_resistance.py` — 9
      tests). Honest framing: this is a hand-rolled pilot, not a
      full ``mutmut`` sweep. The bar is "the most likely mutations
      to slip past careful review are caught"; broader coverage
      remains a post-v2.0 backlog item.
  15. **CLI integration smoke** for the Typer entry point.
      ``--help``, ``--version``, every subcommand's help, the
      installed-entry-point shape via subprocess
      (`test_cli_integration_smoke.py` — 15 tests).
  16. **Render determinism** in-process and across processes with
      distinct ``PYTHONHASHSEED`` values. 30 in-process renders
      byte-identical; subprocess renders with three distinct seeds
      identical to each other (`test_render_determinism.py` —
      5 tests).
  17. **Adversarial-input robustness**: unicode display names
      (CJK, RTL, accented, emoji), control characters and ANSI
      escapes in slugs and subdomains, 1000-char display names,
      200-slug and 200-attribution inputs, punycode IDN subdomains
      (`test_adversarial_render.py` — 13 tests). Threat model:
      data-quality robustness, not security boundary enforcement.
  18. **Cross-version cache compatibility**: synthesized v1.9.8-
      shape cache loads through v1.9.9 reader; new v1.9.9 surfaces
      derive from existing cache fields without re-collection;
      ``_CACHE_VERSION`` constant pinning prevents silent schema
      bumps (`test_cache_cross_version_compatibility.py` — 7 tests).
  19. **Render-time performance bounds**: typical (10 slugs), large
      (100), and stress (1000) inputs render under generous time
      budgets; ratio of large-input time to small-input time is
      sub-quadratic (`test_render_performance.py` — 8 tests; 1
      skip on machines too fast for a stable ratio).
  20. **Expanded mutation library**: 6 named mutations beyond the
      original 3 (stream swap, empty-string-vs-None contract,
      case-sensitivity invariant). All caught by the existing test
      suite (`test_mutation_resistance.py` — 15 tests total).
  21. **Three-way trigger differential agreement**: renderer +
      aggregator + regex-parser must agree on every fixture
      (`test_trigger_differential_agreement.py` — 6 tests).
      Breaks the two-implementation circularity by adding a third
      independent code path.
  22. **Catalog-driven Hypothesis property tests**: inputs drawn
      from the live fingerprint catalog rather than hand-curated
      fixtures (`test_catalog_driven_corpus.py` — 5 tests).
      Caught the `Data & Analytics` KeyError bug at first run.
  23. **Suite-wide humble-tone enforcement**: catalog descriptions
      and formatter top-level constants must avoid overclaim words
      (`test_humble_tone_global.py` — 4 tests). Caught the okta
      "strong" violation at first run.
- **Synthetic 19-fixture corpus** at
  `validation/synthetic_corpus/fixtures/` (M365+Okta, GWS+AWS,
  multi-cloud SaaS, hardened minimal, Azure-native, GCP-native,
  hybrid, healthcare, fintech, public-sector, media, education,
  Heroku legacy, SaaS-only, AWS-family-only). Generator at
  `validation/synthetic_corpus/generator.py` is deterministic and
  publicly-reproducible.
- **Corpus aggregator** at `validation/corpus_aggregator.py` emits
  anonymized firing statistics for both the estimator path and the
  authoritative render-based path. Run output committed at
  `validation/synthetic_corpus/aggregate.json`: 8/19 multi-cloud
  fires (42.1%), 11/19 ceiling fires (57.9%).
- **Render snapshots** of all 21 fixtures (2 v1.9.2 agentic-UX +
  19 synthetic) at `validation/synthetic_corpus/render_snapshots.md`
  give the maintainer the operator-facing panel text for each
  fixture without re-running the renderer.
- **Threshold sensitivity analysis** at
  `validation/threshold_sensitivity.md` sweeps each ceiling-trigger
  threshold across plausible values and reports the firing-rate
  shape. Makes the threshold choice falsifiable instead of intuitive.
- **Distinct-invariant audit** at `validation/invariant_audit.md`
  collapses the 182-test count to 51 distinct invariants and assigns
  each "what we honestly do not test" item a specific milestone
  (v1.9.10 for empirical corpus, cosmic-ray, Bayesian
  re-validation; v1.9.11 for agentic UX; post-v2.0 for memory
  bounds).
- **Coverage-gap audit** at `validation/coverage_gap_audit.md`
  categorizes the 1648 uncovered lines by risk surface (MCP server
  runtime is the largest gap; per-source error paths is the
  second-largest).
- **Performance baseline** at `validation/performance_baseline.md`
  records the actual measured render times (10 slugs: 0.9 ms,
  100 slugs: 1.5 ms, 1000 slugs: 9.2 ms) so the test budgets can
  be assessed against real numbers instead of intuition.
- **Agentic UX runbook** at
  `validation/agentic_ux_v199_runbook.md` documents the
  smallest-cost LLM invocation for the maintainer to validate
  agent-readability of the new surfaces against API-key-controlled
  cost (~$0.016 per focused run on Haiku 4.5).
- **`category_for_slug` public accessor** added to formatter.py
  for the corpus aggregator and threshold sensitivity script;
  removes the `_CATEGORY_BY_SLUG` private-import warning.
- Coverage at 84% total (89% on formatter.py, up from 83% pre-v1.9.9).
- ruff lint and ruff format clean across 205 files.
- pyright on `recon_tool/` and the validation tooling reports 0
  errors, 0 warnings, 0 informations.
- See `validation/v1.9.9-detection-gap-ux.md` for the per-fixture
  trigger behaviour notes and the test-quality manifesto.
- See `validation/v1.9.9-corpus-run.md` for the synthetic-corpus
  validation evidence.

### Scope notes

- The multi-apex CT SAN traversal item in the v1.9.9 roadmap section
  (pull subdomains from all observed apex certs rather than just the
  queried apex's) is deferred to v1.9.9.1. It touches external HTTP
  behaviour and warrants its own validation pass against the v1.9.4
  hardened corpus; bundling it with the three panel surfaces here
  would have obscured which change drove any behavioural shift in CT
  traversal. The wordlist additions ship in v1.9.9 because they are
  internal to the probe loop and the CT sort, with no observable change
  in HTTP request volume.
- The CT-by-org-name search hinted at in the same roadmap section
  carries the same external-HTTP rationale and likewise defers to
  v1.9.9.1 or later.
- No JSON schema changes ship: the rollup vendor list and the ceiling
  phrasing are panel-only. `tests/test_json_schema_file.py` would catch
  drift if a future patch ever surfaces either as a structured JSON
  field; that decision is explicitly out of scope here.

## [1.9.8] - 2026-05-13

**v1.9.8 bridge milestone: catalog metadata richness pass on top of
the v1.9.7 presence floor.** v1.9.7 lifted every detection to a
non-empty description; v1.9.8 lifts every detection to a
substantive, scope-narrowed, externally-referenced description.
After this pass every detection in every category satisfies all
three proxy signals of the new advisory richness audit
(`--report-richness`): description length, scope-narrowing language,
and external `reference` URL. No engine code changes ship in this
release.

This is the v1.9.8 step of the v1.9.4 to v2.0 linear sequence in
`docs/roadmap.md`.

### Headline numbers

| Metric | Before (v1.9.7) | After (v1.9.8) |
|---|---|---|
| Detections with `reference` URL | 76 of 566 (13.4%) | **566 of 566 (100%)** |
| Categories at 100% reference | 0 of 8 | **8 of 8** |
| Detections passing richness audit (all 3 signals) | partial | **566 of 566 (100%)** |
| Non-default weights with inline rationale | 0 of 4 | **4 of 4** |
| Richness audit (advisory) | not present | `--report-richness` flag |

### Added

- **`scripts/check_metadata_coverage.py --report-richness`.** Advisory
  pass that scores each description against three proxy signals:
  long-desc (length floor of 80 chars, proxies signal 1), scope-narrow
  (presence of scope-narrowing tokens, proxies signal 2), and
  `reference` (external URL). Detections failing two or more signals
  are surfaced as a per-category worklist. The audit never gates;
  presence-gate exit code is unchanged. The token set is tuned to the
  catalog's actual writing style: explicit-negation tokens (`not`,
  `does not`) plus the catalog idioms it uses to narrow scope
  (`alternative`, `legacy`, `functionally equivalent`, `typically
  paired`, `same semantics`, `cname through`, `chain through`,
  `subdomain cnames into`, `government cloud`, and similar).
- **Reference URLs on 490 detections** across every fingerprint file.
  Every detection in every category now points at a canonical vendor
  product or docs root (`help.okta.com/en-us/...`,
  `docs.aws.amazon.com/...`, `docs.github.com/en/organizations/...`),
  chosen to be stable enough for a future maintainer to re-verify the
  pattern without chasing rotted deep links.
- **Description-quality lift across the catalog.** Every short
  cname_target index entry in `surface.yaml` (the v1.9.3.x
  catalog-growth artifacts) was expanded into a proper three-signal
  description: what the slug detects, what the chain narrows to, and
  what it does not prove. Comparable lift in `ai.yaml` and
  `verticals.yaml`. Existing block-scalar descriptions in
  `security.yaml`, `email.yaml`, `productivity.yaml`,
  `crm-marketing.yaml`, and `data-analytics.yaml` were left alone
  where they already satisfied the rubric.
- **Inline weight rationale** on all four non-default weights in
  `security.yaml`: `ping-identity` `pingoneemail=` TXT (0.6),
  `cyberark` `*.idaptive.{com,app}` CNAME (0.7), `sonatype`
  `^OSSRH-\d+$` TXT (0.8), `beyond-identity`
  `authenticator.beyondidentity.com` CNAME (0.5). Comment lives above
  the `weight:` key in each detection block.
- **`validation/v1.9.8-metadata-audit.md`** documenting the pass:
  before/after reference coverage, end-state richness numbers per
  category, weight-rationale table, scope and non-goals.

### Changed

- **`CONTRIBUTING.md` "Detection description rubric".** Stale
  "v1.9.7+" pointer on the advisory metadata-richness reference
  updated to "v1.9.8+ advisory" so contributors land on
  `--report-richness`.

### Fixed

- **`recon_tool/http.py`** `asynccontextmanager` deprecation warning
  surfaced by a recent pyright/typeshed update. Annotation switched
  from `AsyncIterator` to `AsyncGenerator` per the typeshed change;
  no runtime behavior difference.
- **`tests/test_mcp_path_isolation.py`** subprocess.run call now
  carries the `# noqa: S603 — argv list, no shell.` annotation
  matching the pattern in `tests/test_metadata_coverage.py` and
  `scripts/release.py`.

### Scope

In scope:
- Full description-quality lift across the catalog.
- Full `reference` URL coverage across the catalog.
- Inline rationale on every non-default weight.
- `--report-richness` advisory mode in
  `scripts/check_metadata_coverage.py`.
- Rubric pointer cleanup in `CONTRIBUTING.md`.

Out of scope (stays out by design):
- Engine changes (`signals.py`, `merger.py`, `absence.py`,
  `fusion.py`) — v1.9.8 is data + tooling only.
- New fingerprints — v1.9.8 does not add or remove detections.

### Quality gate

`ruff check`, `pyright`, `pytest`,
`scripts/validate_fingerprint.py` (414 entries passed),
`scripts/check_metadata_coverage.py` (PASS, every detection in every
category has a non-empty description, and every detection satisfies
all three richness signals), and all pre-commit hooks pass on a clean
tree.

## [1.9.7] - 2026-05-13

**v1.9.7 bridge milestone: metadata-coverage gate flip (presence,
not coverage) plus full catalog backfill.** The v1.9.0 advisory
gate measured description coverage as a percentage with a 70
percent threshold on three "gated" categories (identity, security,
infrastructure). That framing invited gate-gaming: writing
placeholder descriptions to clear a percentage rather than
explaining what each detection claims. v1.9.7 replaces the
percentage with a presence check, gates every category, and
backfills the full 298-detection gap so the gate ships enforcing
on a clean tree.

This is the v1.9.7 step of the v1.9.4 to v2.0 linear sequence in
`docs/roadmap.md`. The deliverable is the gate flip, the backfill,
the per-detection gap reporting, the pre-commit hook, and the
description rubric in CONTRIBUTING.md.

### Headline numbers

| Metric | Before (v1.9.6) | After (v1.9.7) |
|---|---|---|
| Total detections | 566 | 566 |
| Detections with description | 268 (47 percent) | **566 (100 percent)** |
| Gated categories | 3 (identity, security, infrastructure) | **all 8** |
| Gate type | percentage threshold (70 percent) | **presence (every detection)** |
| CI behavior | advisory (`--report-only` in ci.yml) | **enforcing in CI and release.yml** |

Backfill per category:

| Category | Before | After | Added |
|---|---|---|---|
| ai | 100 percent | 100 percent | 0 |
| crm-marketing | 32 percent | 100 percent | 32 |
| data-analytics | 0 percent | 100 percent | 13 |
| email | 46 percent | 100 percent | 20 |
| infrastructure | 56 percent | 100 percent | 146 |
| productivity | 9 percent | 100 percent | 41 |
| security | 31 percent | 100 percent | 44 |
| verticals | 89 percent | 100 percent | 2 |
| **total** | **268** | **566** | **+298** |

### Added

- **`CONTRIBUTING.md` "Detection description rubric (v1.9.7+)"
  section.** Three-part rubric: (a) what the slug detects, (b)
  what it does not detect, (c) common false positives if known.
  Plus tone guidance (humble, no overclaim, no em-dashes) and
  two worked examples (good vs placeholder). Sets the bar for
  new contributions; reviewer judgement is the enforcer.
- **`.pre-commit-config.yaml` metadata-coverage hook.** Fires
  the presence gate locally before push when any
  `recon_tool/data/fingerprints/*.yaml` is touched. Catches
  missing descriptions in the developer loop rather than in CI.
- **Per-detection gap reporting in `scripts/check_metadata_coverage.py`.**
  On failure the script emits the exact slug + detection-rule
  pairs missing a description, grouped by category, so a
  contributor sees "fix these N entries" rather than "your
  category coverage dropped to 87 percent."

### Changed

- **`scripts/check_metadata_coverage.py`: presence gate replaces
  percentage threshold.** Dropped `--threshold` and
  `_DEFAULT_THRESHOLD = 0.70`; dropped the `_GATED_CATEGORIES`
  allowlist. Every category gates; every detection must carry a
  non-empty `description`. Reference and weight coverage remain
  advisory diagnostics, not gating.
- **`.github/workflows/ci.yml`: metadata-coverage step is now
  enforcing.** Removed `--report-only` from the metadata-coverage
  invocation. CI fails the build when any detection is missing a
  description.
- **`.github/workflows/release.yml` runs the metadata-coverage
  gate.** Added to the `test` job, mirroring `ci.yml`. Prevents
  a catalog regression from reaching PyPI just because the
  tests passed.
- **All 298 backfilled descriptions follow the rubric.**
  Vendor-specific text covers what the pattern matches, what
  inference the slug supports, common false positives where
  known, and acquisition / rebrand history where it affects
  reading the slug name (for example, Pardot is now Salesforce
  Marketing Cloud Account Engagement; Auth0 is an Okta property
  since 2021; SignalFx is sold as Splunk Observability Cloud).

### Notable findings from the backfill

- **The "infrastructure" category is the bulk of the catalog.**
  332 of 566 detections (59 percent) live in
  `infrastructure.yaml` and `surface.yaml` (CNAME-target rules
  for the surface-attribution pipeline). The detection patterns
  there map to CDNs, cloud-provider endpoints, hosted-app
  platforms, and DNS providers; descriptions document both the
  vendor and the specific surface the pattern fires on (apex
  delegation, edge proxying, branded-subdomain hosting, regional
  endpoints, and so on).
- **Many detections cover legacy vendor domains.** The catalog
  carries CNAMEs for products whose vendor was acquired and
  rebranded but whose hostnames persist (ExactTarget for
  Salesforce Marketing Cloud, Mandrill for Mailchimp
  Transactional, FireEye for Trellix, Idaptive for CyberArk
  Identity, Wildbit for Postmark, and similar cases). Each
  description notes the rebrand so the reader does not chase a
  vendor name that no longer markets under that brand.
- **Pure deliverability signals are not enforcement signals.**
  Echoing the v1.9.6 `email_security_policy_enforcing` lesson,
  several email-vendor descriptions explicitly note that SPF
  includes authorize outbound sending only and do not imply
  inbound mail handling. The rubric's "what it does not detect"
  framing surfaces this consistently across the catalog.

### Real-company-data discipline

The backfill describes vendor products and the specific evidence
patterns recon matches against. No real-organization names appear
in descriptions. Acquisition and rebrand history is sourced from
publicly available vendor announcements and does not reveal
customer identities.

### Quality bar verification

- [x] Per-category gap report on failure: the script prints
  every slug + detection-rule pair that lacks a description,
  grouped by category, so a contributor sees "fix these N
  entries" not "coverage dropped to 87 percent."
- [x] Pre-commit hook entry added to `.pre-commit-config.yaml`
  scoped to fingerprint YAML changes; the gate fires locally
  before push.
- [x] "What good looks like" rubric in `CONTRIBUTING.md` with
  two worked examples (good vs placeholder).
- [x] Backfill before flip: zero detections missing
  descriptions in any category before the gate flipped from
  advisory to enforcing. The flip is in the same release as
  the backfill, but the backfill is committed before the
  workflow-file edits.
- [x] Reference-presence reporting remains advisory. Reference
  coverage stays low (22.9 percent on infrastructure, lower
  elsewhere); the rubric notes reference URLs are nice to have
  but harder to source defensively, so they do not gate.

### Tests

- Total: 2314 passed, 1 skipped, 4 deselected (unchanged test
  count, the v1.9.7 change is a data and gate edit).
- Coverage: 83.4 percent (above the 80 percent gate, unchanged).
- ruff, pyright, pre-commit (including the new metadata-coverage
  hook), and the fingerprint validator all clean.

### Roadmap

- v1.9.7 bridge milestone **closed**.
- Next in sequence: v1.9.8 (catalog metadata richness pass) and
  v1.9.9 (detection-gap UX surfaces).
- New post-v2.0 backlog item added: machine-readable CLI surface
  inventory for downstream skill and agent authors. See
  `docs/roadmap.md` Backlog "Machine-readable CLI surface
  inventory" for the rationale (improve recon's surface
  inventory; leave agent-behavior layer to skill files).

## [1.9.6] - 2026-05-13

**v1.9.6 bridge milestone — CPT-change discipline (concept, not
parameter).** Ships the discipline that distinguishes "the corpus
disagrees, so the number must be wrong" (corpus-fitting, prohibited)
from "the corpus disagrees, so the topology must be asking the wrong
question" (concept-driven, the right cycle). Bundles the first
canonical application: the v1.9.5 `email_security_policy_enforcing`
"not yet" disposition closes by removing `dkim_present` as an
evidence binding — DKIM publication is a deliverability hygiene
signal, not a policy-enforcement signal.

This is the v1.9.6 step of the v1.9.4 → v2.0 linear sequence in
`docs/roadmap.md`. Deliverables: the discipline in `CONTRIBUTING.md`,
a PR-template prompt that surfaces the discipline at review time,
the audit confirmation that no automated CPT-fitting tooling has
emerged, the `policy_enforcing` redefinition with its concept
comment in the YAML, the stability-update delta report, and the
audit-resolution document closing four external-audit findings.

### Headline verdict change

`email_security_policy_enforcing` v1.9.5 `not yet` → v1.9.6
**stable**. Binary criterion (b1) goes from 119/129 to 119/119;
criterion (b2) eligible set grows by 10 as the dkim-only domains
correctly move to det-silent + sparse. Total stability verdict count:
**8 stable, 1 not yet** (`okta_idp`, unchanged — corpus-limited).

### Added

- **`CONTRIBUTING.md` "CPT-change discipline (v1.9.6+)" section.**
  Worked examples (v1.9.3 surgery on `email_security_strong`; v1.9.6
  surgery on `email_security_policy_enforcing`), anti-pattern catalog
  (4 reviewer rejection examples), decision tree, and the concept-
  comment requirement. Stays terse; the rubric makes future
  contributors pause before number-driven CPT changes.
- **`.github/pull_request_template.md`** — new root-level default PR
  template (the existing `PULL_REQUEST_TEMPLATE/fingerprint.md` is
  preserved for fingerprint-only PRs via the `?template=` URL
  parameter). Carries the CPT-change-discipline non-blocking
  checkbox plus the fingerprint, no-real-company-data, and
  no-Claude-trailer reviewer prompts. The checkbox is the
  conversation starter, not a CI gate — reviewer judgement is the
  enforcement.
- **`validation/v1.9.6-stability-update.md`** — short delta report
  against `v1.9.5-stability.md`, showing the per-metric movement on
  `email_security_policy_enforcing` and confirming all other nodes'
  verdicts unchanged. Includes "what this does not validate" notes.
- **`docs/security-audit-resolutions.md`** — closure record for
  external audit findings. Keyed by *topic* rather than vendor-
  specific ID so the record is portable across audit tools. Four
  initial entries closing (HIGH) MCP doctor/install shadow-load via
  v1.9.3.4, (MEDIUM) A/AAAA CNAME validation leak via v1.9.4,
  (MEDIUM) original CNAME chain walking via v1.9.3.5+v1.9.4
  mitigation, (INFORMATIONAL) Splunk regex-slug example via v1.9.4.
  Each entry cites the closure commit SHA, the pinning test, and a
  file:line receipt against current code. SECURITY.md gets a
  forward pointer.

### Changed — engine

- **`recon_tool/data/bayesian_network.yaml`:
  `email_security_policy_enforcing` evidence list shrinks from 5
  bindings to 4.** Removed `signal: dkim_present` (was
  `likelihood: [0.85, 0.30]`). Concept comment in the YAML cites the
  v1.9.5 stability report finding (10/129 b1 failures, all
  `evidence_used = (signal:dkim_present,)` alone, producing posterior
  ≈ 0.486 from a single weak-LR signal) and explains why the right
  fix is binding removal rather than likelihood retuning:

  > "The corpus-fitting reflex was to lower the likelihood for the
  > absent case from 0.30 to 0.20, lifting the dkim-only posterior
  > to 0.59. That would have improved the criterion number while
  > making the node a worse predictor of what its name says. The
  > right answer was removing the binding — the node's claim is
  > enforcement, and DKIM doesn't speak to enforcement."

  Node description also tightened: "Observable email-authentication
  policy is enforcing (DMARC reject/quarantine + strict SPF +
  optional MTA-STS enforce)." — removed "+ DKIM" since DKIM is no
  longer evidence.

- **`tests/test_node_stability_criteria.py`:
  `email_security_policy_enforcing` binding list mirrored** — the
  parametrized test's directory must stay in sync with the YAML so
  the directory-completeness sanity check passes. Inline comment in
  the test file cross-references the YAML concept comment.

### Notable findings

- **The redefinition improves the layer's honesty, not just the
  criterion number.** The 10 dkim-only domains in the v1.9.5
  corpus genuinely don't have an enforcing posture (DKIM alone,
  no DMARC, no MTA-STS, no strict SPF). The v1.9.5 layer reported
  them with posterior ≈ 0.486 and non-sparse — confidently
  uncertain, in a way that hurts the (b1) criterion. The v1.9.6
  layer reports them sparse=true with no firings — explicitly
  hedged. Both criterion (b1) and the layer's truthfulness
  improve simultaneously.
- **Diagnostic ECE rises slightly (0.128 → 0.154) — this is a
  numerator artifact, not a regression.** Removing 10
  well-classified non-sparse observations from a small eligible
  set raises per-bin variance. Brier improves (0.0346 → 0.0331).
  Both numbers stay comfortably below the 0.20 / 0.15 advisory
  thresholds. The headline verdict change (not yet → stable) is
  driven by the (b1) binary criterion, not by these diagnostics.
- **Audit-finding closure documentation pattern.** The
  `docs/security-audit-resolutions.md` file is keyed by topic
  rather than audit-tool ID so it stays portable. Scanners that
  re-flag a closed finding (because they trace introduction
  commits but not subsequent fix commits) get authoritatively
  answered by the file. Closure precedence is documented in the
  file's process-notes footer.

### Real-company-data discipline

- Reuses the v1.9.4 / v1.9.5 corpus; no new corpus runs needed for
  the engine-isolated re-inference. The re-inference uses saved
  evidence (slugs + signals) from the gitignored NDJSON, so the
  v1.9.6 stability comparison is fully isolated from upstream DNS
  drift.
- `docs/security-audit-resolutions.md` uses generic placeholder
  hostnames (`internal.example`, `attacker.example`) — no real
  internal infrastructure of any organization, consistent with the
  project's no-real-company-data policy.

### Quality bar verification

- [x] **Worked example in CONTRIBUTING.md** — v1.9.3 surgery is the
  historical case; v1.9.6 surgery on `policy_enforcing` is the
  live case shipping in this release.
- [x] **PR-template addition** — non-blocking CPT-change-discipline
  checkbox added to a new root-level
  `.github/pull_request_template.md`.
- [x] **Anti-pattern catalog** — four worked reviewer rejections in
  `CONTRIBUTING.md` (corpus-rate tuning without concept comment,
  ECE-driven likelihood adjustment, priors-override
  miscalibration patch, automated CPT fitting).
- [x] **No automated CPT-fitting tooling** — confirmed by grep for
  `def (learn_cpt|fit_cpt|auto_tune|optimize_cpt|empirical_bayes|
  fit_likelihood|tune_likelihood)` across the repo (zero matches)
  and for write-paths against `bayesian_network.yaml` (zero
  matches). The audit IS the discipline, not a CI test.

### Tests

- Total: 2314 passed, 1 skipped, 4 deselected (unchanged test count
  — the v1.9.6 fix is a data-file change; the criterion-(a) test's
  binding directory updates without adding new tests).
- Coverage: 83.43% (≥ 80% gate, unchanged).
- ruff + pyright clean on `recon_tool/` + `tests/` + `validation/`.
- pre-commit (ruff, ruff-format, pyright, actionlint) clean.
- `validate_fingerprint.py` 414/414.

### Roadmap

- v1.9.6 bridge milestone **closed**.
- Next in sequence: v1.9.7 (metadata-coverage gate flip — replace
  the percentage threshold with a binary "every detection in
  identity/security/infrastructure has a non-empty description"
  presence check; flip from advisory to enforcing once backfill
  reaches zero).

## [1.9.5] - 2026-05-13

**v1.9.5 bridge milestone — per-node stability dispositions for the
v1.9 Bayesian layer.** Decides, does not ship, per-node stability
criteria for the 9-node v1.9.3+ topology. The atomic EXPERIMENTAL
label that covered the whole `--fusion` layer through v1.9.4 was
over-broad: `m365_tenant` and `email_security_policy_enforcing`
should not share a label. v1.9.5 produces an explicit per-node
verdict against three behavioral criteria; v2.0 ships with that
disposition table baked into the network as committed, without a
`stability` schema field. The field itself enters the schema the
first time a post-v2.0 patch introduces a node that does not
immediately qualify as `stable`.

This is the v1.9.5 step of the v1.9.4 → v2.0 linear sequence in
`docs/roadmap.md`. The deliverable is the verdict report, the
parametrized regression test, and the disposition decisions — no
engine changes, no schema changes, one new validation script and
one new test file.

### Headline verdict

| Verdict | Count | Nodes |
|---|---|---|
| **stable** | 7 | `m365_tenant`, `google_workspace_tenant`, `federated_identity`, `email_gateway_present`, `email_security_modern_provider`, `cdn_fronting`, `aws_hosting` |
| **not yet** | 2 | `okta_idp` (criterion (c) — only 7 firings on the 141-domain combined corpus, threshold 10), `email_security_policy_enforcing` (criterion (b1) — 10 of 129 det-positive-HIGH non-sparse observations have posterior ≤ 0.5, all driven by `signal:dkim_present` alone) |

Both `not yet` nodes carry explicit dispositions in
`validation/v1.9.5-stability.md`. Neither disposition is *Split*
or *Remove*; both stay in the network as v2.0 ships.

### Added

- **`validation/v1.9.5-stability.md`** — full per-node verdict
  report: methodology, per-node table joining the (a) test result
  with the (b1)(b2)(c) analyzer outputs, prose interpretation for
  each `stable` cluster, and explicit dispositions for the two
  `not yet` nodes (`okta_idp`: keep, expand corpus;
  `email_security_policy_enforcing`: redefine in v1.9.6 with a
  CPT-change-discipline concept comment, choosing among raising
  the prior, widening the sparse threshold, or tightening the
  weak-likelihood signals). Anonymized aggregates only; no
  per-domain detail.
- **`validation/compute_node_stability.py`** — analyzer for
  criterion (b) and (c). Reads the v1.9.4 hardened + soft NDJSON,
  computes per-node firing count, (b1) ratio (det-positive-HIGH
  non-sparse → posterior > 0.5), (b2) ratio (det-silent → sparse),
  Brier score, log-score, and 10-bin ECE. Filters slug bindings by
  deterministic high-confidence threshold (≥ 0.70); signal
  bindings are binary. Pure-propagation nodes have criterion (c)
  marked `n/a`. Output is publicly-reproducible from the corpus
  NDJSON.
- **`tests/test_node_stability_criteria.py`** — parametrized
  regression test for criterion (a) (evidence-response
  correctness). 20 assertions covering all 9 nodes:
  bound-evidence sensitivity (any evidence binding raises the
  node's posterior by ≥ 0.01 from baseline) and unrelated-evidence
  inertia (a d-separated binding leaves the posterior at baseline
  within 1e-9). Pure-propagation nodes
  (`email_security_modern_provider`) get the bound-evidence test
  via each parent's evidence — the CPT must propagate. Plus two
  sanity tests pinning root-baseline = prior and directory
  completeness against the shipped network. The test failing is
  a regression signal that future patches must satisfy before
  reaching a release tag.

### Notable findings

- **`email_security_policy_enforcing` (b1) failure is exactly
  one pattern, 10 times.** Every one of the 10 failing
  observations has `evidence_used = ('signal:dkim_present',)`
  and nothing else. With prior 0.25 and likelihood [0.85, 0.30],
  the resulting posterior is ≈ 0.486 — just below the 0.5
  threshold. The n_eff threshold for sparse is satisfied by the
  single binding, so the layer doesn't hedge either. This is the
  exact calibration gap v1.9.6's CPT-change discipline exists to
  address: the disagreement is the *signal*, not the fix; the
  right question is which conceptual claim
  `policy_enforcing` is making (target population for prior,
  evidence requirement for non-sparse, or weak-likelihood
  meaning).
- **`okta_idp` firing count is corpus-limited, not engine-limited.**
  All other criteria pass cleanly (b1=7/7, b2=134/134, Brier
  0.022, ECE 0.144). Okta's public DNS fingerprint is thin; many
  Okta-using orgs don't surface the `okta` slug. The disposition
  is to keep the node and expand the validation corpus, not
  change the engine.
- **Pure-propagation node criterion-(c) handling.**
  `email_security_modern_provider` has no direct evidence
  bindings by design — provider presence is captured entirely
  through CPT propagation from `m365_tenant`,
  `google_workspace_tenant`, and `email_gateway_present`. The
  analyzer marks (c) `n/a` for this node and gates stability on
  (a) and (b) only. The (a) test exercises propagation from each
  of the three parents; all three propagate correctly.
- **Diagnostic calibration metrics are uniformly within
  threshold.** Every node's ECE is ≤ 0.144 (threshold 0.20) and
  Brier is ≤ 0.0346 (threshold 0.15). The criterion-(b) failure
  for `policy_enforcing` is a binary-check failure, not a
  calibration-error failure; the layer is well-calibrated overall
  but fails the strict "det-positive HIGH ⇒ posterior > 0.5" gate
  on the dkim-only pattern.

### Real-company-data discipline

The 141-domain corpus reuses v1.9.4's stratified samples (50
hardened-adversarial across five postures + 91 soft v1.9.0
calibration domains). Per the project's no-real-company-data
policy:

- Corpus files (`v1.9.4-hardened.txt`, `v1.9.0-soft.txt`) and
  NDJSON results are gitignored.
- `validation/v1.9.5-stability.md` carries only per-node
  aggregates — no per-organization detail.
- The analyzer (`validation/compute_node_stability.py`)
  anonymizes by design; no domain names print to stdout.
- The criterion-(a) test uses no corpus data — it operates on
  synthetic inputs against the shipped network.

### Quality bar verification

- [x] Per-node verdict table in `validation/v1.9.5-stability.md`
  (one row per node, three columns plus diagnostics; pass requires
  all three).
- [x] Numeric backing for criterion (b): per-node Brier score,
  log-score, ECE on the v1.9.4 corpus, with ECE ≤ 0.20 and Brier
  ≤ 0.15 thresholds documented (advisory; not gating).
- [x] Independent-firing threshold (c) explicit: N ≥ 10 from
  roadmap §v1.9.5; per-node firing count from the v1.9.4 corpus,
  not a self-report.
- [x] Criterion-(a) test in code as parametrized pytest test —
  20 assertions covering both directions (bound-evidence raises,
  unrelated-evidence inert) across all 9 nodes plus 2 sanity
  tests.
- [x] `not yet` verdicts route to specific dispositions before
  v2.0: `okta_idp` → keep + corpus expansion; `policy_enforcing`
  → redefine in v1.9.6 with a CPT-change-discipline concept
  comment.
- [x] No fast-tracking on numbers alone: `okta_idp` has excellent
  (b) numbers but fails (c) and remains `not yet`. The threshold
  is *all three*.

### Tests

- Total: 2314 passed, 1 skipped, 4 deselected (v1.9.4 → v1.9.5:
  +20 tests from the new `test_node_stability_criteria.py`).
- Coverage: 83.43% (≥ 80% gate, unchanged).
- ruff + pyright clean on `recon_tool/` + `tests/`.
- pre-commit (ruff, ruff-format, pyright, actionlint) clean.
- `validate_fingerprint.py` 414/414.

### Roadmap

- v1.9.5 bridge milestone **closed**.
- Next in sequence: v1.9.6 (CPT-change discipline) — the
  `email_security_policy_enforcing` disposition routes directly
  into v1.9.6's milestone scope: pick one of the three candidate
  changes (raise prior / widen sparse threshold / tighten weak
  likelihoods), document the concept in
  `bayesian_network.yaml`, and re-run this stability report to
  confirm (b1) reaches 129/129.

## [1.9.4] - 2026-05-12

**v1.9.4 bridge milestone — hardened-adversarial behavior validation.**
Validates the **design property** behind the v1.9 asymmetric-
likelihood Bayesian layer (`docs/correlation.md` §4.8.3): on
minimal-DNS / wildcard-cert / heavily-fronted apexes, the layer
must hedge — flagging `sparse=true`, reporting wide credible
intervals, and refusing to assert high-confidence posteriors on
evidence-binding-silent nodes. The corpus stratifies across five
hardening postures (heavy edge-proxied, privacy-focused, major
financial, defense / national-security, major government).

This is the v1.9.4 step of the v1.9.4 → v2.0 linear sequence in
`docs/roadmap.md`. The deliverable is the validation report and
the failure-mode catalog in `correlation.md` — no engine or
schema changes.

### Headline result

| Metric | Result |
|---|---|
| Spot-check agreement on high-confidence posteriors | **100%** (157/157 non-sparse) |
| Overall sparse-flag rate (hardened) | **64.0%** (288/450 observations) |
| Multi-signal correlation depth (hardened) | 92.0% (46/50 domains have ≥ 2 firings) |
| Cross-source conflicts | 0 / 50 |
| Soft-corpus regression check | -17 high-confidence posteriors v1.9.0 → v1.9.3+ topology, fully accounted for by the `email_security_strong` split |

The asymmetric-likelihood design property holds. The layer
hedges on hardened targets without over-claiming.

### Added

- **`validation/v1.9.4-calibration.md`** — full calibration
  report: per-node sparse-rate trend (v1.9.0 → v1.9.3+ →
  v1.9.4-hardened), high-confidence survival ratios (soft →
  hardened), per-category breakdown across five hardening postures,
  soft-corpus regression tripwire, defensive value interpretation,
  reproducibility instructions. Anonymized aggregates only; no
  per-domain detail.
- **`validation/analyze_v19_4_hardened.py`** — analyzer for the
  trend, survival-ratio, and per-category aggregates from the
  hardened + soft-current + soft-original NDJSON runs. Output is
  publicly-reproducible (no proprietary data).
- **`docs/correlation.md` §4.8.10 — Failure-mode catalog:
  hardening pattern fingerprints.** Documents the distinctive
  sparse-rate fingerprint each hardening pattern produces at the
  Bayesian layer, with per-pattern defensive read. Patterns
  (edge-proxied, privacy-focused, financial, defense, government)
  carry no per-organization detail. Cross-references the v1.9.4
  calibration report's data.
- **Family-of-companies / portfolio rollup workflow in
  `AGENTS.md` and `agents/claude-code/skills/recon/SKILL.md`.**
  Agent guidance for synthesizing a unified report across an
  operator-supplied set of related apexes (parent + subsidiaries,
  M&A brand portfolio, holding-company structure). The operator
  owns the relationship — recon never infers ownership. Five
  rollup axes: identity stack consistency, email gateway
  consistency, cloud footprint overlap, posture divergence
  (the highest-signal output — outlier siblings are the
  actionable finding), and per-brand notable findings.
  Lightweight agent-side precursor to the heavier
  `recon batch --self-audit` Python rollup in
  `docs/roadmap.md` backlog; ships first because validating
  the report shape on real workflows is cheaper at the skill
  layer than in committed schema.

### Notable findings

- **`email_gateway_present` high-confidence survival ratio = 0.57**
  (soft → hardened). The cleanest demonstration of the asymmetric-
  likelihood design property: hardened orgs do not surface
  Proofpoint / Mimecast / Barracuda MX records publicly, and the
  Bayesian layer correctly retreats rather than over-claiming.
- **`cdn_fronting` high-confidence survival = 0.84** with 60%
  hardened high-conf: CDN-fronting is part of the hardening
  posture, not hidden by it. The layer correctly fires on the
  visible front while reporting everything behind it as sparse.
- **`email_security_policy_enforcing` survival = 0.98**: DMARC
  policy is a public TXT record that defenders publish regardless
  of other hardening. Fires routinely; no posture hides this.
- **Two hardening categories (financial, government) produce an
  identical signature** from the Bayesian layer's perspective —
  "M365 + CDN-fronted + strong DMARC, everything else sparse" —
  even though their internal stacks differ. The layer cannot
  distinguish posture from posture when both apply the same
  public-DNS hygiene.

### Notes on no-regression

The v1.9.0 91-domain soft corpus was re-run on the current
(v1.9.3+) topology and compared against the original v1.9.0
results. All non-`email_security_strong` nodes have sparse rates
within 1-2 percentage points across both runs (within sampling
noise). The 17-posterior reduction in high-confidence count is
fully accounted for by the v1.9.3 `email_security_strong` split:
the original node (78 high-conf at 52.6% deterministic agreement,
the calibration weak spot v1.9.3 fixed) became `modern_provider`
(0 high-conf, always sparse — by design) + `policy_enforcing`
(62 high-conf at 100% agreement). No node had its calibration
*degraded* by the topology surgery.

### Real-company-data discipline

The hardened-adversarial corpus uses real organization apexes
sampled across five categories of public-DNS hardening posture.
Per the project's no-real-company-data policy:

- The corpus file (`validation/corpus-private/v1.9.4-hardened.txt`)
  is gitignored. Real apex names never appear in committed files.
- The NDJSON results file
  (`validation/corpus-private/v1.9.4-hardened/results.ndjson`) is
  gitignored.
- The calibration report (`validation/v1.9.4-calibration.md`) and
  failure-mode catalog (`docs/correlation.md` §4.8.10) carry only
  category-level aggregates: per-pattern sparse rates, per-pattern
  defensive reads. No per-organization detail.
- The analyzer script
  (`validation/analyze_v19_4_hardened.py`) anonymizes by design;
  no domain names print to stdout.

### Quality bar verification

- [x] Hardened corpus has explicit inclusion criteria documented at
  the top of the corpus file (5 criteria, qualify on ≥ 3).
- [x] Full v1.9.0 91-domain corpus re-run against the v1.9.3 topology
  alongside the hardened subset.
- [x] Per-hardening-pattern result rows in the failure-mode catalog
  (5 categories, each with per-node sparse rate + defensive read).
- [x] Survival rate quantified per node (high-conf% hardened /
  high-conf% soft).
- [x] No regression on the soft corpus (sparse rates within
  sampling noise on every node that exists in both topologies).
- [x] Failure-mode catalog cross-referenced to defensive guidance
  per category.
- [x] Reproducibility section in `validation/v1.9.4-calibration.md`
  documents the corpus-build methodology and the analyzer invocation.

### Tests

- 2294 passed, 1 skipped, 4 deselected (the dns.py walker security
  fix and SIEM regex-slug fix added new pinning tests; net +5
  versus v1.9.3.10).
- Coverage 83.43% (≥ 80% gate, unchanged).
- ruff + pyright clean on `recon_tool/` + `tests/`.
- Local `validate_fingerprint.py` passes 414/414.
- Local pytest passes including the v1.9.3.10 panel tests against
  the new corpus data.
- **Property-test strategy tightened in
  `tests/test_exposure.py`.** The Hypothesis strategy for
  `EvidenceRecord.raw_value` previously used an over-permissive
  alphabet (Unicode `L|N|P` categories), allowing draws like the
  literal English word ``"should"`` — which is in
  `EXPOSURE_DISCOURAGED_COPY_TERMS`. The Property-8 neutral-copy
  test then walked every string field of the exposure assessment,
  including the *echoed* evidence value, and the natural-English
  token spuriously failed a check that exists to validate
  *recon-authored* prose. Strategy now uses a DNS-realistic
  alphabet (alphanumerics + ``. - _ = ; : / @``) and filters out
  any draw containing a discouraged-copy term. The fix narrows the
  strategy toward realistic DNS record content; genuine coverage of
  the discouraged-term gate is unaffected because the test's true
  surface — recon-authored prose — was never the source of the
  failure.

### Security fixes (bundled with the v1.9.4 validation milestone)

The hardened-adversarial validation surfaced two audit findings
already in flight. Bundling the fixes with v1.9.4 keeps the
security work attached to the validation that motivated it.

#### CNAME chain walker: A/AAAA internal-DNS leak (audit finding, MEDIUM)

The v1.9.3.5 fix added a resolved-address private-IP check
(`_hop_resolves_publicly`) called by `_resolve_cname_chain` after
the suffix denylist. A subsequent security audit established that
this call sequence creates an internal-DNS oracle: invoking A/AAAA
on an attacker-influenced target causes the recursive resolver to
chase deeper CNAMEs *while answering the address query*,
potentially querying private/internal names *before* the explicit
walker has applied its suffix denylist to those deeper hops. That
is the original CNAME-chain-leakage vulnerability the chain walker
was supposed to prevent.

**Fix:** removed the inline A/AAAA call from
`_resolve_cname_chain`. The walker now uses **suffix-only**
defense — every hop's name is validated against the private-suffix
denylist, but no A/AAAA queries are issued during the walk. CNAME
queries do not cause recursive resolvers to chase further records,
making them the safe primitive for attacker-influenced names.

**Cost:** the split-horizon protection that v1.9.3.5 added (where a
public-suffix name resolves to private IPs via split-horizon DNS)
is no longer in place. The suffix denylist alone is the primary
defense. A future patch may add a terminus-only A/AAAA check
(resolve A/AAAA only after the entire chain has been suffix-
validated, and only on the last hop) if the split-horizon attack
pattern proves common enough to warrant the bounded leak risk.
v1.9.4 errs on the side of zero internal-DNS leakage.

**Tests:** `tests/test_cname_chain_validation.py::TestResolveCnameChainBlocksPrivateTargets::test_walker_does_not_resolve_a_aaaa_during_walk`
pins the v1.9.4 security invariant by tracking every DNS query
the walker issues and asserting only `CNAME` queries fire — never
`A` or `AAAA`. Future regression that re-introduces inline A/AAAA
fails this test before it can reach a release tag. The
`_hop_resolves_publicly` helper is preserved for callers who already
know the name is trusted (no current callers); the function-level
docstring documents the constraint.

#### Splunk SIEM example: unescaped regex slugs (audit finding, INFORMATIONAL)

The v1.9.3.8 shadow-IT alert example used
`match(current_slugs, mvjoin(baseline_slugs, "|"))`, which treats
every baseline slug value as a regex alternation. A baseline slug
containing regex metacharacters such as `.*` would match any
current slug and silently suppress the shadow-IT alert.

**Fix:** switched to `mvfilter(NOT in(current_slugs, baseline_slugs))`
in both `examples/siem/splunk/savedsearches.conf` and the README's
copy-pasteable SPL snippet. `in()` performs literal set-membership;
slug values are never interpreted as regex.

**Tests:** `tests/test_siem_examples.py::TestSplunkSearchSafety`
pins the safe pattern (3 tests covering the conf, the README, and
absence-of-unsafe-pattern in executable SPL). Future regression
that reverts to the unsafe form fails this test.

#### MCP doctor/install path isolation (audit finding, HIGH — already fixed)

The audit also flagged the v1.9.2.1 MCP doctor/install code path
that called `python -m recon_tool.server` with inherited cwd/env,
allowing a workspace-shadow attack. **This finding was already
closed in v1.9.3.4** (see v1.9.3.4 CHANGELOG entry): `mcp_doctor.py`
spawns the subprocess with an empty `tempfile.TemporaryDirectory`
cwd + `PYTHONSAFEPATH=1` env; `mcp_install.py` persists
`PYTHONSAFEPATH=1` in the fallback launch block + warns operators
when the fallback is used; `recon_tool/server.py` carries a
runtime guard that refuses cwd-shadow loads. Audit replays the
original finding against pre-v1.9.3.4 code; no further action
required.

### Housekeeping (bundled with v1.9.4)

Pre-commit's `ruff` + `ruff-format` surfaced drift unrelated to
the validation milestone but accumulated since the project's last
broad format pass. Bundled here so the v1.9.4 commit lands on a
clean tree rather than carrying the drift forward into v1.9.5.

- **`.pre-commit-config.yaml` ruff hook args fixed.** The hook
  was configured with `args: [check, --fix]`, but
  `astral-sh/ruff-pre-commit@v0.11.6` already invokes
  `ruff check` from the hook entry. The duplicate `check`
  was parsed as a filename, producing
  `E902 The system cannot find the file specified` on every
  run. Reduced args to `[--fix]`.
- **64 files reformatted by `ruff-format`** — line-ending
  normalization (Windows working-copy LF/CRLF drift) plus minor
  whitespace cleanups. No behavioral changes; the diffs are
  whitespace-only.
- **12 `UP038` / `S603` lint fixes** applied across
  `recon_tool/bayesian.py`, `recon_tool/cache.py`,
  `recon_tool/sources/cert_providers.py`,
  `scripts/check_metadata_coverage.py`, and five test files
  (`test_explain_integration.py`, `test_exposure.py`,
  `test_json_schema_contract.py`, `test_mcp_path_isolation.py`,
  `test_server_resources.py`). `isinstance(x, (A, B))` is rewritten
  to `isinstance(x, A | B)` per `UP038` (semantically equivalent on
  Python 3.10+). The single `S603` site in
  `test_mcp_path_isolation.py` — a deliberate subprocess invocation
  that *is* the test's subject — gets a targeted
  `# noqa: S603` with a justification comment rather than a code
  change, because rewriting away the subprocess call would defeat
  the test.

These fixes are why pre-commit had been failing locally on commit;
CI's narrower gate (`ruff check recon_tool/`, no `ruff-format`)
was masking the drift. v1.9.4 is the first commit on the cleaned-
up tree.

### Roadmap

- v1.9.4 bridge milestone **closed**.
- Next in sequence: v1.9.5 (per-node stability dispositions —
  takes the per-node firing counts from this run + the soft-corpus
  re-run as raw inputs).

## [1.9.3.10] - 2026-05-11

**Make subdomain-level surface intelligence visible by default.**
The default panel previously had two surfaces hidden behind `--full`
/ `--domains`: the chain walker's unclassified CNAME termini (chains
we walked but the catalog couldn't classify) and the per-provider
subdomain count (multi-cloud distribution across the apex's surface).
Both addressed real operator-facing detection-gap concerns surfaced
during empirical testing.

The implicit message of the prior panel was "they only use the
services we listed." That's wrong. The correct implicit message is
"they use AT LEAST the services we listed, plus N unclassified
surfaces we walked but couldn't name, plus their subdomains are
distributed across these specific providers in these specific
counts."

### Added

- **Default-panel "Unclassified surface" section.** When the chain
  walker reaches CNAME termini the catalog couldn't classify, the
  default panel now renders a one-line count plus up to two
  representative `subdomain → terminus` examples, with a discovery
  hint pointing at `recon discover <domain>` for triage. Renders only
  when `unclassified_cname_chains` is non-empty; absent otherwise.
  Coexists with the existing `--full`-mode unclassified-chain
  surface — the new section is gated by `not show_domains` so the
  two paths stay mutually exclusive.
- **Per-provider counts in the Subdomain line.** Previously listed
  surface-attributed services as a flat name list (`AWS CloudFront,
  Fastly, Stripe`); now shows counts (`Stripe (18), Fastly (12), AWS
  CloudFront (10)`) sorted by count descending. Dropped the apex-
  evidence filter that hid the multi-cloud picture on tenants whose
  apex and subdomains share a provider — the Subdomain line answers
  a different question from the Cloud line (provider distribution
  across the surface vs apex provider), so the duplication is
  intentional surfacing, not noise.
- **`tests/test_unclassified_surface_panel.py`** — 11 tests pinning
  the new section: singular/plural noun handling, discovery-hint
  presence, example count cap, terminus is chain's last hop, absence
  when field empty, `--domains` mode mutual exclusion, isolation from
  related-domains rendering.

### Changed — documentation

- **`docs/roadmap.md` substantially compressed.** Shipped milestones
  (v1.7.0, v1.8.0, v1.9.0, v1.9.2, v1.9.3) collapsed from full prose
  to one-line shipped stubs that point at the CHANGELOG for detail.
  v1.9.2 and v1.9.3 retain expandable `<details>` blocks for readers
  who want the historical rationale inline. `Current Fingerprint
  Library Assessment` rewritten to reflect v1.9.3.9 totals
  (414 entries, 343 unique slugs) and the empirical finding that the
  catalog is comprehensive for top-tier enterprise vendors. Detection-
  gap honesty paragraph added: passive DNS architecturally cannot see
  server-side API consumption.
- **`docs/roadmap.md` Backlog expanded** with detection-gap items
  surfaced during empirical validation:
  - Passive-DNS ceiling phrasing in the panel (Category-1 framing fix
    so absence-of-finding doesn't read as evidence of absence).
  - Subdomain enumeration breadth (CT SAN-set traversal beyond the
    queried apex, longer common-prefix wordlist, CT-by-org-name).
  - Stratified-corpus validation as standing practice (per-cloud
    10-domain reference sets to surface bias by design).
  - Cloud-provider rollup at apex level (top-of-panel multi-cloud
    indicator when ≥2 cloud-categorized providers across the surface).
  Each is backlog rather than committed because the trigger heuristic
  / wordlist / reference-set curation needs explicit design before
  shipping.

### Empirical validation (documented for the record)

Validated against a stratified sample of 6 known-rich-stack public
companies (gitignored private corpus). Highlight: zero unclassified
CNAME chain termini across the sample on top-tier vendors. The
catalog is comprehensive for known enterprise stacks; residual gaps
are architectural (Category-1 server-side API consumption) rather
than catalog. This finding shifts the v2.0 priority from "add more
fingerprints" to "make the architectural limit visible to operators".

### Tests

- 2289 passed, 1 skipped (+11 unclassified-surface-panel tests, was
  2278 in v1.9.3.9).
- Coverage 83.43% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

## [1.9.3.9] - 2026-05-11

**Catalog growth: cloud-vendor coverage gap fill (29 new
fingerprints, vendor-doc-sourced).** Closes a systematic coverage
blindspot surfaced during operator testing: a Solidifi/realmatters
lookup showed solid M365 + Cloudflare + Mailchimp + Atlassian
detection but missed several known GCP-customer service categories.
Diagnosis: the historical corpus-observed catalog-growth path
(scan a private corpus, fingerprint unclassified CNAME patterns)
has a built-in bias toward the segments our corpus already
represents — heavy GCP, Azure non-O365, Oracle Cloud, IBM Cloud,
Alibaba, the SaaS-PaaS galaxy, and SSE/SASE vendors get
systematically under-classified even when the chain walker
follows CNAMEs to the right terminus.

### Added — vendor-doc-sourced fingerprints in `surface.yaml`

Each entry cites the canonical vendor documentation URL in its
`reference` field. The methodology (vendor-doc-sourced as a
complement to corpus-observed) is documented in `CONTRIBUTING.md`
as standing practice for future catalog growth.

**Google Cloud Platform (5 slugs, 6 detections):**
- `firebase-hosting` — `firebaseapp.com`, `web.app`
- `gcp-cloud-functions` — `cloudfunctions.net`
- `firebase-realtime` — `firebaseio.com`
- `looker-studio` — `lookerstudio.google.com`, `looker.com`
- `gcp-storage` — `c.storage.googleapis.com`

**AWS (3 slugs, 3 detections):**
- `aws-amplify` — `amplifyapp.com`
- `aws-cognito` — `amazoncognito.com`
- `aws-waf` — `awswaf.com`

**Azure non-O365 (5 slugs, 6 detections):**
- `azure-blob` — `blob.core.windows.net`, `web.core.windows.net`
- `azure-static-web-apps` — `azurestaticapps.net`
- `azure-container-apps` — `azurecontainerapps.io`
- `azure-api-management` — `azure-api.net`
- `azure-appservice` extended with `azurewebsites.net`

**Oracle Cloud (2 slugs, 2 detections):**
- `oracle-cloud` — `oraclecloud.com`
- `oracle-fusion` — `fa.oraclecloud.com`

**IBM Cloud (1 slug, 2 detections):**
- `ibm-cloud` — `appdomain.cloud`, `bluemix.net`

**Alibaba Cloud (3 slugs, 4 detections):**
- `alibaba-api` — `alicloudapi.com`
- `alibaba-cdn` — `alikunlun.com`, `cdngslb.com`
- `alibaba-cloud` — `aliyuncs.com`

**Additional PaaS (3 slugs, 4 detections):**
- `railway` extended with `up.railway.app`
- `replit` — `replit.app`, `repl.co`
- `glitch` — `glitch.me`

**SSE / SASE / CASB (4 slugs, 6 detections):**
- `zscaler` extended with `zscaler.net`, `zscalerthree.net`,
  `zscalertwo.net`
- `netskope` extended with `netskope.com`, `goskope.com`
- `cato-networks` — `cato-networks.com`
- `prisma-access` — `prismaaccess.com`

**Identity (3 slugs, 3 detections):**
- `onelogin` extended with `onelogin.com`
- `jumpcloud` — `jumpcloud.com`
- `duo` extended with `duosecurity.com`

### Changed

- **`recon_tool/formatter.py`** — `_CATEGORY_BY_SLUG` updated with
  the 22 new slugs that didn't already have a category mapping
  from prior fingerprints (Cloud / Security / Identity / Business
  Apps / Data & Analytics buckets).
- **`CONTRIBUTING.md`** — adds a "Vendor-doc-sourced `cname_target`
  rules" subsection codifying the methodology: every new rule
  cites a vendor doc URL in `reference`; corpus-observed and
  vendor-doc-sourced are both encouraged paths; rules without a
  `reference` will be flagged once the v1.9.7 metadata-richness
  gate is enforcing.

### Catalog totals

- 414 fingerprint entries validated (was 386 in v1.9.3.8).
- 343 unique slugs.
- All slugs map to a defender-visible category.
- 0 cross-file slug-name collisions.

### Notes on residual coverage

This patch closes the biggest visible cloud-vendor gaps but is not
exhaustive. Real-world coverage still depends on the operator
running recon against the right subdomains — a tenant that uses
Firebase Hosting only on `app.example.com` requires that subdomain
to be in scope of the lookup (CT-log enumeration or known-prefix
probing) before the new fingerprint can fire. The catalog now
*can* classify; surfacing requires the chain walker to reach the
right host.

Verticals or vendors still likely under-represented:
SAP / Oracle SaaS apps beyond Fusion, smaller PaaS (Cyclic, Fl0,
Deta), edge/CDN providers outside the top tier (Fastly variants,
BunnyCDN extras), regional clouds (Yandex, OVH, Hetzner, Kakao),
and the long tail of SSE/SASE vendors (iboss, Versa, Aryaka).
Future catalog-growth passes should target these per the
methodology now documented in CONTRIBUTING.md.

### Tests

- 2278 passed, 1 skipped (same headline as v1.9.3.8 — no new tests
  added; the existing slug-uniqueness and metadata-coverage tests
  exercise the additions).
- Coverage 83.32% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.
- Local `validate_fingerprint.py recon_tool/data/fingerprints/`
  passes (414/414 entries; same gate CI runs).

## [1.9.3.8] - 2026-05-11

**Track B quality work — downstream SIEM consumption examples.**
Ships the v2.0 pre-condition for "downstream consumption examples
(at least two SIEMs)" from the v1.9.x quality bar (see
`docs/roadmap.md`). recon's `--json` shape is the v2.0 schema-lock
target; locking that contract without published examples that
actually parse and ingest is premature. This patch makes the
contract real for Splunk and Elasticsearch operators and pins both
mappings against future schema drift via a CI gate.

### Added

- **`examples/siem/`** — cross-SIEM consumption index, plus two
  per-SIEM subdirectories.
- **`examples/siem/splunk/`** — `README.md` (field-mapping table,
  severity mapping, three use-case SPL snippets: shadow-IT
  alerting, DMARC drift, federation discovery), `props.conf`
  (sourcetype definition for `recon:lookup`), `savedsearches.conf`
  (three example saved searches matching the use cases), and
  `expected-splunk-event.json` (the worked output the CI gate
  verifies).
- **`examples/siem/elastic/`** — `README.md` (ECS-aligned field
  mapping table, severity mapping, same use-case framing),
  `ingest-pipeline.json` (Elasticsearch ingest pipeline that
  rewrites recon JSON to ECS namespaces), `index-template.json`
  (field-type pinning so Kibana visualizations don't drift on
  first-write surprises), and `expected-elastic-document.json`
  (worked output).
- **`tests/test_siem_examples.py`** — 33 contract tests pinning
  the worked examples against schema regression. Verifies: the
  shared sample input parses and carries every always-present
  field the SIEM READMEs claim to map; each SIEM's
  expected-output file parses; each README's "always present"
  mapping table references paths reachable in the sample;
  severity mappings consistent between README and worked output;
  the cross-SIEM index README lists both shipped SIEMs.

### Changed

- **`examples/sample-output.json`** enriched with the
  always-present-on-M365 fields the SIEM mappings reference:
  `slugs`, `email_security_score`, `cloud_instance`,
  `msgraph_host`, `primary_email_provider`. Still fictional
  Northwind Traders; no real-company data. Existing consumers of
  the sample see additional fields, not renamed ones —
  schema-additive.

### Notes for downstream consumers

- The SIEM examples are **maintainer-authored, vendor-unverified**.
  Per-example READMEs name the author-of-record. A SIEM-vendor
  employee opening a PR to validate or extend a mapping is welcome.
- The severity mapping documented in both READMEs is
  intentionally inverted from intuition (high recon confidence →
  low severity) because high confidence means strong public-signal
  evidence and a well-characterized posture; low confidence on a
  hardened target is the higher-severity signal worth operator
  review. Operators are expected to tune this for their context;
  the mapping is policy, not derivation.
- The CI gate verifies the worked-example file shapes against the
  shared input — a future schema rename that breaks SIEM ingestion
  fails the test before the schema change can reach a release tag.

### Roadmap

- **Track B item #9 of 10 cleared.** v2.0 pre-condition list shows
  one Track B item remaining: catalog metadata richness pass
  (descriptions ≥ 80%, references ≥ 25%). Track A bridge milestones
  v1.9.4 → v1.9.7 unchanged.

### Tests

- 2278 passed (+33 SIEM-example tests, was 2245 in v1.9.3.7).
- 1 skipped (Py3.10 + Windows shadow-workspace integration test).
- Coverage 83.33% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

## [1.9.3.7] - 2026-05-11

**CI fix: skip PYTHONSAFEPATH-only integration test on Python 3.10.**
The shadow-workspace integration test added in v1.9.3.4
(`test_shadow_workspace_cannot_execute`) asserted that
`PYTHONSAFEPATH=1` prevents a hostile cwd from shadowing
`recon_tool` when spawning `python -m recon_tool.server`. The
assertion is correct on Python 3.11+ but `PYTHONSAFEPATH` was
introduced in 3.11 (PEP 686) and is a no-op on 3.10. The CI matrix
includes Python 3.10, so the test failed for v1.9.3.4 / v1.9.3.5 /
v1.9.3.6.

The defense gap is architectural on 3.10, not a regression: the
v1.9.3.4 product code already routes around the unprotected
pattern.

### Changed

- **`tests/test_mcp_path_isolation.py`** — the shadow-workspace
  integration test now carries an explicit
  `@pytest.mark.skipif(sys.version_info < (3, 11), ...)` with a
  reason explaining the architectural limit. The skip reason
  records the recommended Python 3.10 launch path (`recon mcp`
  via the script entry point, not `python -m recon_tool.server`
  from an untrusted cwd). Unit tests in `TestServerRuntimeGuard`
  and source-inspection tests in `TestMcpDoctorSpawnsSafely`
  continue to run on every Python version — they cover the
  runtime guard and the safe-cwd + env-var contract
  independently.

### Notes for downstream consumers

- No code change to product behaviour. The v1.9.3.4 defenses
  (safe cwd in `mcp_doctor`, persisted `PYTHONSAFEPATH=1` in
  `mcp_install` fallback configs, runtime guard in
  `recon_tool/server.py`) are unchanged.
- On Python 3.10, the safe MCP launch pattern is `recon mcp`
  (the script entry point — has no `-m` and therefore no
  cwd-prepend risk). `mcp_install`'s `warn_if_fallback` already
  recommends this when `recon` is not on PATH.

### Tests

- 2245 passed, 1 skipped (the integration test skips on Py3.10
  and on Windows; runs on Py3.11/3.12/3.13 across ubuntu and
  macos).
- ruff + pyright clean.

This is a CI-only patch; no security regression and no defense
weakening. All four v1.9.3.x security findings remain closed by
v1.9.3.3 → v1.9.3.6.

## [1.9.3.6] - 2026-05-11

**Security: validation harness path containment (audit finding,
informational).** Closes the audit finding *"Validation runner
permits local fixture/persona file exfiltration"* against
`validation/agentic_ux/run.py`. The finding is informational
because the affected code is the maintainer-only validation
harness — not packaged in the wheel, not invoked by CI, not on a
recon end-user's product path — but the gap was real: a future
wrapper or agent calling `python -m validation.agentic_ux.run`
with unvalidated `--personas` / `--fixtures` arguments could have
caused arbitrary local `.md` / `.json` files to be read and
shipped to the configured LLM provider as part of the prompt.

This is the fourth and final patch addressing the security audit.

### Added

- **`validation.agentic_ux.run._validate_name`** — strict
  identifier validator (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`) that
  rejects every selector with a separator, traversal sequence,
  leading dot, leading dash, whitespace, or non-ASCII character.
  Accepts every legitimate in-repo persona/fixture name; raises
  `ValueError` on anything else.
- **`_SAFE_NAME_RE`** — the compiled regex, exposed as a module
  attribute so a future maintainer adding a new persona/fixture
  can see the format contract without re-deriving it.
- **`tests/test_validation_harness_path_containment.py`** — 48
  tests covering: 12 legitimate names accepted, 16 unsafe shapes
  rejected (empty, traversal, absolute paths, separators, dots,
  null bytes, over-length), regex anchoring, both loader entry
  points refusing unsafe names before any filesystem read, and a
  sanity check that all in-repo personas/fixtures still load.

### Changed

- **`_load_persona`** and **`_load_fixture`** now run the new
  validator on the input name *before* building the file path,
  and confirm the resolved path is still under the intended
  directory (`is_relative_to`) — defense-in-depth in case a future
  edit loosens the regex.

### Notes for downstream consumers

- The harness is not packaged in the recon-tool wheel; only the
  recon CLI and MCP server are. End users see no change.
- Maintainers running the harness with the existing committed
  persona/fixture names see no behavioural change.
- Any wrapper passing user-supplied `--personas` / `--fixtures`
  values now needs to surface a sensible error message when an
  unsafe selector is rejected (the `ValueError` carries one).

### Tests

- 2245 passed (+48 harness-containment tests, was 2197 in v1.9.3.5).
- Coverage 83.32% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

### Security audit closed

This patch closes the fourth and final finding from the v1.9.3.x
security audit:

  1. v1.9.3.3 — Release workflow supply-chain isolation (HIGH).
  2. v1.9.3.4 — MCP doctor/install path isolation (HIGH).
  3. v1.9.3.5 — CNAME chain target validation, layer 2 (MEDIUM).
  4. v1.9.3.6 — Validation harness path containment
     (informational, this patch).

Each shipped as its own tag through the v1.9.3.3 hardened release
workflow. The CHANGELOG entries for each carry the per-finding
quality-bar verification.

## [1.9.3.5] - 2026-05-11

**Security: CNAME chain target validation, layer 2 (audit finding,
MEDIUM).** Closes the audit finding *"CNAME chain walking can query
and leak internal DNS names"* with the second of two layers. Layer 1
(suffix denylist) was already in place from v1.9.0; this patch adds
layer 2 (resolved-address private check).

The remaining gap: an attacker who controls a public domain returns
a CNAME to a publicly-named host (passes the suffix denylist) whose
A record resolves to RFC1918 or other private space via split-horizon
DNS. The suffix check alone cannot see this — only resolving the
target's A/AAAA records can.

### Added

- **`recon_tool/sources/dns._is_private_ip_literal`** — returns True
  for RFC1918, loopback, link-local, ULA, reserved, multicast, and
  unspecified IPv4/IPv6 addresses. Defensive on parse failure
  (returns False so the caller falls back to other checks rather
  than dropping legitimate hops on garbage input).
- **`recon_tool/sources/dns._hop_resolves_publicly`** — resolves a
  target's A and AAAA records in parallel and returns True iff at
  least one resolved address is in public space. Fail-open on
  unresolved cases (no A/AAAA records) so CNAME-only intermediate
  hops in legitimate chains continue to walk.
- **`tests/test_cname_chain_validation.py`** — 47 tests covering
  both defense layers plus end-to-end walker behaviour: suffix
  denylist on 17 private/malformed names and 5 public names,
  IP-literal classification across RFC1918/loopback/link-local/ULA
  /multicast/v6 and garbage inputs, hop-resolution helper across
  public/private/mixed/unresolved cases, and four chain-walker
  integration tests (suffix-drop, A-drop, legitimate-public,
  truncate-at-first-failing-hop).

### Changed

- **`recon_tool/sources/dns._resolve_cname_chain`** now calls
  ``_hop_resolves_publicly`` after the suffix check passes. A hop
  whose suffix passes but whose A/AAAA records are all in private
  space is dropped without recording — the walker halts at that
  point. Adds at most two DNS queries per accepted hop (A + AAAA),
  well inside the existing ``_SURFACE_MAX_HOPS=5`` and
  ``_SURFACE_CONCURRENCY=30`` budgets.

### Notes for downstream consumers

- Legitimate public CNAME chains continue to walk identically.
- An operator behind split-horizon DNS will see fewer CNAME hops
  recorded when an attacker-controlled public name resolves to
  their internal range — this is the intended defensive behaviour;
  the previously-leaking internal name no longer appears in
  evidence output.
- The new helpers (`_is_private_ip_literal`, `_hop_resolves_publicly`)
  are module-private (leading underscore). They are not part of the
  public API; callers should not rely on them.

### Tests

- 2197 passed (+47 CNAME-validation tests, was 2150 in v1.9.3.4).
- Coverage 83.32% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

This is the third of four security patches. v1.9.3.6 (validation
harness path containment, informational) remains.

## [1.9.3.4] - 2026-05-11

**Security: MCP doctor/install path isolation (audit finding, HIGH).**
Closes the audit finding *"MCP doctor/install can execute shadowed
recon_tool package"* against `recon_tool/mcp_doctor.py` and
`recon_tool/mcp_install.py` (v1.9.2.1). The finding: `recon mcp
doctor` spawned `python -m recon_tool.server` with inherited cwd and
no environment sanitization. Python's `-m` flag prepends the current
working directory to `sys.path` on Python 3.10 (and absent
`PYTHONSAFEPATH=1` on 3.11+), so an attacker-controlled workspace
containing a `recon_tool/server.py` could shadow the installed
package and execute attacker code as the local user. The installer's
fallback config (used when `recon` is not on PATH) persisted the
same launch form, so future MCP-client launches from untrusted
workspaces inherited the same risk.

The fix is defense-in-depth across three layers:

### Changed

- **`recon_tool/mcp_doctor.py`** — the subprocess is now spawned
  with `cwd` pointing at an empty `tempfile.TemporaryDirectory` and
  `env["PYTHONSAFEPATH"] = "1"` set. The empty cwd guarantees no
  `recon_tool/` directory is reachable via cwd-prepend on any Python
  version; the env var disables cwd-prepend entirely on Python 3.11+.
  Both safeguards together close the attack on every supported
  Python version, including 3.10 where the env var alone is a no-op.
- **`recon_tool/mcp_install.py` — `build_recon_block`** now persists
  `env: {"PYTHONSAFEPATH": "1"}` in the fallback launch block so
  future MCP-client launches on Python 3.11+ inherit the protection.
  The preferred form (when `recon` is on PATH) is unchanged — it
  invokes the script entry point, which has no cwd-prepend concern,
  so the env block stays clean.
- **`recon_tool/mcp_install.py` — `warn_if_fallback`** (new) exposes
  a warning when the fallback launch form would be persisted.
  Surfaced by `recon mcp install` so operators on Python 3.10 see
  the residual-risk hint and can install `recon` to PATH for the
  safer launch form.
- **`recon_tool/server.py` — `_detect_cwd_shadow_install`** (new)
  runs at server startup before any tool handlers register. It
  resolves `recon_tool.__file__` and refuses to start when the
  package was loaded from a path under the current working
  directory unless cwd contains a legitimate `recon-tool` named
  `pyproject.toml` (the source-checkout case). The runtime guard
  is the final defense — it catches the attack regardless of how
  the server was launched, including any MCP client config that
  pre-dates the v1.9.3.4 mitigations.

### Added

- **`tests/test_mcp_path_isolation.py`** — 10 tests across the
  three defense layers: (a) source inspection asserts `mcp_doctor.py`
  sets `PYTHONSAFEPATH=1` and passes a safe `cwd`; (b) unit tests
  prove the install fallback persists the env var and the preferred
  form omits it; (c) runtime-guard tests cover normal install,
  shadow workspace (refuses), and legitimate source checkout
  (allows). The shadow-workspace integration test launches a real
  subprocess with a malicious `recon_tool/server.py` and asserts the
  installed module loads, not the shadow.

### Notes for downstream consumers

- MCP clients already configured via `recon mcp install` keep
  working; the persisted env-block addition is backward-compatible.
- Operators with hand-edited MCP client configs that point at
  `python -m recon_tool.server` SHOULD add `"env":
  {"PYTHONSAFEPATH": "1"}` to those configs on Python 3.11+, or
  re-run `recon mcp install` to refresh the canonical block.
- The runtime guard refuses to start if cwd looks suspicious. If
  you legitimately run `python -m recon_tool.server` from a source
  checkout, the checkout's `pyproject.toml` must have
  `name = "recon-tool"` (the project's own pyproject.toml does).

### Tests

- 2150 passed (+9 path-isolation tests passing; 1 shadow-workspace
  integration test skipped on Windows). One pre-existing flaky
  exposure-copy hypothesis test (unrelated; tracked separately).
- Coverage 83.24% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

This is the second of four security patches addressing the audit
findings. Remaining: v1.9.3.5 CNAME chain target validation
(MEDIUM), v1.9.3.6 validation harness path containment
(informational).

## [1.9.3.3] - 2026-05-11

**Security: release workflow supply-chain isolation (audit finding,
HIGH).** Closes the audit finding *"Dev deps can tamper release
artifacts"* against `.github/workflows/release.yml` (introduced in
v1.9.3.1). The finding: the v1.9.3.1 release workflow installed the
dev extra (`uv sync --extra dev`) and ran `pip-audit` for SBOM
generation in the same workspace as the just-built `dist/` directory,
BEFORE `actions/upload-artifact` sealed the wheel and sdist into
GitHub-managed storage. A compromised dev dependency (or transitive
of pip-audit) executing during SBOM generation could have modified
the release artifacts; those modified artifacts would then have been
published to PyPI under the project's trusted-publisher identity.

The fix is structural — workspace isolation, not just ordering.

### Changed

- **`.github/workflows/release.yml` restructured** with an explicit
  supply-chain isolation contract documented in the header comment:
  - **`build` job is now PURE.** Runs only `uv sync --no-dev` and
    `uv build`, then immediately uploads `dist/` as a sealed artifact.
    No dev dependencies installed; no pip-audit; no SBOM generation;
    no `run:` step exists between `uv build` and the dist upload.
    Steps that previously ran here have been moved.
  - **New `sbom` job** runs on a separate runner. Re-derives the
    locked requirements text from `uv.lock`, installs `pip-audit`
    via `uv tool install` (isolated venv), and generates the
    CycloneDX SBOM from the requirements text alone. `dist/` does
    not exist in this runner. A compromised pip-audit cannot reach
    release artifacts because they are sealed in GitHub storage and
    not present on this filesystem.
  - **`sbom` depends on `test`, not on `build`.** This makes the
    parallel-runner isolation structurally obvious — the two jobs
    run on different workspaces with no shared state. A future
    contributor adding `needs: build` to `sbom` would be regressing
    the threat model; the new contract test catches this.
  - **`github-release`** now `needs: [build, sbom]` so the release
    cannot ship without an SBOM. `publish-pypi` is unchanged —
    still the only job with `id-token: write`, still only downloads
    `dist/` and publishes.

### Added

- **`tests/test_release_workflow_contract.py`** — 13 contract tests
  that parse `release.yml` and assert the isolation properties hold:
  build job has no `--extra dev`, no `pip-audit`, no SBOM steps;
  no `run:` step between `uv build` and dist upload; sbom job does
  not depend on build; sbom job does not download `dist/`;
  `id-token: write` is restricted to `publish-pypi`; github-release
  attaches both `dist/` and `sbom/`. The test is structural — it
  inspects the workflow YAML, not the runtime — so it runs in
  ~1 second on every pytest invocation and catches regressions
  that would otherwise only surface after a tampered release.

### Tests

- 2141 passed (+13 release-workflow contract tests, was 2128).
- Coverage 83.31% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

### Notes for downstream consumers

- The `dist/` artifact published to PyPI is structurally unchanged
  by this patch. Existing `pip install recon-tool` workflows are
  unaffected.
- The SBOM artifact attached to the GitHub Release continues to be
  named `recon-tool-<version>.cdx.json`. Consumers pulling the SBOM
  by stable name see no change.
- Future v1.9.x.y releases ship through the hardened workflow.

## [1.9.3.2] - 2026-05-10

**Track B quality work — Top-3 influential edges in `--explain-dag`.**
Closes the v2.0 explainability gap on the `--explain-dag` surface.
The v1.9.0 renderer reported a posterior and a flat evidence list but
didn't show *which* evidence drove the answer — exactly the question
a defending operator asks when disputing a verdict. v1.9.3.2 surfaces
each fired binding's log-likelihood-ratio contribution + its share of
total |LLR| influence, ranked top-3 per node, inline in both the text
narrative and the Graphviz DOT export.

The ranking matches the v1.9.x quality bar: LLR is quantified per
binding (not count or presence), sorted by absolute LLR descending,
ties broken by `(kind, name)` for diff-stability, single-binding case
uses singular header ("Top influence:"), no fake top-3 on sparse
targets, no section emitted when zero bindings fired.

### Added

- **`recon_tool.bayesian.EvidenceContribution`** dataclass — engine-side
  representation of a fired binding's LLR + influence_pct.
- **`recon_tool.models.NodeEvidence`** dataclass — public-facing
  counterpart, surfaced through `PosteriorObservation.evidence_ranked`
  in the cache, JSON output, and renderer.
- **`PosteriorObservation.evidence_ranked: tuple[NodeEvidence, ...]`** —
  schema-additive field. Default empty tuple preserves v1.9.0 / v1.9.3
  JSON shape for consumers that don't read this field.
- **`tests/test_explain_dag_top3.py`** — 16 tests covering LLR
  correctness (hand-verified against three canonical bindings from
  the seed network), ranking determinism (sort key, tie-break),
  sparse/zero-binding behaviour, and a snapshot pinning the rendered
  m365_tenant block. Future renderer changes must update the snapshot
  deliberately.

### Changed

- **`render_dag_text`** emits a "Top influence" or "Top influences
  (ranked, N fired)" section after the evidence list when ≥ 1 binding
  fired. Section header pluralizes correctly; when more than 3 fired,
  header reads "Top influences (ranked top 3 of N fired)".
- **`render_dag_dot`** node labels include a "top influences:" suffix
  with the top-3 ranking inline so DOT-rendered diagrams carry the
  same visibility the text narrative provides.
- **`docs/correlation.md` Example 1 (dense M365-federated stack)**
  regenerated with v1.9.3.2 output. The reading commentary explains
  *why* `entra-id` outranks `microsoft365` in evidence influence
  (likelihood ratio 44 vs 32) and how the ranking lets an operator
  audit which facts drove a verdict.
- **Cache + JSON serialization** round-trips `evidence_ranked` through
  `cache.py` and `formatter.py`. The forward-compat tests added in
  v1.9.3.1 already cover the case where an older reader encounters
  the new field (it ignores it gracefully).

### Roadmap

- **Track B "Top-3 influential edges" item closed.** v2.0
  pre-condition list shows 8 remaining (was 9 after v1.9.3.1).
  Two Track B items remain: catalog metadata richness pass and
  downstream consumption examples. Track A bridge milestones
  v1.9.4-v1.9.7 unchanged.

### Tests

- 2128 passed (+16 top-3 tests, was 2112 in v1.9.3.1).
- Coverage 83.32% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

## [1.9.3.1] - 2026-05-10

**Track B quality work — SECURITY.md and supply-chain hardening.**
Closes four entries from the roadmap "Known gaps" section in one
patch: SECURITY.md (already shipped pre-v1.9.3.1, audited and
left in place), CycloneDX SBOM as a release asset, gitleaks
secrets-scanning in CI, and a forward-compat cache test. Per the
v1.9.x quality bar (docs/roadmap.md), each sub-item ships against
explicit acceptance criteria a reviewer can verify.

### Added

- **CycloneDX SBOM as release asset.** Every GitHub Release now
  carries a `recon-tool-<version>.cdx.json` file generated by the
  release workflow from the same locked dependency set the audit
  gate validates. Consumers can pin their SBOM tooling against the
  stable name. Generated via `pip-audit --format=cyclonedx-json`,
  written to a separate `sbom/` directory so the PyPI publish job
  only sees wheels and sdists. Includes runtime + transitive
  dependencies with their licenses.
- **`.github/workflows/secrets-scan.yml`** — gitleaks runs on
  every PR, every push to main, and a weekly Sunday 06:00 UTC
  scheduled scan against the historical branch tree. Read-only
  workflow permissions; failures non-bypassable. Three triggers
  cover the realistic leak surfaces: pre-merge (PR), bypassed-PR
  (push to main), and historical-leak rotation (weekly).
- **`tests/test_cache_forward_compat.py`** — 10 regression tests
  pinning the implicit "ignore unknown fields, load known fields
  cleanly" contract that `recon_tool.cache.tenant_info_from_dict`
  has always honoured but never tested. Covers unknown top-level
  fields, unknown nested-dict keys (in `cert_summary`,
  `posterior_observations[]`, `evidence[]`), higher
  `_cache_version`, and confirms malformed-input rejection still
  works. The contract matters because a v1.10 cache writer that
  adds a new field must not require a v1.9 reader to crash on the
  file — operators upgrading and downgrading recon between
  machines hit this case routinely.

### Changed

- **`docs/roadmap.md` Known-gaps section updated.** Four of six
  items now strike-through to "shipped"; the remaining two
  (mutation testing, SLSA provenance) explicitly deferred to
  post-v2.0. Track B v2.0 pre-condition list reflects 9 remaining
  items (was 10 before v1.9.3.1).
- **`docs/roadmap.md` Track B "SECURITY.md and supply-chain
  hardening" item** marked shipped with a back-reference to this
  changelog entry. Quality-bar verification per-item:
  - SECURITY.md: real scope (defensive, passive-only,
    explicit out-of-scope), 48-hour ack SLA, 7-day assessment,
    30-day fix; nick@pueo.io reporting channel; coordination
    policy implicit via the MCP-specific threat-model section.
  - Secrets scanning: PR + push + weekly schedule (three triggers).
  - SBOM: CycloneDX format, generated by the release workflow,
    runtime + transitive with licenses.
  - Forward-compat cache test: 10 tests covering both top-level
    and nested unknown-field cases plus malformed-input rejection.
  - Transitive-pin rationale: `python-multipart>=0.0.27` carries
    its `CVE-2026-42561` rationale comment in `pyproject.toml`;
    audit found no other un-rationalized transitive pins.
  - `pip-audit` confirmed fail-on-vulnerability default;
    no advisory-only relaxation.

### Tests

- 2112 passed (+10 forward-compat, was 2102 in v1.9.3).
- Coverage 83.29% (≥ 80% gate).
- ruff + pyright clean on `recon_tool/` + `tests/`.

## [1.9.3] - 2026-05-09

**v1.9.3 bridge milestone — Bayesian-network topology surgery.**
Resolves the `email_security_strong` definitional gap that produced
the 52.6% v1.9.0 calibration disagreement. Per
[docs/roadmap.md §v1.9.3](docs/roadmap.md), this is topology surgery,
not CPT tuning — the v1.9.0 node parameterized its CPT on
modern-mail-provider presence (M365 / GWS / gateway) but tested
policy-enforcement signals (DMARC / DKIM / SPF / MTA-STS) via its
evidence bindings. Different claims; no parameter tuning could
reconcile them.

**Calibration impact.** Spot-check agreement on
`email_security_policy_enforcing` (the evidence-driven half of the
split) is **100%** on the v1.9.3 spot corpus. See
[validation/v1.9.3-calibration.md](validation/v1.9.3-calibration.md)
for the full calibration aggregate and reproducibility instructions.

### Changed (EXPERIMENTAL surface)

- **`bayesian_network.yaml` topology** bumped to v1.9.3 (frozen
  2026-05-09; 9 nodes, was 8). The topology stability contract
  acknowledges bridge milestones as planned exceptions.
- **`email_security_strong` removed** from
  `recon_tool/data/bayesian_network.yaml`. Consumers pinning the
  v1.9.0 node name in `posterior_observations[]` must update. The
  EXPERIMENTAL label on the whole `--fusion` surface accommodates
  this; no separate deprecation patch — the node's calibration was
  the explicit weak spot v1.9.x was committed to fixing.
- **`federated_identity` parents expanded** from `[m365_tenant]` to
  `[m365_tenant, google_workspace_tenant]`. The v1.9.0 single-parent
  network systematically under-attributed federation when the path
  didn't go through M365 (Okta + GWS, Auth0 + custom IdP, standalone
  SAML). Four-entry CPT preserves the M365-path numbers and seeds
  GWS-path values.

### Added

- **`email_security_modern_provider`** node — provider-presence
  claim. Parents `[m365_tenant, google_workspace_tenant,
  email_gateway_present]`; no evidence bindings (pure CPT
  propagation). Provider presence is fully observable through the
  parent slugs.
- **`email_security_policy_enforcing`** node — policy-enforcement
  claim. Root node, prior 0.25. Evidence bindings carried over from
  the v1.9.0 node: `dmarc_reject`, `dmarc_quarantine`,
  `mta_sts_enforce`, `dkim_present`, `spf_strict`. Provider-
  independent — a Zoho or Fastmail tenant with a strict DMARC
  reject policy fires this node identically to an M365 one.
- **`tests/test_bayesian_v193_topology.py`** — 11 regression tests
  pinning the new topology against silent reversion.
- **`validation/v1.9.3-calibration.md`** — per-release calibration
  aggregate (sensitivity, synthetic ECE, spot-check); part of the
  standing per-release publish discipline.
- **`docs/correlation.md §4.8.9`** — *Definitional discipline: the
  v1.9.3 split.* The v1.9.3 gate the roadmap required: explicit
  definitions of both new nodes, why they are separate claims, and
  the principle behind questioning topology before tuning numbers.

### Roadmap

- **v1.9.3 bridge milestone closed.** v1.9.4 (hardened-adversarial
  behavior validation) is next. The full v1.9.0 corpus will be
  re-run against the v1.9.3 topology as part of v1.9.4 to certify
  cross-vertical calibration.
- **Roadmap restructured** — items previously in
  *v1.9.x — Optional feature additions* that v2.0 polish requires
  (catalog metadata richness, SECURITY.md + supply-chain hardening,
  downstream consumption examples, top-3 influential edges in
  `--explain-dag`) moved to a new *Required quality work for v2.0*
  section. v2.0 pre-conditions now enumerate ten items across two
  tracks: six bridge milestones (Track A) plus four required
  quality items (Track B).

## [1.9.2.2] - 2026-05-08

**Catalog growth from the v1.9.2-pre-release corpus scan — 39 new
fingerprints.** The 4,270-domain scan that gated v1.9.2 surfaced 86
unclassified CNAME patterns. v1.9.2.2 ships the **39 new fingerprints**
(33 application-tier SaaS + 6 infrastructure-tier CDNs) that survived
hand-reviewed LLM-assisted triage against the project's existing
`recon-fingerprint-triage` skill rubric. The remaining 47 candidates
were dropped: 27 intra-org self-references (e.g. Microsoft's own
`dc-msedge.net`, Baidu's `shifen.com`, Alibaba's `tbcache.com`),
12 already-covered slugs, 4 niche one-offs, 2 unclear pending more
corpus exposure.

This is a follow-up patch to v1.9.2 (which was harness-only with no
recon_tool/ changes) and to v1.9.2.1 (MCP UX, also no catalog
changes). The "no bundling" rule applies: shipping fingerprint
additions in their own patch keeps each tag attached to one
user-facing story.

### Added

- **39 new `cname_target` fingerprints** in
  `recon_tool/data/fingerprints/surface.yaml`:
  - **Identity / Security:** Akamai EAA (Zero Trust), Fortinet
    FortiWeb Cloud, plus extended Okta (FedRAMP `okta-gov.com`
    and DNSSEC `okta-dnssec.com` patterns) and Ping Identity
    (PingOne `ping.cloud`).
  - **Email & Communication:** Hostinger Email, Rackspace Email.
  - **Productivity & Collaboration:** BigMarker, CampusPress,
    Fluid Topics (Antidot), Framer, Gatsby Events, GitBook,
    Mintlify, Refined (Confluence theme), Stova (Aventri),
    Tistory (Kakao), Tumblr, Weglot, WordPress.com.
  - **Marketing:** Movable Ink, Prowly, Terminus (Sigstr),
    Uberflip (ZoomInfo).
  - **Business Apps:** Amplience, Q4 Inc. (IR Platform),
    Talentera.
  - **Commerce:** Fanatics Retail Group, SAP Commerce Cloud.
  - **Certain (Cvent)** event management.
  - **Infrastructure-tier CDNs:** Edgio CDN (Limelight),
    EdgeCDN (Bitban), Lumen CDN (Footprint), Medianova CDN,
    Merlin CDN, plus extended Gandi (`partners.gandi.net` +
    `vip.gandi.net` web-redirect), easyDNS URL forwarding,
    IONOS hosting (`adsredir.ionos.info`), Kinsta managed
    WordPress, and Google Cloud (`bc.googleusercontent.com`
    extending the existing `gcp-app` slug).
- **36 new formatter category mappings** in
  `recon_tool/formatter.py:_CATEGORY_BY_SLUG` for the new slugs
  (three slugs — okta, ping-identity, gcp-app — reuse existing
  entries rather than introducing duplicate names).
- **`validation/triage_llm.py`** — programmatic LLM-assisted
  triage runner. Reads a `candidates.json` produced by
  `validation/triage_candidates.py`, batches the entries to an
  Anthropic chat model with the project's triage rubric as the
  system prompt, parses the structured response into a markdown
  triage report (kept local — references real sample subdomains)
  plus a proposed-stanzas YAML diff (only generic patterns,
  safe to commit). Dev tool only; not a runtime dependency.
  End users do not need an LLM API key for any recon CLI
  surface.

### Changed

- `recon_tool/data/fingerprints/surface.yaml` — appended catalog-
  growth section under the existing Microsoft 365 entry. Catalog
  validator confirms **385 / 385 entries pass** schema (was 346).

### Tests

- Existing 2091 tests still pass at 84.03% coverage. No new tests
  added — fingerprint behavior is data-driven and exercised by the
  catalog validator (`recon fingerprints check`), the match-mode
  audit (`validation/audit_fingerprints.py`), and the existing
  per-detection unit tests in `tests/test_fingerprints*.py`.

### Fixed

- **`tests/test_mcp_install.py::test_envvar_expands_in_cli_config_path`
  cross-platform regression.** The test added in v1.9.2.1 used a
  `$VAR` POSIX form with an inverted polarity check that
  reassigned to `%VAR%` (Windows-only) after ``os.path.expandvars``
  successfully expanded the POSIX form. On Linux the resulting
  `%VAR%` literal never gets re-expanded by Python's stdlib, so
  the install never wrote to the temp dir and the assertion
  failed. v1.9.2.1's CI publish job consequently failed on Linux
  even though the local Windows test pass count was 2091. This
  patch swaps to the curly-brace `${VAR}` POSIX form which
  ``os.path.expandvars`` handles identically on every platform.
  Net effect: PyPI did not receive a v1.9.2.1 release; users
  upgrading skip from 1.9.2 to 1.9.2.2.

### Roadmap

- Standing-work discipline restored: every release window now
  includes at least one private-corpus scan plus the resulting
  catalog growth in the same release window (v1.9.2 +
  v1.9.2.2 together). The "no bundling" rule is preserved by
  separating the harness work (v1.9.2), MCP UX (v1.9.2.1), and
  catalog growth (this) into three tagged releases that share a
  release window but not a single tag. v1.9.2.1 was tagged on
  GitHub but its release workflow failed at the test job
  (regression noted under Fixed above), so PyPI never received
  it; the MCP UX features it introduced ride along with this
  v1.9.2.2 wheel.

## [1.9.2.1] - 2026-05-08

**MCP works by default — interactive misuse caught, install + live
self-check shipped.** Three independent UX patches bundled because
they share a single user-facing story: "I ran the MCP server and it
either confused me or didn't connect." Operators who launched
`python -m recon_tool.server` (or `recon mcp`) directly in a shell
hit a Pydantic JSON-parse traceback the first time their stray
newline reached the JSON-RPC parser; this release intercepts that
case with an explicit "this is not a REPL" panel. Operators who
wanted to wire recon into an MCP client had to copy-paste a JSON
block into a per-OS, per-client config file by hand;
`recon mcp install --client=<name>` now does that idempotently.
And operators who installed but couldn't tell whether the wiring
actually worked had only static-shape diagnostics; `recon mcp
doctor` now spawns the server and walks a real initialize +
tools/list handshake the way a client would.

These are roadmap "v1.9.x — Optional feature additions (parallel
to the bridge milestones)" entries — they ship as a bundle here
rather than as three separate patches because the underlying
narrative is one user-facing change, and CHANGELOG readers benefit
from seeing the three components together. The next bridge
milestone (v1.9.3 — `email_security_strong` definitional gap) is
unaffected.

### Added

- **`recon_tool/server.py:_print_tty_misuse_panel` + TTY guard.**
  When `sys.stdin.isatty()` returns True and the
  `RECON_MCP_FORCE_STDIO` env var is unset, `main()` prints a
  human-readable panel explaining that the server speaks JSON-RPC
  over stdio and exits cleanly. The previous behavior — feeding
  the user's stray newlines into the FastMCP JSON parser and
  surfacing a Pydantic stack trace — is preserved behind
  `RECON_MCP_FORCE_STDIO=1` (case-insensitive; `1`, `true`,
  `yes`, `on` all enable the bypass). The TTY check itself
  catches `AttributeError`, `ValueError`, and `OSError` from
  `isatty()` so embedded environments with stubbed-out or
  closed-handle stdin don't crash before the JSON-RPC loop ever
  starts.
- **`recon mcp install --client=<name>` (`recon_tool/mcp_install.py`).**
  Idempotent merge of the canonical `mcpServers.recon` block into
  the right config file for six clients: claude-desktop,
  claude-code, cursor, vscode, windsurf, kiro. Per-OS path table
  (Windows / macOS / Linux), `--scope user|workspace|auto`,
  `--config-path` override (with `~` and env-var expansion),
  `--force` to refresh canonical fields, `--dry-run` to preview
  without writing. `--force` is field-
  preserving: only `command` and `args` are authoritative on the
  install side; the user's hand-curated `autoApprove` list,
  `env` overrides, `disabled` flags, and any other keys they've
  added to the recon block all survive a `--force` rerun. Reads
  with `utf-8-sig` so a UTF-8 BOM (Windows Notepad / certain
  PowerShell redirects) doesn't trip JSON parsing; writes with
  `ensure_ascii=False` and `newline="\n"` so non-ASCII content
  in sibling configs round-trips byte-for-byte and disk format
  stays platform-agnostic. Refuses to clobber unparseable JSON,
  top-level non-object configs, or a `--config-path` that points
  at a directory rather than a file; preserves sibling
  `mcpServers` entries; falls back from `recon` to `python -m recon_tool.server`
  when `recon` is not on PATH so GUI clients (Claude Desktop,
  Windsurf) that don't inherit the shell PATH still launch the
  server. Idempotent rerun is genuinely free — when no canonical
  field would change, the file is not rewritten and its mtime is
  not bumped, avoiding spurious file-watcher reloads in clients
  like Cursor and VS Code. Writes are atomic — content goes to a
  sibling tempfile in the same directory, gets ``fsync``'d where
  the filesystem supports it, then ``os.replace``'d into place,
  so a partial-write failure (disk full, antivirus mid-scan,
  network drive drop, OS crash) leaves either the old config
  intact or the new config fully on disk — never a half-written
  truncation.
- **`recon mcp doctor` (`recon_tool/mcp_doctor.py`).** End-to-end
  self-check: spawns the server through the running interpreter
  (`python -m recon_tool.server`), opens a real `stdio_client` +
  `ClientSession`, performs `initialize` + `tools/list`, and
  asserts the response includes the canonical anchor tools
  (`lookup_tenant`, `analyze_posture`, `assess_exposure`,
  `find_hardening_gaps`, `chain_lookup`). 30-second handshake
  timeout. Spawned-server stderr is captured to a tempfile rather
  than forwarded to the terminal; on a successful run, that
  capture is dropped (no banner flood above the checks); on a
  crash during ``initialize``, the trailing twelve lines of the
  captured stderr are spliced into the failure detail so the user
  sees the actual ImportError / traceback / missing-dependency
  message instead of an opaque ``BrokenPipeError``. Distinct from
  the existing `recon doctor --mcp`, which remains the static-
  shape sibling (package import, FastMCP introspection, copy-
  pasteable config snippet).

### Changed

- **`recon mcp` is now a typer sub-typer instead of a leaf command.**
  Bare `recon mcp` (no subcommand) still starts the server — the
  callback uses `invoke_without_command=True` so backward
  compatibility is preserved. New subcommands (`install`,
  `doctor`) live under it. No change to existing scripts or MCP
  client configs.

### Tests

- 72 new tests across `tests/test_mcp_install.py` (55),
  `tests/test_mcp_doctor.py` (10 including a real
  subprocess-spawning live handshake and a server-stderr
  capture-on-crash case), plus TTY-guard and field-preservation
  cases in `tests/test_server.py`. New tests pin: BOM-stripped
  reads, unicode round-trip without `\u` escapes, LF line endings
  on Windows, idempotent rerun (mtime stable), user `env` /
  non-empty `autoApprove` / `disabled` / unknown-key preservation
  under `--force`, `~` and env-var expansion in `--config-path`,
  directory-path refusal, `Path.home()` failure, `OSError` /
  `ValueError` / `AttributeError` paths through
  `_stdin_is_tty()`, and case-folded / whitespace-tolerant
  `RECON_MCP_FORCE_STDIO` parsing, atomic-write debris cleanup,
  and partial-write-failure preservation of the original config.
  Full suite: 2091 passing.

### Roadmap

- Closes three "v1.9.x — Optional feature additions" entries.
  Bridge sequence (v1.9.3 → v1.9.7 → v2.0) unaffected.

## [1.9.2] - 2026-05-08

**Agentic UX validation harness — first v1.9.x bridge milestone toward
v2.0.** Operators are not the only persona that reads recon's `--fusion`
output: the MCP server is a primary surface, and an AI agent reading
recon JSON is itself a production user. v1.9.2 ships a reproducible
harness that drives three persona prompts (security analyst,
due-diligence researcher, ops engineer) across two fixtures
(`contoso.com` dense lookup and a hand-stripped `northwindtraders.com`
hardened-sparse variant) under both `--fusion`-on and `--fusion`-off
arms — twelve sessions per run — and scores the transcripts against
the five-check rubric defined in `docs/roadmap.md`. The shipped
artifact (`validation/v1.9.2-agentic-ux.md`) is the first calibration
input for the v2.0 schema-lock disposition decisions; subsequent runs
against other providers append to that record.

### Added

- **`validation/agentic_ux/` harness.** `providers.py` is a
  multi-provider chat adapter (Anthropic / OpenAI / xAI Grok) with
  optional-import SDK loading; `score.py` is the binary rubric
  scorer (regex/keyword scans, no LLM-as-judge); `run.py` is the
  CLI entry point (`python -m validation.agentic_ux.run`) that
  orchestrates the 3 × 2 × 2 matrix, totals realized cost from API
  responses, and writes a self-contained markdown report. The
  module is decoupled from `recon_tool` so the harness can run
  against captured recon JSON from any version.
- **Persona scaffolds.** `personas/{analyst,researcher,ops}.md` —
  none mention `posterior_observations`, `sparse=true`,
  `--explain-dag`, or credible intervals; the rubric measures
  whether the agent finds those affordances unprompted.
- **Committed fixtures.** `fixtures/contoso-dense.json` (full
  `recon contoso.com --json --fusion` output, Microsoft fictional
  brand) and `fixtures/hardened-sparse.json` (hand-stripped to one
  slug for `northwindtraders.com`, also Microsoft fictional). Real
  apexes never get committed, per the no-real-company-data
  invariant in `validation/README.md`.
- **`validation/v1.9.2-agentic-ux.md`** — the first canonical run
  artifact (Anthropic Claude Sonnet 4.6). Subsequent runs append.

### Changed

- **`docs/roadmap.md`** — bridge milestones renumbered. v1.9.1 was
  consumed by the conflict-provenance optional feature, so the
  bridge sequence now reads v1.9.2 (this release) → v1.9.3
  (`email_security_strong` topology surgery) → v1.9.4
  (hardened-adversarial validation) → v1.9.5 (per-node stability
  criteria) → v1.9.6 (CPT-change discipline) → v1.9.7
  (metadata-coverage gate). Cross-references and the v2.0
  pre-conditions table updated to match. The introductory
  paragraph of the bridge section now explains the renumbering
  explicitly.
- **`validation/__init__.py`** — added so `validation` is a proper
  package rather than an implicit namespace package. Defeats
  pyright import-resolution flakiness without changing the
  runtime contract (existing `python -m validation.<name>`
  invocations are unchanged).

### Tests

- **`tests/test_agentic_ux.py`** — 26 new tests covering the
  provider-adapter shape with mocked SDK clients (no network),
  rubric scoring on synthetic transcripts (positive and negative
  cases for every check), runner orchestration (12-session matrix,
  fusion-stripping correctness), and the report writer (required
  sections present, cost rendering correct).

Total: 2012 tests passing.

### Roadmap

- Closes the **v1.9.2 — UX validation via agentic QA** bridge
  milestone toward v2.0. Findings from the first canonical run map
  directly to the v2.0 schema-lock disposition decisions in
  `docs/roadmap.md`.

## [1.9.1] - 2026-05-05

**Conflict provenance on `NodePosterior`.** First v1.9.x optional-feature
patch from the bridge plan in `docs/roadmap.md`. The v1.7 conflict-aware
merger captures *which sources disagreed on which fields*; the v1.9.0
fusion layer rolled this into a uniform n_eff penalty and dropped the
detail. v1.9.1 carries the structured provenance through to every
`PosteriorObservation` so both `--explain-dag` and the `--json` output
can name the disagreeing sources alongside the existing top-level
`evidence_conflicts` array. Schema-additive — required key added to
`PosteriorObservation`; emits `[]` when no conflicts dampened the
interval. EXPERIMENTAL alongside the rest of the v1.9 fusion surface.

### Added

- **`ConflictProvenance` (engine) and `NodeConflict` (model) dataclasses.**
  `recon_tool.bayesian.ConflictProvenance` is the inference-side record
  carrying `field`, `sources`, and `magnitude` (n_eff units). The
  `recon_tool.models.NodeConflict` mirror is the serializable
  TenantInfo-side counterpart and round-trips through cache.
- **`infer(..., conflicts=...)` parameter.** Structured per-conflict
  records replace the count-only path when supplied; the legacy
  `conflict_field_count` parameter remains a backward-compatible entry
  point (its callers are unchanged). When both are passed, `conflicts`
  wins and the count is derived from `len(conflicts)`.
- **`PosteriorObservation.conflict_provenance` field.** Always present
  in `--json` output as a (possibly empty) array. Each entry:
  `{field, sources: [...], magnitude}`. Documented in
  `docs/recon-schema.json` under a new `NodeConflict` `$def`.
- **`--explain-dag` rendering.** Text renderer adds a `**Conflicts:**`
  line per node listing each disagreement as
  `` `field` (source-a vs source-b, -1.50 n_eff) `` when non-empty;
  the line is omitted when no conflicts dampened the interval. DOT
  renderer appends `conflicts: <field-list>` to node labels for the
  same nodes.
- **Cache forward-compat.** Pre-v1.9.1 cached entries (no
  `conflict_provenance` key) parse cleanly to an empty tuple; the
  parser tolerates malformed conflict entries via the same
  `try/except` pattern used elsewhere in `_parse_posterior_observations`.

### Changed

- **`PosteriorObservation` schema** in `docs/recon-schema.json` —
  `conflict_provenance` added as a required key (always present, empty
  array when no conflicts). `NodeConflict` `$def` added alongside.
- **`recon_tool/bayesian.py`** — `_conflict_provenance(info)` extracts
  structured records from `MergeConflicts`; the legacy
  `_conflict_count(info)` helper is removed (its single caller now
  uses the structured path).
- **`recon_tool/cli.py`** — fusion construction site maps
  `ConflictProvenance` → `NodeConflict` when populating
  `PosteriorObservation.conflict_provenance`.

### Tests

- **`tests/test_conflict_provenance.py`** — 12 new tests covering:
  empty provenance when no merge_conflicts; populated provenance with
  field/source/magnitude detail; source deduplication; explicit
  `conflicts=` argument overriding `conflict_field_count`; legacy
  count-only path yields empty provenance; JSON shape (always-present
  array, empty when clean); cache round-trip including a pre-v1.9.1
  payload; text renderer surfaces conflicts; text renderer omits the
  conflict line when clean; DOT renderer annotates conflict-bearing
  nodes.

Total: 1982 tests passing.

### Roadmap

- Marks the **conflict provenance on `NodePosterior`** bullet from the
  v1.9.x optional-features list as shipped.
- Patch-release discipline: this lands as a single-feature patch per
  the v2.0 bridge plan; no other unrelated work in this version.

## [1.9.0] - 2026-05-04

**Probabilistic fusion layer (v1.9), EXPERIMENTAL.** Adds the third
correlation layer planned in `docs/roadmap.md`: a small discrete
Bayesian network with exact variable-elimination inference, calibrated
80% credible intervals via effective-sample-size construction, and
asymmetric one-sided likelihoods that refuse overconfident verdicts on
hardened-target sparse evidence. Fully gated behind `--fusion`; the
default panel and v1.0 JSON shape are unchanged. Full validation
report at
[`validation/v1.9-validation-summary.md`](validation/v1.9-validation-summary.md);
formal model and citations in
[`docs/correlation.md` §4.8](docs/correlation.md).

### Added

- **`recon_tool/data/bayesian_network.yaml`** — committed network
  topology and CPTs (8-node seed: m365_tenant, google_workspace_tenant,
  federated_identity, okta_idp, email_gateway_present,
  email_security_strong, cdn_fronting, aws_hosting). Schema v1,
  network topology v1.9.0 (frozen 2026-05-04). Likelihoods
  strictly in `(0, 1)`; degenerate hard-evidence factors rejected.
- **`recon_tool/bayesian.py`** — pure-Python variable-elimination
  inference engine. Topology validation (DAG, complete CPTs,
  parent reachability), TenantInfo adapter, posterior + 80% credible
  interval per node, n_eff calibration with conflict dampener.
  Asymmetric one-sided likelihoods (Jeffrey-style updating;
  cautious-updating literature: Walley 1991, Augustin et al. 2014,
  Taroni et al. 2014).
- **`recon_tool/bayesian_dag.py`** — plain-English narrative
  renderer + Graphviz DOT export for the inference DAG.
- **`PosteriorObservation` model** — new dataclass on TenantInfo;
  populates `posterior_observations` in `--json` output when
  `--fusion` is on. Empty array otherwise. Round-trips through cache.
- **`--explain-dag`** CLI flag with `--explain-dag-format text|dot`.
  Implies `--fusion`. 4 worked examples in correlation.md §4.8a.
- **`get_posteriors`** and **`explain_dag`** MCP tools — read-only,
  cache-aware, rate-limited like `lookup_tenant`.
- **`~/.recon/priors.yaml`** — operator-supplied root-node prior
  override. Local-only, never shipped, never sent over the wire,
  never persisted in cache. Loader logs an info-level message when
  applied so operators see when an override is shaping output.
- **`scripts/check_metadata_coverage.py`** — per-category description
  / reference / weight coverage report. Wired into CI as advisory
  (will flip to enforcing once the catalog reaches the 70% target on
  identity / security / infrastructure).
- **`validation/synthetic_calibration.py`** — publicly-reproducible
  ground-truth calibration experiment using the network's own joint
  distribution. Reports marginal vs conditional ECE, per-node
  reliability tables, and identifies calibration weak spots
  (currently `email_security_strong` and `aws_hosting`).
- **JSON schema entry** for `posterior_observations` in
  `docs/recon-schema.json` ($defs/PosteriorObservation, EXPERIMENTAL).
- **Mermaid diagrams** in correlation.md: three-layer dataflow,
  Bayesian DAG topology, sparse-vs-dense interval illustration.
- **Sensitivity-bound regression guard.** ±0.10 perturbation of any
  single CPT entry produces ≤ 0.139 posterior shift (median 0.019,
  95th percentile 0.109). Test: `tests/test_bayesian_sensitivity.py`.

### Changed

- **`docs/correlation.md`** — substantial expansion of §4.8 with the
  full v1.9 derivation: generative model, variable elimination
  (citations: Zhang & Poole 1994; Koller & Friedman 2009),
  asymmetric likelihood with literature grounding, credible-interval
  calibration (Beta moment-matching; Wilson approximation),
  identifiability discussion, relationship to the existing Beta
  layer, validation strategy with publicly-reproducible numbers.
  §3 expanded to a three-layer comparison table. §4.1–4.7 trimmed
  of repetitive boilerplate. Citations added throughout (Pearl 1988,
  Russell & Norvig, Blondel et al. 2008, Traag et al. 2019,
  Naeini et al. 2015, Jeffrey 1965, Walley 1991, etc.).
- **`docs/roadmap.md`** — v1.9 status updated to shipped.

### Tests

- **244 new tests** added across:
  - `test_bayesian_canonical.py` — verifies engine matches Pearl
    Burglary-Earthquake-Alarm and the medical-test example to four
    decimal places under the noisy-likelihood model.
  - `test_bayesian_inference.py` — schema validation, priors override,
    variable elimination correctness on a hand-checked toy network,
    credible interval shape, TenantInfo adapter.
  - `test_bayesian_dag.py` — text + DOT renderer correctness,
    confidence-label thresholds, sparse-flag rendering.
  - `test_bayesian_fuzz.py` — 39 adversarial schema inputs (empty,
    null, cycles, unicode, boundary likelihoods).
  - `test_bayesian_hypothesis.py` — property-based testing with
    Hypothesis: 550 random valid networks + evidence sets verify
    closed-form Bayes match, prior recovery on no evidence,
    invariants under random conflicts, determinism.
  - `test_bayesian_sensitivity.py` — CPT ±0.10 perturbation bound.
  - `test_bayesian_validation_rounds.py` — 24 inference invariants.
  - `test_v19_robustness.py` — cache round-trip with malformed
    entries, CLI flag combinations, MCP error paths, determinism +
    concurrency, scale stress (15-node chain, 10-child wide network).
  - `test_fusion_integration.py` — end-to-end --fusion path.
  - `test_metadata_coverage.py` — CI gate behavior.

Total: 1938 tests passing. Coverage on new modules:
`recon_tool/bayesian.py` 98%, `recon_tool/bayesian_dag.py` 92%.

## [1.8.1] - 2026-05-03

**Hardening release driven by a 10-domain diverse deep-dive against
v1.8.0.** Per-target output quality surfaced four issues that the
105-domain batch validation missed because it scored corpus medians
rather than individual results. All four are fixed and re-validated.
Full report at
[`validation/v1.8-validation-summary.md`](validation/v1.8-validation-summary.md).

### Fixed

- **CT-cache fallback gap.** `_detect_cert_intel` early-returned on
  any provider response, even an empty one. CertSpotter rate-limited
  responses look like a successful empty answer (HTTP 200, no
  issuances), so when crt.sh was degraded and CertSpotter was
  rate-limited the CT-cache fallback never fired and `cert_summary`
  stayed null even when a populated cache entry existed. Now an
  empty `(subdomains=[], cert_summary=None, infrastructure_clusters=None)`
  response is treated as soft failure: the loop continues to the next
  provider and, if all return empty, the CT cache is consulted.
- **`chain_motifs` and v1.7 `cert_summary` extensions silently
  dropped on cache write.** `tenant_info_to_dict` did not include
  `chain_motifs`, `wildcard_sibling_clusters`, or
  `deployment_bursts` in its serialized form, so cache-served
  lookups always returned zero motifs and empty wildcard / burst
  collections — even when the original resolve produced matches.
  Both directions of the round-trip now preserve them. Round-trip
  regression tests in `tests/test_cache_roundtrip.py`.

### Added

- **Eight new chain motifs covering Microsoft-internal and
  vendor-specific chain shapes.** Catalog grew from 10 to 18.
  Microsoft: `tm_to_azurefd`, `azurefd_to_msedge`, `akamai_to_msedge`,
  `tm_to_powerapps`. Salesforce: `salesforce_chain`. Adobe:
  `adobe_experience_cloud`, `akamai_to_adobe`. Oracle Cloud:
  `oracle_cloud_chain`. The deep-dive observed that real-world
  chains for hardened-target enterprises terminate inside a single
  vendor's perimeter (e.g. `trafficmanager.net -> azurefd.net ->
  t-msedge.net`), which the v1.7 third-party-only catalog did not
  cover.
- **Twenty-six more fingerprint slugs seeded with relationship
  metadata.** v1.8.0 shipped 8 seeded slugs; v1.8.1 brings the total
  to 34 across openai, anthropic, salesforce, salesforce-mc,
  marketo, segment, meta, sendgrid, mailchimp, akamai, azure-tm,
  fastly, azure-fd, aws-acm, atlassian, workplace-meta, adobe-idp,
  adobe-sign, apple, onetrust, okta, 1password, jamf, stripe,
  docusign, google-site. Surfaced as the `fingerprint_metadata`
  block in `--json`.
- **FastMCP transport smoke test for the v1.8 graph tools.**
  `tests/test_mcp_graph_tools.py::TestMcpToolRegistry` invokes
  `get_infrastructure_clusters` and `export_graph` through
  `mcp.call_tool` — the same dispatch the stdio JSON-RPC handler
  uses on `tools/call`. Confirms registration + reachability beyond
  the unit tests.

### Validation

- 10-domain diverse deep-dive (one apex each from hyperscale tech,
  global payments, productivity SaaS, heavy-industrial manufacturing,
  higher-ed research, EHR, non-profit messaging, federal agency,
  warehouse retail, and national news media) re-run with caches
  cleared. `chain_motifs`: 0 -> 19 observations across 4 domains.
  `fingerprint_metadata`: 6 -> 29 distinct slugs surfaced, per-domain
  coverage 0-4 -> 4-16. Cluster partition quality preserved (the
  hyperscale-tech apex hit modularity 0.82 on 247 nodes).
- 1789 tests passing, 0 failed (was 1774 in v1.8.0 + 15 new
  regression tests). Ruff and pyright clean.

### Internal

- Repo-root `.gitignore` strengthened with `*.com.json`,
  `*.org.json`, `/v1_*_dive/`, `/sc-*.json` etc. patterns so ad-hoc
  validation lookups can't accidentally land in commits.
- MCP server banner tool count corrected from "19 total" to "20
  total" (the v1.8.0 banner forgot `cluster_verification_tokens`).

## [1.8.0] - 2026-05-03

**Graph correlation.** Second milestone of the v1.7-v1.9 build plan in
[`docs/roadmap.md`](docs/roadmap.md). Builds a structural layer on top
of the v1.7 cert intelligence: SAN co-occurrence becomes communities,
fingerprint metadata becomes ecosystem hyperedges, and absence rules
turn vertical profiles into hedged baseline checks. Zero new network
surface — every new field is a re-projection of evidence already in
the pipeline. See [`docs/correlation.md`](docs/correlation.md) for the
formal framing.

### Fixed

- **CertSpotter `Z`-suffix dates rejected on Python 3.10.**
  `build_cert_summary` called `datetime.fromisoformat()` directly on
  CertSpotter `not_before` / `not_after` strings, which end in `Z`.
  Python 3.10's parser rejects `Z` (only 3.11+ accepts it), so every
  CertSpotter cert entry was silently skipped and `cert_summary`
  returned None — disabling `top_issuers`,
  `wildcard_sibling_clusters`, `deployment_bursts`, and the
  `top_issuer` ecosystem hyperedge. New `_parse_iso_datetime()`
  helper in `recon_tool/sources/cert_providers.py` normalizes `Z` →
  `+00:00` before parsing. Pre-existing v1.7.0 bug surfaced by the
  v1.8 corpus validation. Regression test in
  `tests/test_cert_providers.py`.
- **`shared_slugs` ecosystem hyperedge noise floor.** Validation
  showed 195/200 hyperedges firing on trivial "every enterprise has
  Microsoft365 + Adobe + DocuSign" coincidences. `_MIN_SLUG_OVERLAP`
  raised 2 → 3, and a new `_baseline_slugs()` filter strips slugs
  with >50 % corpus prevalence (`_BASELINE_FREQ_THRESHOLD = 0.5`)
  from the overlap intersection before the threshold check. Adaptive
  per-batch — engages only when the batch exceeds
  `_MIN_BATCH_FOR_BASELINE = 5` so synthetic test fixtures stay
  deterministic. Two new tests in `tests/test_ecosystem.py`.

### Added

- **CT co-occurrence graph + Louvain communities** — new
  `recon_tool/infra_graph.py` builds an in-memory graph from cert
  entries (nodes = SAN hostnames, edges = shared-cert co-occurrence,
  attributes carry issuer name) and runs Louvain via pure-Python
  `networkx`. The report — algorithm, modularity, node/edge counts,
  cluster list — surfaces as the always-present top-level
  `infrastructure_clusters` envelope in `--json`. Capped at 500 nodes
  with deterministic connected-components fallback above the cap.
  Skipped envelope when no graph could be built.
- **`get_infrastructure_clusters` + `export_graph` MCP tools** —
  read-only exposure of the already-computed graph. The first emits
  the cluster envelope; the second emits the raw co-occurrence graph
  (nodes + weighted edges + cluster_assignment) for downstream Mermaid
  / GraphViz / CSV pipelines. Edges retained on the report up to
  `MAX_EDGES_RETAINED = 2000`, sorted by weight desc.
- **Fingerprint relationship metadata** — fingerprint YAML schema gains
  three optional fields: `product_family`, `parent_vendor`, and
  `bimi_org`. Eight built-in slugs now carry metadata (Microsoft 365,
  Google Workspace, GitHub, Cloudflare, Slack, AWS Route 53,
  AWS CloudFront, AWS SES). Surfaced as the always-present
  `fingerprint_metadata` map in `--json`, keyed by slug.
- **Ecosystem hypergraph (`recon batch --json --include-ecosystem`)** —
  new `recon_tool/ecosystem.py` builds cross-domain hyperedges of four
  types: shared CT top issuer, shared BIMI VMC organization, shared
  fingerprint parent_vendor, and pairwise fingerprint-slug overlap
  (≥2). Emitted as a `ecosystem_hyperedges` array sibling to the
  per-domain `domains` array in the batch JSON wrapper. Off by default;
  flag is mutually-exclusive with `--md`/`--csv`/`--ndjson`. Capped at
  `MAX_HYPEREDGES = 200`.
- **Vertical-baseline anomaly rules** — profile YAML gains
  `expected_categories` and `expected_motifs`. The new
  `compute_baseline_anomalies()` in `recon_tool/profiles.py` surfaces
  hedged "absence is observable, not a verdict" observations when an
  expected category/motif is missing from the result. Wired into the
  posture pipeline so anomalies appear inline with regular observations
  when `--profile` is set. Seeded for `fintech` and `healthcare`
  profiles.

### Schema

- New top-level fields (always emitted on per-domain `--json`):
  - `infrastructure_clusters` (object) — see
    [`docs/recon-schema.json#/$defs/InfrastructureClusterReport`](docs/recon-schema.json).
  - `fingerprint_metadata` (object) — see
    [`docs/recon-schema.json#/$defs/FingerprintMetadata`](docs/recon-schema.json).
- New batch wrapper shape (only when `--include-ecosystem` is set):
  `{ ecosystem_hyperedges: [...], domains: [...] }`. The hyperedge
  shape is documented under
  [`docs/recon-schema.json#/$defs/EcosystemHyperedge`](docs/recon-schema.json).
- All v1.8 fields are stable. `infrastructure_clusters.edges` is not
  emitted in the default JSON envelope (kept behind the `export_graph`
  MCP tool to bound payload size).

### Changed

- **Repo layout** — `claude-code/` and `clients/` consolidated into a
  unified `agents/` directory: `agents/claude-code/` (full plugin),
  plus per-client folders for Cursor, Windsurf, Kiro, and VS Code.
  Each agent folder ships its own MCP config + README. The unified
  index at [`agents/README.md`](agents/README.md) lists every
  supported client. README, `docs/mcp.md`, and `validation/README.md`
  link references updated; old `clients/` directory removed.
- **CT provider Protocol** — `CertIntelProvider.query()` now returns a
  3-tuple `(subdomains, cert_summary, infrastructure_clusters)`. Both
  built-in providers (`CrtshProvider`, `CertSpotterProvider`) compute
  the cluster report alongside the summary so the graph layer is
  populated on the same code path that already runs CT analysis.

### Internal

- New module `recon_tool/infra_graph.py` (105 stmts, 92% test coverage).
- New module `recon_tool/ecosystem.py` (97 stmts, 95% test coverage).
- 63 new tests across `tests/test_infra_graph.py`,
  `tests/test_ecosystem.py`, `tests/test_baseline_anomalies.py`,
  `tests/test_mcp_graph_tools.py`, plus extensions to
  `tests/test_fingerprints.py` and `tests/test_json_schema_contract.py`.
- `pyright` config gains `venv = ".venv"` + `include = ["recon_tool", "tests"]`
  so type-checking resolves through the editable install rather than
  any stale user-site `recon-tool` wheel that may be present.
- `networkx>=3.0` added as a runtime dependency. Pure-Python; ships no
  learned weights or aggregate intelligence.

### Validation gate

- Full pytest suite green (1774 passed, 0 failed). New v1.8 modules at
  92-95% line coverage. Ruff and pyright both clean across `recon_tool`
  and `tests`. JSON schema drift test updated.
- 105-domain corpus run with `--include-ecosystem` completed with **0
  errors**. Cluster partition quality on the 11 domains with
  buildable graphs: **mean modularity 0.563, max 0.883**. Fingerprint
  relationship metadata fired on **91 / 105** domains. The run
  surfaced two pre-tag hardening items (CertSpotter `Z`-suffix
  parsing, `shared_slugs` noise floor — see *Fixed* above); both
  were resolved and re-validated against the same corpus before
  tagging. Full report at
  [`validation/v1.8-validation-summary.md`](validation/v1.8-validation-summary.md).

## [1.7.0] - 2026-05-03

**Hardened-target signal recovery.** The first of the v1.7–v1.9 build plan
in [`docs/roadmap.md`](docs/roadmap.md). This release squeezes more usable
defensive intelligence out of CT logs and resolution chains we already
collect — every new field is a post-processing layer on existing passive
observables. Zero new network surface, zero new credentials, zero
ownership claims. See [`docs/correlation.md`](docs/correlation.md) for
the latent-variable framing.

### Added

- **Wildcard SAN sibling expansion** — when a CT cert covers `*.example.com`,
  recon now harvests every concrete (non-wildcard) SAN from that same
  cert as a candidate sibling cluster. Surfaced under
  `cert_summary.wildcard_sibling_clusters` in `--json`. Bounded
  (≤10 clusters, ≤20 names per cluster). Works for both crt.sh and
  CertSpotter providers.
- **Temporal CT issuance bursts** — co-issued cohorts inside a 60-second
  window with ≥3 distinct names become `cert_summary.deployment_bursts`
  entries: relative window deltas + name list. Output is intentionally
  relative — co-issuance is observable; "same owner" is not.
  Bounded (≤8 bursts, ≤25 names per burst).
- **CNAME chain motif library** — new `recon_tool/data/motifs.yaml` and
  loader at `recon_tool/motifs.py`. Each motif names an ordered
  proxy/CDN/origin shape (e.g. Cloudflare → AWS origin, Akamai → Azure
  origin); fires on a related subdomain's CNAME chain when its markers
  appear in order. Surfaced as a top-level `chain_motifs` array in
  `--json`. Catalog ships with 11 CDN→origin shapes covering the major
  cloud providers; users extend additively via `~/.recon/motifs.yaml`.
  Chain length capped at 4. Per-lookup observation cap at 50.
- **Cross-source evidence conflicts in `--json`** — top-level
  `evidence_conflicts` array (always present, empty when no conflicts).
  Each entry names a merged field where 2+ sources gave different
  values, with all candidates preserved. The legacy `conflicts` dict
  emitted under `--explain` is unchanged for backwards compatibility.

### Schema

- New stable v1.7+ top-level fields: `evidence_conflicts`, `chain_motifs`.
- New stable v1.7+ nested fields: `cert_summary.wildcard_sibling_clusters`,
  `cert_summary.deployment_bursts`.
- New `$defs` entries in `docs/recon-schema.json`: `EvidenceConflict`,
  `ChainMotif`, `CertBurst`.
- `docs/schema.md` updated with worked examples for each new field.

### Internal

- `models.py` gains `CertBurst`, `ChainMotifObservation`, and
  `serialize_conflicts_array()`.
- `cert_providers.py` `build_cert_summary()` now accepts SAN lists per
  cert entry; both providers attach `dns_names` to each cert metadata
  record so the wildcard / burst pipelines can consume them.
- `dns.py` `_classify_related_surface()` invokes the motif matcher
  alongside the existing `cname_target` rule classifier; results land
  in `_DetectionCtx.chain_motifs` and propagate through the merger.

### Validation gate

- 67 new/updated tests across `test_motifs.py`, `test_cert_providers.py`
  (wildcard cluster + burst paths), and `test_json_schema_*` (new
  fields + conflict-array shape). Every new feature carries explicit
  "does not fire when…" coverage alongside the positive case
  (per-roadmap discipline).
- Full private-corpus run is the user's responsibility (corpus is
  gitignored). The corpus delta will land alongside the v1.7.0 PyPI tag.

## [1.6.1] - 2026-05-03

**Patch release - streaming batch + 26 new fingerprints from a 4,270-domain
corpus run.** Re-ran the discovery loop on a 4.3x-larger private corpus
(~4,270 domains across 5 geos and 9 verticals), surfaced 1,620 unclassified
suffixes, triaged to 117 candidates, added 26 new ``cname_target``
fingerprints. Also fixes the "no visible progress on big batches" UX gap
discovered during the corpus run.

### Added

- ``recon batch --ndjson`` — streams one JSON object per line, flushed as
  each domain completes. Eliminates the buffer-everything-then-emit
  pattern of ``--json``. Recommended for any batch over a few hundred
  domains; gives visible progress and constant memory use. Mutually
  exclusive with ``--json`` / ``--md`` / ``--csv``. Skips post-batch
  enrichment (token clustering, tenant peers) because those need all
  results before any can emit; ``--json`` keeps the enrichment for
  smaller batches.
- ``validation/find_gaps.py`` and ``validation/diff_runs.py`` auto-detect
  input shape: JSON array, single JSON object, or NDJSON. Both also pick
  up ``*.ndjson`` files when scanning a directory.
- ``validation/scan.py`` defaults to NDJSON now (writes ``results.ndjson``);
  ``--json-array`` opts back into the legacy single-array shape.
- 26 new ``cname_target`` fingerprints from the corpus run:
  Paradox.ai Olivia, Jibe Apply, Career.page, Happydance Careers,
  EasyRedir, SAP Customer Data Cloud (Gigya), F5 Distributed Cloud
  (Volterra), Radware Cloud, ForgeRock Identity Cloud, IO River,
  Section.io, Azion Edge, Acquia Cloud, Pagely, Outreach, Zuddl,
  Postman Hosted Status, Site24x7, Salesforce Marketing Cloud
  (exacttarget.com / sfmc-content.com extension), AWS S3 Static
  Website, AWS EC2, Microsoft 365 China (svc.sovcloud.cn extension),
  Webflow proxy-ssl-geo extension, PagerDuty internal status page.
  Catalogue: 163 cname_target rules across ~95 unique slugs.

### Changed

- README MCP-Server section trimmed: the prominent ``> [!WARNING]``
  block was relocated. The full safety details still live in
  ``docs/mcp.md``; the soft "keep approvals manual" line below the
  config snippet remains in the README.

### Notes

- The streaming ``--ndjson`` mode trades batch-wide enrichment
  (``shared_verification_tokens``, ``tenant_id_peers``,
  ``display_name_peers``) for memory bound and visible progress. If you
  rely on cluster fields, use ``--json`` for batches that fit in memory.
- The corpus and run outputs stay private under
  ``validation/corpus-private/`` and ``validation/runs-private/``
  (gitignored). Only the generic patterns surfaced for triage become
  catalog additions.

## [1.6.0] - 2026-05-03

**Minor release - catalog grown from real validation.** Used the
v1.5.2 discovery loop on a curated 986-domain corpus spanning F500
US, US SMB, EU, APAC, LATAM, Africa/ME, government/edu/nonprofit,
B2B SaaS, and dev tools. Mined 548 unclassified terminal suffixes,
triaged to 46 high-quality candidates, added 17 new
``cname_target`` fingerprints. Adds an MCP discovery tool so AI
agents can mine candidates inline. Brand-stem heuristic catches
cross-zone same-brand abbreviations. Adds a ``scan.py`` wrapper
that bundles the four-step loop into a single timestamped
invocation suitable for monthly-cadence runs.

### Added

- 17 new ``cname_target`` fingerprints from the v1.6.0 corpus run:
  Swoogo (events), UptimeRobot (status), bl.ink (URL shortener),
  GoDaddy Workspace Email, cloud.gov (US federal PaaS), Pantheon
  (Drupal/WordPress hosting), jobs2web (recruiting),
  Presspage (PR), Localist (event calendar), RainFocus (event
  management), Squarespace external customer, HubSpot CMS EU CDN,
  Akamai staging zone, Azure App Service / Cloud Services VM
  pattern, AWS API Gateway (5 regions), AWS Network Load Balancer
  (5 regions). Catalog now has 137 cname_target rules across
  ~80 unique slugs.
- New MCP tool ``discover_fingerprint_candidates``. Wraps the
  ``recon discover`` pipeline so AI agents can mine fingerprint
  candidates without shelling out. Same input/output shape as the
  CLI subcommand.
- New ``validation/scan.py`` — bundles
  ``recon batch`` + ``find_gaps`` + ``triage_candidates`` +
  ``diff_runs`` into one timestamped invocation. Each scan writes
  ``results.json``, ``gaps.json``, ``candidates.json``, optional
  ``diff.json``, and ``meta.json`` capturing the run metadata.
  Designed for monthly-cadence drift detection on private corpora.
- Brand-stem abbreviation detection in
  ``recon_tool.discovery.looks_intra_org_brand``. Catches cases
  where a sibling zone uses an abbreviated brand label
  (``examplecorp.com`` → ``ec.net``). The 3-character prefix must
  appear as a standalone DNS label in the suffix; the 5-char
  brand-label floor avoids matching incidental short sequences.
- ``validation/README.md`` documents the monthly cadence with
  ``scan.py`` and the gitignored ``corpus-private`` /
  ``runs-private`` workspace convention.

### Changed

- Brand-label extractor now skips 5+ second-level public
  suffixes (``co``, ``ac``, ``com``, ``net``, ``gov``, ``edu``,
  ``ne``, ``or``, ``go``, ``mil``, ``biz``) when extracting the
  brand stem from a multi-part TLD apex.

### Notes

- The corpus run wasn't shipped to GitHub — only the framework is
  generic and committed; real corpora and run outputs stay local
  under ``validation/corpus-private/`` and ``validation/runs-private/``
  (gitignored).
- ``scan.py`` is the recommended entry point for recurring
  validation. Run monthly (or whatever cadence works) with
  ``--label`` to tag the run; subsequent runs auto-diff against
  the most recent prior unless ``--no-compare`` is passed.

## [1.5.2] - 2026-05-02

**Minor release - discovery loop in production.** Closes the gaps that
showed up the first time we used the v1.5.1 loop end-to-end on real
domains: batch / corpus runners couldn't opt into the discovery hooks,
the three-step pipeline was clunky for single-domain users, the
intra-org heuristic mis-handled multi-part TLDs, and CI's
validate-fingerprints check wasn't gating PyPI deploys. Also adds 11
new fingerprints surfaced from the first discovery-loop runs.

### Added

- New `recon discover <domain>` subcommand. Single-shot pipeline that
  resolves the domain with `--include-unclassified`, applies the
  intra-org and already-covered filters, and emits a candidate JSON
  consumable by the `/recon-fingerprint-triage` Claude skill. Replaces
  the three-command incantation for single-domain discovery.
- New `recon_tool/discovery.py` library: `find_candidates`,
  `extract_brand_label`, `looks_intra_org_brand`,
  `load_existing_patterns`. Shared between the `discover` command and
  the standalone `validation/` scripts.
- `recon batch` accepts `--include-unclassified` and `--no-ct`,
  matching the single-domain flags. Threaded through the resolver to
  the DNS source and into `format_tenant_dict`.
- `validation/run_corpus.py` plumbs the same two flags through to
  `run_batch_validation_sync`. Big corpus runs can now use the
  discovery hook and the polite-mode knob.
- Discovery-loop hint in `--full` panel: when `unclassified_cname_chains`
  is non-empty, a subtle dim-italic line invites the user into the
  catalogue-growth loop with the exact `recon discover <domain>`
  command. Default panel unchanged.
- 11 new fingerprints from the first production discovery runs:
  PingOne (`pingone.com`), Salesloft (`salesloft.com`), Pendo
  (`pendo.io`), Docebo (`docebopaas.com`), Skilljar (`skilljarapp.com`),
  Bizzabo (`bizzabo.com`), Instatus (`instatus.com`), Frontify
  (`frontify.com`), ReadMe (`readmessl.com`), WP Engine variant
  (`wpeproxy.com`), WorkOS variant (`workos-dns.com`).

### Changed

- Intra-org heuristic now skips second-level public suffixes (`co`,
  `ac`, `org`, `net`, `gov`, `edu`, ...) when extracting the apex's
  brand label. `contoso.co.uk` correctly resolves to brand `contoso`
  instead of `co`. Same brand-label extractor used by the
  `recon discover` subcommand and `validation/triage_candidates.py`.
- `release.yml` test job now runs the same `validate-fingerprints`
  check as `ci.yml`. Closes the gap where a duplicate-slug regression
  could reach PyPI through release.yml even though ci.yml caught it.

### Notes

- The discovery loop is now usable end-to-end with one command.
  `recon discover pingidentity.com` produces a candidate list, the
  Claude skill turns it into YAML stanzas, the user applies the diff
  and re-runs. Validated on this release: 11 new fingerprints came
  from running the loop on 10 fresh domains.
- No schema changes. v1.0 contract intact.

## [1.5.1] - 2026-05-02

**Minor release - fingerprint discovery loop.** Wires up the
machinery for growing the fingerprint catalog from real-world DNS
data: a JSON hook for unclassified CNAME chains, polite-mode knobs
for big runs, validation tooling that surfaces gap candidates, and
a Claude Code skill that turns those candidates into ready-to-apply
YAML stanzas.

### Added

- New `--include-unclassified` flag on `recon <domain>`. Adds an
  `unclassified_cname_chains` array to `--json` output: every CNAME
  chain the surface classifier resolved but couldn't attribute to a
  fingerprint. Wildcard echoes are filtered before this list is
  populated. Off by default (keeps the v1.0 schema narrow); on for
  the discovery loop.
- New `--no-ct` flag on `recon <domain>`. Skips crt.sh and
  CertSpotter entirely; discovery falls back to common-subdomain
  probes + apex CNAME walks. For high-volume validation runs where
  you want zero load on public CT services. Threaded through the
  resolver to the DNS source.
- New `validation/find_gaps.py` — reads a run (single JSON file or
  directory) and surfaces unclassified terminal hostname suffixes
  ranked by frequency. Filters intra-org chains.
- New `validation/diff_runs.py` — compares two run directories.
  Reports new attributions, lost slugs, aggregate slug-frequency
  changes. Use after adding fingerprints to confirm uplift.
- New `validation/triage_candidates.py` — programmatic filter on
  `gaps.json`: drops already-fingerprinted patterns (substring
  match against the catalog), intra-org chains, and one-off noise
  below `--min-count`. Output is the LLM-triage-ready candidate
  list.
- New Claude Code skill `agents/claude-code/skills/recon-fingerprint-triage/`
  that consumes either a single recon JSON or a `candidates.json`
  and proposes `cname_target` YAML stanzas with tier and category.
- New `UnclassifiedCnameChain` model + `unclassified_cname_chains`
  property on the v1.0 JSON schema (optional, surfaced only with
  `--include-unclassified`).
- `.gitignore` carve-outs: `validation/corpus-private/`,
  `validation/runs-private/`, `validation/local/`. Users can curate
  private corpora without risk of leaking targets.

### Changed

- `recon_tool/fingerprint_validator.py` cross-file duplicate-slug
  check is now name-aware. A slug appearing in multiple files is a
  duplicate only when display names disagree; same-slug, same-name
  across files is the legitimate "split detection rules across
  files" pattern that `surface.yaml` uses to extend apex
  fingerprints with cname_target rules. (This also unblocked the
  v1.5.0 CI regression.)
- `validation/README.md` rewritten to document the discovery loop,
  the polite-mode knobs, the gitignored corpus convention, and how
  to contribute back generic patterns.

### Notes

- The discovery loop is opt-in. Default `recon <domain>` output is
  unchanged; the JSON contract is unchanged unless
  `--include-unclassified` is passed.
- Programmatic vs LLM split is intentional: deterministic noise
  filtering happens in `triage_candidates.py`, judgment calls
  (real SaaS vs intra-org, tier, category, slug canonicalization)
  happen in the skill.

## [1.5.0] - 2026-05-01

**Minor release - external surface attribution.** Per-subdomain
classification of related domains via CNAME chain walks, surfacing
SaaS and infrastructure providers that don't publish apex DNS
verification tokens. The default panel surfaces newly-attributed
slugs through the existing `Services` block; `--full` adds an
`External surface` section that lists each subdomain alongside its
primary service.

The classifier walks the CNAME chain (cap 5 hops, 30 concurrent
queries, 100 hosts max) for each related domain collected from
crt.sh, CertSpotter, and the common-subdomain probe. Application-tier
matches (Auth0, Shopify, Zendesk, Mailgun, Apigee, ...) take
precedence over infrastructure-tier matches (Fastly, CloudFront,
Akamai, Cloudflare, ...) when both appear in the same chain. The
full chain stays in the JSON `evidence` array for `--explain`
consumers.

### Added

- New `cname_target` detection type in the fingerprint YAML schema,
  with a `tier: application | infrastructure` field that governs
  attribution precedence when a chain matches both.
- New `surface.yaml` fingerprint file seeding 50+ application and
  infrastructure CNAME-target patterns drawn from live validation
  across a private corpus spanning consumer goods, payments, retail,
  productivity SaaS, and national news media apexes.
- `surface_attributions` field on `TenantInfo` and the JSON output;
  see `docs/recon-schema.json` for the schema definition.
- `External surface` section in `--full` panel output: two-column
  subdomain → service map, sorted alphabetically.
- New AWS slugs: `aws-app-runner`, `aws-global-accelerator`. New
  third-party slugs: `apigee`, `mulesoft`, `submittable`,
  `loop-returns`, `attentive`, `iterable`, `intercom`, `hubspot`,
  `cloudflare-pages`, `github-pages`.

### Changed

- `_VALID_DETECTION_TYPES` extended with `cname_target`. Existing
  `cname` rules continue to fire on the apex / common-subdomain
  probes; the new type fires on every related domain's CNAME chain.
- Several surface-attribution slugs categorize as Cloud rather than
  the Business Apps fallback: `aws-app-runner`,
  `aws-global-accelerator`, `mulesoft`, `cloudinary`, `apigee`,
  `heroku`, `webflow`, `cloudflare-pages`, `github-pages`.
- Test `test_all_fingerprint_slugs_unique` now allows duplicate
  fingerprint names when the slug also matches (same logical
  service split across YAML files); name collisions on different
  slugs are still a failure.

### Notes

- A-only related domains (no CNAME) remain unclassified. Recovering
  those requires ASN/IP intelligence, which the project's invariants
  exclude.
- The classifier adds at most 100 CNAME queries per lookup, run with
  concurrency 30 — roughly a 2-5x increase in DNS volume on domains
  with sprawling CT footprints. Observed wall-clock impact on the
  validation corpus was under 1s per domain.

## [1.4.8] - 2026-04-29

**Patch release - skill refinements from running it in anger.** Docs-only.
Seven friction points surfaced from real skill use against the v1.4.7
artifact have been smoothed in `agents/claude-code/skills/recon/SKILL.md` and
`AGENTS.md`. No behavior, schema, or fingerprint changes.

### Changed

- MCP-vs-CLI decision is now explicit: agents look at their available-tools
  list for `recon:*` tools rather than calling speculatively to test
  connectivity.
- "Picking a profile" now shows both CLI (`--profile <name>`) and MCP
  (`analyze_posture(domain, profile="<name>")`) invocation syntax.
- `recon delta` section calls out the cache location (`~/.recon/cache/`)
  and the first-run empty-diff case so agents do not report "no changes"
  when there is no baseline to compare against.
- Default mode includes a collapsed sample panel so a cold reader of the
  skill knows what "relay verbatim" actually delivers.
- New "Explain mode" section documents `--explain` and the MCP
  `explanation_dag` field with guidance on summarising the provenance
  chain rather than dumping it.
- Full-mode headline template cites `docs/recon-schema.json` v1.0 so
  future skill editors know where the field-name contract lives.
- Output-size guidance is concrete ("3–10 KB depending on org size")
  instead of "several KB".

## [1.4.7] - 2026-04-29

**Patch release - machine-readable JSON schema.** Adds the v1.0 stable
contract as a committed JSON Schema artifact so downstream consumers
(agents, CI pipelines, SDKs in other languages) can validate
`recon <domain> --json` output without re-deriving the shape from sample
runs. No behavior, fingerprint, or formatter changes.

### Added

- `docs/recon-schema.json` — JSON Schema 2020-12 description of the
  `recon <domain> --json` v1.0 contract, including a `$defs/DeltaReport`
  entry consumers can target for `recon delta` validation.
- `tests/test_json_schema_file.py` — drift guard that fails CI when the
  emitted JSON output and the committed schema fall out of sync in
  either direction (extra output key not declared, or required schema
  field not emitted).
- README — agent-driven install snippet ("paste this prompt to your AI"
  with the stable raw.githubusercontent.com SKILL.md URL) so users with
  AI clients that have file-write tools can wire up the skill in one
  exchange. Pointer to the new schema artifact for downstream
  validators.

### Changed

- `tests/conftest.py` — promoted the fully-populated `TenantInfo`
  fixture from `test_json_schema_contract.py` to a shared pytest
  fixture so the new drift-guard tests use the same object without
  cross-test imports.

## [1.4.6] - 2026-04-29

**Patch release - skill best-practices alignment.** Docs-only change. No
behavior, schema, or fingerprint changes. Refines the Claude Code skill
and portable AGENTS.md against the official Anthropic skill-authoring
guidance and the `anthropics/skills` reference repo.

### Added

- `agents/claude-code/skills/recon/SKILL.md`: `argument-hint` and `allowed-tools`
  fields in skill frontmatter (per Claude Code skill spec).
- "Before first invocation" section: install probe via `recon --version`
  with explicit user approval before `pip install` — useful when the skill
  is loaded outside the bundled plugin (e.g., copied into Kiro skills).
- "Two invocation modes" section: default mode relays the CLI panel
  verbatim; `--full --json` mode writes to disk and replies with a 3-line
  headline so structured output never floods the conversation context.
- Evidence-citation guidance in the output-voice rules — fingerprint
  claims should reference the record type (MX, TXT, CNAME, etc.).

### Changed

- Tightened skill description; trigger phrases and exclusions still
  surface for skill auto-loading.
- AGENTS.md mirrors the SKILL.md body so Kiro / agents.md-aware tools
  pick up the same install-probe and two-mode invocation patterns.

## [1.4.5] - 2026-04-29

**Patch release - multi-client integration assets.** Docs-only change. No
behavior, schema, or fingerprint changes. Adds drop-in install assets so
Claude Code, Kiro, Windsurf, Cursor, and VS Code users can wire up the recon
MCP server and pick up agent guidance without re-deriving it per session.

### Added

- `agents/claude-code/` — full Claude Code plugin scaffold with `.claude-plugin/plugin.json`,
  `.mcp.json` MCP server registration, and a `skills/recon/SKILL.md` skill that
  teaches Claude when and how to use recon in recon's neutral-observation voice.
- `agents/{kiro,windsurf,cursor,vscode}/` — copy-pasteable MCP config snippets
  and per-client install matrix for non-Claude-Code agents. (Originally
  shipped under `clients/`; consolidated into `agents/` in v1.8.0.)
- `AGENTS.md` at repo root — portable agent guidance in the
  [agents.md](https://agents.md) format. Auto-detected by Kiro and other
  agents.md-aware tools; can be referenced from `.windsurfrules`,
  `.cursor/rules/`, or `.github/copilot-instructions.md`.
- `docs/mcp.md` — Kiro added to the per-client config table; PATH gotcha
  expanded to cover all GUI Electron clients.

### Changed

- README links the new `agents/claude-code/` plugin, sibling `agents/` folders, and
  `AGENTS.md` so users of any supported AI client can find their install path.

## [1.4.4] - 2026-04-27

**Patch release - fingerprint hardening and packaged validator reliability.**
Keeps the public surface stable while tightening broad built-in fingerprint
patterns, making catalog validation work from installed wheels, and grounding
the next roadmap work in validation metrics.

### Added

- Fingerprint match-mode audit reports now include catalog health metrics:
  total fingerprints, detection-rule count, match-mode distribution, metadata
  coverage, and weighted-detection count.
- Roadmap and contributor docs now call out measured fingerprint-library
  priorities, metadata expectations, weak-area notes, and MCP/catalog
  consumption guidance.

### Changed

- Broad Marketo, dmarcian, EasyDMARC, Akamai, AWS ELB, and AWS S3 fingerprint
  substrings were tightened and documented with detection descriptions.
- The 50-domain live validation pass completed with 50 successes, no errors,
  no partial results, no low-confidence results, and only optional `crt.sh`
  degradation observed by `recon doctor`.

### Fixed

- `recon fingerprints check` now uses a packaged validator module instead of
  shelling out to a repo-local `scripts/validate_fingerprint.py` path, so the
  stable command works from installed distributions.

## [1.4.3] - 2026-04-27

**Patch release - validation-driven reliability and local-safety hardening.**
Keeps the public surface stable while bounding long-running MCP state,
tightening local cache paths, and fixing passive DNS/fingerprint edge cases
found during review.

### Changed

- The exposure terminology guard now acts as neutral-copy guidance for
  recon-authored prose, not as a runtime blocklist for domain names, evidence
  strings, or caller phrasing.
- Certificate-transparency ingestion now bounds response processing before
  filtering and sorting, reducing CPU and memory spikes from very large
  provider responses.
- Release workflow OIDC permission tests now pin least-privilege publishing
  scope to the publish job.

### Fixed

- Ephemeral MCP fingerprints now have per-session, per-fingerprint, and total
  detection caps to prevent unbounded process growth.
- CSV batch output now neutralizes spreadsheet formula prefixes in exported
  cells.
- Fingerprint specificity validation now reuses regex safety checks and skips
  specificity evaluation when schema validation already failed.
- Result-cache and CT-cache domain operations now validate and normalize
  domain input before constructing paths, blocking traversal outside cache
  directories.
- Reverse DNS hosting detection now skips non-global A records before issuing
  PTR lookups.
- Subdomain TXT fingerprints now require `subdomain:regex` format, and the
  affected built-in records use explicit subdomain prefixes.

## [1.4.2] — 2026-04-26

**Patch release — doctor status calibration and documentation cleanup.**
Keeps runtime behavior stable while making optional enrichment outages less
alarming and tightening public documentation organization.

### Changed

- `recon doctor` now reports `crt.sh` outages as `WARN` optional enrichment
  degradation instead of a hard `FAIL`. Core source failures still render as
  `FAIL`.
- Documentation is now organized from `docs/README.md`; `docs/roadmap.md` is
  forward-looking and no longer duplicates `CHANGELOG.md`.
- MCP, release, stability, limitations, fingerprint, signal, and weak-area docs
  were refreshed to remove stale counts, stale version wording, and outdated
  command references.

### Removed

- Removed tracked `CLAUDE.md` and added it to `.gitignore`; agent-local guidance
  should stay local instead of shipping in the public repository.

## [1.4.1] — 2026-04-26

**Quality release — sparse-result diagnosis and validation-driven
hardening.** Keeps the public product surface stable while improving how
thin passive evidence is explained, compared, and audited.

### Added

- **Sparse-result diagnosis.** Thin default-panel output now distinguishes
  edge-heavy footprints, custom or self-hosted mail, minimal public DNS, and
  generic sparse public signal cases. The wording remains hedged and points
  users at the passive-only weak-area guidance.
- **Semantic validation comparisons.** Live corpus runs now compare
  per-domain provider, confidence, partial/degraded state, services, slugs,
  and sparse diagnoses. Comparison artifacts classify changes by severity and
  by type (`regression`, `improvement`, `mixed`, `review`, `neutral`).
- **Fingerprint match-mode audit tooling.** New validation helpers audit
  multi-detection fingerprints and classify them as alternate evidence,
  corroborating evidence that needs review, or broad patterns that should be
  tightened before any `match_mode: all` change.

### Changed

- Validation summaries now include sparse-diagnosis rollups so weak-area
  trends are visible across a corpus run.
- Sparse-diagnosis insights are promoted earlier in the default panel so a
  thin run reads as an explained passive result.

### Fixed

- Version metadata fallback and `uv.lock` now track the package version
  consistently.

## [1.4.0] — 2026-04-21

**Hardening release — parser, cache, MCP server coherence, and a
sharper sense of scope.** Targets the three hot paths that real
validation runs have stressed most (malformed upstream responses,
cache round-trips under adversarial inputs, MCP server state
transitions), rebundles the MCP server into the default install,
exposes the fingerprint / signal / profile catalogs as MCP
resources, adds staleness timestamps to every result, and uses the
roadmap to state plainly what recon is — and what it deliberately
leaves to sister tooling.

### Changed

- **MCP is bundled in the default install again.** `pip install
  recon-tool` now installs the `mcp` runtime dependency directly; the
  `recon-tool[mcp]` extra is no longer required. Users who had been
  installing the extra keep working unchanged; users who had avoided
  MCP on purpose can still choose not to run `recon mcp`. No public
  API or CLI surface changed.
- Documentation (`README.md`, `SECURITY.md`, `docs/mcp.md`,
  `docs/security.md`, `docs/stability.md`) updated to reflect the
  bundled-MCP default and the expanded MCP threat model.
- **Fictional-example policy codified and enforced across the tree.**
  The project no longer commits real-company apex domains as examples,
  targets, test corpora, or regression fixtures. Rationale: no upside
  from naming real orgs in a passive-recon tool's public materials;
  accumulating reputational, trademark, and defamation exposure over
  the lifetime of the repository and its forks. See the new
  "Fictional-example policy" section in `CONTRIBUTING.md` for the
  full rule and carve-outs (vendor/product detection names and the
  upstream service hostnames recon itself queries are unaffected).
- **`tests/fixtures/corpus-public.txt` removed.** The 40 real-apex
  corpus previously bundled for `recon fingerprints test <slug>` is
  no longer in-tree. The command now looks for `~/.recon/corpus.txt`
  first, falls back to a new fictional-only `tests/fixtures/
  corpus-example.txt`, and prints a banner when the example file is
  in use so operators know zero matches are expected. Supply your own
  corpus with `--corpus path/to/file` to exercise real detections.
  `docs/performance.md` rewritten to describe methodology without
  naming specific targets.
- **Historical CHANGELOG entries sanitized.** v1.3.0 and v1.2.0
  narrative prose that named specific real apexes has been rewritten
  to describe the behavior in neutral terms. No functional content
  was lost; dated release facts remain intact.
- **`/validation/` gitignore carve-outs.** The directory remains
  ignored for local corpora and result artifacts, with three tracked
  exceptions: `validation/run_corpus.py` (the runner, no company
  names), `validation/corpus-example.txt` (fictional format demo),
  and `validation/README.md` (policy + usage).

### Added

- **MCP resources — `recon://fingerprints`, `recon://signals`,
  `recon://profiles`.** Agents can browse the three catalogs as
  read-only JSON without spending a tool invocation on introspection.
  Each resource is a deterministic projection over the already-loaded
  YAML catalogs (no network calls) — the same data that powers
  `recon fingerprints list` / `recon signals list` / `recon profiles
  list` in the CLI. Changes require `reload_data` to take effect.
- **Staleness timestamps — `resolved_at` and `cached_at` on every
  `TenantInfo`.** `resolved_at` is stamped when live resolution
  produces the result; `cached_at` is populated only by the on-disk
  cache read path. Both flow through the JSON serializer so agents
  can tell at a glance whether they are looking at fresh data or a
  2-minute-old cache hit, and decide whether to re-resolve. Cache
  round-trips preserve `resolved_at` — it reflects when the data was
  first produced, not when the cache entry was last written.
- Reusable live-validation tooling around the existing diverse 50-domain
  corpus. `recon_tool.validation_runner` now summarizes batch JSON,
  compares runs, renders markdown summaries, and
  `validation/run_corpus.py` executes a corpus run through the public
  CLI entrypoint and writes `results.json`, `summary.json`, and
  `summary.md`.
- `docs/roadmap.md` now opens with an explicit "What recon is (and
  what it isn't)" section naming recon as the passive-DNS primitive
  and pointing active scanning, credentialed enrichment, company
  research, and GTM briefing generation at sister tooling. The
  "Intentionally out of scope" list grew accordingly (remote / HTTP
  MCP transport, firmographic enrichment, news / funding / hiring
  feeds, verdicted maturity scores) so external contributors know
  what will be declined up front.

### Fixed

- Hardened malformed-upstream handling for `crt.sh`, CertSpotter, Azure
  metadata, OIDC discovery, and GetUserRealm so invalid or unexpected
  JSON shapes fail explicitly instead of collapsing into generic error
  paths.
- Tightened cache safety and correctness: cache and CT cache now use
  path containment on read/write paths, reject traversal consistently,
  preserve empty `display_name` values on round-trip, and narrow
  filesystem/JSON exception handling.
- Closed MCP server state gaps: cache reload now clears rate-limiter
  state, re-evaluation refreshes cached tenant info, ephemeral
  fingerprint clearing re-merges cached detections, and in-flight tenant
  lookups reserve and release rate-limit slots atomically.
- Reworked fingerprint derived caches into a lock-coherent typed cache
  state so ephemeral inject/clear/reload operations keep detection and
  M365-derived views consistent.

### Validation

- Added regression coverage for malformed upstream bodies, cache
  traversal and round-trip edge cases, server in-flight lookup
  semantics, ephemeral fingerprint cache invalidation, and
  validation-runner summaries.
- Quality gate green on release prep: `pytest tests` (1585 passed, 4
  deselected), `ruff check .`, and `pyright recon_tool tests`.

## [1.3.1] — 2026-04-21

**Security patch — six findings resolved.** External static-analysis
pass surfaced a cluster of low-to-medium issues, mostly reachable only
via local CLI or MCP stdio, but all worth closing. No behavior changes
for legitimate use; each fix tightens a containment boundary that was
previously relying on trust rather than enforcement.

### Fixed

- **Unbounded ephemeral fingerprint injection (MCP DoS)** — Medium.
  ``inject_ephemeral_fingerprint`` had no cap; a long-running MCP
  server could be driven into unbounded memory growth by a
  prompt-injected client calling the tool in a loop. Added a
  ``_MAX_EPHEMERAL_FINGERPRINTS = 100`` cap in
  ``recon_tool.fingerprints``; the MCP tool surfaces capacity
  errors as clean JSON rejections (``EphemeralCapacityError``).
- **Release workflow OIDC scope** — Medium. ``id-token: write`` was
  granted at the workflow level, meaning ``test`` and ``build`` jobs
  (which install and execute dependency code) could mint PyPI
  trusted-publisher tokens. Compromised dependency = publishing
  artifact under our identity. Workflow default is now
  ``contents: read``; each job opts into the scope it actually needs.
  Only ``publish-pypi`` and ``github-release`` request elevated
  permissions.
- **CSV formula injection** — Medium. ``display_name`` originates
  from the attacker-influencable ``FederationBrandName`` response
  and was written verbatim to CSV cells. A value starting with ``=``
  / ``+`` / ``-`` / ``@`` / ``\t`` / ``\r`` would execute as a
  formula when the CSV is opened in a spreadsheet. Added
  ``_csv_safe`` which prefixes unsafe leading characters with a
  single quote; applied to every textual field in
  ``format_tenant_csv_row``.
- **Specificity gate unbounded regex** — Low. ``evaluate_pattern``
  compiled and searched regexes against the synthetic corpus
  without the length cap that ``_validate_regex`` enforces at
  schema-validation time. A pathological regex submitted via PR,
  MCP ephemeral injection, or ``recon fingerprints new`` could
  hang CI or the local wizard. Added a 500-char length guard in
  ``evaluate_pattern`` itself so the gate is safe even when called
  outside the schema validator.
- **Cache clear path traversal** — Low. ``recon cache clear
  <domain>`` forwarded the raw domain to ``cache.cache_clear``
  which built a path directly from it. A crafted argument like
  ``../../.config/settings`` escaped the cache directory and
  unlinked whatever ``.json`` file the user could touch. Added
  ``_safe_cache_path`` using ``Path.is_relative_to`` plus an input
  character guard; traversal attempts now return ``False``
  (nothing deleted) rather than following the path.
- **CT cache ``_safe_path`` prefix-bypass** — Low. The containment
  check used ``str(path).startswith(str(cache_dir.resolve()))`` —
  path-prefix rather than path-aware. A crafted domain like
  ``../ct-cache-malice/evil`` resolved to a sibling directory whose
  path string still matched the prefix. Replaced with
  ``Path.is_relative_to`` and added a character-level input guard.
  Same class of bug as the cache-clear traversal; same fix shape.
- **PTR lookup on private IPs** — Low. ``_detect_hosting_from_a_record``
  unconditionally reverse-resolved the apex A-record IP, including
  RFC1918 / loopback / link-local addresses. A malicious domain
  could publish an A record pointing to an internal IP and the
  tool would ask the operator's resolver for the internal PTR —
  leaking internal DNS names into recon's output. Added
  ``ip.is_private or ip.is_loopback or ip.is_link_local or
  ip.is_reserved or ip.is_multicast`` check before the PTR query.
- **crt.sh unbounded accumulation** — Low. ``filter_subdomains``
  added every matching name into a set, then sorted the full set
  before slicing to ``MAX_SUBDOMAINS``. A domain with a very large
  CT history (tens of thousands of entries) would force the whole
  set into memory and sort it. Added a ``hard_cap = max_count * 10``
  break during accumulation — enough headroom to still prioritize
  high-signal subdomains correctly, bounded enough that no single
  domain can spike CPU.

### Validation

- Full quality gate: ruff check + format clean, pyright 0 errors,
  bandit 0 issues, actionlint clean.
- Pytest: 1550 pass (prior count).
- Each fix is targeted at a reported finding; none of them change
  observable behavior for legitimate input (no CHANGELOG entries
  needed in user-facing docs beyond this one).

## [1.3.0] — 2026-04-21

**Portfolio discovery in batch mode.** When ``recon batch`` resolves
multiple domains, the JSON output now surfaces two new correlation
signals: cryptographically-strong tenant-ID sharing (same M365
customer account) and hedged display-name overlap (same brand after
normalization). Uses data already collected — zero new network
calls, zero new sources.

### Added

- **Tenant-ID clustering (``shared_tenant``)**: When 2+ domains in a
  batch share the same Microsoft 365 tenant ID, each domain's JSON
  entry carries a ``shared_tenant`` list naming the other peers.
  Cryptographically strong — same tenant ID = same M365 customer
  account. Not hedged; this is provable via OIDC discovery. Three
  sibling apexes belonging to the same corporate group collapse to a
  shared peer set in the batch output.
- **Display-name clustering (``shared_display_name``)**: When 2+
  domains' tenant display names normalize to the same key,
  each entry carries a ``shared_display_name`` list with the raw
  display names (for audit), the normalized key, and the peer
  domains. Conservative match — exact normalized equality only
  (``Acme Corp`` + ``Acme Corp.`` cluster; ``Acme`` + ``Acme Holdings``
  do not). Normalization strips one trailing corporate suffix
  (``inc`` / ``llc`` / ``gmbh`` / etc.) and collapses whitespace /
  punctuation.
- ``recon_tool.clustering.compute_tenant_clusters`` and
  ``compute_display_name_clusters`` — pure functions exposed for
  the MCP server and external consumers who want to run the
  clustering on their own ``TenantInfo`` lists. 11 new unit tests
  covering the tenant / display-name paths.

### Use case

Portfolio discovery on a candidate domain list. An IT reseller or
M&A analyst runs ``recon batch portfolio.txt --json`` and the output
names which apexes belong to the same corporate group, without any
additional lookups. Pairs well with the existing
``shared_verification_tokens`` clustering for a three-tiered signal:

- **Tenant-ID match** — provable, same customer account.
- **Display-name match** — hedged, same brand text.
- **Verification-token match** — hedged, same operator-scoped
  credential.

The JSON fields are independent — a pair can appear in one, two, or
all three. Downstream consumers rank them however they like.

### Validation

- Portfolio smoke test on a three-apex group sharing a single M365
  tenant and display name: all three fields populate correctly with
  symmetric peer lists.
- Full test suite: 1550 pass (1539 + 11 new clustering tests).
- Static gate: ruff + format + pyright + bandit + actionlint all
  clean.

## [1.2.1] — 2026-04-21

**Security patch.** The MCP ``inject_ephemeral_fingerprint`` tool
validated schema but bypassed the v1.2 specificity gate. A caller
could inject a pattern like ``cname:\.com$`` and poison every
subsequent lookup in that session with false positives. Blast radius
was small (in-memory, per-session, could not persist), but the gate
is cheap and worth enforcing everywhere the catalog accepts input.

### Fixed

- ``inject_ephemeral_fingerprint`` now runs every detection pattern
  through ``recon_tool.specificity.evaluate_pattern`` and rejects the
  injection with a clear diagnostic when any pattern exceeds the 1%
  synthetic-corpus match threshold. Same gate as
  ``recon fingerprints check`` and ``recon fingerprints new``, so
  the three ingress paths are now consistent.

### Validation

- Expanded validation sweep against a 31-domain weak-area corpus
  (heavy-Cloudflare, higher-ed, Chinese/APAC, regulated verticals,
  EU fintech, self-hosted, IDN). All 31 resolve without error;
  sparse results on thin-signal domains are honest, not empty.
- Security audit pass on userrealm.py (defusedxml + xml_escape both
  confirmed in use), the ``recon fingerprints check`` subprocess
  path (list form, sys.executable, no shell), and the MCP rate
  limiter (monotonic clock, soft cap, no bypass via table-flood).
  No other findings.

## [1.2.0] — 2026-04-21

**Contribution trust.** v1.1 gave contributors the plumbing; v1.2 adds
the guards that make contributions *safe to merge*. A
pattern-specificity gate rejects over-broad regexes before review; a
scaffolding wizard runs every check before emitting YAML; a test
command resolves a new fingerprint against a public domain corpus so
contributors can see what it actually matches. No engine changes, no
new detections — the point is that the next wave of detections
(community or solo) can't accidentally poison the catalog.

### Added

- **Pattern-specificity gate** (`recon_tool/specificity.py`). Every
  detection regex is now matched against a synthetic adversarial
  corpus of ~1500 strings spanning TXT / SPF / MX / CNAME / NS. If a
  pattern matches more than 1% of the corpus, `recon fingerprints
  check` rejects it as over-broad. The threshold is calibrated so all
  227 built-in entries pass, while a deliberately-broad pattern like
  `cname:\.com$` fails with a clear diagnostic. Off by default with
  `--skip-specificity` for debugging; on by default for PRs and CI.
- **`recon fingerprints new <slug>`** — scaffolding wizard. Prompts
  for name, category, detection type, pattern, optional description
  and reference. Runs three guards before emitting YAML: (1) slug
  uniqueness against the built-in catalog, (2) schema validity,
  (3) specificity. Prints a paste-ready entry or writes to a file
  via `--output`.
- **`recon fingerprints test <slug>`** — runs one fingerprint against
  a domain corpus and reports which match. Contributors point at their
  own corpus with `--corpus path/to/file` or drop a list at
  `~/.recon/corpus.txt`. Helps answer "is my regex too loose or too
  tight" without hand-resolving DNS.
- **`tests/fixtures/corpus-example.txt`** — fictional-company example
  corpus showing the expected file format. Real-company corpora are
  never committed; see CONTRIBUTING.md for the rationale. (Note:
  earlier point releases bundled a public-companies corpus; it was
  removed in v1.4.0.)
- **`docs/weak-areas.md`** — honest list of deployment shapes where
  recon looks sparse by design (heavy-CDN orgs, Chinese / APAC tech
  stacks, regulated verticals behind web proxies, fully self-hosted
  shops, parked / portfolio apexes). Names what the sparse result
  actually means and what to do instead of over-interpreting it.
  Linked from limitations.md.
- **`docs/performance.md`** — published batch wall-clock and memory
  numbers (50 / 100 / 500 domains), methodology for reproducing,
  per-step time budget. Stops users from guessing where the latency
  goes.

### Changed

- **`scripts/validate_fingerprint.py`** — now runs the specificity
  gate on every pattern in addition to the runtime schema check and
  cross-file duplicate-slug check. `--skip-specificity` opts out
  when debugging.
- **CONTRIBUTING.md** — fingerprint PR section updated for the new
  `fingerprints new` / `test` / `check` workflow. New "engine changes
  go through a design doc" heads-up before the signals section —
  fingerprints are data and can iterate freely; signal / fusion /
  absence engines are inference code and bad changes affect every
  domain recon analyses.

### Deferred to post-1.2

- **Bulk fingerprint additions.** Each QA round during v1.2 planning
  suggested 20-100 new fingerprints, mostly based on pattern-matching
  `<vendor>-domain-verification=` by analogy. Spot-checks showed
  most of those patterns don't exist — the SaaS in question uses
  account-based verification or API-key auth rather than DNS.
  Catalog growth is welcome but each entry needs vendor-doc
  verification, which is proper v1.2+ work. The infrastructure in
  this release makes each new entry a small PR going forward.

**Contribution-ready.** The fingerprint catalog is now one file per
category, new CLI inspect commands let contributors audit the data
without opening YAML, and CI gained an `actionlint` gate so the kind
of unresolvable-action-ref regression that broke the first v1.0.2 tag
can't reach `main` again. No user-visible detection or output changes
in this release — this is infrastructure for everything that comes
next.

### Added

- **Per-category fingerprint layout** — ``recon_tool/data/fingerprints.yaml``
  (one 60KB file, 235 entries, 8 duplicate slugs) is now
  ``recon_tool/data/fingerprints/`` (8 per-category files, 227 unique
  slugs, zero duplicates). The eight files:
  - ``ai.yaml`` — AI / LLM providers, agent frameworks.
  - ``email.yaml`` — email platforms, gateways, DMARC / DKIM tooling.
  - ``security.yaml`` — EDR, SIEM, IdP, zero-trust, credential hygiene.
  - ``infrastructure.yaml`` — cloud, CDN, DNS, CAs, CI/CD.
  - ``productivity.yaml`` — suites, helpdesk, HR, knowledge.
  - ``crm-marketing.yaml`` — CRM, sales intel, ad platforms.
  - ``data-analytics.yaml`` — warehouses, BI, observability.
  - ``verticals.yaml`` — education, nonprofit, payments, misc.
  The loader globs ``data/fingerprints/*.yaml`` in sorted order; custom
  ``~/.recon/fingerprints.yaml`` still works as a single file and a
  new ``~/.recon/fingerprints/`` directory is also accepted for users
  who want per-category organization of their overrides. Slug order
  after load is deterministic and identical to the monolith except
  for the 8 duplicates, which are now collapsed into single entries
  with their detection rules merged.
- **``recon fingerprints list`` / ``show`` / ``check``** — contributor
  and user inspection commands for the fingerprint catalog.
  - ``list`` supports ``--category`` substring and ``--type`` exact
    filters, plus ``--json`` for scripting.
  - ``show`` renders the full definition (detection rules, patterns,
    descriptions, references) for a single slug. Synthetic slugs
    (``exchange-onprem``, ``self-hosted-mail``) that are emitted by
    source-layer probes rather than loaded from YAML are documented
    here too — users who see those slugs in their output can always
    find provenance without grepping code.
  - ``check`` validates the catalog against the runtime schema and
    surfaces cross-file duplicate slugs. Wraps
    ``scripts/validate_fingerprint.py`` with sane defaults.
- **``recon signals list`` / ``show``** — same pattern for the signal
  catalog. ``show`` surfaces candidates, metadata conditions,
  contradictions, requires-signals chains, expected-counterparts,
  and positive-when-absent lists — everything the absence and
  two-pass evaluators look at.
- **``actionlint`` in pre-commit and CI.** Catches unresolved action
  refs, bad shell in ``run:`` blocks, and deprecated expressions at
  commit time and in a dedicated ``workflow-lint`` CI job. The
  v1.0.2 release regressed because ``astral-sh/setup-uv@v8`` isn't a
  real floating tag; ``actionlint`` catches that class of error
  locally and in CI. Pinned to ``actionlint@v1.7.12``.
- **``scripts/split_fingerprints.py``** — the one-shot migration
  script that produced the split, kept in the repo for audit. A
  reviewer can re-run it against the pre-split monolith to verify
  the split is reproducible.

### Changed

- **``scripts/validate_fingerprint.py`` now accepts a directory** and
  pools slugs across files for a cross-file duplicate-slug check.
  Single-file invocation is unchanged — directories are an additive
  capability for the split-catalog layout.

### Docs

- **CONTRIBUTING.md** updated for the split-catalog layout —
  "find the right file" step added, PR template checklist swapped to
  the new ``recon fingerprints check`` command, fingerprint-add
  recipe now shows ``recon fingerprints show <slug>`` as the
  post-add verification step.
- **CLAUDE.md** reflects 227-fingerprint count (down from 235) and
  the new ``data/fingerprints/`` directory layout.

### Process guards

The first v1.0.2 tag push failed because ``astral-sh/setup-uv@v8``
isn't a published floating tag — only ``v8.0.0`` and ``v8.1.0`` exist.
Two guards now prevent that class of regression:

1. ``actionlint`` runs in pre-commit on every commit touching
   ``.github/workflows/``.
2. ``actionlint`` runs as the first job in CI so PRs with unresolved
   action refs fail at the workflow-lint stage, before any Python
   work executes.

Before future tag pushes, verify each bumped action ref exists with
``gh api repos/<owner>/<repo>/git/refs/tags/<ref>`` — especially for
actions that don't publish floating majors.

## [1.0.2] — 2026-04-20

**Polish pass.** Toolchain current, test suite pyright-clean, dead code
removed, seven bug fixes surfaced by CLI edge-path audits, provider
attribution improved for self-hosted mail, "we looked and found nothing"
now returns a sparse result instead of an error. Validated against
450 domains across eight corpora (international banking, pharma,
mining, telecom, logistics, government agencies, UN / NGO bodies, EDU /
state gov, DTC startups, plus a 50-domain diverse-industry sweep
covering big tech, automotive, luxury, fast food, Chinese giants,
aerospace, and retail) with zero errors and zero regressions.

### Added

- **Python 3.13** added to the CI test matrix and the package
  classifiers. Supported runtimes are now 3.10 / 3.11 / 3.12 / 3.13.
- **Dependabot** configured for GitHub Actions and Python dependencies
  with weekly cadence and patch/minor grouping.
- **README badges** — CI status, PyPI version, supported Python
  versions, license.
- **CI pyright scope now covers `tests/`** so type-annotation drift
  can't re-accumulate the way it did (652 errors pre-polish → 0 now).

### Changed

- **Email security score is now an inventory, not a grade.** The
  score line went from `Email security 3/5 good (DMARC reject, DKIM,
  SPF strict)` → `Email security 3/5: DMARC reject, DKIM, SPF strict`
  → `Email security: DMARC reject, DKIM, SPF strict`. The verdict
  adjectives (`weak` / `basic` / `moderate` / `good` / `strong` /
  `excellent`) came out first — we see apex DNS, not the full posture,
  so a graded assertion is more than the tool can honestly make. The
  `N/5` fraction came out next: even without the adjective, `3/5` was
  read as "mediocre" and the controls aren't equally weighted anyway
  (DMARC `reject` is load-bearing, BIMI is decorative). The machine-
  readable `email_security_score` field stays in `--json` for
  consumers that genuinely need to sort or filter. The same `/5`
  stripping now extends to `--posture` and `--exposure` panels and
  to `compare_postures` assessment summaries so the format stays
  consistent everywhere.
- **Provider attribution no longer over-credits on-prem Exchange.**
  Large orgs with self-operated mail infrastructure used to fall
  through to `Exchange Server (on-prem / hybrid)` as the primary
  provider whenever `owa.<apex>` / `autodiscover.<apex>` resolved,
  even when the public MX clearly routed through their own
  operator-owned mail hostnames. A synthetic `self-hosted-mail`
  slug now fires when MX records exist and none of them match a
  recognized cloud provider or gateway fingerprint, and that slug is
  recognized as a primary email provider in the topology computation.
  The Exchange on-prem detection still fires as a secondary service
  signal in the same output, so the hybrid-identity reality of these
  orgs is still visible — it's just no longer promoted to the
  Provider line. Roughly a third of the diverse 50-domain validation
  corpus got more accurate Provider lines as a result, most of them
  large industrial and APAC orgs running self-operated mail.
- **DKIM inference behind commercial gateway.** When MX points to a
  commercial email gateway (Proofpoint, Mimecast, Cisco IronPort,
  Barracuda, Trend Micro, Trellix, Symantec) AND DMARC is enforcing
  (`quarantine` or `reject`), the score now credits DKIM with the
  annotation `DKIM (inferred via Proofpoint)` (etc.). Fortune-500
  orgs with enforcing DMARC almost always DO sign with DKIM — just at
  custom selectors the tool can't enumerate. Without this inference
  the apex score penalized orgs for a control they effectively have.
  The inference chain is visible in the score string so the user can
  audit it.
- **`partial=True` semantic tightened.** The JSON `partial` flag now
  fires only when a core source (OIDC, UserRealm, Google Identity,
  DNS) is degraded — not when a CT provider (crt.sh, CertSpotter) is
  degraded. CT pipelines are chronically flaky and the code handles
  their degradation gracefully via fallback + cache, so they shouldn't
  flip the global `partial` bit. The per-source status is still
  surfaced in the `degraded_sources` list for consumers who want the
  detail.
- **GitHub Actions bumped to current majors** — `checkout v4 → v6`,
  `setup-python v5 → v6`, `setup-node v4 → v6`, `upload-artifact v4 →
  v7`, `download-artifact v4 → v8`, `setup-uv v5 → v8`,
  `action-gh-release v2 → v3`. Node 20 deprecation warnings are now
  gone; `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround removed since
  all pinned actions target Node 24 natively.
- **"All sources empty, no errors" returns a sparse `TenantInfo`**
  instead of raising `ReconLookupError`. "We looked and found nothing"
  is a valid observation, not a failure. Previously, a domain with
  no detectable patterns would get a hard error in single-domain
  lookups and an `error` entry in batch output; now both paths emit
  a clean result with `provider = "Unknown (no known provider
  pattern matched)"`. Raising is reserved for the case where every
  source actually failed.

### Removed

- **Three more narrative-judgment signals** in the same class as
  Shadow IT Risk / Complex Migration Window / Governance Sprawl
  (retired in v1.0.1). None were observation — they stitched two
  observable facts into a critique that only DNS can't actually make.
  - `Security Stack Without Governance` — "security investment may
    lack email-layer controls" is opinion; the two underlying
    observations (security tools + DMARC not enforcing) are already
    visible on their own lines.
  - `AI Adoption Without Governance` — inferred "shadow AI
    deployment" from absence of specific IDPs; speculative.
  - `DevSecOps Investment Without Email Governance` — inferred that
    engineering security investment "hasn't extended to email";
    pure narrative.
- **Dead code in `sources/dns.py`** — `_safe_resolve_sync` and
  `_set_resolver` had no callers (including tests). The sync resolver
  helper was for a testing pattern that's no longer in use; the
  resolver override was never wired up.

### Docs

- **`docs/roadmap.md` trimmed from 631 → 207 lines.** The historical
  per-release detail now points to CHANGELOG.md (source of truth);
  the post-1.0 ethos and "intentionally out of scope" sections kept
  but tightened. Invariants and priority order stay front and center.
  Added a concrete v1.1 target describing the planned split of
  `fingerprints.yaml` into per-category files — design sketch, scope
  breakdown, non-goals, and the reason it waits for v1.1 (coherent
  with the community-contribution pipeline).
- **`docs/signals.md` trimmed from 130 → 74 lines.** Large
  auto-generated signal table removed (signals.yaml itself is the
  source of truth and shorter). Design rules section added listing
  retired signals and the invariant each violated, so contributors
  can see why something wouldn't be accepted before proposing it.
- **`docs/fingerprints.md` tightened.** Detection-types table kept.
  Added a concrete "Testing a new fingerprint" recipe. Email security
  score table updated for the gateway-inferred DKIM path. Removed
  implementation-detail notes about enrichment tiers that belonged in
  code comments, not user docs.

### Fixed

- **Test suite pyright-clean.** 652 errors → 0. `tests/` execution
  environment relaxes `reportPrivateUsage` (tests legitimately
  white-box private APIs) and parameter-type rules (pytest fixtures
  inject by name), but keeps structural checks on. Fixture generators
  get proper `Iterator[T]` return types; test assertions now
  null-guard before calling `re.match`; unused destructured variables
  are prefixed with `_`.
- **`recon cache clear` now actually clears everything for a domain.**
  Previously it only cleared the CT subdomain cache at
  `~/.recon/ct-cache/`; the TenantInfo result cache at
  `~/.recon/cache/` was left untouched and silently served stale
  JSON on subsequent runs. This surfaced during validation — after
  updating recon, a cached TenantInfo result kept showing retired
  signals like "AI Adoption Without Governance" even after a
  `cache clear <apex>`. The command now clears both caches and
  reports each count separately; `cache_clear` / `cache_clear_all`
  helpers added to `cache.py`.
- **`recon doctor` no longer emits empty error messages.** Many
  `httpx` exception classes (`ReadTimeout`, `ConnectTimeout`) raise
  with an empty message string, so `str(exc)` rendered as
  `FAIL  crt.sh (cert transparency) — ` with nothing after the em-
  dash. A module-level `_fmt_exc(exc)` helper falls back to
  `type(exc).__name__` when the message is empty; applied
  everywhere in `cli.py` that previously did `render_error(str(exc))`
  on a catch-all `Exception`.
- **Wildcard-DNS guard on Exchange-on-prem detection.** Domains that
  point `*.<apex>` at a single IP (so every subdomain resolves to
  the same address) used to trigger every probed prefix in
  `_detect_exchange_onprem` and get mislabelled as running Exchange
  Server. The detector now probes a nonsense prefix and bails when
  it also resolves — an unambiguous wildcard signature.
- **IDN / Punycode domains accepted.** The validator regex anchored
  the TLD at `[a-z]{2,}`, which rejected every `xn--`-prefixed TLD
  (e.g. `xn--p1ai` for Russian, `xn--fiqs8s` for Chinese). The
  pattern now allows letters, digits, and internal hyphens in the
  TLD (letter-first, alphanumeric-last, min two chars) so IDN
  domains are accepted while numeric and hyphen-bracketed TLDs
  still reject.
- **`--profile` no longer a no-op without `--posture`.** Profile
  lenses only apply to posture observations, so running
  `recon <domain> --profile fintech` without a posture-enabling
  flag silently produced identical output to `recon <domain>`.
  Passing `--profile` now auto-enables posture rendering.
- **Hardening Controls panel renders colored check marks.** The
  `--exposure` panel built its ✓/✗ line with f-string Rich markup
  (`[green]✓[/green]`) appended to a `Text` object. `Text.append`
  does not parse markup, so those tags rendered as literal text.
  Style is now passed via the `style=` kwarg.

### Refactor

- **Test file names de-versioned.** Fourteen test files named after
  the QA round or release when they were written (e.g.
  `test_v090_absence.py`, `test_v093_clustering.py`) renamed to
  their subject matter (`test_absence_engine.py`,
  `test_clustering.py`, etc.) via `git mv` so history is preserved.
  Docstring leading lines also stripped of the `v0.9.x — QA Round
  N:` preamble. Post-1.0 the version of introduction is no longer
  meaningful context for where tests live.

## [1.0.1] — 2026-04-20

**Accuracy & reliability pass** driven by a 150-domain validation sweep
across large, mid-size, and regional targets in multiple regions and
industries. All fixes stayed inside the project invariants
(passive-only, zero credentials, no engine expansion, hedged output).

### Fixed

- **`autodiscover.<apex>` no longer false-positives `exchange-onprem`
  on Microsoft 365 cloud tenants.** The detector queried type A and
  relied on dnspython returning empty when the name was a CNAME to
  `autodiscover.outlook.com`. dnspython chases CNAMEs on type-A
  queries, so M365 domains were flagging as on-prem. The detector now
  queries CNAME first for `autodiscover` and suppresses when the
  immediate target is in the M365 cloud zone
  (`*.outlook.com` / `*.office.com` / `*.cloud.microsoft` /
  `*.mail.protection.outlook.com` / `*.office365.com`). Genuine
  hybrid Exchange (CNAME to org-owned infra, or direct A) still
  fires. Other prefixes (`owa`, `outlook`, `exchange`, `mail-ex`,
  `webmail`) keep the A-or-CNAME path — those names are on-prem-only
  when they resolve. See `sources/dns.py::_detect_exchange_onprem`,
  regression tests in `test_dns_subdetectors.py::TestExchangeOnpremAutodiscover`.

- **`GoogleIdentitySource` no longer claims "Managed" Workspace on
  every domain.** The `_is_workspace_domain` heuristic searched the
  `accounts.google.com/ServiceLogin` response body for the `hd=`
  parameter and the word `"identifier"`. Both are always present in
  Google's sign-in page (the URL parameter is echoed verbatim into
  the body, and the page is an identifier-capture form), so the
  check returned `True` for every queryable domain — including
  fabricated ones. The body heuristic is removed. Managed Workspace
  customers are still detected via the DNS fingerprint path (MX
  `aspmx.l.google.com`, SPF `_spf.google.com`, DKIM
  `google._domainkey`, GWS module CNAMEs to `ghs.googlehosted.com`).
  A federated IdP redirect still triggers the `Federated` detection.
  This removes the cascade of phantom "Dual Email Provider",
  "Google-Native Identity", and "Google Cloud Investment" insights
  from M365-primary targets.

- **`cisco-identity` TXT no longer mis-attributed as the SSO IdP.**
  The slug fires on the `cisco-ci-domain-verification=` TXT token,
  used by many Cisco products (Duo, Customer Identity, Secure Email,
  Intersight) — not specifically the org's SSO IdP. Removed from
  `_IDP_SLUG_MAP` in `insights.py`; the federated-auth insight now
  correctly falls back to the generic `ADFS/Okta/Ping` line when
  no dedicated IdP evidence is present. The slug still emits the
  `Cisco (Identity)` service fact.

- **12% of big-enterprise lookups timed out at the 120s aggregate
  budget — now 0%.** Root cause: when CertSpotter rate-limited with
  HTTP 429, `_RetryTransport` slept **30s × 3 retries = 90s** per
  query while CertSpotter's own application code already handled 429
  by breaking the pagination loop. HTTP-layer retry was fighting
  application-layer handling and burning the aggregate budget.
  `http_client(retry_transient=False)` is a new flag that skips
  `_RetryTransport`; CertSpotter opts in. Page-level
  `@retry_on_transient` on `_fetch_page` also removed for the same
  reason (3 × 8s = ~25s of accumulated delay on slow-CT targets).
  Single-domain lookup time on the worst-case targets went from 120s
  (timeout) to 2-12s.

### Changed

- **`CertSpotter _MAX_PAGES` 4 → 2, `_CT_TIMEOUT` 8 → 6,
  `MAX_RELATED_ENRICHMENTS` 25 → 15.** Budget tightening to reduce
  per-domain fan-out under batch concurrency. Two CertSpotter pages
  still cover ~500 certs, and the enrichment cap is prioritised so
  high-signal subdomain prefixes (auth, login, sso, api, …) survive.

### Removed

- **`Shadow IT Risk` signal.** Framed sanctioned enterprise SaaS
  (Canva / Mailchimp / Airtable) as "shadow IT risk" at any scale.
  Violated the "observable facts in neutral language" invariant and
  misread the common-case consumer-brand SaaS footprint of a large
  org as a defect.
- **`Complex Migration Window` signal.** Narrative synthesis on top
  of "security stack + dual-provider email" observations. The tool
  can observe the two inputs; it cannot observe that a migration is
  in progress. Violated the "no timeline narrative generation"
  invariant.
- **`Governance Sprawl` signal.** Depended on `Shadow IT Risk`.
- **`expected_counterparts` on `AI Adoption` and
  `Agentic AI Infrastructure`.** Produced "Missing Counterparts"
  absence insights like `AI Adoption — Missing Counterparts: Lakera,
  Okta, CyberArk, Beyond Identity` on nearly every AI-adopting
  target. The listed slugs were vendor recommendations, not
  observable co-occurrence relationships — their absence does not
  constitute a defect observable from DNS. The
  `expected_counterparts` mechanism itself remains available for
  user-customised signals in `~/.recon/signals.yaml`; no built-in
  signal currently uses it.

### Note on exit codes

Sparse-evidence domains (zero slugs, zero services, no provider pattern
matched) previously raised `ReconLookupError` in the CLI path, printed
"No information found for {domain}", and exited with code 3
(`EXIT_NO_DATA`). They now render a clean `Unknown` panel and exit 0.

- Scripting consumers that relied on exit code 3 as "no data found"
  must switch to checking the JSON output's `provider` field for
  `"Unknown (no known provider pattern matched)"` or the empty
  `services` / `slugs` lists.
- Exit code 3 still fires when the resolver genuinely can't get a
  clean result from *any* source (all sources errored). That's rare.
- Exit code 4 (`EXIT_INTERNAL`) is unchanged.

### Note on upgrade

- `google_auth_type` is now `None` more often: the source only
  populates it on a genuine federated redirect. Any consumer that
  depended on the previous "Managed" default on every domain was
  consuming a bogus signal — switch to the DNS-backed
  `primary_email_provider` / slug set instead.
- Consumers relying on `Shadow IT Risk`, `Complex Migration Window`,
  or `Governance Sprawl` in the signals output will no longer see
  those names. No replacement — the underlying observations (consumer
  SaaS slugs, dual-provider detection, security stack) are still
  present in the slug/service set.

## [1.0.0] — 2026-04-17

**Stability commitment.** recon is now 1.0. From this release forward,
all surfaces tagged **stable** in `docs/stability.md` will not break
between patch or minor releases. Breaking changes require a major
version bump and a deprecation window.

### Added

- **`docs/security.md`** — engineering-level threat model. Trust
  boundaries, attack surface, mitigations with file:line refs
  (validator.py domain regex, http.py SSRF protections, fingerprints.py
  ReDoS heuristic, ct_cache.py path-traversal guard), known limitations
  (DNS rebinding with sub-second TTLs), out-of-scope.
- **`docs/limitations.md`** — honest inventory. What recon can't see
  (Copilot/Gemini, heavily proxied domains, internal services,
  network-level facts), what it underclaims on (bundled AI, dormant
  dual-provider, sovereignty when OIDC is silent), known noise
  patterns, when to reach for something else.
- **`docs/schema.md`** — JSON output contract. ~45 stable fields
  documented with types, nullability, allowed values. Nested object
  shapes for `cert_summary` and `bimi_identity`. Experimental fields
  (`slug_confidences`) separately tagged.
- **`tests/test_json_schema_contract.py`** — conformance tests that
  assert every stable field is present and correctly typed on both
  rich and sparse fixtures.
- **`scripts/release.py`** — semi-automated release flow. Clean-tree
  check, version-bump consistency, CHANGELOG entry check, quality gate
  (ruff + pyright + pytest + coverage), git commit + tag, confirm-to-push.
  `--dry-run` flag for testing.
- **`docs/release-process.md`** — full release documentation. Human
  half (`scripts/release.py`), automated half (GH Actions), pre-release
  checklist, hotfix workflow, yanking a broken release, SemVer
  commitment, Python support policy.

### Changed

- **`docs/stability.md`** — fully expanded. Full CLI flag table, all 17
  MCP tools (stable), full list of stable JSON fields, CLI exit codes,
  YAML schema commitments, Python support policy (CPython N-2 = 3.10,
  3.11, 3.12).
- **JSON output — always-present fields.** `detection_scores`,
  `cert_summary`, and `bimi_identity` are now always present in
  `--json` output (null when unavailable) rather than conditionally
  emitted. Backward compatible for consumers that check
  `field is not None`; slight breaking change for consumers that
  relied on `field in payload` as a presence check. This was a
  schema-conformance fix for 1.0.
- **Dev Status classifier** — `pyproject.toml` updated from
  `Development Status :: 4 - Beta` to
  `Development Status :: 5 - Production/Stable`.

### Roadmap

- All v1.0 deliverables shipped. `docs/roadmap.md` updated accordingly.
- Post-1.0 ideas (NetworkX graph, portfolio detection, temporal CT
  evidence, feedback-driven posterior tuning) remain in the roadmap as
  non-commitments.

## [0.11.0] — 2026-04-17

Community & confidence. The biggest build yet. Three themes:
(1) `--confidence-mode strict` drops hedging qualifiers when evidence
is dense. (2) Community fingerprint pipeline enables outside
contributions without drowning in bad YAML. (3) Bayesian fusion
(experimental) replaces the three-bucket detection-score threshold
with a principled per-slug posterior.

### Added

- **`--confidence-mode {hedged,strict}`** CLI flag. Default `hedged`
  (unchanged). `strict` drops hedging qualifiers ("observed",
  "likely", "indicators") on dense-evidence targets (High confidence
  + 3+ corroborating sources). Sparse-data output is never touched —
  the "never overclaim when evidence is thin" invariant stays
  load-bearing. New module `recon_tool/strict_mode.py`.
- **Community fingerprint pipeline.**
  - `scripts/validate_fingerprint.py` — local validator that runs the
    same checks recon uses at runtime (regex safety, required fields,
    detection types, weight range, `match_mode`). Exits 0/1 with
    per-entry error messages.
  - `CONTRIBUTING.md` — new fingerprint submission section with
    validate command, chained-pattern guidance, PR checklist.
  - `.github/ISSUE_TEMPLATE/fingerprint_request.md` — structured
    template for requesting new fingerprints.
  - `.github/PULL_REQUEST_TEMPLATE/fingerprint.md` — structured
    template for fingerprint PRs.
  - `.github/workflows/ci.yml` — new `validate-fingerprints` job that
    runs on every PR.
- **Bayesian fusion (experimental).** New module `recon_tool/fusion.py`.
  Pure-Python Beta conjugate update. Per-source priors ranked by
  informational content (OIDC > DKIM > MX > TXT > A/CNAME). Opt-in
  via `--fusion`. Emits `slug_confidences` tuple on TenantInfo and
  in `--json` output. Tagged **experimental** — algorithm and field
  shape may evolve.
- **`docs/stability.md`** — stability policy for 1.0. Lists stable
  vs experimental surfaces. Documents what "stable" means
  (backward-compat guarantee between patch and minor releases).

### Changed

- No behavior change by default. Strict mode, fusion, and the
  community pipeline are all opt-in or additive.

## [0.10.3] — 2026-04-17

MCP agent ergonomics. The server now self-documents so AI clients
call tools correctly without prompt babysitting. All changes stay
inside the local-stdio-only invariant — no HTTP transport, no
hosted mode, no server mode.

### Added

- **Rich Server Instructions.** FastMCP is now initialized with a
  3400-character instructions block that injects a user manual
  into the model's context every session. Covers: when to use
  which tool, composition patterns (`lookup_tenant` → `analyze_posture`
  → `simulate_hardening`), the passive-only invariant, confidence
  semantics, and when to use `explain=True`.
- **`recon doctor --mcp`** flag. Validates the MCP server setup:
  mcp package installed, server module imports cleanly, Server
  Instructions present, tools enumerate, `recon` on PATH. Emits
  copy-pasteable JSON config for Claude Desktop, Cursor, VS Code +
  Copilot, and Windsurf.
- **Windsurf config** documented in `docs/mcp.md`
  (`~/.codeium/windsurf/mcp_config.json`).
- **PATH gotcha note** for GUI MCP clients (Claude Desktop,
  Windsurf) that don't inherit the shell PATH. Includes the
  `python -m recon_tool.server` fallback pattern.

### Changed

- No behavior change in the MCP tools themselves. Just better
  agent ergonomics on top of the existing surface.

## [0.10.2] — 2026-04-17

Passive coverage depth. Three targeted expansions to detection
coverage and run-over-run intelligence, all staying inside the
passive / zero-creds / per-domain-storage invariants.

### Added

- **Medium-tier subdomain enrichment.** New `medium_subdomain_lookup`
  in `sources/dns.py` adds MX + DKIM probing on top of the lightweight
  CNAME + TXT tier for the highest-signal subdomain prefixes (`auth`,
  `sso`, `login`, `idp`, `api`, `mail`). Catches SaaS and email tenants
  that publish verification records on subdomains distinct from the
  apex. Capped at 6 subdomains per lookup to stay within the DNS budget.
- **`recon delta <domain>`** CLI command. Reads the previous cached
  `TenantInfo` from `~/.recon/cache/`, runs a fresh lookup, diffs
  services / slugs / auth / DMARC / confidence / email-security-score,
  and updates the cache with the new snapshot. No manual export file
  required. The existing `--compare previous.json` flag still works
  for explicit baselines.
- **Chained fingerprint pattern documentation.** Added a `match_mode: all`
  section to `docs/fingerprints.md` explaining how to require multiple
  detections (across record types) before a fingerprint fires.
  Infrastructure has been in place since earlier versions; now documented
  for contributors.

### Changed

- **Resolver enrichment pipeline.** `_enrich_from_related` now splits
  capped subdomains into medium-tier (top-signal prefixes, MX + DKIM)
  and lightweight (everything else, CNAME + TXT only). Separate domains
  continue to get the full DNS lookup.

### Roadmap

- Added **v0.10.3 — MCP agent ergonomics** (Server Instructions, tool
  docstring polish, `recon doctor --mcp`).

## [0.10.1] — 2026-04-16

Provider accuracy + UX depth. Follow-up to v0.10 that addresses
structural detection issues exposed during real-world validation:
SSO hub mislabeling, DKIM undercount on Fortune 500 targets,
service miscategorization, and the "everyone has both providers"
noise problem.

### Added

- **Generic DKIM selector probing.** dns.py now probes `s2`,
  `dkim`, `mail`, `k2` as TXT records on top of the existing
  Exchange (`selector1`/`selector2`), Google (`google`), and ESP
  selectors. Large enterprises using non-standard selectors now
  get DKIM credit on the email security score instead of
  "No DKIM selectors observed" false negatives.
- **`email_confirmed_slugs` parameter** in `detect_provider()`.
  Filters slug-based secondary providers to only those with MX
  or DKIM evidence — dormant account registrations no longer
  clutter the Provider line.

### Changed

- **SSO hub label.** `federated-sso-hub` slug display changed
  from "Shibboleth / SAML SSO hub" to "SSO hub". A DNS A record
  at `sso.domain.com` can't distinguish Entra ID from Okta from
  Shibboleth — the previous label overstated what the tool
  knows. Okta and ADFS specific detections (via `okta.*` /
  `adfs.*` subdomains) keep their specific labels.
- **Service categories rethink.**
  - `"Other"` renamed to `"Business Apps"` across
    `_SERVICE_CATEGORIES_ORDER`, `_CATEGORY_BY_SLUG`, and
    `_categorize_service()`.
  - Microsoft Teams, XMPP/Jabber, Slack → Collaboration (was
    Business Apps / Other).
  - Intune / MDM → Identity (was Business Apps / Other).
- **Gateway + DKIM → confirmed primary.** `_compute_email_topology`
  now promotes gateway+DKIM evidence to `primary_email_provider`
  (confirmed) instead of `likely_primary_email_provider`
  (inferred). DKIM proves the provider signs mail for this
  domain — that's not inference, it's confirmation. Weaker non-MX
  evidence (TXT, OIDC, UserRealm) still sets `likely_primary`.
- **Provider-line secondaries filtered.** Dormant account
  detections (M365 tenant exists but no DKIM or MX evidence) no
  longer show as "(secondary)" in the default Provider line.
  They still appear in `--full` and `--json` output.

### Example diffs

Hybrid-Exchange target before: `Provider     Exchange Server (on-prem / hybrid) behind Trend Micro gateway + Microsoft 365 (account detected) + Google Workspace (account detected)`

Hybrid-Exchange target after: `Provider     Microsoft 365 (primary) via Trend Micro gateway + Google Workspace (secondary)` — M365 confirmed via DKIM, GWS confirmed via DKIM too.

GWS-primary target before: `Provider     Google Workspace (primary) + Microsoft 365 (secondary)`

GWS-primary target after: `Provider     Google Workspace (primary)` — M365 tenant exists but has no MX/DKIM evidence, so it's not shown in the default Provider line.

## [0.10.0] — 2026-04-16

CT resilience + UX overhaul. Two themes: (1) when live CT providers
both fail, a per-domain cache serves as fallback; (2) the default
panel output is now tight enough for a CEO glance — zero redundancy
between header, services, and insights.

### Added

- **Per-domain CT cache.** New `recon_tool/ct_cache.py` stores CT
  provider results as JSON files in `~/.recon/ct-cache/{domain}.json`.
  Seven-day default TTL, one file per domain, no aggregated store.
  Successful provider queries automatically populate the cache.
- **CT cache fallback.** When both crt.sh and CertSpotter are
  degraded, the fallback chain now checks the per-domain CT cache
  before returning an empty subdomain set. The panel shows "CT: from
  local cache, N days old" so users know they're seeing cached data.
- **Cache CLI commands.**
  - `recon cache show [domain]` — inspect cache state for a domain
    or list all cached domains with subdomain counts and age.
  - `recon cache clear [domain]` — remove cache for a specific domain.
  - `recon cache clear --all` — remove all cached CT data.
- **Cache age in panel output.** When CT data comes from cache, the
  Note section shows "CT: from local cache, N days old (M subdomains)"
  in info tone (not warning) so it reads as a recovery event, not an
  error.
- **`ct_cache_age_days` field** in JSON output — `null` when data
  comes from a live provider, integer when from cache.

### Changed

- **`_detect_cert_intel()` now caches on success.** Every successful
  CT provider query writes to the per-domain cache, so future
  degraded runs have fresh fallback data.
- **Degraded-source rendering** updated to distinguish live fallback
  ("CT fallback: crt.sh → certspotter") from cache fallback ("CT:
  from local cache, 3 days old").
- **UX overhaul — insight curation.** Aggressive dedup: 18
  restatement prefixes dropped (insights that just re-list services
  already visible in the categorized block). Default mode caps at 5
  insights + email score; `--full` shows all. Vague labels like
  "Complex Migration Window" and "Governance Sprawl" cut entirely.
- **UX — Email row cleanup.** Protocol config (DKIM, DMARC, SPF,
  MTA-STS, BIMI, TLS-RPT, Exchange Autodiscover) removed from the
  default Email services row — the email security score insight
  already covers these. Provider-line services (M365, Google
  Workspace, gateway) also stripped from Email to eliminate
  duplication. `--full` still shows everything.
- **UX — no decorative color.** Section headers changed from
  `bold cyan` to `bold`. Color reserved for functional meaning
  (green=high confidence, yellow=warning) per modern CLI norms.
- **UX — CT note suppressed.** Routine "CT fallback: crt.sh →
  certspotter" notes suppressed in default output — infrastructure
  plumbing that added noise on nearly every run. Cache fallback
  and actual warnings still surface.
- **Provider accuracy.** When Exchange Autodiscover AND an M365
  tenant are both detected, the Provider line now reads "Microsoft
  365 via [gateway]" instead of "Exchange Server (on-prem / hybrid)".
  On-prem only leads when no M365 tenant is found (e.g. vatican.va).
- **Bundled AI inference.** M365 presence → "Microsoft Copilot
  (likely)" in Services > AI. Google Workspace → "Google Gemini
  (likely)". Hedged with "(likely)" to distinguish from DNS-
  confirmed detections like Anthropic.

## [0.9.4] — 2026-04-16

Infrastructure-only release. No feature changes. Toolchain and release
hygiene to make the 1.0 stability commitment credible.

### Added

- **`SECURITY.md`** — vulnerability reporting policy at the repo root
  (GitHub's standard location). Separate from the `docs/security.md`
  threat model planned for 1.0.
- **Pre-commit hooks** — `.pre-commit-config.yaml` with Ruff (lint +
  format) and Pyright. Prevents bad code from reaching CI.
- **`pip-audit` in CI** — dependency vulnerability scanning runs on
  every PR and every release build.
- **Coverage gate** — CI now fails if test coverage drops below 80%.
  Current coverage: 87%.
- **`uv.lock`** — reproducible builds via uv lockfile. Development
  workflow uses `uv sync --extra dev`; end-user install instructions
  (`pip install recon-tool`) are unchanged.

### Changed

- **MCP packaging changed in this release.** At the time, `pip install
  recon-tool` no longer pulled in the MCP dependency tree. Current
  releases ship the MCP server in the default install; see the README
  for up-to-date packaging guidance.
- **CI migrated from pip to uv.** Both `ci.yml` and `release.yml` now
  use `astral-sh/setup-uv@v5` for faster, reproducible installs.
- **Trusted Publisher on PyPI** — release pipeline already uses
  OIDC-based publishing via `pypa/gh-action-pypi-publish`; no static
  API tokens.

### Developer notes

- `pip install -e ".[dev]"` still works but `uv sync --extra dev` is
  now the recommended development workflow.
- Pre-commit can be activated with `pre-commit install` after cloning.
- `pip-audit` is included in the `[dev]` extra for local use.

## [0.9.3] — 2026-04-15

This release is the *Sparse-Target Amplification + UX Refinement* pass.
Themes: (1) extract more hedged signal from the same passive sources —
especially on heavily-proxied, minimal-DNS, managed-auth targets where
older releases went silent; (2) redesign the default CLI output so
professional users never feel like they're looking at hobbyist-grade dump
output; (3) validation-driven fixes from real-world runs against EDU,
nonprofit, religious, and sparse commercial targets. Everything stays
within the passive / zero-creds / zero-additional-network invariants.

### Validation-driven refinements

- **Categorized Services refinements**:
  - `"AWS Route 53"` renders as `"AWS Route 53 (DNS)"` under Cloud so
    the row can't be misread as "primary cloud = AWS". Same treatment
    for `azure-dns`, `gcp-dns`, CDN providers (`(CDN)`),
    edge/serverless platforms (`(edge)`), and WAFs (`(WAF)`).
  - `google-managed` / `google-federated` slugs render as
    `"Google Workspace (managed identity)"` / `"(federated identity)"`
    instead of the raw slug.
  - CAA issuer fingerprints collapse to one `"CAA: N issuers
    restricted"` entry instead of four separate rows overwhelming
    Security.
  - `"CAA: "` prefix stripped when a CAA-derived fingerprint is
    classified in a non-Security category (e.g.
    `"CAA: AWS Certificate Manager"` → `"AWS Certificate Manager"`
    in Cloud).
  - Exchange Autodiscover classified as Email instead of Other.
  - Verification-token artefacts (`"(site verified)"`,
    `"(domain verified)"`, `"Domain Connect (…)"`) filtered from
    the categorized Services block — they're ownership receipts,
    not deployed products.
  - Identity row dropped when its only entry is a
    `"<provider> (managed identity)"` echo of an Email row.
- **Insights dedup and curation**:
  - Four overlapping dual-provider signals (`Dual provider`,
    `Dual Email Provider`, `Dual Email Delivery Path`,
    `Secondary Email Provider Observed`) collapse to one canonical
    line.
  - Three overlapping AI-adoption signals collapse to one
    `"AI Adoption Without Governance"` line when the governance
    version fires.
  - On sparse targets (`Email security 0/5` / `1/5` / `2/5`), the
    subsequent `"No DMARC record"`, `"No DKIM selectors"`, and
    `"DMARC: none"` lines are dropped as redundant — the score
    line already says it.
  - `"Cloud-managed identity indicators (Entra ID native)"` only
    fires on pure M365 targets (no Google Workspace present) —
    on dual-provider targets the Auth line already says
    `"Managed (Entra ID + Google Workspace)"` so the insight
    would be pure restatement.
  - Meta-signals (`requires_signals` only, no candidates) that
    fire with an empty `matched` list — for example
    `"Complex Migration Window"` — render as a bare name instead
    of a `"Name: "` dead-end with nothing after the colon.
  - Raw slugs in signal insight text now humanize through a
    ~90-entry map: `"sendgrid, mailchimp"` → `"SendGrid, Mailchimp"`,
    `"crewai-aid"` → `"CrewAI"`, `"google-managed"` →
    `"Google Workspace (managed)"`, etc.
  - Variant-slug dedup: when a signal's matched list carries both
    `"google-workspace"` and `"google-managed"`, the variant
    collapses into the parent so the insight doesn't read
    `"Google Workspace, Google Workspace (managed)"`.
- **Sparse-signal observation**: new hedged two-sided insight that
  fires when service density is low and the target isn't an M365
  tenant. States explicitly: *"Sparse public signal — few
  observable records beyond MX and identity. Consistent with a
  small organization, a parked or dormant domain, or a
  heavily-proxied target. Observation, not a verdict."* This is
  the explicit answer to "why is this panel thin" that the
  previous output left the user guessing about.
- **Provider line / Auth line consistency**:
  - Slug-only fallback in `detect_provider` always adds the
    `"(primary)"` qualifier now (was inconsistent before —
    topology path labelled, fallback path didn't). Multi-provider
    fallback follows the same `"primary + secondary"` format as
    the topology path.
  - Auth line `"Unknown + Managed (GWS)"` bug: `GetUserRealm`
    returns `NameSpaceType=Unknown` for non-M365 domains; that
    value now gets filtered at display time so Google-only
    domains read `"Managed (Google Workspace)"` instead of
    leaking the "Unknown" token.
  - Auth line `"(GWS)"` abbreviation replaced with
    `"(Google Workspace)"` in the mismatched-auth branch (the
    same-auth compound branch already used the full name —
    inconsistent before).
  - Auth line `"Entra ID"` claim only fires when `microsoft365`
    is in `slugs`, not just when `tenant_id` is set. A domain
    with a registered but inactive M365 tenant no longer gets
    a false "Entra ID" label on the Auth line.
- **Panel layout**:
  - Hero header shows `display_name` once — when it falls back to
    the raw domain (no company name extractable), the duplicated
    hostname line that looked like a bug is gone.
  - Long Provider-line values wrap with an explicit continuation
    indent matching the label column, instead of Rich's default
    column-0 wrap that made `"…Google \\nWorkspace"` ugly.
  - Panel width reduced from 80 → 78 to avoid terminal
    wrap-to-next-line artefacts at the 80-char boundary.
  - Confidence line single-space between dots and label (was
    double-space).
- **Degraded-sources Note reframing**:
  - Two tiers now: **info tone** (default color) when only CT
    sources were degraded AND a CT fallback successfully reached
    another provider (reads as a routine fallback event, not a
    warning); **warning tone** (yellow) when a non-CT source is
    down or every CT provider failed.
  - When CT fallback succeeded with zero subdomains, the Note
    line is suppressed entirely — the outcome is identical to a
    clean run on a domain with no related CT data, so mentioning
    the fallback every time was persistent noise.
  - Wording changed from `"Some sources unavailable"` (false
    alarm when fallback recovered) to `"CT fallback: crt.sh →
    certspotter (N subdomains)"` in the recovered-but-informative
    case, and `"All CT providers unavailable"` when genuinely
    failed.
- **Confidence downgrade logic**:
  - v0.9.2 auto-downgraded confidence on any `degraded_sources`.
    v0.9.3 skips the downgrade when the ONLY degraded sources
    are CT providers AND a CT fallback successfully recovered
    data. Previously, every domain looked up while crt.sh was
    flaking got stuck at `medium` even when the fallback chain
    fully recovered.
- **JSON schema hole fixed**: `format_tenant_dict` now emits the
  `slugs` field explicitly. Downstream tooling used to have to
  reconstruct slug sets from the `detection_scores` field because
  the top-level `slugs` field was missing from the output.
  Also added `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host`, and `lexical_observations` to the emitted
  dict — they were on `TenantInfo` but not surfaced in
  `--json`.

### Docs and roadmap

- **Roadmap rewritten** (`docs/roadmap.md`): collapsed from the
  original 191-line, four-release (`v0.9.3 → v0.9.4 → v0.9.5 →
  v1.0`) gold-plated plan into a tighter ~150-line priority-
  ordered list. CT source resilience promoted from "Later/maybe"
  to `What's next #1` — three-provider fallback chain + local
  per-domain JSON cache with 7-day TTL. Community fingerprint
  pipeline elevated from "Later/maybe" to 1.0 scope.
  `--confidence-mode strict` flag added as a future item for the
  hedging-on-dense-evidence complaint. Bayesian evidence fusion,
  property-graph core, counterfactual simulation, temporal CT
  all demoted to "Post-1.0 ideas". Forward dates and version-
  number sequencing removed per feedback. 1.0 metrics made
  explicit (≥80% signal coverage, zero unhedged assertions on
  sparse-evidence fixtures, MCP idempotent/cache-aware, stability
  tags on every public surface).
- **README example panel updated** to the v0.9.3 hero layout. The
  old bordered-panel example no longer matched reality — a new
  user reading the README would see an example format the tool
  doesn't produce anymore.

### Added — Sparse-target inference

- **`positive_when_absent` absence-engine extension + hedged
  hardening observations.** The `Signal` schema gains a new
  `positive_when_absent` field. When a parent signal fires AND none
  of the listed adversary-friendly / consumer-SaaS slugs are
  detected, the absence engine emits a hedged two-sided positive
  observation: *"Edge Layering — Hardening Pattern Observed: fits a
  deliberately hardened target, a dormant / parked domain, or a
  small shop behind an edge proxy. Hedged observation, not a
  verdict."* The v0.9.3 `Edge Layering` signal carries a 14-slug
  exclusion set (`slack`, `notion`, `atlassian`, `dropbox`, `canva`,
  `hubspot`, `salesforce`, `zoom`, `miro`, `airtable`, `intercom`,
  `mailchimp`, `monday`, `clickup`) so a hardened-enterprise proxy
  target finally gets a positive reading without any confident
  verdict. Wired through `merger.build_insights_with_signals`,
  `cli._build_explanations`, and `server._lookup_tenant_json_with_explain`
  so the hardening observation shows up in every `--explain` output
  path. 14 unit tests pin the invariant.
- **CT subdomain lexical taxonomy** (`recon_tool/lexical.py`). A
  pure-Python rule parser that classifies CT-discovered subdomains
  into environment (`dev-`, `stg-`, `uat-`, `prd-`, `sbx-`), region
  (`us-east`, `eu-west`, `ap-southeast`, `apne1`), and tenancy-shard
  (`t-1234`, `org-acme`, `tenant-xyz`) taxonomies. No ML, no bundled
  embeddings, no generated candidates. Emits hedged
  ``LexicalObservation`` entries on the standard insights list:
  "Mature environment separation pattern observed (3 env-prefixed
  subdomains e.g. dev, stg, prod) — consistent with multi-environment
  deployment pipelines. Observation, not a verdict." A threshold of
  `MIN_MATCHES=2` prevents single-subdomain coincidences from firing
  the signal; sample labels are capped at 3 so `--explain` shows
  evidence without flooding. 30 unit tests cover env/region/shard
  classification, label boundary rules, and observation hedging.
- **OIDC tenant metadata enrichment** (`sources/oidc.py`). The
  `parse_tenant_info_from_oidc` parser now extracts the Microsoft
  extensions `cloud_instance_name`, `tenant_region_sub_scope`, and
  `msgraph_host` from the discovery response — fields that were
  already in the JSON we fetched but silently discarded. These
  distinguish commercial M365 (`microsoftonline.com`), US Government
  Community Cloud (`microsoftonline.us` + `GCC`), GCC High / DoD
  (`microsoftonline.us` + `DOD`), Azure China 21Vianet
  (`partner.microsoftonline.cn`), and Azure B2C (`*.b2clogin.com`)
  tenancies. Surfaced in `TenantInfo.cloud_instance`,
  `TenantInfo.tenant_region_sub_scope`, and `TenantInfo.msgraph_host`;
  rendered by a new `_sovereignty_insights` generator in
  `insights.py` as a hedged insight line ("Likely US Government
  Community Cloud (GCC) tenant (observed
  cloud_instance=microsoftonline.us)"). 13 unit tests pin the
  detection rules and the hedging invariants.
- **Shared verification token clustering**
  (`recon_tool/clustering.py`, new module). In-memory, batch-scope,
  never persisted. When two or more domains in a single `recon batch`
  run share the same `google-site-verification`, `MS=`,
  `atlassian-domain-verification`, Zoom, or similar TXT token, each
  domain's JSON output gains a `shared_verification_tokens` array
  with per-token peer attribution. Exposed programmatically via a
  new read-only `cluster_verification_tokens` MCP tool that accepts
  a list of domains and returns the cluster map from cached
  `TenantInfo` — zero extra network calls. Shared tokens are
  **hedged "possible relationship (observed)"** signals, never
  acquisition verdicts — a reused token implies a shared SaaS
  account operator, not corporate identity. 21 unit tests cover
  normalization, symmetry, multi-peer clusters, and deterministic
  ordering.
- **Custom profile templates + `--profile` flag**
  (`recon_tool/profiles.py`, new module). YAML files in
  `~/.recon/profiles/*.yaml` (or the built-in `data/profiles/`
  directory) define a lens: `category_boost` multipliers,
  `signal_boost` per-signal multipliers, `focus_categories` filters,
  `exclude_signals` blocklists, and a `prepend_note` header.
  Profiles are additive-only — they reweight and reorder existing
  observations, never add new intelligence. Six built-in profiles
  ship in `data/profiles/`: `fintech`, `healthcare`, `saas-b2b`,
  `high-value-target`, `public-sector`, `higher-ed`. The CLI gains `--profile
  <name>` on the lookup command; the MCP `analyze_posture` tool
  gains an optional `profile` argument. Custom profiles override
  built-ins when the name matches — one of the few exceptions to
  the usual additive-only invariant, on the grounds that profiles
  are explicitly user-facing lenses and explicit override is the
  expected mode. 25 unit tests cover built-in discovery, custom
  profile loading, invalid YAML handling, boost multipliers,
  category filtering, and deterministic ordering.
- **DMARC aggregator fingerprinting** — four new vendors added to
  the existing `dmarc_rua` detection pipeline: URIports,
  DMARC Advisor, PowerDMARC, Mimecast DMARC Analyzer. Total
  fingerprint count now **227** (was 208). The `DMARC Governance
  Investment` signal's `requires.any` list was expanded to cover
  the new slugs, so RUA addresses pointing to these vendors now
  fire the governance-maturity signal end-to-end.
- **EDU / nonprofit / marketing fingerprints** — 15 new
  fingerprints: Canvas LMS, Blackboard, Moodle, Ellucian
  Banner, Handshake, Top Hat (higher-ed LMS/SIS), Dynamics 365
  Marketing, Salesforce Marketing Cloud (SFMC), Emma, iContact,
  MailerLite (marketing automation), VMware Cloud, Salesforce
  NPSP, Blackbaud, Classy (nonprofit CRM/fundraising).
  TXT-verification detection merged into existing Netlify and
  WP Engine entries.
- **Exchange on-prem / hybrid detection**
  (`dns._detect_exchange_onprem`). Probes `owa.`, `outlook.`,
  `exchange.`, `mail-ex.`, `webmail.`, `autodiscover.` subdomains.
  `autodiscover` uses A-only resolution (not CNAME) to avoid
  M365 false-positives — M365 autodiscover is CNAME to
  `outlook.com`. Emits `exchange-onprem` slug. Wired into the
  parallel `asyncio.gather` detector set.
- **Federated SSO hub detection** (`dns._detect_idp_hub`).
  Probes 15 identity-provider subdomain prefixes (`shibboleth`,
  `weblogin`, `idp`, `wayf`, `sp`, `sso`, `saml`, `cas`,
  `raven`, `webauth`, `harvardkey`, `kerberos`, `okta`, `adfs`,
  `federation`) for A records. Emits `federated-sso-hub`,
  `okta-sso-hub`, or `adfs-sso-hub` slugs depending on match.
- **SPF redirect chain following** (`dns._follow_spf_redirect`).
  Follows `redirect=` directives in SPF records up to 3 hops,
  collecting additional SaaS fingerprint matches from the
  redirect targets. Silent failure via try/except.
- **A → PTR cloud hosting detection**
  (`dns._detect_hosting_from_a_record`). Resolves the apex A
  record, then performs a PTR lookup on the resulting IP.
  Pattern table covers AWS EC2/ELB, Azure VM, GCP Compute,
  Linode, DigitalOcean, Hetzner, OVH, and Vultr.
- **Higher-ed profile** (`data/profiles/higher-ed.yaml`). Sixth
  built-in posture profile for universities, colleges, research
  institutions, and academic computing. Boosts identity (1.6×),
  email (1.5×), infrastructure (1.3×). Prioritises federated
  identity, LMS detection, email governance. Excludes GTM
  signals that don't apply to universities.
- **MX always-emit for `has_mx_records` plumbing**. `_detect_mx`
  now emits an `EvidenceRecord` for every MX host even when no
  fingerprint matches, so the downstream `has_mx_records` check
  works regardless of fingerprint coverage.
- **Email security scoring honesty**. The email security score
  now requires MX-backed evidence (`primary_email_provider`,
  `likely_primary_email_provider`, `dmarc_policy`, or
  outbound-email slug) before scoring. Domains with zero email
  infrastructure no longer get a misleading `0/5 weak` label.
  Score `0` with monitoring records reads "DMARC monitoring
  mode, SPF soft/neutral — no strict controls" instead of
  "no protections detected".
- **Provider "account detected" variants**. When identity
  endpoints show a registered account but MX records don't
  confirm active email delivery, the provider line now reads
  `"(account detected, no MX)"` or `"(account detected,
  custom MX)"` instead of claiming the provider as primary.
- **Explanation DAG serialization** (`explanation.build_explanation_dag`).
  Produces a JSON-serializable provenance DAG from any list of
  `ExplanationRecord` instances: node types `evidence`, `slug`,
  `rule`, `signal`, `insight`, `observation`, `confidence`; edge
  types `detected-by`, `contributes-to`, `fired`. Every terminal
  node is reachable from at least one evidence node via a short
  path (asserted by the v0.9.3 property-based harness). `--explain
  --json` on the CLI and the MCP `lookup_tenant` with `explain=true`
  both emit the DAG under a new `explanation_dag` key alongside
  the existing flat `explanations` list — old consumers stay
  working, new consumers get the structured view. 17 unit tests
  pin the shape, the node types, the edge semantics, and
  determinism.
- **Property-based hedging regression harness**
  (`tests/test_v093_hedging_invariants.py`). Hypothesis-driven
  fuzz testing that asserts five hedging invariants against
  random slug subsets and random OIDC metadata: (1) every
  `positive_when_absent` output is hedged and two-sided; (2) the
  emitted SignalMatch name carries the `"Hardening Pattern
  Observed"` suffix; (3) sovereignty insights never claim
  certainty; (4) the signal pipeline never raises or emits
  duplicate names; (5) every absence signal references a
  legitimately-firing parent. Plus a static pass over every
  loaded signal to reject forbidden confident-verdict language
  (`definitely`, `proven`, `confirmed `, `guaranteed`). Runs in
  under 5 seconds on default settings so it's always on. This is
  the mechanical floor that makes every other v0.9.3 item safe to
  ship — a future PR that reintroduces confident-wrong language
  fails CI before merge.

### Added — UI/X refinements

- **Default panel redesign** (`formatter.render_tenant_panel`).
  Complete visual rewrite of the lookup output. The old bordered
  Rich Panel with an 80-column frame is replaced by a plain-text
  hero layout: company name in bold, apex domain on a dim second
  line, a horizontal rule, then a 13-column label / value fact
  block (Provider, Tenant, Auth, Cloud, Confidence), then a
  hierarchical Services section broken into seven display
  categories (Email, Identity, Cloud, Security, AI, Collaboration,
  Other), then a compact 1–2 line High-Signal Related Domains
  section, then curated Insights, and — only when sources are
  actually degraded — a subtle yellow Note line. `--full`,
  `--verbose`, `--explain`, and `--domains` add additional
  sections (full tenant_domains list, evidence chain, conflict
  annotations, cert summary) after the core layout without
  breaking its structure.
- **Disciplined color palette**: subtle cyan/teal for section
  headers (`Services`, `High-signal related domains`, `Insights`),
  green **only** when confidence is `High`, default text for
  Medium/Low confidence (no alarmist yellow, no red, no
  high-chroma anywhere), subtle yellow for the degraded-sources
  Note line (only when it appears). Graceful monochrome fallback
  — terminals without color support still render the full layout
  as plain text.
- **Categorized services classifier**. A 120+ slug → category
  lookup table (`_CATEGORY_BY_SLUG`) gives every detected slug a
  deterministic home in one of the seven display categories.
  Services whose slug isn't in the table fall through to a
  prefix-based classifier (`DMARC`/`DKIM`/`SPF` → Email,
  `DNS:`/`CDN:`/`Hosting:` → Cloud, etc.). Pass-2 dedup via
  lowercase-prefix matching prevents the same detection from
  appearing twice under two different display names (e.g.
  `"Atlassian"` + `"Atlassian (Jira/Confluence)"`).
- **Curated Insights filter** (`formatter._curate_insights`).
  Drops the repetitive laundry-list entries the old panel dumped
  verbatim (`Security stack: …`, `Infrastructure: …`,
  `PKI: …`, `Google Workspace modules: …`, mid-size org-size
  hints). Kept: signal firings, hardening observations,
  sovereignty hints, email security scores, topology notes.
- **Compact related-domains block**. Picks up to 8 high-signal
  subdomains (prefixes `login.`, `sso.`, `auth.`, `idp.`, `api.`,
  `admin.`, `portal.`, `dashboard.`, `support.`, `status.`,
  `app.`, `cdn.`) and displays them as a wrapped 1–2 line comma
  list with a `(N total — M more, use --full to see all)`
  footer. The old panel's 10-entry vertical list is replaced
  entirely — it was the single biggest consumer of vertical
  space on enterprise targets.
- **Fixed misleading Provider line** (`formatter.detect_provider`
  + new `_pick_single_primary` helper). The old format
  `"{gateway} (email gateway, likely delivering to X + Y)"`
  read as ambiguous dual email; the new format promotes ONE
  primary and demotes the rest to `"(secondary)"`. Selection
  rule: Microsoft 365 first (most common enterprise primary),
  then Google Workspace, then list-order fallback. Target
  output: `"Microsoft 365 (primary) via Trend Micro gateway +
  Google Workspace (secondary)"`. The word `(dual)` never
  appears anywhere in provider output — and the v0.9.3 property
  tests assert this.
- **Elevated bare `recon` command**. Running `recon` with no
  arguments no longer dumps the raw Typer help. Instead it
  prints a curated 15-line banner: version + one-line value
  prop, the recommended first command, progressive disclosure
  (`--verbose`, `--full`, `--explain`), three worked examples,
  and a gentle hint about `recon doctor`. Calm, professional,
  no emojis. Subtle cyan accents on the version label and
  section headers.
- **Elevated `recon mcp` startup + shutdown UX**
  (`server._print_mcp_banner`, `server.main`). Running `recon
  mcp` no longer hangs silently. The MCP server now prints a
  professional banner to stderr before handing control to the
  FastMCP loop: version, transport (`stdio`), loaded fingerprint
  and signal counts, a curated list of the top 10 tools with
  one-line descriptions, a config hint pointing at
  `docs/mcp.md`. Ctrl+C produces a clean `"MCP server stopped."`
  line, never a raw `asyncio.CancelledError` traceback.
  `BrokenPipeError` / `ConnectionResetError` are caught as clean
  client-disconnect events. Any other exception is rendered as a
  one-line summary, not a Python scream. The banner goes to
  **stderr** so `stdout` stays clean for the stdio transport's
  JSON-RPC framing.

### Added — Models / storage plumbing

- `SourceResult` gains `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host` (all `str | None`, default `None`).
- `TenantInfo` gains `cloud_instance`, `tenant_region_sub_scope`,
  `msgraph_host`, `shared_verification_tokens` (tuple of
  `(token, peer_domain)` pairs — batch-scope only, not cached),
  and `lexical_observations` (tuple of hedged observation
  statements).
- `Signal` gains `positive_when_absent: tuple[str, ...]`.
- `cache.py` round-trips every new field except
  `shared_verification_tokens` — that one is intentionally
  batch-scope-only to prevent a single-domain lookup from
  inheriting peers from a previous batch run.
- New `recon_tool/clustering.py` — `ClusterEntry` frozen
  dataclass + `cluster_tokens` + `compute_shared_tokens` pure
  functions.
- New `recon_tool/lexical.py` — `LexicalObservation` frozen
  dataclass + `classify_subdomains` + `lexical_observations`
  pure functions.
- New `recon_tool/profiles.py` — `Profile` frozen dataclass +
  `load_profile` / `list_profiles` / `reload_profiles` /
  `apply_profile`.

### Changed

- **Fingerprint count: 208 → 227**. Added URIports, DMARC
  Advisor, PowerDMARC, Mimecast DMARC Analyzer, Canvas LMS,
  Blackboard, Moodle, Ellucian Banner, Handshake, Top Hat,
  Dynamics 365 Marketing, Salesforce Marketing Cloud (SFMC),
  Emma, iContact, MailerLite, VMware Cloud, Salesforce NPSP,
  Blackbaud, Classy. Merged TXT-verification detection into
  existing Netlify and WP Engine entries.
- **Signal schema: `positive_when_absent` field added** (opt-in,
  defaults to empty tuple, fully backward compatible with
  pre-v0.9.3 signals.yaml).
- **Default panel layout**: the v0.9.2 bordered Rich Panel with
  80-char width is gone. See UI/X section above. The
  `render_tenant_panel` function signature is unchanged; callers
  still pass its return value to `console.print`.
- **Provider line format**: the v0.9.2
  `"{primary} (primary email via {gateway} gateway)"` format is
  gone. The v0.9.3 format is
  `"{primary} (primary) via {gateway} gateway"`. Same
  information, half the parentheses. When `primary` is inferred
  from non-MX evidence the label becomes `"(likely primary)"`.
- **Gateway-only format**: the v0.9.2 `"{gateway} (email
  gateway)"` is replaced with `"{gateway} gateway (no
  inferable downstream)"` — more explicit about why no primary
  is shown.
- **Insights curation**: the v0.9.2 panel dumped every generated
  insight verbatim. v0.9.3 curates out repetitive laundry lists
  (Security stack, Infrastructure, PKI, Google Workspace
  modules, low-signal org-size hints) that duplicated data
  already visible in the Services block.

### Fixed

- **Provider line ambiguity on dual-DKIM domains.** The old
  `detect_provider` concatenated every likely-primary-email
  provider name with ` + `, producing "Trend Micro gateway
  (likely delivering to Google Workspace + Microsoft 365)" on
  targets where DKIM selectors for both providers existed. The
  new `_pick_single_primary` helper promotes one primary and
  demotes the rest, eliminating the ambiguous "dual" reading.
- **Bare `recon` UX failure**. Running `recon` with no arguments
  used to dump the raw Typer help — ~30 lines of
  machine-generated flag documentation with no value
  proposition, no examples, no suggested first command. Now
  emits a curated banner that tells users what the tool does
  and gives them the exact command to run next.
- **`recon mcp` silent-start failure**. Running `recon mcp`
  used to produce no output at all — just a silent hang on
  stdio. First-time users reported thinking the command had
  crashed. Now prints a professional startup banner to stderr
  with the tool list and config hint, and catches `KeyboardInterrupt`
  cleanly so Ctrl+C produces a `"MCP server stopped."` message
  instead of a raw `asyncio.CancelledError` traceback.
- **Categorized Services double-counting.** In edge cases where
  a service name matched a slug via fingerprint display-name
  lookup AND the raw service name didn't round-trip back
  through the `name_to_slug` map, the categorizer could file
  the same detection under two display names. The new
  lowercase-prefix dedup in pass 2 of `_categorize_services`
  catches both cases.

### Internal

- **Test count**: 1479 passing (1483 total, 4 integration tests
  deselected by default). 123 net new tests across v0.9.3 — 14
  for positive-absence, 30 for lexical, 21 for clustering, 13
  for OIDC enrichment, 25 for profiles, 17 for explanation DAG,
  1 compound test class (TestHardeningObservationIsHedged et
  al.) with ~10 individual tests for the property-based
  hedging harness.
- **Coverage**: 88% package-wide (up from 89% baseline; the
  small dip is because new modules start at high coverage and
  pull the weighted average slightly toward the larger existing
  surfaces). New v0.9.3 modules: `clustering.py` 100%,
  `lexical.py` 98%, `profiles.py` 90%, `absence.py` 100%.
- **Dead code removed**: ~320 lines of v0.9.2 panel body in
  `formatter.py`, plus three unused helper functions
  (`_is_compact_noise`, `_low_scored_service_names`,
  `_annotate_single_source`) that only existed to support the
  old panel. Net formatter change: +~700 lines of new v0.9.3
  layout code minus ~600 lines of deleted old code.
- **Ruff clean**: all checks pass.
- **Pyright clean**: 0 errors, 0 warnings on the package.

### Breaking (for JSON / CLI consumers)

- **Panel output format**. If your tooling parses the default
  `recon <domain>` terminal output (text scraping), it will
  break — the layout is entirely redesigned. Use `--json` for
  programmatic consumers; the `--json` shape is unchanged
  except for the new additive fields (`cloud_instance`,
  `tenant_region_sub_scope`, `msgraph_host`,
  `shared_verification_tokens`, `lexical_observations`, and
  the new `explanation_dag` key under `--explain --json`).
- **Provider string format** in `--json` output follows the new
  `"(primary) via gateway + (secondary)"` convention described
  above. Consumers matching on the exact v0.9.2 string
  `"(primary email via X gateway)"` need to update.

## [0.9.2] — 2026-04-14

This release is a reliability and honesty pass driven by real-world batch
runs across 15 diverse enterprise domains. v0.9.1 was catastrophically
unreliable on CT-heavy targets (27–93% batch failure rate depending on
upstream CT provider state). v0.9.2 raises that to 100% on the same
corpus while surfacing per-source failure reasons so users can see
exactly what went wrong when a lookup is incomplete.

### Breaking (for JSON / signal-name consumers)

- The signal **"Legacy Provider Residue"** has been renamed to
  **"Secondary Email Provider Observed"**. The detection logic and
  `exclude_matches_in_primary` guard are unchanged — only the surface
  name and description differ. Any downstream tool matching on the old
  signal name (in `--json` output's `signals[].name`, in MCP tool
  responses, or in `signals.yaml` overrides) needs to update its
  reference. The rename is described under the Fixed section below.

### Fixed

- **Catastrophic batch timeout rate on CT-heavy domains.** The 60-second
  aggregate resolver timeout cancelled the entire pipeline when crt.sh
  and CertSpotter both exhausted retries, producing 27–93% failure rates
  on enterprise targets depending on upstream CT state. Raised default
  `RESOLVE_TIMEOUT` to 120 seconds and made it configurable via the
  `--timeout` CLI flag.
- **"No information found" hid real errors.** When every source
  transiently failed, the CLI rendered a single generic message with no
  indication of which source failed or why. `ReconLookupError` now
  carries a `source_errors` tuple of `(source_name, reason)` pairs, and
  the CLI renders each one as a dim second line so users can tell
  whether the domain is genuinely empty or whether a transient failure
  hid real data.
- **No source-level retry for transient network failures.** The HTTP
  transport layer retried 429/503 status codes, but timeouts and
  connection resets caused individual sources to return immediately
  with an error — cascading up to a false "no information" verdict on
  domains that would have resolved fine on a retry. A new
  `retry_on_transient` decorator in `recon_tool/retry.py` retries up to
  two times on `httpx.TimeoutException`, `ConnectError`, `ConnectTimeout`,
  `ReadError`, `WriteError`, `RemoteProtocolError`, `asyncio.TimeoutError`,
  and `OSError`, with 0.5s and 1.5s backoff. Applied to `OIDCSource`
  and `GoogleIdentitySource` — the two single-point-of-failure sources
  most sensitive to transient failures. UserRealm and DNS already have
  internal fallback paths.
- **CertSpotter pagination missing.** The provider sent a single GET
  with no `after=` cursor, returning only the first page of issuances.
  Large enterprise domains silently truncated to a fraction of their CT
  footprint, and the caller had no idea the response was partial. Added
  a pagination loop capped at 4 pages (controlled by `_MAX_PAGES`) with
  graceful handling of HTTP 429 — on rate limit, the provider returns
  what's been collected rather than raising.
- **CT provider attribution invisible.** When crt.sh was degraded and
  CertSpotter picked up the fallback, users saw the same generic
  "Some sources unavailable (crt.sh)" note regardless of whether the
  fallback produced 0 or 100 subdomains. New `ct_provider_used` and
  `ct_subdomain_count` fields on `SourceResult` and `TenantInfo` track
  which provider actually contributed, and the panel bottom Note line
  now reads e.g. *"Some sources unavailable (crt.sh) — CT data via
  certspotter (87 subdomains)"*. Plumbed through the disk cache too.
- **"Legacy Provider Residue" mislabeled active dual-use.** On a major
  dev platform owned by a major tech company (M365 primary + Google
  Workspace secondary via DKIM), the signal fired as "Legacy Provider
  Residue: google-workspace". But in that case, both providers are
  actively used — not legacy residue at all. Renamed to **"Secondary
  Email Provider Observed"** with neutral two-sided wording that
  describes the observation without asserting whether it's active dual
  use, migration residue, or a legacy tenant.
- **Provider field silent when MX patterns don't match.** On
  custom/self-hosted email setups, `primary_email_provider` came back
  as `None` and the Provider line said just "Unknown". Rewrote the
  fallback to "Unknown (no known provider pattern matched)" so users
  understand that the tool looked and came up empty rather than
  silently skipping MX analysis.
- **`compute_inference_confidence` missed non-Microsoft corroboration.**
  The corroboration check required `m365_detected`, `display_name`, or
  `auth_type` on a non-OIDC source — fields that only populate for
  Microsoft-side sources. A domain with a tenant_id from OIDC and
  Google Workspace auth confirmation couldn't reach HIGH inference
  confidence because the Google-side fields weren't recognized as
  corroboration. Expanded the check to include `google_auth_type` and
  `tenant_domains` as valid signals.
- **Related-domains list indent regression.** (Carried over from
  v0.9.1 — not a v0.9.2 change, but the bank-run validation exposed a
  latent edge case where the footer line's text was slightly too long
  for the panel, causing Rich to wrap the last word to the panel
  margin. Shortened the footer text.)

### Added

- **`--timeout` CLI flag** — configurable per-lookup aggregate timeout,
  defaults to 120s (was 60s hardcoded). The batch pipeline and every
  resolve path honors the override.
- **`retry_on_transient` decorator** (`recon_tool/retry.py`) — shared
  async retry helper for source-level transient failures. Narrow
  exception list, short backoff, bounded attempts. 12 unit tests
  covering every transient exception class and the non-retry path.
- **CertSpotter pagination loop** — `CertSpotterProvider.query` now
  iterates up to `_MAX_PAGES` pages via the `after=<id>` cursor,
  accumulating subdomains and cert metadata across the full response.
  Stops early on 429, empty page, or missing issuance id.
- **CT provider attribution fields** on `SourceResult` and `TenantInfo`:
  `ct_provider_used` (which CT provider actually succeeded) and
  `ct_subdomain_count` (how many came back after filtering). The count
  is the **filtered** subdomain count — what's left after the wildcard
  removal, noise-prefix skip, and `MAX_SUBDOMAINS` cap in
  `filter_subdomains` — not the raw issuance count returned by the API.
  Surfaced in the JSON output, the disk cache, and the panel bottom
  Note (panel only when degraded sources are also present, so clean
  runs aren't cluttered with reassurance text).
- **`render_source_status_panel()`** in `formatter.py` — compact
  per-source status panel (✓/✗ with brief reason) rendered under
  `--explain` so users can see which sources succeeded and which
  failed without needing `--verbose`. Previously only available in
  the verbose status-line stream during resolution.
- **Partial-success rendering at the merger boundary.** `merge_results`
  already returned a partial `TenantInfo` when `tenant_id` was `None`
  but any source produced services — v0.9.2 tightens the rejection
  path so that when every source returns zero services AND zero
  tenant_id, the raised `ReconLookupError` carries the concrete
  per-source reasons instead of a generic message.
- **18 new tests in `tests/test_retry.py`** covering the retry decorator
  against every supported transient exception class, the non-retry
  semantic-failure path, and instance-method binding.
- **23 new tests in `tests/test_cache_roundtrip.py`** covering every
  `TenantInfo` field including v0.9.1 topology fields and v0.9.2 CT
  provider attribution. Fully exercises the serialize/deserialize
  round-trip and the cache_put/cache_get disk operations in isolated
  temp directories.
- **23 new tests in `tests/test_posture_validation.py`** covering the
  posture rule YAML validator (malformed rules, custom rule loading,
  metadata condition edge cases).
- **21 new tests in `tests/test_formatter_coverage.py`** covering panel
  render edge cases (empty services, degraded + no CT, truncation,
  single-source annotation, M365 classification).
- **30 new tests in `tests/test_cli_coverage_extra.py`** covering
  version and debug callbacks, doctor --fix scaffold, batch
  validation and JSON/CSV modes, exposure/gaps/posture/explain/full/md
  flag combinations, and mutually-exclusive output flag rejection.
- **25 new tests in `tests/test_explanation_coverage.py`** covering
  explanation insight classification branches, `explain_confidence`,
  `explain_observations`, and `serialize_explanation` round-trip.
- **4 new tests in `tests/test_merger_error_surfacing.py`** — R2
  regression guards: source errors carried on the exception, partial
  success when any source produced services, neutral message when
  sources returned empty without errors.
- **13 new tests in `tests/test_cert_providers.py`** covering the
  CertSpotter pagination loop (cursor advance, 429 handling, empty
  pages, missing id, MAX_PAGES cap).
- **1310 total tests** (was 1165 on v0.9.1), 100% passing,
  **88% total coverage** (was 84%), every core logic file ≥80%.

### Changed

- `ReconLookupError` — added `source_errors: tuple[tuple[str, str], ...]`
  field carrying per-source failure reasons. Backward compatible
  (defaults to empty tuple).
- `TenantInfo` — added `ct_provider_used: str | None` and
  `ct_subdomain_count: int` fields. Backward compatible.
- `SourceResult` — added matching `ct_provider_used` and
  `ct_subdomain_count` fields.
- `detect_provider()` in `formatter.py` — when nothing matches, returns
  *"Unknown (no known provider pattern matched)"* instead of the bare
  "Unknown" label, so users know the tool looked and came up empty.
- `compute_inference_confidence()` in `merger.py` — corroboration check
  now accepts `google_auth_type` and `tenant_domains` as valid signals
  in addition to the existing Microsoft-side fields. Raises HIGH
  inference confidence on domains where tenant_id comes from OIDC and
  corroboration comes from Google Identity.
- `OIDCSource.lookup` and `GoogleIdentitySource.lookup` — refactored to
  use a `_fetch` inner coroutine decorated with `retry_on_transient`.
  External API is unchanged (still never raises; always returns a
  `SourceResult`).
- Signal rename in `data/signals.yaml`: "Legacy Provider Residue" →
  "Secondary Email Provider Observed". Logic and `exclude_matches_in_primary`
  guard unchanged; only the surface name and description are different.
  All tests referencing the old name updated.
- `docs/signals.md` and `tests/test_v090_provider.py` updated for the
  rename.
- `render_warning(domain, error=None)` in `formatter.py` — accepts an
  optional `ReconLookupError` argument and renders its `source_errors`
  as dim second lines. All CLI call sites updated.
- Console initialization: `get_console()` now uses `cast(Any, ...)` on
  `sys.stdout` / `sys.stderr` before calling `reconfigure()` so pyright
  accepts the optional-method access pattern while still working
  correctly on Windows where the Python 3.7+ `reconfigure` method
  exists on `_io.TextIOWrapper`.

### Removed

- Nothing. v0.9.2 is purely additive + bug fixes.


This release is a correctness and honesty pass driven by real-world runs
against heavily-proxied enterprise targets. Several v0.9.0 outputs were
confidently wrong or framed misleadingly; this release fixes them without
changing the core architecture.

### Fixed

- **DKIM wording overclaim** — insights, exposure gaps, and the exposure
  panel all said "DKIM not configured" when the tool had only checked
  common selector names (mail, selector1, google, k1, etc.). Rewrote to
  "No DKIM selectors observed at common names — actual DKIM status
  unknown" so the absence of a match at known selectors is never
  reported as a configured-or-not claim. 3 files touched.
- **Legacy Provider Residue false positives** — the signal was firing
  on the *current* primary email provider, so a GWS-primary domain
  would show "Legacy Provider Residue: google-workspace" and a
  dual-M365+GWS domain would show both primaries flagged as residue.
  New `exclude_matches_in_primary` field on the Signal schema filters
  matched slugs whose display name appears in either
  `primary_email_provider` or the new `likely_primary_email_provider`.
  When neither primary is known, the signal refuses to fire — a
  residue claim is meaningless without a known primary to be residue
  against.
- **Multi-Cloud miscategorizing CDNs** — Cloudflare, Akamai, Fastly,
  and Imperva were triggering a "Multi-Cloud" signal despite being
  edge/CDN providers, not cloud providers. Split into two signals:
  `Multi-Cloud` (AWS/Azure/GCP/fly.io only) and new `Edge Layering`
  (CF/Akamai/Fastly/Imperva). New `edge_layering` posture rule.
- **Absence engine treating competitors as missing counterparts** —
  `expected_counterparts` entries on Enterprise Security Stack,
  Enterprise IT Maturity, and DMARC Governance Investment listed
  alternative vendors (Proofpoint/Mimecast/Barracuda for one;
  Jamf/Kandji and CrowdStrike/SentinelOne for another). Removed
  those three entries. The two remaining entries (AI Adoption,
  Agentic AI Infrastructure) describe genuine complements.
- **"Split-Brain Email Config" pejorative framing** — renamed to
  "Dual Email Delivery Path" (phrase already used in insights).
  Common deliberate enterprise pattern; previous name read as a
  defect.
- **Confidence overclaiming on degraded sources** — headline confidence
  now downgrades one rung (High→Medium→Low) when any source is in
  `degraded_sources`. Previously "High (4 sources)" would render
  while the bottom note said "crt.sh unavailable" — a self-contradiction.
- **v0.9.0 email topology fields were silently broken** —
  `_detect_mx` in the DNS source never passed `source_type` or
  `raw_value` to `ctx.add()`, so no MX EvidenceRecords were ever
  created. `_compute_email_topology` filters evidence by
  `source_type == "MX"` and consequently always returned
  `(None, None)` on live data. The v0.9.0 `primary_email_provider`
  and `email_gateway` fields have never populated from a real
  lookup. Same issue on Google DKIM detections. Fixed both — MX,
  Exchange DKIM, Google DKIM, and ESP DKIM all now create
  EvidenceRecords with correct source types.
- **v0.9.0 topology fields were never serialized to disk cache** —
  `primary_email_provider`, `email_gateway`, `dmarc_pct`, and the
  new `likely_primary_email_provider` are now persisted and restored
  from `~/.recon/cache/*.json`.
- **Related-domain dump indent regression** — continuation lines on
  the Related: section wrapped to the panel border (column 2)
  instead of the value column (column 14). Same issue on the
  bottom degraded-sources note. Both now wrap cleanly with manual
  column-aware indent.
- **Windows cp1252 Unicode crash** — the panel uses `●` confidence
  dots, `→` arrows, `—` em-dashes, and box-drawing glyphs that
  cp1252 cannot encode. On Windows terminals with the default
  codepage this crashed with `UnicodeEncodeError`. The console
  initializer now reconfigures stdout/stderr to UTF-8 with
  error replacement as a safety net.

### Added

- **`likely_primary_email_provider` — hedged downstream inference**
  for gateway-fronted domains. When MX points to an enterprise email
  gateway (Proofpoint, Mimecast, Symantec, Barracuda, Trellix, Trend
  Micro, Cisco IronPort / Secure Email) and no direct provider
  appears in MX, non-MX evidence (DKIM selectors, identity endpoint
  responses, TXT verification tokens) is scanned for provider slugs.
  When found, the tool emits `likely_primary_email_provider` and
  the Provider line renders as e.g. *"Proofpoint (email gateway,
  likely delivering to Google Workspace + Microsoft 365)"*. Hedged
  on purpose: the word "likely" in the field name is load-bearing.
  Never set when `primary_email_provider` is also set, so the two
  fields do not contradict each other. Plumbed through `TenantInfo`,
  `SignalContext`, the formatter `detect_provider` helper, the
  residue-guard filter, the JSON output, and the disk cache.
- **New `Edge Layering` signal** — fires on 2+ CDN/edge providers
  (Cloudflare/Akamai/Fastly/Imperva) as a deliberate hardening
  indicator. Also added `edge_layering` posture rule.
- **B1: single-source detection annotation in the default panel** —
  service names backed by only one weak evidence type render with a
  dim `*` suffix and a one-line footnote explaining the marker.
  No information loss. Uses the existing v0.3.0 per-detection
  corroboration scoring.
- **B2: related-domains truncation** — default panel shows the first
  10 priority-sorted related domains (via existing HIGH_SIGNAL_PREFIXES
  ordering) with a dim footer `…and N more — use --full for the
  complete list`. Full list still renders behind `--domains` or
  `--full`. Continuation lines and footer manually wrapped to the
  value column.
- **B3: panel color hierarchy for insights** — neutral insights
  render in dim so they read as a scannable secondary column below
  the services list. `Label: value`–shaped insights get a bold-dim
  label with the value in normal-dim. Warnings and hedged insights
  punch through in terracotta; transitions in amber.
- **12 new synthetic regression tests** in `tests/test_hardened_corpus.py`
  across six archetypes (hardened edge, dual-provider baseline, true
  legacy residue, dormant/parked, small-shop-on-CDN, and the new
  likely-primary inference cases). Every fixture uses fabricated
  slugs — no real company names anywhere.
- **6 new regression guards** for `_compute_email_topology` covering
  the likely-primary inference paths.
- 1165 total tests (was 1147), 100% passing.

### Changed

- `TenantInfo.likely_primary_email_provider` — new field, defaults to
  `None`, backward compatible.
- `SignalContext.likely_primary_email_provider` — new field, defaults
  to `None`, backward compatible.
- `Signal.exclude_matches_in_primary` — new field, defaults to `False`,
  backward compatible. When `True`, `_evaluate_single_signal` filters
  matched slugs whose display name appears in the combined
  primary/likely-primary string, and refuses to fire when neither is
  known.
- `_compute_email_topology` now returns a triple
  `(primary_email_provider, email_gateway, likely_primary_email_provider)`
  instead of a pair. Call sites and tests updated.
- `detect_provider()` in `formatter.py` accepts an optional
  `likely_primary_email_provider` parameter and renders the hedged
  "email gateway, likely delivering to X" form when appropriate.
- `google_identity.py` now emits a second `EvidenceRecord` with
  `slug="google-workspace"` (in addition to `google-federated` or
  `google-managed`) so the inference path can see Google as a
  downstream provider on gateway-fronted domains.
- `tests/test_integration.py` — replaced real corporate apex
  references with RFC-2606 reserved `example.com` / `example.org`.
  Repo is now clean of real company names outside of fingerprint
  detection targets and the Contoso/Northwind/Fabrikam fictional-
  example convention.
- Refined roadmap with a tight "Now / Soon / Later" plan driven by
  real-world findings from hardened enterprise targets.

### Removed

- `expected_counterparts` from Enterprise Security Stack, Enterprise
  IT Maturity, and DMARC Governance Investment (see Fixed above).
  Tests rewritten as regression guards that pin the *absence* of
  those counterparts.

## [0.9.0] — 2026-04-14

### Added

- **Primary Email Provider Detection** — MX-based topology computation distinguishes primary email providers from secondary/legacy detections. New `primary_email_provider` and `email_gateway` fields on TenantInfo. Enhanced Provider line formatting shows email delivery path (e.g., "Microsoft 365 (primary email via Proofpoint gateway)"). New "Email Gateway Topology" and "Legacy Provider Residue" signals. New email topology insights.
- **Negative-Space Analysis** — new `absence.py` module evaluates `expected_counterparts` on signal definitions. When a signal fires but expected companion services are absent, an absence signal is produced with hedged language. 5 built-in signals ship with `expected_counterparts` definitions for out-of-the-box absence detection. Absence signals appear alongside standard signals in all output formats.
- **DMARC Intelligence Expansion** — `rua=mailto:` extraction identifies paid DMARC report vendors (Agari, Proofpoint EFD, OnDMARC, dmarcian, Valimail, EasyDMARC). `pct=` parsing surfaces phased DMARC rollout. 6 new DMARC vendor fingerprints (detection type `dmarc_rua`). New "DMARC Governance Investment" signal. New `dmarc_phased_rollout` posture observation.
- **Ephemeral Fingerprints via MCP** — 4 new MCP tools: `inject_ephemeral_fingerprint` (inject temporary detection patterns), `reevaluate_domain` (re-evaluate cached data with zero network calls), `list_ephemeral_fingerprints`, `clear_ephemeral_fingerprints`. Session-scoped, in-memory, thread-safe. Validated through the same regex/ReDoS pipeline as built-in fingerprints.
- 6 new DMARC vendor fingerprints: Agari, Proofpoint EFD, OnDMARC, dmarcian, Valimail, EasyDMARC. 208 fingerprints total.
- 3 new signals: Email Gateway Topology, Legacy Provider Residue, DMARC Governance Investment. 44 signals total.
- 1 new posture observation: `dmarc_phased_rollout`.
- 1 new module: `recon_tool/absence.py` (absence signal evaluation engine).
- 189 new tests (958 → 1147 total). 6 Hypothesis property-based tests covering all correctness properties.

### Changed

- `TenantInfo` extended with `primary_email_provider`, `email_gateway`, `dmarc_pct` fields.
- `SignalContext` extended with `dmarc_pct`, `primary_email_provider` fields.
- `Signal` dataclass extended with `expected_counterparts` field.
- `SourceResult` extended with `dmarc_pct`, `raw_dns_records` fields.
- `detect_provider()` in `formatter.py` now accepts topology fields for enhanced Provider line formatting. Falls back to existing slug-based detection when topology fields are None (backward compatible).
- `merge_results()` in `merger.py` computes email topology, propagates DMARC metadata, and runs absence evaluation.
- `_detect_email_security()` in `dns.py` extracts `rua=` and `pct=` from DMARC records.
- MCP server now exposes 16 tools (was 12).
- All backward compatible with existing YAML files — new fields default to safe values.

## [0.8.1] — 2026-04-13

### Changed

- README: removed `~` approximation from fingerprint counts — exact 206 fingerprints, 41 signals throughout. Added `--explain` example after the panel. Added multi-step MCP prompt example.
- docs/fingerprints.md: added YAML snippet example for custom fingerprints. Added "Best for" column to detection types table.
- docs/signals.md: added two-pass evaluation note. Updated Layer 1/2/4 tables with all v0.8.0 signals and updated slug lists.
- docs/mcp.md: added multi-step example prompt for deeper analysis workflows.
- docs/roadmap.md: refined "Now" section with intelligence amplification thesis.
- CHANGELOG.md: added standard [Unreleased] section.
- CLAUDE.md: updated stale fingerprint/signal/test counts to current values.

## [0.8.0] — 2026-04-13

### Added

- 12 new fingerprints: CrewAI AID (`crewai-aid`), LangSmith Enterprise (`langsmith`), MCP DNS Discovery (`mcp-discovery`), Container Signing Attestation/Cosign (`cosign-attestation`), Fastly CDN (`fastly`), Fly.io (`flyio`), Railway (`railway`), AutoSPF (`autospf`), OnDMARC/Red Sift (`ondmarc`), dmarcian (`dmarcian`), EasyDMARC (`easydmarc`), Valimail (`valimail`). ~206 fingerprints total.
- 5 enriched fingerprints with additional detections: Sonatype (+OSSRH Maven Central pattern, weight 0.8), Snyk (+alternate site verification), Ping Identity (+PingOne email trust, weight 0.6), CyberArk (+Idaptive CNAME, weight 0.7), Beyond Identity (+authenticator CNAME, weight 0.5).
- 7 new signals: "Agentic AI Infrastructure" (Layer 2 composite), "AI Adoption Without Governance" (contradiction), "AI Platform Diversity" (Layer 2), "Software Supply Chain Maturity" (Layer 2), "DevSecOps Investment Without Email Governance" (contradiction + metadata), "Edge-Native Architecture" (Layer 2), "Enterprise Email Deliverability" (Layer 1). 41 signals total.
- 4 new posture rules: `agentic_ai_detected`, `supply_chain_security_detected`, `edge_compute_detected`, `email_deliverability_management`.
- 62 new tests (896 → 958 total).

### Changed

- GitHub Advanced Security fingerprint pattern corrected from `_github-challenge:.` to `^_github-challenge-` (hyphen, not colon).
- "AI Adoption" signal updated with new agentic AI slugs (crewai-aid, langsmith, mcp-discovery).
- "Enterprise Security Stack" signal updated with beyond-identity.
- "Dev & Engineering Heavy" signal updated with flyio, railway, fastly.
- "Multi-Cloud" signal updated with fastly, flyio.
- `ai_tooling_detected` posture rule updated with new agentic AI slugs.

## [0.7.3] — 2026-04-12

### Changed

- README: restored "the art is in the correlation" in "What it does" section — it's the thesis, not hype.
- README: Limitations section sharpened — more direct about Cloudflare/proxy gaps producing near-empty results, fingerprint staleness being inevitable without community contributions, and confident-looking output sometimes being wrong.

## [0.7.2] — 2026-04-12

### Changed

- README rewritten with honest, grounded tone. Removed "leading platform" positioning, "Explainable Correlation Engine" branding, inflated comparison table, and repetitive zero-credentials copy. Added Limitations section acknowledging project maturity, fingerprint staleness risk, lack of accuracy benchmarks, and heuristic nature of signal rules. Comparison table now honestly notes paid tools typically have broader coverage.
- Roadmap intro simplified — removed aspirational "signal intelligence" branding.
- Fingerprint count normalized to "~190" across all docs (was inconsistent between 187/194).
- Changelog: removed "Explainable Correlation Engine" branding from v0.7.0 entry.

## [0.7.0] — 2026-04-12

### Added

- `--explain` CLI flag — shows why each insight and signal was produced, including matched evidence, fired rules, confidence derivation, and weakening conditions. Works with `--json` (adds `explanations` key), `--md` (adds Explanations section), and `--chain` (per-domain explanations).
- Explanation module (`recon_tool/explanation.py`) — generates `ExplanationRecord` frozen dataclasses with provenance chains for signals, insights, confidence, and posture observations.
- Enhanced YAML signal engine: `contradicts` key (negation logic — suppress signal when specific slugs are present), `requires_signals` key (meta-signals that fire when other named signals are active), `explain` field (curated human-written explanation text per signal/posture rule).
- Enhanced YAML fingerprint engine: `match_mode: all` (AND logic — require all detections to match), detection `weight` (0.0–1.0 evidence strength per detection rule).
- Two-pass signal evaluation: non-meta signals first, then meta-signals against first-pass results. Cycle prevention at load time.
- Weighted `compute_detection_scores()` — incorporates detection weights into per-slug confidence scoring.
- Conflict-aware merge — `MergeConflicts` frozen dataclass on `TenantInfo` tracks disagreements between sources. Surfaced in `--json` (`conflicts` key) and Rich panel (dim annotations with `--explain`).
- 5 new MCP tools: `get_fingerprints` (list loaded fingerprints with filters), `get_signals` (list loaded signals with layer/category filters), `explain_signal` (query signal definition + live evaluation against a domain), `test_hypothesis` (agent proposes theory, gets likelihood + evidence assessment), `simulate_hardening` (what-if exposure re-scoring with hypothetical fixes).
- `explain` parameter on `lookup_tenant` and `analyze_posture` MCP tools — when true, includes structured explanations in JSON response.
- 7 new fingerprints: n8n, Dify, AutoGen, Snyk, GitHub Advanced Security, Sonatype, Beyond Identity. ~190 fingerprints total.
- 5 new signals using v0.7.0 engine features: "Incomplete Identity Migration" (contradicts), "Split-Brain Email Config" (contradicts), "Security Stack Without Governance" (contradicts + metadata), "Complex Migration Window" (meta-signal), "Governance Sprawl" (meta-signal). 34 signals total.
- 173 new tests: unit tests for all engine changes, 10 Hypothesis property-based tests covering all correctness properties, CLI/MCP integration tests, backward compatibility tests. 896 tests total, 84% coverage.

### Changed

- `evaluate_signals()` now uses two-pass evaluation with `contradicts` suppression. File order within each pass is deterministic.
- `Signal` dataclass extended with `contradicts`, `requires_signals`, `explain` fields.
- `DetectionRule` dataclass extended with `weight` field.
- `Fingerprint` dataclass extended with `match_mode` field.
- `_PostureRule` dataclass extended with `explain` field.
- `render_tenant_panel()` accepts `explain` parameter for conflict annotations.
- MCP server now exposes 12 tools (was 7).
- All backward compatible with existing YAML files — new fields default to safe values.

## [0.6.1] — 2026-04-12

### Changed

- README panel alignment fixed (all lines exactly 72 characters).
- All test fixtures and examples use fictional company names only (Contoso, Northwind Traders, Fabrikam). Zero real company names in the repository.
- Validation corpus fixtures are gitignored — never committed.
- Release workflow: `skip-existing: true` prevents PyPI duplicate upload failures on tag re-pushes.

## [0.6.0] — 2026-04-12

### Added

- CertIntelProvider protocol — abstracts certificate transparency querying behind a clean interface. Two implementations: CrtshProvider (primary) and CertSpotterProvider (fallback). Shared filtering helpers ensure behavioral parity.
- CertSpotter fallback — when crt.sh is down (slow, rate-limited, or unreachable), the tool automatically falls back to CertSpotter's free, unauthenticated API. Zero API keys, zero accounts.
- Generalized `degraded_sources` — replaces the single-boolean `crtsh_degraded` with a `degraded_sources: tuple[str, ...]` field on both SourceResult and TenantInfo. Users and agents always know which public data sources were unavailable and how that affects result quality.
- Degraded sources surfaced in all output formats: Rich panel, JSON (`degraded_sources` list + backward-compatible `partial` key), markdown, and MCP text.
- 61 new tests: unit tests for providers, fallback chain, degraded_sources propagation, and 6 property-based tests (Hypothesis). 723 tests total, 84% coverage.
- Validation corpus — integration test runner (`pytest -m integration`) and accuracy report generator (`python -m tests.validation.generate_report` → `docs/accuracy.md`). Fixture files are local-only (gitignored).

### Changed

- `_detect_crtsh` replaced by `_detect_cert_intel` fallback chain in DNS sub-detector.
- `crtsh_degraded` is now a computed `@property` on SourceResult and TenantInfo (backward-compatible).
- Merger collects and deduplicates `degraded_sources` from all source results.
- README: defensive-use-only banner, "organization" replaces "target" throughout, zero-accounts emphasis.
- Legal docs: "What sees your queries" table showing exactly which services see your IP.
- Roadmap: dependency-ordered Now/Soon sections, custom profiles and `--explain` in Soon.

## [0.5.1] — 2026-04-12

### Added

- Full test coverage for defensive security tools: 12 property-based tests (Hypothesis), MCP integration tests, CLI flag tests, import safety test, banned-terms integration test. 660 tests total, 83% coverage.

### Removed

- `--html` output flag — markdown renders everywhere that matters. HTML was bloat for a focused CLI tool.

### Changed

- All test tasks are mandatory, not optional. No skipping.

## [0.5.0] — 2026-04-11

### Added

- `assess_exposure` MCP tool — structured security posture summary with email/identity/infrastructure sections, hardening control inventory, and 0–100 posture score based on publicly observable controls. For defensive security posture assessment only.
- `find_hardening_gaps` MCP tool — identifies missing or weak security configurations with categorized gaps (email, identity, infrastructure, consistency), severity levels, and "Consider ..." recommendations. For defensive security posture assessment only.
- `compare_postures` MCP tool — side-by-side comparison of two domains' security postures with metrics, control differences, and relative assessment. For defensive security posture assessment only.
- `--exposure` CLI flag — runs exposure assessment from the terminal.
- `--gaps` CLI flag — runs hardening gap analysis from the terminal.
- New `recon_tool/exposure.py` module — pure analysis functions operating exclusively on existing TenantInfo data. Zero new network calls. 14 frozen dataclasses for structured output.
- Extended banned terms enforcement — all new tool output validated against 16 banned terms to ensure neutral, defensive language throughout.
- Legal documentation updated with "Defensive Security Assessment Tools" section covering intended use cases, data source constraints, and language policy.

### Changed

- MCP server now exposes 7 tools (was 4): `lookup_tenant`, `analyze_posture`, `chain_lookup`, `reload_data`, `assess_exposure`, `find_hardening_gaps`, `compare_postures`.

## [0.4.1] — 2026-04-11

### Changed

- Added PyPI trusted publishing via GitHub Actions (OIDC, no API tokens).
- Added package metadata: classifiers, keywords, project URLs for PyPI listing.
- Fixed duplicate file warnings in wheel build by removing redundant `force-include`.

## [0.4.0] — 2026-04-11

### Added

- `--csv` output for batch mode — flat CSV with one row per domain. Columns: domain, provider, display_name, tenant_id, auth_type, confidence, email_security_score, service_count, dmarc_policy, mta_sts_mode, google_auth_type.
- Lightweight local disk cache — `~/.recon/cache/` with configurable TTL (default 24h). CLI flags: `--no-cache` to bypass, `--cache-ttl` to override. JSON files on disk, lazy eviction, no external dependencies.
- `recon mcp` subcommand — start the MCP server from the CLI instead of `python -m recon_tool.server`.
- `recon doctor --fix` — scaffolds template `~/.recon/fingerprints.yaml` and `~/.recon/signals.yaml` with inline YAML comments explaining the format.

### Changed

- Inference language tightened across insights and signals. Derived claims now use hedged language ("suggests," "indicators," "likely") instead of declarative phrasing. Factual observations (DMARC values, DKIM presence, email security scores) remain declarative.
- Removed `_preprocess_args()` sys.argv mutation hack. Domain shorthand routing (`recon contoso.com`) now uses a custom Typer group with `resolve_command()` override — cleaner, safer for library imports, no global state mutation.
- `_SUBCOMMANDS` now includes `"mcp"`.
- Mutual exclusion enforced for output format flags (`--json`, `--md`, `--csv`).

## [0.3.0] — 2026-04-11

### Added

- Google Workspace identity routing — new `GoogleIdentitySource` detects federated vs. managed auth by querying Google's public login flow. Extracts IdP name (Okta, Ping, Entra, etc.) for federated domains. Produces `google-federated`/`google-managed` slugs.
- Google Workspace CNAME module probing — detects active GWS modules (Mail, Calendar, Docs, Drive, Sites, Groups) via `ghs.googlehosted.com` CNAME resolution. Concurrent queries for all 6 prefixes.
- BIMI/VMC corporate identity extraction — fetches VMC certificates from BIMI `a=` URLs and extracts legally verified organization name, country, state, locality. Falls back to regex parsing when `cryptography` library is unavailable.
- Google site-verification token extraction — captures `google-site-verification` token values from TXT records for cross-domain organizational relationship mapping.
- MTA-STS policy fetch — when `_mta-sts` TXT record is found, fetches the policy file and extracts the mode (enforce/testing/none). Adds `mta-sts-enforce` slug for enforcing domains.
- TLS-RPT detection — detects `v=TLSRPTv1` records at `_smtp._tls.{domain}` with `tls-rpt` slug.
- Enhanced CSE config probing — extracts KACLS URL and multiple key service provider names from Google Workspace CSE configuration.
- Evidence traceability — new `EvidenceRecord` frozen dataclass captures source type, raw value, rule name, and slug for every detection. Propagated through the merge pipeline to `TenantInfo`. Included in `--json` output and `--verbose` display.
- Confidence separation — dual confidence model: `evidence_confidence` (how many sources contributed) and `inference_confidence` (strength of logical chain). Backward-compatible `confidence` field = min of both.
- Per-detection corroboration scoring — each detected slug gets a confidence score (high/medium/low) based on how many independent record types corroborate it.
- Fingerprint metadata enrichment — `provider_group` and `display_group` fields on fingerprint YAML entries. Formatter uses these for categorization, falling back to keyword heuristics.
- Cross-domain site-verification correlation in chain mode — domains sharing identical `google-site-verification` tokens are surfaced as organizationally related.
- 5 new Google Workspace signals: Google Workspace Full Suite, Google Federated Identity, Google MTA-STS Enforcing, plus updates to Google-Native Identity and Google Cloud Investment.
- 4 new posture rules: google_federated_identity, google_managed_identity, mta_sts_enforcing, tls_rpt_configured.
- Google Workspace insight generators: federated/managed identity insights, module summary insights.
- New data models: `EvidenceRecord`, `BIMIIdentity`. Extended `SourceResult`, `TenantInfo`, `Fingerprint` with new fields.
- 98 new tests (506 → 604 total). Test coverage 84%.

### Changed

- `default_pool()` now includes `GoogleIdentitySource` (5 sources total).
- `merge_results()` propagates evidence, computes dual confidence, detection scores, and merges Google auth/BIMI/MTA-STS/site-verification data.
- `build_insights_with_signals()` accepts `google_auth_type` and `google_idp_name` parameters.
- `format_tenant_dict()` includes all new fields in JSON output.
- `format_tenant_markdown()` includes Google Workspace section and dual confidence.
- `render_tenant_panel()` shows GWS auth/modules, verbose evidence chains and detection scores.
- `lookup_tenant` MCP tool text format includes GWS auth and module summary.
- `_detect_email_security()` now also queries TLS-RPT, fetches MTA-STS policy, and parses BIMI VMC.
- `_detect_txt()` extracts site-verification tokens and creates evidence records.
- Fingerprints YAML: added `provider_group`/`display_group` to Microsoft 365, Google Workspace, and other key entries. Added TLS-RPT fingerprint.
- 29 signals (was 26). 22 posture rules (was 18).

## [0.2.0] — 2026-04-11

### Added

- Certificate intelligence — crt.sh metadata extraction (issuance velocity, issuer diversity, cert age, top issuers) from the existing crt.sh JSON response. No additional HTTP requests. Surfaced in panel, JSON, and markdown output.
- Metadata-aware signal engine — signals can now match on `dmarc_policy`, `auth_type`, `email_security_score`, `spf_include_count`, and `issuance_velocity` via YAML `metadata` conditions. Supports slug-only, metadata-only, and conjunction signals. 23 → 26 signals (4 layers).
- Neutral posture analysis — new `--posture` flag and `analyze_posture` MCP tool. Produces factual observations about domain configuration (email, identity, infrastructure, SaaS footprint, certificates, consistency) without attack/defense framing. YAML-driven rules in `data/posture.yaml` with `~/.recon/posture.yaml` additive override.
- Delta mode — `--compare previous.json` compares a live lookup against a previous JSON export. Surfaces added/removed services, slugs, signals, and scalar field changes (auth type, DMARC, confidence, domain count). Panel output with +/- markers, JSON output with structured diff.
- Recursive domain chaining — `--chain --depth N` (max 3) follows related domains via CNAME/CT breadcrumbs using BFS. 50-domain cap, visited-set deduplication, aggregate timeout. New `chain_lookup` MCP tool.
- 3 new metadata-aware signals: Federated Identity with Complex Email Delegation, Active Email Sending with Minimal Security, High Certificate Issuance Activity.
- 18 posture observation rules across 6 categories.
- 7 new frozen dataclasses: `CertSummary`, `MetadataCondition`, `SignalContext`, `Observation`, `DeltaReport`, `ChainResult`, `ChainReport`.
- 51 new tests (455 → 506 total). Test coverage 83%.

### Changed

- `--full` now implies `--posture` in addition to `--services`, `--domains`, `--verbose`.
- `evaluate_signals()` now accepts a `SignalContext` instead of positional args. All callers updated.
- "Security Gap — Gateway Without DMARC Enforcement" signal moved from hardcoded Python check to YAML metadata conditions.
- `reload_data` MCP tool now also clears posture rule cache and reports posture rule count.
- README updated: broader audience description, new feature table rows, new CLI examples, new MCP tools listed.
- Roadmap updated: completed items marked, new future items added.

## [0.1.3] — 2026-04-11

### Added

- Common subdomain probing — ~35 high-signal prefixes (auth, login, sso, shop, api, status, cdn, etc.) are probed directly via DNS CNAME lookups. Works even when crt.sh is down.
- 30 new CNAME-based fingerprints for SaaS services discovered via subdomain CNAMEs: Okta (CNAME), Auth0, OneLogin, Salesforce Marketing Cloud, AWS ELB/S3/Elastic Beanstalk, Azure Front Door, Google Cloud Run/App Engine, Zendesk/Freshdesk (hosted), Contentful, Braze, Segment, Statuspage, LaunchDarkly, Cloudinary, Imgix, Optimizely, WalkMe, and more (156 → 186 total).
- crt.sh degraded notice — when crt.sh is unreachable, a subtle note appears in panel, markdown, and JSON output (`"partial": true`) so users know results may be incomplete.
- Lightweight subdomain enrichment — subdomains get CNAME+TXT-only lookups (2 queries each) instead of full DNS fingerprinting (~20 queries each), keeping enrichment fast.

### Changed

- crt.sh subdomain cap raised from 20 to 100, with signal-based prioritization (auth/login/shop/api subdomains first, deep internal subdomains last).
- Enrichment cap raised from 10 to 25, with priority sorting so high-signal subdomains survive the cap.
- Two-tier enrichment: subdomains get lightweight CNAME+TXT lookups, separate domains get full DNS fingerprinting.
- Updated 8 signal rules to include new CNAME-detected slugs (imperva, auth0, onelogin, salesforce-mc, aws-elb, aws-s3, gcp-app, azure-fd, optimizely, walkme, braze, iterable, customerio, launchdarkly, contentful, etc.).

## [0.1.2] — 2026-04-11

### Added

- Google Workspace source — passive CSE config probing (`cse.{domain}/.well-known/cse-configuration`) for detecting Client-Side Encryption and external key managers.
- Google DKIM attribution — `google._domainkey` now adds the `google-workspace` slug, so Google Workspace is detected even when MX points to an email gateway (Proofpoint, Mimecast, Trend Micro, etc.).
- 4 new signal rules: Google-Native Identity, High-Security Posture (CSE), Google Cloud Investment, Dual Email Provider (13 → 24 total).
- Custom signals support via `~/.recon/signals.yaml` (additive, mirrors fingerprint extensibility).
- Certificate transparency integration via crt.sh for passive subdomain discovery.
- Expanded DKIM selector coverage — now checks common ESP selectors (Mailchimp, SendGrid, Mailgun, Postmark, Mimecast) in addition to Exchange and Google.
- SRV record detection for Microsoft Teams (legacy SIP/federation), XMPP, CalDAV, CardDAV.
- 13 new fingerprints: Box, Egnyte, Glean, Datadog, New Relic, PagerDuty, Render, Ping Identity, CyberArk, Lakera, Cato Networks, Rippling, Deel (143 → 156 total).
- `recon doctor` now checks crt.sh connectivity, signal database loading, and custom signals path.
- "Why recon?" comparison table in README.
- Expanded MCP Server section with setup steps, tools table, and config file locations per client.
- `CLAUDE.md` for project context.
- `CHANGELOG.md`, `CONTRIBUTING.md`.
- `examples/` folder with sample JSON output and batch file (all fictional data).
- GitHub Actions CI workflow (Python 3.10–3.13, lint, type check, tests).

### Changed

- Confidence scoring — M365 domains now reach High when OIDC tenant ID is corroborated by UserRealm (display name, auth type, or tenant domains). Previously required 2+ sources returning the same tenant ID, which never happened in practice.
- Non-M365 confidence — domains with 8+ DNS services and 2+ successful sources now reach High. Thresholds adjusted (was: 5 services for Medium, High unreachable).
- Skype for Business / Lync → Microsoft Teams — SRV records `_sip._tls` and `_sipfederationtls._tcp` pointing to `lync.com` now labeled as "Microsoft Teams" (deduplicated with CNAME-based detection). Microsoft retired Skype for Business Online in July 2021.
- Dual provider insight — shortened from "Hybrid/migration signal: Google email + Microsoft services detected" to "Dual provider: Google + Microsoft coexistence". No longer styled as a warning.
- Panel color palette — muted, modern tones replacing harsh ANSI primaries. Labels use `dim` instead of `bold`. Panel border is `dim`. Confidence colors: sage green (High), sky blue (Medium), terracotta (Low).
- Panel alignment — services and insights now use consistent label:value column alignment. Service continuation lines align under the first service name. Long insights word-wrap within the panel.
- All README examples now use fictional companies (Northwind Traders, Contoso, Fabrikam).
- README tagline updated to be more precise and humble.
- Panel output: fixed width (80 chars), related domains now dim instead of cyan.
- Updated Enterprise Security Stack, Zero Trust Posture, and Enterprise IT Maturity signals to include new security slugs.

## [0.1.0] — 2026-04-10

### Added

- Initial release.
- Domain intelligence CLI (`recon lookup`, `recon batch`, `recon doctor`).
- MCP server with `lookup_tenant` and `reload_data` tools.
- Three concurrent data sources: OIDC Discovery, GetUserRealm + Autodiscover, DNS records.
- 143 SaaS/service fingerprints in `data/fingerprints.yaml` across 14 categories.
- Signal intelligence engine with 3-layer evaluation (single-category, cross-category composites, consistency checks).
- Email security scoring (0–5) based on DMARC, DKIM, SPF strict, MTA-STS, BIMI.
- Related domain auto-enrichment from CNAME breadcrumbs.
- Custom fingerprint support via `~/.recon/fingerprints.yaml`.
- Rich terminal output with bordered panels, colored signals, and provider detection.
- Output formats: default panel, `--json`, `--md`, `--services`, `--full`, `--sources`.
- Batch mode with configurable concurrency (1–20) and ordered output.
- Input normalization (URLs, schemes, www prefix, paths, whitespace).
- SSRF protection in HTTP transport.
- Retry with exponential backoff on 429/503 responses.
- Structured exit codes (0, 2, 3, 4).
- `defusedxml` for safe XML parsing.
- Strict type checking with Pyright, linting with Ruff.
