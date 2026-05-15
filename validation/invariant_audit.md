# v1.9.9 — distinct invariant audit and remediation plan

The v1.9.9 ship report quotes "167 new tests across 20 files." A
rigorous review correctly notes that test count is not test
quality: many tests are parametric variants of the same invariant,
and inflated test counts overclaim coverage breadth.

This document audits the distinct *invariants* the v1.9.9 test
suite actually pins, and assigns each "what we don't test" item
from the test-quality manifesto a specific remediation milestone.

## Distinct invariants pinned by v1.9.9 tests

The audit collapses parametric variants and identifies the
underlying claim each test class makes. Where a test file pins
multiple invariants (e.g. fixture firing + suppression both
matter), each invariant is counted separately.

### Multi-cloud rollup (8 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Canonicalization is many-to-one (AWS family → AWS) | `test_multi_cloud_rollup.py::TestCanonicalCloudVendor` |
| Firebase rolls up under GCP at the rollup level | same |
| Non-cloud slugs return None (not empty string) | same + `test_mutation_resistance.py::TestAdditionalMutations` |
| `count_cloud_vendors` is multiset-order independent | `test_count_cloud_vendors_properties.py::TestOrderInvariance` |
| Adding non-cloud slugs is a no-op | same `::TestNonCloudInvariance` |
| Apex+surface stream union semantics | same `::TestStreamUnionSemantics` |
| Vendor count bounded above by distinct input slugs | same `::TestVendorCountBounds` |
| Every Cloud-categorized slug has an explicit rollup decision | `test_cloud_vendor_coverage.py` |

### Ceiling trigger (5 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Fires on sparse-services + multi-domain + low-attribs apex | `test_formatter_ceiling.py` |
| Suppresses on each independent gate (single-domain, dense-services, many-attribs, full mode, empty services) | same + boundary tests |
| Off-by-one boundaries pinned exactly | `test_formatter_ceiling_boundary.py` |
| Empty services is a hard short-circuit (Hypothesis) | `test_catalog_driven_corpus.py::TestCeilingInvariantsOnCatalogInputs` |
| `--full` mode is a hard short-circuit (Hypothesis) | same |

### Wordlist breadth (4 distinct invariants)

| Invariant | Pinned by |
|---|---|
| All 8 v1.9.9 prefixes present in active probe | `test_subdomain_enumeration_breadth.py` + `test_wordlist_sanity.py` |
| All 8 v1.9.9 prefixes present in CT priority | same |
| Prefixes are deduplicated, lowercase, no whitespace | `test_wordlist_sanity.py` |
| Active probe and CT priority maintain parity | same |

### Renderer correctness (8 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Render does not raise on arbitrary TenantInfo (500 examples) | `test_render_fuzz.py` |
| Render output is a non-empty string with display name | same |
| Render is deterministic across N calls (in-process) | `test_render_determinism.py` |
| Render is deterministic across PYTHONHASHSEED values | same |
| No vendor duplication in rollup line | `test_panel_output_sanity.py` |
| Provider count matches listed vendor count | same |
| Ceiling phrasing well-formed (no double-punct) | same |
| Ceiling phrasing avoids overclaim words | same + `test_humble_tone_global.py` |

### JSON / schema (3 distinct invariants)

| Invariant | Pinned by |
|---|---|
| New panel surfaces never leak as substrings into JSON | `test_panel_only_surfaces_json_absence.py` |
| No new top-level data fields in JSON shape | same |
| `_CACHE_VERSION` constant pinning prevents silent bump | `test_cache_cross_version_compatibility.py` |

### Cross-version compatibility (3 distinct invariants)

| Invariant | Pinned by |
|---|---|
| v1.9.8 cache loads via v1.9.9 reader | `test_cache_cross_version_compatibility.py` |
| v1.9.9 surfaces derive from v1.9.8 cache without re-collection | same |
| v1.9.2 agentic-UX fixtures still load and render | `test_agentic_ux_compatibility.py` |

### CLI integration (4 distinct invariants)

| Invariant | Pinned by |
|---|---|
| `--help` and `--version` exit 0 | `test_cli_integration_smoke.py` |
| Every subcommand's help loads | same |
| Unknown input produces a clean error (no traceback) | same |
| Entry-point declaration matches export | same |

### Adversarial robustness (5 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Unicode display names render | `test_adversarial_render.py` |
| Control characters in slugs do not crash render | same |
| Very-large inputs (1000 slugs, 200 attribs) render | same |
| Minimal inputs render | same |
| Punycode IDN subdomains render | same |

### Performance (3 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Render time under bounded budget at 10 / 100 / 1000 slug scales | `test_render_performance.py` |
| Render scaling is sub-quadratic | same |
| Surface-attribution scaling is sub-quadratic | same |

### Test-quality and discipline (5 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Five+ named mutations of the v1.9.9 helpers are caught by existing tests | `test_mutation_resistance.py` |
| Three-way trigger agreement (renderer + aggregator + regex) | `test_trigger_differential_agreement.py` |
| No overclaim words in fingerprint catalog descriptions | `test_humble_tone_global.py` |
| No overclaim words in formatter top-level constants | same |
| Trigger thresholds sensitivity is robust to small parameter changes | `validation/threshold_sensitivity.md` (analysis, not pytest) |

### Adversarial corpus (Hypothesis, drawn from real catalog) (3 distinct invariants)

| Invariant | Pinned by |
|---|---|
| Zero cloud vendors → rollup never fires | `test_catalog_driven_corpus.py::TestMultiCloudInvariantsOnCatalogInputs` |
| Two+ distinct vendors → rollup always fires | same |
| Catalog-categorized inputs that miss the order tuple do not crash render | (caught a real bug — `Data & Analytics` was missing from `_SERVICE_CATEGORIES_ORDER`; fixed) |

## Total distinct invariants: 51

The v1.9.9 ship report's "167 tests" inflates this by ~3.3×. Most
of the inflation is parametric variants in mutation tests, render
fuzz, property tests, and boundary cases. The 51-invariant count
is the honest measurement of what the test suite actually pins.

## Remediation plan for "what we honestly do not test" items

The `validation/v1.9.9-detection-gap-ux.md` test-quality manifesto
lists six "what we don't test" items. Each gets a specific
milestone here.

### 1. Empirical accuracy on real corpus

**Status:** synthetic 19-fixture corpus exists; real-corpus run
deferred to maintainer-local execution.
**Remediation milestone:** v1.9.10 stratified-corpus pre-lock
validation. The aggregator at `validation/corpus_aggregator.py`
is reusable for this; the v1.9.10 deliverable runs it against the
gitignored corpus and emits anonymized stats to
`validation/v1.9.10-corpus-run.md`.
**Definition of done:** the v1.9.10 memo records firing rates from
the real corpus and either confirms they match the synthetic-corpus
shape or documents the divergence.

### 2. Full mutation coverage

**Status:** hand-rolled mutation library covers six named
mutations; cosmic-ray pilot was attempted but interrupted.
**Remediation milestone:** v1.9.10 — full cosmic-ray sweep on
formatter.py (config authored at sweep time, not committed
in advance). Document surviving mutants and either kill them
with new tests or explicitly accept them in the manifesto.
**Definition of done:** the v1.9.10 memo records the cosmic-ray
results (mutation count, killed count, surviving-mutant list with
disposition).

### 3. Agent operator UX on v1.9.9 surfaces

**Status:** v1.9.2 fixtures re-rendered through v1.9.9 panel
(snapshot report at `validation/synthetic_corpus/render_snapshots.md`),
but agent-step not run.
**Remediation milestone:** v1.9.11 documentation polish includes
the agentic-UX runbook (`validation/agentic_ux_v199_runbook.md`)
that names the smallest-cost LLM invocation. Maintainer runs the
agent step locally before v2.0 tag.
**Definition of done:** a `validation/v1.9.9-agentic-ux-update.md`
that captures whether agents read the new surfaces correctly on
the rendered fixtures.

### 4. Performance / memory bounds

**Status:** time bounds at three scales pinned by
`test_render_performance.py`; baseline measured in
`validation/performance_baseline.md`.
**Remediation milestone:** post-v2.0 backlog. The memory dimension
needs a `tracemalloc`-based test; the cold-cache dimension needs a
separate measurement. Neither blocks v2.0.
**Definition of done:** post-v2.0 issue / PR.

### 5. Network / DNS / CT integration paths

**Status:** out of v1.9.9 scope; covered elsewhere by source-
specific test suites.
**Remediation milestone:** none required for v1.9.9 (correctly
out of scope). Existing `tests/test_dns_*.py` etc. cover the
integration paths.

### 6. Bayesian inference layer un-revalidated after v1.9.9 evidence
distribution shift

**Status:** v1.9.9 wordlist additions widen the slug-collection
surface, which changes the evidence distribution flowing into the
network. The calibration was last validated at v1.9.6.
**Remediation milestone:** v1.9.10 — re-run the v1.9.5 stability
checks with the v1.9.9 wordlist additions in place. Document
whether per-node firing counts shift, whether the corpus exposure
threshold (criterion (c)) for `okta_idp` improves, and whether
any node's calibration regresses.
**Definition of done:** the v1.9.10 memo records a stability table
re-run with v1.9.9 evidence in scope.

## Pinning

Each "what we honestly don't test" item now has a named milestone
and a definition of done. The v1.9.10 roadmap section should
incorporate items 1, 2, and 6 as deliverables. Items 3 (agentic
UX) and 4 (perf/memory) are post-v1.9.11 and post-v2.0
respectively. Item 5 is correctly closed as out-of-scope.
