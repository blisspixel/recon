# Supabase CNAME Target Fingerprint

Date: 2026-06-19

## Scope

This memo records the public rationale for adding a high-confidence Supabase
`cname_target` fingerprint. It contains no corpus rows, no customer domains, and
no per-target findings.

The official Supabase custom-domain guide says branded custom hostnames route to
the project hostname under `supabase.co`. That is stable passive CNAME evidence
and fits recon's catalog-growth rules.

The same guide also describes an `_acme-challenge` TXT flow for ownership
validation. That TXT name is generic ACME evidence, so it is not catalogued as a
Supabase-specific fingerprint.

## Catalog Entry

- slug: `supabase`
- category: `Infrastructure`
- confidence: `high`
- detection type: `cname_target`
- pattern: `supabase.co`
- reference: `https://supabase.com/docs/guides/platform/custom-domains`

## Fictional Regression

The regression uses a fictional chain:

```text
api.example.invalid -> abcdefghijklmnopqrst.supabase.co
```

Expected result:

- application attribution: `supabase`
- infrastructure attribution: none
- rollup cloud vendor: `Supabase`

## Validation

Focused tests:

```bash
uv run python -m pytest tests/test_surface_attribution.py tests/test_fingerprints.py tests/test_multi_cloud_rollup.py tests/test_slug_category_invariant.py tests/test_cloud_vendor_coverage.py -q
```

Result: passed with 90 tests.

Focused lint:

```bash
uv run python -m ruff check src/recon_tool/formatter_classify_tables.py tests/test_surface_attribution.py tests/test_fingerprints.py tests/test_multi_cloud_rollup.py
```

Result: passed.

Catalog validation:

```bash
uv run python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints/ --quiet
```

Result: passed with 842 entries.

Full local gate:

```bash
uv run python scripts/check.py
```

Result: passed. Coverage was 86.14 percent. Tests: 3411 passed, 6 skipped,
4 deselected.

External spend: 0 USD.
