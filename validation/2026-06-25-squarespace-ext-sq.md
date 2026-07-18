# Squarespace Managed Subdomain Surface Fingerprint

Date: 2026-06-25

Scope: public rationale for adding one `cname_target` surface fingerprint, plus
aggregate-only notes from maintainer-local private triage. This memo contains no
target company names, target domains, corpus rows, or per-domain findings.

## Candidate Source

After the UltraDNS web-forwarding rule landed, the maintainer-local private gap
run still had 19 aggregate survivors from 1,335 unclassified suffix buckets and
1,723 total observations.

The `ext-sq.squarespace.com` candidate appeared four times in the aggregate set.
After adding this rule, the same re-filter produced 19 existing-pattern drops
and 18 survivors.

The remaining survivors are held for later review because they are target-owned,
generic platform internals, unclear or deprecated endpoints, or lack stable
public vendor documentation.

## Public Evidence

Squarespace support documents `ext-sq.squarespace.com` as the Data field to use
when manually adding a subdomain to a Squarespace site from a Squarespace-managed
domain DNS panel.

Reference:

- https://support.squarespace.com/hc/en-us/articles/205812058-Creating-a-subdomain-for-your-Squarespace-site

## Catalog Decision

Extend the existing high-confidence `squarespace` surface rule:

```yaml
- name: Squarespace
  slug: squarespace
  category: Infrastructure
  confidence: high
  detections:
  - type: cname_target
    pattern: ext-sq.squarespace.com
    tier: application
```

Interpretation boundary:

- This is evidence that the branded subdomain points to Squarespace-hosted site
  content.
- It complements the existing `ext-cust.squarespace.com` third-party
  custom-domain rule.
- It does not infer plan tier, account relationship, or ownership control.

## Reserved Synthetic Regression Shape

```text
blog.scenario.example.invalid -> ext-sq.squarespace.com
```

Expected result: application-tier surface attribution for `squarespace`; no
infrastructure-tier attribution.

## Validation

Focused validation passed:

- `uv run python -m pytest tests/test_surface_attribution.py -q` returned 24
  passed.
- `uv run python -m ruff check src/recon_tool/data/fingerprints tests/test_surface_attribution.py`
  passed.
- `uv run python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints --quiet`
  validated 843 entries with 0 failures.

Full gate passed:

- `uv run python scripts/check.py` returned 3,565 passed, 6 skipped, 4
  deselected, total coverage 86.56 percent, and all gate stages passed.
