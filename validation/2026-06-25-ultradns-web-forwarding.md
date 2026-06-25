# UltraDNS Web Forwarding Surface Fingerprint

Date: 2026-06-25

Scope: public rationale for adding one `cname_target` surface fingerprint, plus
aggregate-only notes from maintainer-local private triage. This memo contains no
target company names, target domains, corpus rows, or per-domain findings.

## Candidate Source

A maintainer-local private gap run was re-filtered with the current public
catalog. The input contained 1,335 unclassified suffix buckets and 1,723 total
observations.

Filter deltas:

- Current catalog before this patch: 13 existing-pattern drops, 21 survivors.
- Sample-aware candidate filter: 17 existing-pattern drops, 20 survivors.
- Sample-aware filter plus the UltraDNS rule in this patch: 18 existing-pattern
  drops, 19 survivors.

The sample-aware filter matters because `find_gaps` buckets CNAME terminals by
their rightmost three labels. A suffix bucket can therefore hide a more specific
hostname label that an existing `cname_target` pattern already covers.

Only one reviewed candidate met the public-tree bar in this pass:
`crs.ultradns.net`, observed three times in the aggregate candidate set. The
remaining survivors are held for later review because they are target-owned,
generic platform internals, unclear or deprecated endpoints, or lack stable
public vendor documentation.

## Public Evidence

UltraDNS public support documents that UltraDNS Web Forwarding records can
create either an A record to an UltraDNS forwarding address or a CNAME to
`crs.ultradns.net`.

UltraDNS product documentation describes Web Forwarding as a managed redirect
service for HTTP traffic, including simple, framed, and HTTP 301 redirection.

References:

- https://dns.ultraproducts.support/hc/en-us/articles/4409648155547-Why-do-I-have-records-that-point-to-crs-ultradns-net-204-74-99-100-or-204-74-99-200
- https://docs.ultradns.com/Content/Traffic_Management_User_Guide/Content/User%20Guides/Traffic_Management_User_Guide/Web%20Forwarding.htm

## Catalog Decision

Add one high-confidence surface rule:

```yaml
- name: UltraDNS (Neustar)
  slug: ultradns
  category: Infrastructure
  confidence: high
  detections:
  - type: cname_target
    pattern: crs.ultradns.net
    tier: infrastructure
```

Interpretation boundary:

- This is evidence that the subdomain is configured as an UltraDNS-managed web
  forward.
- It is not evidence that the destination application is hosted by UltraDNS.
- It is not evidence of broader DNS authority unless NS evidence independently
  supports that.

## Fictional Regression Shape

```text
go.contoso.com -> crs.ultradns.net
```

Expected result: infrastructure-tier surface attribution for `ultradns`; no
application-tier attribution.

## Validation

Focused validation passed:

- `uv run python -m pytest tests/test_triage_candidates.py tests/test_surface_attribution.py -q`
  returned 26 passed.
- `uv run python -m ruff check validation/triage_candidates.py tests/test_triage_candidates.py tests/test_surface_attribution.py`
  passed.
- `uv run python scripts/validate_fingerprint.py src/recon_tool/data/fingerprints --quiet`
  validated 843 entries with 0 failures.
- `python scripts/check_validation_hygiene.py` passed.
- `python scripts/check_text_hygiene.py` passed.

Full gate passed:

- `uv run python scripts/check.py` returned 3,565 passed, 5 skipped, 4
  deselected, total coverage 86.53 percent, and all gate stages passed.
