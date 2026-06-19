# CrowdStrike Match-Mode Validation

Date: 2026-06-19

This note records a public-safe match-mode hardening pass. It uses only
fictional domains and aggregate catalog counts.

## Candidate

`crowdstrike` had two TXT detections:

- `^crowdstrike-falcon-site-verification=`
- `crowdstrike`

The broad TXT pattern could match unrelated records such as procurement notes.
The canonical Falcon verification token contains the broad literal, so a
single valid verification TXT still satisfies both detections when TXT
bookkeeping records every same-record match.

## Before

- Catalog audit: `match modes: any=841`.
- `procurement-note=crowdstrike renewal` on `northwindtraders.com` could fire
  the broad TXT rule as `CrowdStrike Falcon`.
- `crowdstrike-falcon-site-verification=abc123` on `contoso.com` fired the
  canonical verification rule.

## After

- Catalog audit: `match modes: all=1, any=840`.
- Audit recommendation for `crowdstrike`: `already_all`.
- `procurement-note=crowdstrike renewal` on `northwindtraders.com` is removed
  by `match_mode: all` enforcement.
- `crowdstrike-falcon-site-verification=abc123` on `contoso.com` still detects
  `CrowdStrike Falcon` because both TXT patterns match the same record.

## Local Validation

```bash
uv run python -m pytest tests/test_fingerprints.py tests/test_sources/test_dns.py -q
uv run python -m ruff check src/recon_tool/fingerprints.py src/recon_tool/sources/dns_email.py tests/test_fingerprints.py tests/test_sources/test_dns.py
uv run python -m validation.audit_fingerprints
```

Results:

- Focused tests: 72 passed.
- Focused lint: passed.
- Fingerprint audit: 1 `already_all`, 100 `keep_any`, 24 `review_for_all`,
  1 `tighten_patterns`.
