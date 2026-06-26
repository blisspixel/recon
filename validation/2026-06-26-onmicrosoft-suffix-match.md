# Exchange Online DKIM suffix-match validation (2026-06-26)

Aggregate-only memo. No apexes, organization names, tenant IDs, or per-domain
output. Method and counts only, per the data-handling policy.

## Question

`_apply_exchange_dkim` in `sources/dns_email.py` attributed Microsoft 365 when a
DKIM CNAME contained `protection.outlook.com` or `onmicrosoft.com` as a raw
substring. A substring test also fires on a record where the vendor host is a
label inside the name rather than its suffix (for example
`x._domainkey.onmicrosoft.com.example.com`), which is not an Exchange Online
tenant. Does that false-positive shape occur on real data?

## Method

Re-used the per-domain evidence from an existing maintainer-local corpus scan
output (no new network calls). For every hostname-shaped evidence `raw_value`
across the scanned set, counted occurrences of each vendor pattern and split
them into clean dotted-suffix matches versus non-suffix substring matches. Only
counts leave the maintainer machine.

## Result

- Domains scanned: 1150 (a prior-run subset, not the full corpus).
- `onmicrosoft.com`: 825 hostname-shaped evidence values contained it; 823 were
  clean dotted suffixes and 2 were non-suffix substring matches (the
  false-positive shape). Rate 2/825, about 0.24 percent.
- A second pass over every evidence value (parsing SRV-style `priority weight
  port target` records to their target host) measured the other vendor patterns:
  `outlook.com` appeared 303 times, all clean suffixes; `google.com` appeared 757
  times, all clean suffixes; and `lync.com`, `teams.microsoft.com`,
  `manage.microsoft.com`, `enterpriseregistration.windows.net`, and
  `microsoftonline.com` had no evidence occurrence to measure. No pattern other
  than `onmicrosoft.com` produced a non-suffix match.

## Fix

`_apply_exchange_dkim` now matches `protection.outlook.com` and
`onmicrosoft.com` by host suffix (equal or dotted-suffix), normalizing a
trailing dot first. Suffix matching keeps every clean-suffix true positive and
drops only the non-suffix false positives, so there is no true-positive loss; a
genuine Exchange Online DKIM CNAME always carries the vendor host as its suffix.
Regression tests cover the real tenant CNAME, a trailing-dot variant, and the
lookalike false-positive shape (`tests/test_dns_subdetectors.py`).

## Decision on the other patterns

The remaining substring matches against DNS values (`outlook.com` and
`manage.microsoft.com` / `enterpriseregistration.windows.net` / `microsoftonline.com`
in `sources/dns_infra.py`, the SRV-based `lync.com` / `teams.microsoft.com`
checks, and the `google.com` GWS DKIM CNAME fallback in `sources/dns_email.py`)
are left unchanged. The validation above found zero non-suffix matches for them
on this corpus, so converting them to suffix matching would change no behaviour
on observed data while adding risk to core classification logic (the SRV target
parse in particular). Per the project's mirror-not-fitter discipline, detection
is tightened only on a demonstrated false positive, which only `onmicrosoft.com`
showed. If a future corpus pass surfaces a non-suffix match for any of these,
the same suffix-matching fix applies.
