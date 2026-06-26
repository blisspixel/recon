# C3 CT Partial Session Memo (2026-06-26)

This is an aggregate-only maintainer note for the CT-enabled C3 validation
track. It is not a completed full-corpus C3 result and it does not update any
Bayesian calibration claim.

## Session Shape

- Corpus size: 5,241 domains.
- Valid streamed records recovered: 2,693.
- Completion state: partial.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-114954Z/` (gitignored).

## CT Outcome Counts

| Outcome | Count |
|---|---:|
| `cache_hit` | 29 |
| `live_success` | 9 |
| `live_rate_limited` | 23 |
| `breaker_open` | 2,600 |
| `cache_miss` | 1 |

The result confirms the roadmap framing: CT-enabled corpus work is partial and
multi-session under public free-provider limits. The high `breaker_open` count
means this session mostly measured the local limiter state rather than fresh CT
coverage. The nine Bayesian calibration nodes remain covered by the no-CT
calibration pass; CT contributes to certificate, infrastructure-cluster, and
lexical surfaces only.

## Operational Fix From The Session

The first attempt was stopped by an outer process timeout after NDJSON records
had already streamed. The wrapper previously had no controlled way to finalize
that partial stream, so the run directory lacked summary and triage artifacts.

Follow-up code now supports:

- `recon batch --timeout` for per-domain batch resolve bounds.
- `validation/scan.py --max-runtime` for controlled partial NDJSON sessions.
- `validation/scan.py --finalize-existing` for no-network recovery of an
  interrupted run directory.
- Valid-record counting that ignores a malformed trailing NDJSON line left by
  an external kill.
- Process-tree termination for controlled `--max-runtime` stops on Windows.

## Next C3 Step

Continue C3 as bounded partial sessions, preferably after CT limiter cooldown,
and treat `ct_budget_summary.json` plus `meta.json` as the session health record.
Do not compare partial sessions against complete prior scans.

## Retry Session A

After hardening `--ct-retry-from`, a short bounded retry was run against the
degraded CT records from the first partial session.

- Retry corpus size: 2,610 domains.
- Valid streamed retry records: 109.
- Completion state: partial, controlled `--max-runtime` stop.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-155208Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 1 |
| `live_rate_limited` | 1 |
| `breaker_open` | 105 |
| `not_attempted` | 2 |

This retry confirms the hardened continuation path works, including private
retry-corpus placement and partial finalization. It does not close C3: the run
mostly measured continued CT breaker pressure and produced no triage candidates.

## Retry Session B

After tightening CT attempt-outcome accounting, a short bounded retry was run
against the degraded records from Retry Session A. This run tested whether mixed
provider states are reported as live pacing failures instead of collapsing into
the `breaker_open` bucket.

- Retry corpus size: 106 domains.
- Valid streamed retry records: 34.
- Completion state: partial, controlled `--max-runtime` stop.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-171647Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 1 |
| `live_rate_limited` | 33 |

This session confirms the corrected accounting shape: the retry was limited by
live provider pacing, not by all-provider breaker stops. It also added one more
domain with usable CT data. It still does not close C3.

## Combined Session Summary

The three partial sessions were combined with
`validation/summarize_ct_sessions.py`, which deduplicates by domain internally
and emits aggregate counts only.

- Sessions summarized: 3.
- Valid records across sessions: 2,836.
- Records with a domain field: 2,803.
- Unique domains observed across sessions: 2,647.
- Domains with CT data (`cache_hit` or `live_success` as best outcome): 39.
- CT-data coverage ratio across observed domains: 0.014734.
- Domains still degraded or unresolved for CT: 2,608.
- Private aggregate summary:
  `validation/runs-private/c3-ct-session-summary-20260626.json` (gitignored).

Best outcome by unique domain:

| Outcome | Domains |
|---|---:|
| `cache_hit` | 28 |
| `live_success` | 11 |
| `live_rate_limited` | 55 |
| `cache_miss` | 1 |
| `breaker_open` | 2,552 |

This is the correct C3 accounting layer for further partial sessions: track
unique-domain CT coverage across sessions, not raw record counts alone.
