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
