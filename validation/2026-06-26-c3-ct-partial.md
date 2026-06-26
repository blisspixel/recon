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

## Retry Session C

After the retry-corpus synthesis hardening, a small bounded retry was run
against the degraded records from Retry Session B. The goal was to test whether
the latest private retry input path still produces complete, aggregate-safe
artifacts and whether any additional CT data becomes available after limiter
cooldown.

- Retry corpus size: 33 domains.
- Valid streamed retry records: 33.
- Completion state: complete for this retry corpus.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-191156Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 1 |
| `live_rate_limited` | 32 |

This session added one more domain with usable CT data and produced one private
triage candidate. The candidate was promoted only after public-source review:
Descope's custom-domain documentation identifies `cname.descope.com` and
`CNAME.euc1.descope.com` as CNAME targets, so the public catalog now has a
conservative Descope `cname_target` rule. No private domain rows are published.
The slug is explicitly mapped to the Identity panel category and the exposure
identity-provider view so it cannot fall through to generic Business Apps.

## Retry Session D

After provider-health review, a bounded retry was run against the degraded
records from Retry Session C.

- Retry corpus size: 32 domains.
- Valid streamed retry records: 32.
- Completion state: complete for this retry corpus.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-203537Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 1 |
| `live_rate_limited` | 31 |

This session added one more domain with usable CT data and produced no triage
candidates. Because it still recovered new CT data, one more bounded retry was
justified under the C3 decision rule.

## Retry Session E

After cooldown, a bounded retry was run against the degraded records from Retry
Session D.

- Retry corpus size: 31 domains.
- Valid streamed retry records: 31.
- Completion state: complete for this retry corpus.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-204152Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 1 |
| `live_rate_limited` | 28 |
| `not_attempted` | 2 |

This session added one more domain with usable CT data and produced one private
triage candidate. The candidate was promoted only after public-source review:
Infobip's email domain setup documentation names the `email-messaging.com`
tracking and sending host family, so the existing `infobip` slug now has a
conservative `email-messaging.com` `cname_target` rule. The slug is explicitly
mapped to the Email panel category and has a negative lookalike-suffix test. No
private domain rows are published.

## Retry Session F

After the Infobip promotion, one final bounded retry was run against the
degraded records from Retry Session E to check whether the remaining tail still
contained public-source-backed catalog candidates.

- Retry corpus size: 28 domains.
- Valid streamed retry records: 15.
- Completion state: partial, controlled `--max-runtime` stop.
- External spend: 0 USD.
- Private artifacts: `validation/runs-private/20260626-205126Z/` and the
  synthesized retry input under `validation/runs-private/_inputs/` (gitignored).

| Outcome | Count |
|---|---:|
| `live_success` | 2 |
| `live_rate_limited` | 10 |
| `not_attempted` | 3 |

This session added two more domains with usable CT data and produced zero
triage candidates. The live retry loop should stop here: continuing would mostly
measure the same public-provider ceiling while adding little catalog signal.

## Combined Session Summary

The seven partial sessions were combined with
`validation/summarize_ct_sessions.py`, which deduplicates by domain internally
and emits aggregate counts only.

- Sessions summarized: 7.
- Valid records across sessions: 2,947.
- Records with a domain field: 2,909.
- Unique domains observed across sessions: 2,647.
- Domains with CT data (`cache_hit` or `live_success` as best outcome): 44.
- CT-data coverage ratio across observed domains: 0.016623.
- Domains still degraded or unresolved for CT: 2,603.
- Private aggregate summary:
  `validation/runs-private/c3-ct-session-summary-20260626.json` (gitignored).

Best outcome by unique domain:

| Outcome | Domains |
|---|---:|
| `cache_hit` | 28 |
| `live_success` | 16 |
| `live_rate_limited` | 50 |
| `cache_miss` | 1 |
| `breaker_open` | 2,552 |

This is the correct C3 accounting layer for further partial sessions: track
unique-domain CT coverage across sessions, not raw record counts alone.

## Closure Read

C3 should close as a partial CT validation track after the public-tree gate
passes. The track exercised CT retry behavior, cache fallback, attempt-outcome
accounting, aggregate summarization, candidate triage, and disclosure controls.
It did not and should not try to force full CT coverage through free public
search endpoints.
