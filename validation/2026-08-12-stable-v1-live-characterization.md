# Stable-v1 live product-quality characterization

Observed 2026-08-12. Recon 2.10.3, Python 3.14.4, MCP SDK 2.0.0.

Aggregate-safe convenience-sample characterization. This memo contains no
apex, organization, tenant, record-value, or per-domain row. It is a product
contract and performance diagnostic, not a population estimate, ablation, or
fusion decision.

## Decision summary

- The stable-v1 live-characterization prerequisite is complete. The no-CT path
  completed 50 of 50 attempts. The CT path completed 47 of 50; all three
  failures were bounded resolver timeouts.
- Every successful result passed claim validation, memory-cache and disk-cache
  round trips, JSON serialization, and a real warm `lookup_tenant` MCP call.
  No product-contract failure was observed.
- Four of 47 successful pairs, 8.5 percent, had any positive CT-attributable
  observable delta. CT-provider access was heavily degraded: 44 successful
  rows reported a rate-limited outcome, two reported live success, and one
  reported a cache miss.
- These CT results do not establish population utility and do not change the
  default. Provider rate limiting, three timeouts, one convenience sample, and
  a single network environment confound a promotion or retirement decision.
- The independent Draft 2020-12 schema-interoperability gate is green and
  remains blocking. It is separate from this network characterization.

The next decision-bearing work is the preregistered evaluation: freeze the
public sampling-frame declaration and private-frame SHA-256 commitment before
collection, collect at least 155 reference-positive and 183
reference-negative eligible cluster-excluded units, then run the frozen A3
versus A0 four-arm ablation.

## Reproduction boundary

The run used the documented command shape:

```bash
python -m validation.characterize_live_quality \
  --corpus validation/corpus-private/consolidated.txt \
  --output validation/runs-private/<UTC-stamp>/characterization.json \
  --network-class wifi \
  --sample-size 50 \
  --sampling-seed stable-v1-characterization-20260812 \
  --normalize-source \
  --exclude-invalid-source \
  --execute-network
```

The source and selected-frame commitments reproduce membership without
publishing it:

| Frame measure | Value |
|---|---:|
| Source input rows | 5,241 |
| Rows changed by apex normalization | 62 |
| Canonical duplicates removed | 39 |
| Invalid rows explicitly excluded | 3 |
| Eligible canonical rows | 5,199 |
| Deterministically selected rows | 50 |
| Source SHA-256 | `87178ba2b8ce596eaec26a59a1e57cdefe080a1f1109c1efcac19c24cf9cfdef` |
| Selection SHA-256 | `15b3d256ed25183c3187836b768ed0515d87d0be55b7c54279897e50aa6101c1` |
| Sampling method | `sha256-rank-without-replacement-v1` |
| Identifiers written | 0 |
| Per-domain rows written | 0 |

The exact repository revision was
`d8cc0896fc6369aeaeb9b1fcae69f165bbafecb4`; the working tree was dirty with
the characterization and product-contract fixes under review.

## Environment and method

| Measure | Value |
|---|---|
| Platform | Windows 11, AMD64 |
| Processor | AMD64 Family 25 Model 33 Stepping 2 |
| Network | Wi-Fi |
| Execution | Sequential, alternating CT/no-CT pair order by row parity |
| Resolver timeout | 120 seconds |
| Result isolation | Empty config and cache per row and mode |
| Optional direct probes | Disabled |
| Default target-owned HTTP | MTA-STS only |
| Event-loop instrumentation | asyncio debug, 0.01-second heartbeat, 0.05-second slow-callback threshold |
| Allocation instrumentation | `tracemalloc` around each measured product stage |
| Runtime logging | Suppressed during private rows to prevent identifier disclosure |
| Elapsed wall time | 1,329.808 seconds |

An unrelated CPU-heavy pytest process from another workspace overlapped this
run. Together with `tracemalloc` and asyncio debug instrumentation, that makes
the loop-lag and tail-latency values conservative diagnostics rather than
product SLOs.

## Live results

| Measure | CT disabled | CT enabled |
|---|---:|---:|
| Attempts | 50 | 50 |
| Successful product-contract rows | 50 | 47 |
| Failures | 0 | 3 timeouts |
| Partial successful results | 9 | 6 |
| Cold resolver p50 | 6.676 s | 6.837 s |
| Cold resolver p95 | 12.220 s | 34.302 s |
| Cold resolver maximum | 15.052 s | 118.113 s |
| Peak traced allocation p50 | 36,937,504 bytes | 36,942,630 bytes |
| Peak traced allocation p95 | 39,000,022 bytes | 37,051,506 bytes |
| Warm disk read plus render p50 | 0.026 s | 0.038 s |
| Warm disk read plus render p95 | 0.062 s | 0.078 s |
| Warm MCP call p50 | 0.011 s | 0.025 s |
| Warm MCP call p95 | 0.030 s | 0.058 s |
| JSON result p50 | 12,360 bytes | 12,408 bytes |
| JSON result p95 | 29,343 bytes | 33,149 bytes |
| MCP result wire p50 | 27,755 bytes | 27,867 bytes |
| MCP result wire p95 | 62,409 bytes | 71,269 bytes |
| Maximum event-loop lag p50 | 4.107 s | 4.081 s |
| Maximum event-loop lag p95 | 8.231 s | 6.704 s |
| Slow-callback observations | 394 | 374 |

The event-loop figures include tracing and concurrent-machine contention. They
show that the present instrumented cold path can monopolize the loop for
seconds, but they do not isolate a production root cause or justify a timing CI
threshold. A clean-machine, stage-specific follow-up is required before moving
work to threads or setting an SLO.

## Paired CT marginal value

| Measure across 47 successful pairs | p50 | p95 | Maximum |
|---|---:|---:|---:|
| CT resolver latency delta | -0.263 s | 29.193 s | 113.649 s |
| Added service count | 0 | 3 | 12 |
| Added fingerprint-slug count | 0 | 3 | 9 |
| Evidence-count delta | 0 | 11 | 20 |
| Related-domain-count delta | 0 | 0 | 40 |
| Surface-attribution-count delta | 0 | 0 | 19 |
| Insight-count delta | 0 | 3 | 5 |

The negative median latency delta is alternating-order noise, not evidence that
CT is faster. Only four pairs had any positive observable delta. CT-enabled
successes reported `live_rate_limited` 44 times, `live_success` twice, and
`cache_miss` once. Aggregate degradation markers recorded `crt.sh` on all 47
successful CT rows and Cert Spotter on 46.

## Limits and remaining channels

- The private source is a legacy convenience corpus. Normalization and explicit
  invalid-row exclusion are fully counted, but the selected frame is not a
  probability sample and supports no population claim.
- This is one Wi-Fi run on a dirty working tree with concurrent CPU contention.
  It characterizes the observed environment, not a cross-platform budget.
- Rate limiting means the CT comparison primarily characterizes current
  provider availability and bounded degradation, not CT's attainable signal
  ceiling.
- Classified versus unclassified observable surface, batch and graph workflow
  timings, independent outcome labels, and the preregistered ablation remain
  unmeasured here.
- No threshold, arm, margin, or decision rule was changed after observing these
  results.
