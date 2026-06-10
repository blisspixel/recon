# Operational contract

The concrete runtime behavior a downstream integrator can depend on: the
timeouts, resource caps, exit codes, cache and partial-result semantics, and
determinism guarantees. These are not part of the locked JSON schema (see
[schema.md](schema.md) for that), but they are the operational behavior recon
holds itself to. Values here are current as of the latest release; they can move
within the stability contract, and the load-bearing ones are gated by tests
(see [assurance-case.md](assurance-case.md)).

The single most important guarantee: **no single attacker-influenceable input
can make recon crash, hang, or consume unbounded resources.** Every external
boundary is bounded by a named cap and a timeout, and every failure degrades to
a clean "we cannot tell" result. The bounds below are how that holds.

## Timeouts

| Timeout | Value | Scope |
|---|---|---|
| `RESOLVE_TIMEOUT` | 120 s | Aggregate wall-clock for the whole resolve pipeline (all sources + related-domain enrichment); on expiry raises `ReconLookupError(error_type="timeout")`. Override per call or with `--timeout`. |
| `DNS_QUERY_TIMEOUT` | 5 s | Per-DNS-query lifetime (total, including retries across nameservers); on expiry the query returns empty, not an error. |
| `_CT_TIMEOUT` | 6 s | Per CT-provider HTTP call (crt.sh, CertSpotter). |
| `DEFAULT_TIMEOUT` | 10 s | Default httpx client timeout for the shared HTTP client. |
| BIMI VMC / MTA-STS fetch | 5 s | The two opt-in / standard direct fetches. |
| `_MAX_TOTAL_RETRY_SLEEP` | 30 s | Cumulative cap on retry backoff sleeping for a single HTTP request across all retries, so repeated 429s cannot stack toward the aggregate budget. Per-attempt `Retry-After` is also clamped to 30 s. |

## Resource caps

A representative set; the full list lives in the source constants the
[assurance case](assurance-case.md) cross-references.

| Boundary | Cap |
|---|---|
| HTTP response body | `_MAX_RESPONSE_BYTES` = 10 MB, aborted mid-read; compressing `Content-Encoding` is refused (decompression-bomb guard) since recon requests identity encoding |
| HTTP redirects / retries | `MAX_REDIRECTS` = 5; `MAX_RETRIES` = 3 (429/503 only) |
| Domain input | `_MAX_INPUT_LENGTH` = 500 chars; source-derived display strings `_MAX_DISPLAY_LEN` = 200 |
| DNS regex-match inputs | `_MAX_TXT_MATCH_LENGTH` = 4096; `_MAX_SUBDOMAIN_TXT_MATCH_LEN` = 4096; `_MAX_CNAME_MATCH_LEN` = 255; SPF redirect depth = 3 |
| Related-domain enrichment | `MAX_RELATED_ENRICHMENTS` = 15 (6 deeper-tier) |
| CT extraction | `MAX_SUBDOMAINS` = 100; `_MAX_CRTSH_ENTRIES` = 2000; `_MAX_SANS_PER_CERT` = 2000; `_MAX_CRTSH_CERT_SUMMARY_ENTRIES` = 1000 (bounds CertSpotter too); `_MAX_PAGES` = 2; `_CT_GLOBAL_CONCURRENCY` = 2 |
| CT cert intelligence | wildcard clusters 10 (20 names); bursts 8 (25 names) |
| CT co-occurrence graph | `MAX_GRAPH_NODES` = 500; `_MAX_GRAPH_ENTRIES` = 1000; `_MAX_SANS_PER_CERT_FOR_EDGES` = 60; `_MAX_EDGE_ISSUER_SAMPLES` = 32; clusters 20 (50 members); `MAX_EDGES_RETAINED` = 2000 |
| Identity | `_MAX_AUTODISCOVER_DOMAINS` = 1000 federated domains |
| Fingerprint catalog | pattern length 500; `_MAX_CATALOG_ENTRIES_PER_FILE` = 2000; ephemeral (MCP) fingerprints 100 / 20 detections each / 500 total / 200-char fields |
| Cache files | `_MAX_CACHE_FILE_BYTES` = 5 MB; `_MAX_CT_CACHE_FILE_BYTES` = 5 MB (oversized = miss) |
| Batch input | 10000 domains; 1 KB / line; 10 MB / file |

## Exit codes

A script can branch on the outcome without parsing output (full contract in
[schema.md](schema.md#exit-codes)):

| Code | Constant | Meaning |
|---|---|---|
| 0 | `EXIT_SUCCESS` | Completed and produced output |
| 1 | `EXIT_ERROR` | General / uncaught error (also the Python default) |
| 2 | `EXIT_VALIDATION` | Bad input rejected before work (malformed domain, missing file, mutually exclusive flags, refused unsafe invocation) |
| 3 | `EXIT_NO_DATA` | Target resolved but no information available |
| 4 | `EXIT_INTERNAL` | recon classified its own caught network/pipeline failure |

## Cache and partial-result semantics

- **Disk caches never raise to the caller.** Any read failure (missing, stale,
  corrupt, oversized, or deeply-nested-JSON) degrades to a clean miss. TenantInfo
  cache TTL is 24 h; the CT-subdomain cache TTL is 30 days; both evict lazily by
  mtime. The TenantInfo write is atomic (`mkstemp` + `os.replace`).
- **Partial / degraded results are honored, not dropped.** `all_sources_failed`
  is raised only when *every* source errored and no tenant was found; if any
  source returns a clean result (even with no services), it is kept as a sparse
  "looked and found nothing" answer. A failed source is recorded in
  `degraded_sources`, and confidence is downgraded one level when a source is
  degraded, except when only the CT providers degraded and a CT cache fallback
  recovered the data.
- **CT is cache-first and fault-tolerant.** A fresh CT cache entry short-circuits
  the live providers; on live failure the cache is the final fallback, annotated
  with `ct_attempt_outcome` (`cache_hit`, `live_success`, `cache_miss`,
  `live_rate_limited`, `live_other_failure`, `breaker_open`). A mid-pagination
  429 returns partial CT data rather than an error.
- **Sparse is flagged, not hidden.** A thin result carries `sparse=true` in the
  JSON; the credible interval widens rather than collapsing on a fake-confident
  point estimate (see [correlation.md](correlation.md)).

## Determinism and reproducibility

- **Same input, same output.** The CT community-detection layer uses a fixed
  Louvain seed and normalizes node insertion order before partitioning (network
  responses arrive in non-stable order); above the node cap it falls back to
  deterministic connected components. Cluster, member, edge, burst, and
  subdomain orderings are all sorted/canonical. Enriched services/slugs and
  `degraded_sources` are emitted sorted.
- **Same source, same artifact.** The release build is bit-for-bit reproducible
  (`SOURCE_DATE_EPOCH` pinned to the tagged commit), gated by the
  `reproducible-build` CI job and verifiable by a consumer; see
  [supply-chain.md](supply-chain.md).
