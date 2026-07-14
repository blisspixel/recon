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
| Google CSE / BIMI VMC / MTA-STS fetch | 5 s | The two opt-in direct-probe classes and the standard default MTA-STS policy fetch. |
| `_MAX_TOTAL_RETRY_SLEEP` | 30 s | Cumulative cap on retry backoff sleeping for a single HTTP request across all retries, so repeated 429s cannot stack toward the aggregate budget. Per-attempt `Retry-After` is also clamped to 30 s. |

For 429 and 503 responses, a numeric `Retry-After` value is accepted only when
it is finite and non-negative, then clamped to 30 seconds. Date-form,
malformed, negative, and non-finite values use exponential backoff instead.
`Retry-After: 0` retries without sleeping. The cumulative sleep cap still
applies across all attempts.

## Resource caps

A representative set; the full list lives in the source constants the
[assurance case](assurance-case.md) cross-references.

| Boundary | Cap |
|---|---|
| HTTP response body | `_MAX_RESPONSE_BYTES` = 10 MB, aborted mid-read; compressing `Content-Encoding` is refused (decompression-bomb guard) since recon requests identity encoding |
| HTTP redirects / retries | `MAX_REDIRECTS` = 5; `MAX_RETRIES` = 3 (429/503 only) |
| Domain input | `_MAX_INPUT_LENGTH` = 500 chars before normalization; normalized DNS presentation form = 253 ASCII octets total and 63 per label; source-derived display strings `_MAX_DISPLAY_LEN` = 200 |
| DNS regex-match inputs | `_MAX_TXT_MATCH_LENGTH` = 4096; `_MAX_SUBDOMAIN_TXT_MATCH_LEN` = 4096; `_MAX_CNAME_MATCH_LEN` = 255; SPF redirect depth = 3 |
| Related-domain enrichment | `MAX_RELATED_ENRICHMENTS` = 15 (6 deeper-tier) |
| CT extraction | `MAX_SUBDOMAINS` = 100; `_MAX_CRTSH_ENTRIES` = 2000; `_MAX_SANS_PER_CERT` = 2000; `_MAX_CRTSH_CERT_SUMMARY_ENTRIES` = 1000 (bounds CertSpotter too); `_MAX_PAGES` = 2; `_CT_GLOBAL_CONCURRENCY` = 2 |
| CT cert intelligence | wildcard clusters 10 (20 names); bursts 8 (25 names) |
| CT co-occurrence graph | `MAX_GRAPH_NODES` = 500; `_MAX_GRAPH_ENTRIES` = 1000; `_MAX_SANS_PER_CERT_FOR_EDGES` = 60; `_MAX_EDGE_ISSUER_SAMPLES` = 32; clusters 20 (50 members); `MAX_EDGES_RETAINED` = 2000 |
| Identity | `_MAX_AUTODISCOVER_DOMAINS` = 1000 federated domains |
| Fingerprint catalog | pattern length 500; `_MAX_CATALOG_ENTRIES_PER_FILE` = 2000; ephemeral (MCP) fingerprints 100 / 20 detections each / 500 total / 200-char fields |
| Cache files | `_MAX_CACHE_FILE_BYTES` = 5 MB; `_MAX_CT_CACHE_FILE_BYTES` = 5 MB (oversized = miss) |
| Persisted rate-limiter state | 64 KiB per provider; versioned, provider-bound, finite numeric fields only |
| PyPI update metadata | 5 MiB response body and 100 JSON nesting levels |
| Batch input | 10,000 non-comment input records before deduplication; 1 KiB UTF-8 per logical line; 10 MiB UTF-8 total |

## Exit codes

A script can branch on the outcome without parsing output (full contract in
[schema.md](schema.md#exit-codes)):

| Code | Constant | Meaning |
|---|---|---|
| 0 | `EXIT_SUCCESS` | Completed and produced output |
| 1 | `EXIT_ERROR` | General / uncaught error (also the Python default) |
| 2 | `EXIT_VALIDATION` | Bad input rejected before work (malformed domain, missing file, mutually exclusive flags, refused unsafe invocation) |
| 3 | `EXIT_NO_DATA` | Target resolved but no information available, or `recon delta` had no cached baseline |
| 4 | `EXIT_INTERNAL` | recon classified its own caught network/pipeline failure |

For single-domain lookup paths, only a structured resolver error with
`error_type="no_data"` maps to exit 3. A first `recon delta` call also exits 3
when no cached snapshot exists; it performs no live resolution and emits no
delta payload. Aggregate timeout,
`all_sources_failed`, and unknown structured resolver failures preserve their
concrete message and map to exit 4. Successful JSON, Markdown, and plain
payloads are written alone to stdout. Human progress and `--verbose` source
diagnostics use stderr, so a successful structured stdout stream can be parsed
without removing presentation lines. Verbose source diagnostics use explicit
`match`, `no match`, and `error` states; a clean negative observation is not
styled or labeled as a transport failure.

Interactive cache-miss lookups use one deterministic, outcome-neutral progress
message; chain resolution uses a separate label for that selected operation.
Progress text does not claim that an individual collector, inference pass, or
posture analysis is currently running. `--debug` enables diagnostics from both
owned logger namespaces (`recon` and `recon_tool`), installs one CLI stderr
handler per namespace without adding another on repeat configuration, and
prevents propagation to host root handlers. Direct handlers explicitly
installed on an owned or child logger by an embedding host are preserved and
remain the host's responsibility.

MCP lookup tools preserve the same distinction. Only `error_type="no_data"`
uses `No information found for ...`; timeouts and total source failure retain
truthful failure text instead of being presented as an empty observation.

The `recon doctor` health check follows the same convention: it exits 0 when
every check passes or only optional enrichment (for example crt.sh) is degraded,
and exits 1 when a core check fails, so a CI or monitoring job can gate on
environment health instead of always reading success. `recon doctor --mcp`
follows the same rule for MCP setup: it exits 1 when the server cannot be
validated (package missing, server import failure, or no tools registered).

## Batch CSV contract

`recon batch <file> --csv` emits RFC 4180 CSV with this canonical column order:

`domain,provider,display_name,tenant_id,auth_type,confidence,email_security_score,service_count,dmarc_policy,mta_sts_mode,google_auth_type,error`

Every input retained after batch deduplication produces one data row. A
successful lookup leaves `error` empty. A failed lookup populates `domain` and
`error` while leaving the observation columns empty, so spreadsheet users and
machine consumers can distinguish an observed sparse result from a lookup
failure without parsing human text.

Before RFC 4180 quoting, recon neutralizes spreadsheet formulas in every
textual cell. If the first character after leading ASCII spaces is `=`, `+`,
`-`, `@`, a tab, a carriage return, or a newline, recon prefixes the cell with
a single quote. This applies to successful observation fields and to failure
domains and messages. Consumers that require the unmodified structured values
should use JSON rather than the spreadsheet-oriented CSV surface.

## Cache and partial-result semantics

- **Disk caches never raise to the caller.** Any read failure (missing, stale,
  corrupt, non-object, wrong-shaped, numerically invalid, oversized, or
  deeply-nested JSON) degrades to a clean miss. Normal
  TenantInfo reads use a 24 h TTL; `recon delta` may retain the same entry for up
  to 30 days as its comparison baseline. The per-domain CT cache TTL is 30 days.
  Both caches admit data through a bounded regular-file descriptor, reject
  symbolic links, stable redirected cache directories, mutation during the
  read, materially future mtimes, and expired data before JSON decoding, then
  write atomically with a sibling `mkstemp` file followed by `os.replace`.
- **Cache identity follows lookup identity.** Result and CT payloads are bound
  to the validated domain in their filename. Registrable-apex and literal-host
  entries are independent. `recon cache show <host> --exact` inspects a literal
  CT key; `recon cache clear <host> --exact` removes that host from both caches.
  Without `--exact`, cache commands retain normal apex reduction. CT entries
  written before v2.6.1 lack the binding metadata and repopulate on demand.
- **Rate-limiter warm starts fail closed.** Persisted state is versioned and
  provider-bound. Oversized, nested, stale, cross-provider, non-finite,
  overflowing, or out-of-range fields are ignored as one invalid snapshot.
  Writes use a random exclusive temporary path and atomic replacement.
- **Partial / degraded results are honored, not dropped.** `all_sources_failed`
  is raised only when *every* source errored and no tenant was found; if any
  source returns a clean result (even with no services), it is kept as a sparse
  "looked and found nothing" answer. A failed source is recorded in
  `degraded_sources`, and confidence is downgraded one level when a source is
  degraded, except when only the CT providers degraded and a CT cache fallback
  recovered the data.
- **Granular failure is not negative evidence.** DNS and detector markers may
  identify one unavailable observation channel, including `dns:apex_txt`,
  `dns:dmarc`, `dns:mta_sts`, `http:mta_sts_policy`, or `dns:mx`. Bayesian
  absence factors, cohort denominators, exposure scores, and hardening-gap
  output mask only the affected channel. `NXDOMAIN` and `NoAnswer` remain clean,
  observed empty responses. Legacy `dns` and current `dns_records` markers mask
  every DNS channel.
- **Observed empty is not authenticated denial.** The resolver adapter does not
  retain the authority section, recursive-resolver identity, or DNSSEC denial
  validation, and its private-canonical safety suppression also returns an
  empty list. Current public surfaces may describe the operational result as no
  record observed, but the internal claim-contract layer does not promote it to
  an authoritative or authenticated negative certificate.
- **DMARC follows RFC 9989 discovery semantics.** ASCII space or tab around
  `=` and case-insensitive tag names are accepted; the `DMARC1` value remains
  case-sensitive. A missing or invalid `p`, or an invalid `sp` or `np`, falls
  back to effective `none` only when `rua` contains a syntactically valid
  reporting URI. The exact reject claim signs only an explicit valid `p` value,
  so fallback `none` remains unresolved for that narrower predicate. The DMARC
  service and raw record remain visible, while stable `dmarc_policy` stays null
  rather than fabricating an explicit `p=none`.
- **CT is cache-first and fault-tolerant.** A fresh CT cache entry short-circuits
  the live providers; on live failure the cache is the final fallback, annotated
  with `ct_attempt_outcome` (`cache_hit`, `live_success`, `cache_miss`,
  `live_rate_limited`, `live_other_failure`, `breaker_open`). A mid-pagination
  429 returns partial CT data rather than an error. When providers fail in
  different ways, live attempted failures are labeled ahead of a separate open
  breaker so `breaker_open` means every failed provider was stopped locally.
  Cache reuse preserves the full certificate summary and infrastructure
  cluster report, including wildcard sibling clusters and deployment bursts;
  a summary-only entry is still a usable hit.
- **Batch identity is canonical.** Valid URL, sub-host, and apex spellings that
  reduce to the same registrable apex are resolved once, preserving the first
  occurrence. Malformed inputs deduplicate by their trimmed, lowercased raw
  spelling, so each distinct normalized malformed spelling produces one
  diagnostic record. The 10,000-record limit is enforced before this
  deduplication. Line and stream limits are applied to UTF-8 bytes, not Unicode
  code-point counts.
- **Sparse is flagged, not hidden.** `sparse=true` means the uncertainty band's
  effective display mass is at its floor. The model score and band remain
  model-relative and do not replace explicit unresolved output (see
  [correlation.md](correlation.md)).

## Determinism and reproducibility

- **Same captured evidence and version, same interpretation.** A domain string
  alone is not the complete input: DNS, CT, identity responses, cache state,
  catalog data, model data, and software versions can change. Given the same
  normalized evidence snapshot, options, and installed recon, catalog, model,
  and Public Suffix List versions, interpretation is deterministic. The CT
  community-detection layer uses a fixed Louvain seed and normalizes node
  insertion order before partitioning; above the node cap it falls back to
  deterministic connected components. Cluster, member, edge, burst, and
  subdomain orderings are sorted and canonical. Enriched services, slugs, and
  `degraded_sources` are emitted sorted.
- **Same-job build repeatability is checked.** With `SOURCE_DATE_EPOCH` fixed,
  CI builds the same source twice inside one Ubuntu job and requires matching
  wheel and sdist hashes under that job's resolved toolchain. This does not
  promise byte identity across independently resolved environments; signed
  provenance remains the source-to-workflow verification mechanism. See
  [supply-chain.md](supply-chain.md).
- **Apex normalization is deterministic per installed version.** Input is
  reduced to its registrable apex (eTLD+1) using the Public Suffix List bundled
  in the pinned `publicsuffixlist` dependency, so the same input yields the same
  `queried_domain` for a given install. The reduction can change only when that
  dependency is upgraded and the PSL itself has changed (a new or retired public
  suffix), never within a version. It is not a security boundary: an unknown
  suffix falls back to the validated host rather than guessing.
