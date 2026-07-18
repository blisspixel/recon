# Performance

Status: measured local-compute characterization, not a service-level objective
Review date: 2026-07-14

recon is a passive, concurrent DNS and HTTP-endpoint client. A default lookup
is usually dominated by CT provider time and the slowest identity-discovery
request. Batch work, cold CLI startup, fingerprint sweeps, inference, and CT
correlation also expose bounded local costs. The optimization rule is therefore
to separate network wait from local work, improve measured Python paths first,
and preserve exact evidence and failure semantics.

## Historical measured numbers

The numbers below are retained as historical context from a dev laptop (Ryzen
7, 32GB RAM, residential fiber, Windows 11), one run per corpus size, with no
warm cache. The original run date, exact recon commit, provider state, Python
version, and dispersion were not recorded, so these figures are not a current
benchmark and must not be treated as an SLO or regression threshold.

| Corpus | Wall clock | Memory peak | Notes |
|--------|-----------|-------------|-------|
| 50 domains | ~90s | ~180 MB | CT-cache cold: first run hits crt.sh for every domain |
| 100 domains | ~180s | ~240 MB | Sustained ~0.55 domains/sec; CT-cache starts helping on sibling domains |
| 500 domains | ~16 min | ~420 MB | CT provider rotation + rate-limit backoff dominates past ~300 domains |

The historical observation was that a warm CT cache was roughly three times
faster. That multiplier has not been revalidated against the current provider
rotation and 30-day cache policy.

## Pre-optimization local-compute characterization

The table below is a July 11, 2026 CPU-only reference characterization from the working
tree based on commit `747f359` on Windows 11, Python 3.14.4, an AMD Ryzen 9
5950X, and 64 GiB RAM.
Each current median is from nine repetitions after one warm-up, except that the
catalog case deliberately clears the process cache before every measurement.
Peak allocation is one `tracemalloc` observation and covers Python-managed
allocations only.

Reproduce the current deterministic, network-free fixture catalog with:

```bash
uv run python scripts/characterize_performance.py --repetitions 9
```

The JSON output records the commit, dirty-worktree state, runtime, host, method,
exact fixture shape, median, nearest-rank p95, maximum, and traced peak allocation.
Use `--skip-stress` for a shorter pass. The script is diagnostic and has no
host-dependent timing assertion in CI.

| Local operation | Synthetic shape | Median | Python peak |
|---|---:|---:|---:|
| Fingerprint catalog load | 847 YAML entries, cold | 476 ms | 6.4 MiB |
| TXT fingerprint matching | 100 values x 298 rules | 35 ms | 91 KiB |
| TXT fingerprint matching | 1,000 values x 298 rules | 348 ms | 91 KiB |
| Bayesian inference | 1 domain, shipped 9-node network | 11 ms | 84 KiB |
| Bayesian inference | 100 sequential domains | 1,153 ms | 90 KiB |
| CT graph | 50 nodes, 10 exact fixture entries | 25 ms | 0.9 MiB |
| CT graph | 200 nodes, 40 exact fixture entries | 74 ms | 3.6 MiB |
| CT graph | 1,000 x 20 dense fixture, 200-host pool | 440 ms | 12.8 MiB |
| CT graph | 1,000 repeated 60-SAN hyperedges | 163 ms | 6.1 MiB |
| Panel rendering | 1,000 synthetic services | 17 ms | 270 KiB |

A separate bounded-stress pass found the CT graph's important tail shape. The
post-aggregation values in the table were recorded against the implementation
described by this document. One thousand repeated 60-SAN entries took 2.31
seconds before consecutive identical hyperedges were aggregated. The same
fixture took 163 ms
afterward, a 14 times stage improvement on this workstation,
with identical edge counts, edge weights, issuer ordering, and caps. The dense
1,000 x 20 case took 440 ms after the change and remains dominated by the
eight-run partition-stability sweep; repeated-hyperedge aggregation does not
solve that shape.

This is characterization, not a production benchmark. It excludes network
time, uses fictional synthetic shapes, measures one operating system and
machine, and does not report statistically stable tail latency. The current
product baseline still needs the environment, corpus, cache, repetition, p50,
p95, degradation, and stage controls listed below.

Built-in profiling explained where the Python-first passes should start:

- Cold catalog loading was dominated by parsing 11 built-in YAML files. The
  generated-artifact checkpoint below removes that cost while keeping the YAML
  source and canonical runtime validator.
- Large TXT sweeps spend most local time dispatching string patterns through
  `re.search`. An immutable precompiled-pattern cache can be evaluated without
  changing the public fingerprint model.
- The small Bayesian network spends local time in factor multiplication,
  evidence-free prior recomputation, uncertainty calculations, and development
  contracts. Cache only immutable reference calculations and preserve exact
  differential behavior.
- CT graph time has two shapes. Renewal-heavy repeated SAN sets previously
  repeated the same pair expansion and are now aggregated in Python. Dense
  non-repeated graphs are dominated by repeated Louvain runs used for partition
  stability. Do not replace that layer until the CT-value benchmark qualifies
  the output itself.
- Panel rendering is already too small to justify a native boundary.

The current result is not a case for Rust, Go, or Mojo. It is a case for the
reproducible stage benchmark already required by the roadmap, followed by
small Python algorithm and cache experiments. The binding decision and
promotion thresholds are in
[ADR-0010](adr/0010-evidence-gated-native-acceleration.md).

## July 12, 2026 optimization checkpoint

The v2.5.1 work applies four bounded changes without changing the public CLI,
JSON, MCP, cache, timeout, or evidence contracts:

- Repeated fingerprint regex searches use a 2,048-entry cache of compiled
  standard-library patterns. Pattern length remains capped at 500 characters,
  flags are part of the cache key, invalid expressions remain non-matches, and
  catalog reload or ephemeral-catalog mutation clears the cache.
- A fusion-enabled batch loads one Bayesian network and one prior-override
  snapshot, then reuses those immutable batch-local objects for every domain.
  There is no process-global model cache, so a later invocation still observes
  configuration changes.
- CT partition stability reuses the already computed seed-1729 primary
  partition. The same eight seeds and the same pairwise adjusted Rand index are
  retained, but seed 1729 is no longer evaluated twice.
- Full quality-gate tests run in at most four file-grouped worker processes.
  Test files stay intact within a worker, pytest-cov combines worker coverage,
  and focused developer tests remain serial unless the developer opts in.

Diagnostic measurements on the same Windows workstation and CPython 3.14.4.
The stage harness and full local gate both ran from clean implementation commit
`47c5494`:

| Checked operation | Before | After | Observed change |
|---|---:|---:|---:|
| TXT matching, 1,000 values x 298 rules | 348 ms median | 115 ms median | 3.02 times faster |
| Complete batch fusion, 25 synthetic sparse records | 864 ms median | 355 ms median | 58.9 percent lower stage time |
| Full local suite | 4,502 pass in 330.53 s, serial without coverage | 4,522 pass in 88.83 s, four workers with branch coverage | 73.1 percent lower pytest wall time |

The matcher after-value is from five repetitions after one warm-up in the
checked-in harness. The batch-fusion comparison used five repetitions after a
warm-up and includes network parsing, prior lookup, inference, slug scoring,
and result adaptation in both paths. The suite comparison also includes 20 new
tests and about 32.5 seconds of real retry sleeps and accidental live lookups
removed from the tests, so it measures the combined quality-gate improvement,
not xdist in isolation. These are local diagnostics, not portable SLOs.

The compiled matcher preserves exact differential output for representative
built-in records and catalog lifecycle tests. The batch tests assert one model
and prior load per invocation. Graph tests assert the exact seed set and
unchanged stability output. The full branch-aware project result remains above
the blocking 90.2 percent baseline ratchet.

## July 12, 2026 generated catalog checkpoint

The split YAML files remain canonical contributor source and remain in the
source distribution. The wheel ships one compact, deterministic JSON runtime
artifact. The generator validates all 847 entries, preserves source-file,
entry, detection, and repeated-slug order, and emits canonical UTF-8 JSON with
sorted object keys and one LF terminator. Local, CI, and release gates reject
any byte drift. Custom and session-scoped fingerprints still use the existing
runtime validation and lifecycle paths.

The network-free harness compared the full canonical YAML parse and validation
path with the generated runtime path on Windows 11, CPython 3.14.4, and an AMD
Ryzen 9 5950X. Each median is from 15 repetitions after three warm-ups. Both
cases clear the catalog and compiled-regex caches on every repetition. The
measurement ran from clean implementation commit `157bf6c`.

| Checked operation | Median | Nearest-rank p95 | Python peak |
|---|---:|---:|---:|
| Canonical split YAML reference, 847 entries and 1,045 rules | 558.188 ms | 628.801 ms | 6,561.1 KiB |
| Generated JSON runtime, same ordered catalog | 44.339 ms | 53.379 ms | 1,835.7 KiB |

The observed median stage gain is 12.59 times, above the predeclared five-times
gate, with 72.0 percent less traced peak Python allocation. Exact dataclass and
all-accessor differential tests are the correctness authority; timing remains
a dated local diagnostic, not a CI threshold or portable SLO. The wheel remains
pure Python and universal. Excluding canonical YAML from the wheel offsets the
generated artifact. Two fixed-epoch builds were byte-identical. Relative to
the v2.5.1 baseline, the wheel decreased from 658,489 to 646,442 bytes, down
12,047 bytes or 1.83 percent, and installed package files decreased from
2,285,156 to 2,248,617 bytes, down 36,539 bytes or 1.60 percent. The wheel
remains `py3-none-any`, contains no canonical YAML copy, and loads all 847
entries in a clean isolated environment.

This follows the [Python 3.14 JSON documentation](https://docs.python.org/3.14/library/json.html),
reviewed 2026-07-12, which documents ordered decoding, `sort_keys`, and compact
separators. It also follows [Hatch reproducible-build guidance](https://hatch.pypa.io/latest/config/build/),
reviewed 2026-07-12, which documents deterministic timestamps and
`SOURCE_DATE_EPOCH`. The artifact contains data, not executable serialization;
bounded JSON decoding and the canonical fingerprint validator remain in the
runtime path.

## July 13, 2026 MCP discovery checkpoint

This network-free checkpoint measures the recon v2.5.7 local stdio protocol
surface on Python 3.14.4 and production MCP SDK 1.28.1 using protocol
2025-11-25. A real `ClientSession` initialized the packaged server and requested
tools, resources, resource templates, and prompts. Result models were serialized
as compact UTF-8 JSON with protocol aliases, null fields omitted, and no pretty
printing. Counts exclude JSON-RPC envelopes and transport framing, so they
characterize result bodies rather than bytes placed on the wire.

| Discovery result | Entries | Compact result-body bytes |
|---|---:|---:|
| `initialize` | 1 | 8,754 |
| `tools/list` | 22 | 70,538 |
| `resources/list` | 5 | 1,959 |
| `resources/templates/list` | 0 | 24 |
| `prompts/list` | 1 | 287 |
| Total | 29 | 81,562 |

Summing the compact JSON encodings of each output-schema object yields 41,997
bytes; input-schema objects yield 4,696 and annotation objects yield 1,947.
Raw UTF-8 description text contributes 19,351 bytes before JSON quoting and
escaping. These component measurements exclude the surrounding tool-record
keys and array structure, so they are not intended to sum to the 70,538-byte
listing. Output schemas alone dominate the `tools/list` result body. They are
not decorative: the official
[MCP 2025-11-25 tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
defines them as the validation contract for structured results and recommends
including serialized text alongside structured content for backward
compatibility. The same specification supports paginated tool listings, but a
client that accumulates every page still receives the complete definitions.
Initialization can also carry server instructions under the official
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

Optional resource contents are not automatic discovery context.

| Resource | Raw UTF-8 text bytes | Compact `resources/read` result-body bytes |
|---|---:|---:|
| `recon://fingerprints` | 274,639 | 313,863 |
| `recon://signals` | 23,810 | 26,452 |
| `recon://profiles` | 5,141 | 5,640 |
| `recon://schema` | 60,292 | 64,987 |
| `recon://surface-inventory` | 76,197 | 84,755 |

A full `get_fingerprints` result was 402,285 result-body bytes because the
stable protocol path carries both text and structured content. Existing
`get_fingerprints(category, limit, offset)` pagination reduced a 20-item result
to 9,676 bytes, 97.6 percent below the full result. Agents should use bounded
pages for browsing, while an exhaustive no-match check must consume every page
or read the complete resource.

A hypothetical primary listing containing `lookup_tenant`, `analyze_posture`,
`assess_exposure`, `find_hardening_gaps`, `compare_postures`,
`cluster_verification_tokens`, and `chain_lookup` measured 21,759 result-body
bytes, 69.2 percent below the complete tool listing and above the engineering
plan's 30 percent threshold. This does not justify a runtime profile yet.
Model-context treatment is client-dependent, the base protocol has no
interoperable client-selected tool filter, and all 22 names are stable. The
full registry remains the default until at least one representative client
proves that an opt-in profile produces an end-to-end context benefit while
retaining direct specialist access.

Representative results used the fictional `SAMPLE_INFO` and `SAMPLE_RESULTS`
objects in `tests/test_exposure_cli.py`, patched into the ordinary resolver and
dispatched through the real in-process `mcp.call_tool` path.

| Tool result | Compact result-body bytes |
|---|---:|
| Text lookup | 783 |
| JSON lookup | 4,835 |
| Explained JSON lookup | 10,475 |
| Posture analysis | 463 |
| Explained posture analysis | 1,504 |
| Exposure assessment | 5,573 |
| Hardening gaps | 2,511 |
| Hardening simulation | 2,433 |

These are exact payload characterizations, not token counts or latency SLOs.
Repeated discovery calls were byte-identical in the measured process.

## July 14, 2026 bounded batch-scheduling checkpoint

Retained-output batch modes previously passed one coroutine per input to
`asyncio.gather`. The semaphore bounded active lookups, but the official
[asyncio task documentation](https://docs.python.org/3.14/library/asyncio-task.html#asyncio.gather)
specifies that supplied coroutines are automatically scheduled as tasks. At the
10,000-domain admission cap, scheduling therefore created 10,000 tasks before
the required ordered result list was considered.

The retained-output path now uses a fixed input-ordered outer worker pool. It
creates at most the requested concurrency in batch worker tasks, cancels and
awaits every worker on failure or caller cancellation, and writes each result
back to its input index. An admitted lookup can still create its bounded
internal source tasks. Per-domain lookup behavior, error shaping, post-batch
enrichment, and output order remain unchanged. Progress reports the same
per-domain outcomes, but later inputs are now admitted when a worker becomes
available, so their progress timing can differ. NDJSON keeps its separate
rolling completion-order scheduler and still releases completed results
immediately.

This local one-off `tracemalloc` characterization used the uv-managed Python
3.14.4 runtime on Windows 11 Pro build 26200, an AMD Ryzen 9 5950X, and 64 GB of
RAM. The working tree was based on commit
`cce7e50558a26d4dcb1d1cab9eed6931ca27ac2c` and contained the worker-pool change.
The fixture was an await-once synthetic processor at seven-way concurrency. The
exact allocation bytes are a diagnostic receipt, not a reproducible benchmark
or gate; the deterministic task bound is enforced separately by
`tests/test_batch_streaming.py`. This measures scheduling allocations, not DNS,
HTTP, result payloads, throughput, or a product SLO.

| Inputs | Previous outer tasks | Batch worker tasks | Previous traced peak | Worker-pool traced peak |
|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | 7 | 1,173,378 bytes | 57,433 bytes |
| 5,000 | 5,000 | 7 | 5,808,794 bytes | 241,072 bytes |
| 10,000 | 10,000 | 7 | 11,638,234 bytes | 480,232 bytes |

At the input cap, the scheduling peak fell 95.9 percent. Retained JSON, CSV,
Markdown, panel, ecosystem, and summary modes still require O(input count)
result storage by contract. Operators who need completion-order streaming and
constant completed-result memory should continue to use NDJSON.

## Python version policy

The package continues to require Python 3.11 or newer. Python 3.14 is the
preferred development and characterization runtime because users receive its
interpreter, import, and asyncio improvements without a compatibility break.
CI still runs the full functional and coverage contract on Python 3.11 through
3.14 across Windows, macOS, and Linux, with a non-blocking 3.14t dependency
probe.

Reviewed July 13, 2026 against current official guidance:

- [Python 3.14.6 release documentation](https://www.python.org/downloads/release/python-3146/)
  documents the current stable 3.14 line, asyncio and import optimizations,
  subinterpreters, and the experimental JIT. These capabilities must still be
  measured on recon-shaped work.
- [Python free-threading guidance](https://docs.python.org/3/howto/free-threading-python.html)
  requires intentionally parallel code and documents single-thread and memory
  tradeoffs. recon's one-event-loop detector state does not gain an automatic
  speedup.
- [InterpreterPoolExecutor](https://docs.python.org/3.14/library/concurrent.futures.html#interpreterpoolexecutor)
  isolates interpreter state and serializes call data. A local 100-inference
  experiment reached 2.18 times stage speedup, below ADR-0010's provisional
  three-times promotion floor and without material end-to-end evidence.
- [asyncio eager task execution](https://docs.python.org/3.14/library/asyncio-task.html#eager-task-factory)
  changes task-order semantics and mainly helps coroutines that complete
  synchronously. recon's normal source tasks perform real I/O, so a global
  eager-task factory is not justified.
- [Python's regular-expression API](https://docs.python.org/3.14/library/re.html#re.compile)
  provides compiled pattern objects for repeated operations. A bounded cache
  delivered the measured matcher gain without a new engine or dependency.
- [pytest-xdist distribution modes](https://pytest-xdist.readthedocs.io/en/stable/distribution.html)
  and [pytest-cov worker support](https://pytest-cov.readthedocs.io/en/latest/xdist.html)
  support file-grouped parallel execution with combined coverage.

The project does not enable a global eager task factory, create multiple event
loops, require free-threading, depend on the experimental JIT, or dispatch
ordinary batch work through subinterpreters. A Python 3.14 fast path will be
added only when runtime capability detection, an exact older-version fallback,
and a product-shaped benchmark all justify it.

## Ranked next optimization work

1. Reuse one SSRF-safe HTTP connection pool across batch domains. Preserve
   request-specific timeouts, retry and cancellation behavior, per-request DNS
   rebinding checks, CT provider policy, and degraded-source reporting. Promote
   only after a synthetic warm-batch benchmark shows a material connection or
   throughput gain with no failure-rate regression.
2. Complete the remaining batch-wide bounds before raising concurrency. The
   retained-output scheduler is now fixed-size and input-ordered. Next avoid
   constructing discarded per-domain renderings in summary mode, then replace
   pairwise ecosystem overlap and unbounded peer materialization with an
   indexed, capped design that reports omitted counts. Characterize sparse and
   dense-correlation tails at 100, 1,000, and 10,000 synthetic domains.

Rust remains a possible future implementation detail only if one stable,
coarse capability still clears ADR-0010 after these Python changes. Go still
has no independent service boundary, and Mojo still has no accelerator kernel
to own.

## Current runtime and interop constraints

Checked July 11, 2026 against official documentation:

- [Python 3.14 free threading](https://docs.python.org/3/howto/free-threading-python.html)
  is supported but optional. It benefits code designed for parallel threads;
  it is not an automatic speedup for recon's async network workflow.
- [PyO3 supports free-threaded CPython](https://pyo3.rs/main/free-threading),
  but its [ABI feature guidance](https://pyo3.rs/main/features) states that
  `abi3` does not support free-threaded builds and `abi3t` starts with Python
  3.15. Supporting recon's current Python 3.14t probe would therefore require a
  separate native artifact in addition to regular stable-ABI wheels.
- [Maturin distribution guidance](https://www.maturin.rs/distribution.html)
  requires platform-compatible native wheels and explicit Linux compatibility.
  This is materially broader than recon's current `py3-none-any` release.
- [Go cgo](https://pkg.go.dev/cmd/cgo) creates a C boundary with explicit
  pointer and lifetime constraints. More importantly, recon has no separate
  service or worker lifecycle that would justify a Go process boundary.
- The official [Mojo FAQ](https://docs.modular.com/mojo/faq) describes the
  current 1.0 beta path: core language stabilization is still in progress and
  not all library APIs will be stable at 1.0. Its
  [system requirements](https://docs.modular.com/mojo/requirements/) provide
  Windows support through WSL rather than a native Windows toolchain. recon has
  no tensor, GPU, or accelerator workload for Mojo to own.

Broad language speedup and infrastructure-cost multipliers are not accepted as
project evidence. Only recon-shaped end-to-end and stage measurements can open
a language boundary.

## Methodology

The command below remains useful for local characterization, but one timing run
is not a benchmark. A current baseline must record the commit, Python and OS
versions, hardware, network class, provider outcomes, cache state, corpus
shape, repetition count, p50/p95, peak allocation, and degraded-source count.
Use a newline-delimited list of apex domains stored locally. Public
performance-validation inputs use only reserved synthetic examples; any real
corpus remains private under the data policy.

```bash
recon cache clear --all                                # start cold
time recon batch path/to/your-corpus.txt --json > /dev/null
```

See [CONTRIBUTING.md](../CONTRIBUTING.md#no-evaluated-target-data) for
why the project does not commit a real-company corpus. Local corpora
conventionally live at `~/.recon/corpus.txt`; they are never
transmitted anywhere recon does not already query.

## Budget knobs

- **Per-lookup timeout.** `--timeout N` (default 120s) bounds the
  entire pipeline for one domain. CT providers are the usual cause
  of long tails; lower the budget to fail fast if you're sweeping
  many domains.
- **CT cache TTL.** `~/.recon/ct-cache/` entries live 30 days by
  default. On a sweep of sibling domains (portfolio discovery),
  the first domain warms the cache and subsequent domains reuse it.
- **Batch concurrency.** `recon batch` uses concurrency 5 by default;
  `--concurrency N` changes the number of in-flight lookups, but raising it
  also raises the per-provider rate-limit pressure on crt.sh /
  CertSpotter. Keep it conservative.

## Where the time goes

On a single domain with a warm cache:

| Step | Typical |
|------|---------|
| DNS resolution (MX, TXT, CNAME, etc.) | 50-300 ms |
| OIDC discovery | 100-400 ms |
| GetUserRealm | 100-400 ms |
| Google Identity endpoint | 200-800 ms |
| CT provider query (warm) | 10-50 ms |
| CT provider query (cold) | 1-15 s |
| Merge, inference, and rendering | usually tens of milliseconds locally; not yet a product SLO |
| CT graph construction and stability | shape-dependent; 25 ms to 440 ms in the checked-in synthetic fixtures |

The CT provider step is the swing variable. Cold runs against a
crt.sh backend under load can hit multi-second latencies; we have
a CertSpotter fallback, but that provider rate-limits aggressively
past ~20 queries/minute.

## If recon is slow for you

1. Run `recon doctor`. The most common cause is a CT provider that's
   unreachable from your network.
2. Check `~/.recon/ct-cache/` exists and is writable.
3. Drop `--timeout` to 60 if you'd rather fail fast on slow domains.
4. For batch work on hundreds of domains, run overnight with a
   generous budget rather than interactively with a tight one.

## Next measurement gate

The active engineering plan requires a reproducible synthetic characterization
before performance-driven code changes:

- single, batch, graph, and MCP workflows;
- cold and warm p50/p95 wall time;
- peak allocation and blocked-loop observations;
- stage timing for DNS, identity, CT, merge, inference, and rendering;
- partial and degraded-source counts;
- CT marginal signal gain relative to latency cost.
- cold CLI startup and catalog-load contribution;
- local CPU profiles for fingerprint matching, inference, graph construction,
  serialization, and rendering;
- the same workload on regular and free-threaded Python only after it includes
  justified parallel CPU work.

Only measured blocking I/O should move to a thread. Timing results should guide
budgets and design decisions, while deterministic functional checks remain the
CI gate.
