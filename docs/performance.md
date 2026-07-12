# Performance

Status: historical characterization, not a current service-level objective
Review date: 2026-07-10

recon is a passive, concurrent DNS + HTTP-endpoint client. Latency is
dominated by two variables: CT-log query time (crt.sh / CertSpotter,
chronically flaky) and the slowest of the identity-endpoint queries
(OIDC discovery, GetUserRealm, Google Identity). Tuning is mostly
about timeout caps, not algorithmic work.

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

## Current local-compute characterization

The table below is a July 11, 2026 CPU-only characterization from the working
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

Built-in profiling explains where a Python-first pass should start:

- Cold catalog loading is dominated by parsing 11 built-in YAML files. A
  validated generated artifact, more selective loading, or another Python-side
  representation should be measured before considering native parsing.
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
Use a newline-delimited list of apex domains stored locally. The project ships
only fictional examples; any real corpus remains private under the data policy.

```bash
recon cache clear --all                                # start cold
time recon batch path/to/your-corpus.txt --json > /dev/null
```

See [CONTRIBUTING.md](../CONTRIBUTING.md#fictional-example-policy) for
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
