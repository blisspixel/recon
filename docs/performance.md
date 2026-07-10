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
| Synthesis / formatting | <50 ms |

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

Only measured blocking I/O should move to a thread. Timing results should guide
budgets and design decisions, while deterministic functional checks remain the
CI gate.
