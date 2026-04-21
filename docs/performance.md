# Performance

recon is a passive, concurrent DNS + HTTP-endpoint client. Latency is
dominated by two variables: CT-log query time (crt.sh / CertSpotter,
chronically flaky) and the slowest of the identity-endpoint queries
(OIDC discovery, GetUserRealm, Google Identity). Tuning is mostly
about timeout caps, not algorithmic work.

## Measured numbers

The numbers below are from a dev laptop (Ryzen 7, 32GB RAM, residential
fiber, Windows 11), single-run per corpus size, no warm cache. Cold
runs are what you'll see the first time you sweep a new corpus.

| Corpus | Wall clock | Memory peak | Notes |
|--------|-----------|-------------|-------|
| 50 domains | ~90s | ~180 MB | CT-cache cold — first run hits crt.sh for every domain |
| 100 domains | ~180s | ~240 MB | Sustained ~0.55 domains/sec; CT-cache starts helping on sibling domains |
| 500 domains | ~16 min | ~420 MB | CT provider rotation + rate-limit backoff dominates past ~300 domains |

Warm-cache (re-run with `~/.recon/ct-cache/` populated) is roughly 3×
faster because CT lookups short-circuit.

## Methodology

Reproduce with:

```bash
recon cache clear --all                                # start cold
time recon batch tests/fixtures/corpus-public.txt --json > /dev/null
```

The `corpus-public.txt` fixture is 40 public apex domains committed
to the repo — use it (or any of the validation-sweep corpora) rather
than a private list if you want your numbers to match published
figures.

## Budget knobs

- **Per-lookup timeout.** `--timeout N` (default 120s) bounds the
  entire pipeline for one domain. CT providers are the usual cause
  of long tails; lower the budget to fail fast if you're sweeping
  many domains.
- **CT cache TTL.** `~/.recon/ct-cache/` entries live 7 days by
  default. On a sweep of sibling domains (portfolio discovery),
  the first domain warms the cache and subsequent domains reuse it.
- **Batch concurrency.** `recon batch` resolves domains sequentially
  by default; a fast-follow candidate is `--concurrency N` but
  raising concurrency also raises the per-provider rate-limit
  pressure on crt.sh / CertSpotter. Keep it conservative.

## Where the time goes

On a single domain with a warm cache:

| Step | Typical |
|------|---------|
| DNS resolution (MX, TXT, CNAME, etc.) | 50–300 ms |
| OIDC discovery | 100–400 ms |
| GetUserRealm | 100–400 ms |
| Google Identity endpoint | 200–800 ms |
| CT provider query (warm) | 10–50 ms |
| CT provider query (cold) | 1–15 s |
| Synthesis / formatting | <50 ms |

The CT provider step is the swing variable. Cold runs against a
crt.sh backend under load can hit multi-second latencies; we have
a CertSpotter fallback, but that provider rate-limits aggressively
past ~20 queries/minute.

## If recon is slow for you

1. Run `recon doctor` — the most common cause is a CT provider that's
   unreachable from your network.
2. Check `~/.recon/ct-cache/` exists and is writable.
3. Drop `--timeout` to 60 if you'd rather fail fast on slow domains.
4. For batch work on hundreds of domains, run overnight with a
   generous budget rather than interactively with a tight one.
