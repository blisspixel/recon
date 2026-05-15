# Render performance baseline (v1.9.9)

The performance tests in `tests/test_render_performance.py` use
absolute time budgets (0.5s for 10 slugs, 5s for 1000 slugs). A
rigorous review correctly notes that absolute budgets are vibes
without a baseline measurement: 0.5s could be either generous or
tight depending on the host. This document records the actual
baseline measurement so future regressions can be assessed against
real numbers, not against my intuition at write time.

## Baseline measurements

Measured 2026-05-14 on Windows 11, Python 3.10.11. Median of 11
renders per cell, `Console(no_color=True, record=True, width=120,
file=io.StringIO())`. Methodology in
`tests/test_render_performance.py:_render_timed`.

| Slug count | Median render time | Test budget | Headroom |
|---|---|---|---|
| 10 | 0.9 ms | 500 ms | 555× |
| 100 | 1.5 ms | 1000 ms | 666× |
| 1000 | 9.2 ms | 5000 ms | 543× |

The test budgets are far above the measured baselines. This is
deliberate — the tests catch order-of-magnitude regressions, not
micro-perf shifts. A regression that pushed the 1000-slug time to
50 ms would still pass the test (50 ms < 5000 ms budget) but would
show up as a 5× slowdown in this baseline doc.

## What the test budgets actually catch

| Regression | Caught by test? |
|---|---|
| 2× slowdown on 1000-slug rendering (9 ms → 18 ms) | No (still under budget) |
| 100× slowdown (9 ms → 0.9 s) | No (still under 5 s budget) |
| 1000× slowdown (9 ms → 9 s) | Yes |
| Any change that takes 1000-slug rendering above 5 s | Yes |
| Sub-quadratic scaling violation (test_*_scaling_is_subquadratic) | Yes — independent property check |

## What this baseline does not cover

- **Cold-cache rendering** (first call after import). The baseline
  measures warm-cache rendering after import overhead has settled.
  Cold rendering is more variable and would need a separate
  measurement.
- **Memory bounds.** The render path's peak memory use at scale is
  not measured. A regression that introduced a quadratic memory
  pattern would not be caught by these tests.
- **Production-like inputs.** The baseline uses synthetic slug lists
  that all canonicalize to cloud vendors. Real-world inputs have a
  mix of cloud, SaaS, and unknown slugs; their performance shape may
  differ.

## Remediation if these gaps matter

1. Add a cold-cache baseline measurement to this file. Quick win.
2. Add a memory-bound test (`tracemalloc` snapshot before and
   after) to `test_render_performance.py`. Half a day's work.
3. Run the perf measurement against the v1.9.4 hardened corpus
   (gitignored) to capture the real-world shape. Reuses the
   aggregator's render path.

Items 1-3 are post-v2.0 backlog. The current performance test
discipline is "no order-of-magnitude regressions" — sufficient for
the panel's interactive use case, insufficient for a high-throughput
batch use case that a future caller might want.

## How to refresh this baseline

```bash
python -c "
import io, time, statistics
from rich.console import Console
from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, TenantInfo

def render_at(slug_count):
    cloud_slugs = ('aws-cloudfront', 'cloudflare', 'fastly', 'akamai', 'gcp-compute', 'azure-cdn')
    slugs = tuple((cloud_slugs[i % len(cloud_slugs)] + f'-{i}') if i >= len(cloud_slugs) else cloud_slugs[i] for i in range(slug_count))
    services = tuple(s.replace('-', ' ').title() for s in slugs)
    info = TenantInfo(
        tenant_id='tid', display_name='Contoso', default_domain='contoso.com',
        queried_domain='contoso.com', confidence=ConfidenceLevel.HIGH,
        domain_count=5, tenant_domains=('a.com','b.com','c.com'),
        services=services, slugs=slugs,
    )
    times = []
    for _ in range(11):
        start = time.perf_counter()
        c = Console(no_color=True, record=True, width=120, file=io.StringIO())
        c.print(render_tenant_panel(info))
        c.export_text()
        times.append(time.perf_counter() - start)
    return statistics.median(times)

for n in (10, 100, 1000):
    t = render_at(n)
    print(f'{n} slugs: median {t*1000:.1f}ms')
"
```

Update the table above with the new measurements; record host info
(OS, Python version) at the top so the comparison stays meaningful.
