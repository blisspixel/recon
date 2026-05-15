"""v1.9.9 — render-time performance bounds.

The renderer must complete in bounded time even on pathological
inputs. A regression that introduced quadratic behaviour in slug
iteration, surface attribution rendering, or vendor canonicalization
would surface as a latency cliff at scale.

These tests pin a soft upper bound on rendering time across three
input sizes: typical (~10 slugs), large (~100 slugs), and stress
(~1000 slugs). The bounds are generous on purpose — the test catches
order-of-magnitude regressions, not 10% slowdowns. Tight latency
budgets would couple the test to host hardware; soft bounds catch
real regressions while staying portable.

The single critical invariant: time scales *no worse than linearly*
in the slug count. If a future refactor introduces O(n²) iteration
through `_categorize_services` or the surface_attributions block,
the stress case would jump from ~50 ms to seconds and the test
would catch it.
"""

from __future__ import annotations

import time

import pytest
from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _render_timed(info: TenantInfo) -> float:
    """Render once, return elapsed wall-clock seconds.

    We use ``time.perf_counter`` for high-resolution wall-clock
    timing. The renderer writes to a ``StringIO``-backed Rich Console
    so the measurement excludes terminal-IO latency.
    """
    import io

    start = time.perf_counter()
    console = Console(no_color=True, record=True, width=120, file=io.StringIO())
    rendered = render_tenant_panel(info)
    console.print(rendered)
    _ = console.export_text()
    return time.perf_counter() - start


def _build_tenant(slug_count: int) -> TenantInfo:
    """Build a TenantInfo with N cloud-categorized slugs and matching
    services. Each slug fires under the rollup canonicalization so
    the panel exercises both the Services block and the Multi-cloud
    rollup at scale."""
    cloud_slugs = ("aws-cloudfront", "cloudflare", "fastly", "akamai", "gcp-compute", "azure-cdn")
    slugs = tuple(
        (cloud_slugs[i % len(cloud_slugs)] + f"-{i}") if i >= len(cloud_slugs) else cloud_slugs[i]
        for i in range(slug_count)
    )
    services = tuple(s.replace("-", " ").title() for s in slugs)
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-perf",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=5,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk"),
        services=services,
        slugs=slugs,
    )


def _build_surface_heavy_tenant(attrib_count: int) -> TenantInfo:
    """Build a TenantInfo with N surface attributions. Exercises the
    Subdomain summary aggregation, which iterates all attributions."""
    attribs = tuple(
        SurfaceAttribution(
            subdomain=f"sub{i}.contoso.com",
            primary_slug="fastly",
            primary_name="Fastly",
            primary_tier="infrastructure",
        )
        for i in range(attrib_count)
    )
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-perf-surface",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=5,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk"),
        services=("Cloudflare", "Fastly"),
        slugs=("cloudflare", "fastly"),
        surface_attributions=attribs,
    )


class TestSlugScalingBounds:
    """Time bounds at three slug-count scales. The thresholds are
    generous so the tests run on any host; they catch
    order-of-magnitude regressions, not micro-optimizations."""

    @pytest.mark.parametrize(
        ("slug_count", "budget_seconds"),
        [
            (10, 0.5),  # typical apex
            (100, 1.0),  # large apex
            (1000, 5.0),  # stress test
        ],
    )
    def test_render_under_budget_at_slug_scale(self, slug_count, budget_seconds):
        info = _build_tenant(slug_count)
        # Three runs to warm the import cache, then take the median.
        # Single-shot timing is noisy on Windows due to background
        # process activity; the median is more stable.
        timings = sorted(_render_timed(info) for _ in range(3))
        median = timings[1]
        assert median < budget_seconds, (
            f"render at {slug_count} slugs took median {median:.3f}s, budget {budget_seconds}s. "
            f"A regression here suggests super-linear scaling in slug iteration."
        )


class TestSurfaceAttributionScalingBounds:
    """Time bounds at three surface-attribution scales. The Subdomain
    aggregation iterates all attributions; quadratic behaviour would
    surface here, not in the slug-count test above."""

    @pytest.mark.parametrize(
        ("attrib_count", "budget_seconds"),
        [
            (10, 0.5),
            (100, 1.0),
            (1000, 5.0),
        ],
    )
    def test_render_under_budget_at_attrib_scale(self, attrib_count, budget_seconds):
        info = _build_surface_heavy_tenant(attrib_count)
        timings = sorted(_render_timed(info) for _ in range(3))
        median = timings[1]
        assert median < budget_seconds, (
            f"render at {attrib_count} surface attribs took median {median:.3f}s, budget {budget_seconds}s. "
            f"A regression here suggests super-linear scaling in surface_attributions iteration."
        )


class TestLinearScalingProperty:
    """The strongest perf invariant: time scales no worse than
    linearly in N. The test runs at N=100 and N=1000 and asserts the
    ratio is below ~50× — generous enough to absorb constant-factor
    overhead, tight enough to catch O(n²) behaviour."""

    def test_slug_scaling_is_subquadratic(self):
        info_small = _build_tenant(100)
        info_large = _build_tenant(1000)

        t_small = sorted(_render_timed(info_small) for _ in range(3))[1]
        t_large = sorted(_render_timed(info_large) for _ in range(3))[1]

        # Avoid division by zero on very fast machines.
        if t_small < 0.001:
            pytest.skip("baseline timing too short to compute ratio reliably")

        ratio = t_large / t_small
        # 10× input → at most ~50× output (generous for non-O(n) with
        # constant overhead; would catch O(n²) which would be ~100×).
        assert ratio < 50, (
            f"render scaling ratio {ratio:.1f}× over 10× input; expected sub-quadratic. "
            f"Likely cause: a refactor introduced nested iteration."
        )

    def test_attrib_scaling_is_subquadratic(self):
        info_small = _build_surface_heavy_tenant(100)
        info_large = _build_surface_heavy_tenant(1000)

        t_small = sorted(_render_timed(info_small) for _ in range(3))[1]
        t_large = sorted(_render_timed(info_large) for _ in range(3))[1]

        if t_small < 0.001:
            pytest.skip("baseline timing too short to compute ratio reliably")

        ratio = t_large / t_small
        assert ratio < 50, f"surface-attribution scaling ratio {ratio:.1f}× over 10× input; expected sub-quadratic."
