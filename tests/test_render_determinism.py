"""v1.9.9 — render-time determinism property tests.

The user-facing contract of ``render_tenant_panel`` is that the same
TenantInfo always produces the same output. Non-deterministic
rendering would surface as:

  * Diff churn on golden-file snapshots and validation memos.
  * Flaky CI runs when batch outputs are compared run-to-run.
  * Inconsistent ``recon delta`` results when the upstream data
    has not changed.

The most likely sources of non-determinism are dict / set iteration
ordering and unstable sorting on equal-weight keys. Python 3.7+ dicts
preserve insertion order, but ``set`` does not; converting through a
set without re-sorting is the classic regression. Hash randomization
(``PYTHONHASHSEED``) means a non-deterministic codebase passes the
first N runs and surfaces only on the (N+1)-th.

These tests render the same TenantInfo many times and assert
byte-identical output. If a future refactor introduces a set-based
ordering bug, this is the test that catches it.

A second test runs across separate processes with different
``PYTHONHASHSEED`` values to surface dict-hash-ordering bugs that
within-process determinism would miss (within a single Python
process, ``PYTHONHASHSEED`` is fixed for the lifetime).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from rich.console import Console

from recon_tool.formatter import _CLOUD_VENDOR_BY_SLUG, render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo

_known_cloud_slugs = sorted(_CLOUD_VENDOR_BY_SLUG.keys())


def _render(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


def _three_vendor_tenant() -> TenantInfo:
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=8,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk"),
        services=("AWS CloudFront", "Cloudflare", "GCP Compute Engine"),
        slugs=("aws-cloudfront", "cloudflare", "gcp-compute"),
        surface_attributions=(
            SurfaceAttribution(
                subdomain="api.contoso.com",
                primary_slug="fastly",
                primary_name="Fastly",
                primary_tier="infrastructure",
            ),
        ),
    )


class TestInProcessDeterminism:
    """Same TenantInfo rendered N times in the same Python process
    must produce byte-identical output. Catches set / unstable-sort
    issues even when PYTHONHASHSEED is fixed."""

    def test_thirty_renders_byte_identical(self):
        info = _three_vendor_tenant()
        outputs = [_render(info) for _ in range(30)]
        first = outputs[0]
        for i, out in enumerate(outputs[1:], start=2):
            assert out == first, (
                f"render iteration {i} differed from iteration 1; "
                f"non-deterministic rendering would produce diff-churn at scale"
            )

    def test_thirty_renders_full_mode_byte_identical(self):
        info = _three_vendor_tenant()
        outputs = [_render(info, show_domains=True) for _ in range(30)]
        assert all(o == outputs[0] for o in outputs[1:])

    @given(
        slugs=st.lists(st.sampled_from(_known_cloud_slugs), min_size=2, max_size=10, unique=True),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_determinism_holds_on_arbitrary_slug_sets(self, slugs):
        """Hypothesis-driven: arbitrary cloud-slug sets render
        deterministically. Catches ordering bugs that only appear on
        specific input shapes (e.g. when the iterator hits a
        particular bucket order in the underlying dict)."""
        info = TenantInfo(  # type: ignore[arg-type]
            tenant_id="tid",
            display_name="Contoso",
            default_domain="contoso.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.HIGH,
            domain_count=4,
            tenant_domains=("a.com", "b.com", "c.com"),
            slugs=tuple(slugs),
            services=tuple(s.replace("-", " ").title() for s in slugs),
        )
        first = _render(info)
        # Three renders is enough to surface within-process ordering
        # bugs; the cross-process check covers PYTHONHASHSEED.
        assert _render(info) == first
        assert _render(info) == first


class TestCrossProcessDeterminism:
    """Two subprocess invocations with different ``PYTHONHASHSEED``
    values render the same TenantInfo to byte-identical output. This
    is the test that catches dict-hash-ordering bugs the in-process
    test cannot see (PYTHONHASHSEED is fixed for the lifetime of one
    interpreter)."""

    _RENDER_SCRIPT = textwrap.dedent(
        """
        from rich.console import Console
        from recon_tool.formatter import render_tenant_panel
        from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo

        info = TenantInfo(
            tenant_id='tid',
            display_name='Contoso, Ltd',
            default_domain='contoso.com',
            queried_domain='contoso.com',
            confidence=ConfidenceLevel.HIGH,
            domain_count=8,
            tenant_domains=('contoso.com', 'contoso.net', 'contoso.co.uk'),
            services=('AWS CloudFront', 'Cloudflare', 'GCP Compute Engine'),
            slugs=('aws-cloudfront', 'cloudflare', 'gcp-compute'),
            surface_attributions=(
                SurfaceAttribution(
                    subdomain='api.contoso.com',
                    primary_slug='fastly',
                    primary_name='Fastly',
                    primary_tier='infrastructure',
                ),
            ),
        )
        console = Console(no_color=True, record=True, width=120)
        console.print(render_tenant_panel(info))
        import sys
        sys.stdout.write(console.export_text())
        """
    )

    def _render_in_subprocess(self, hash_seed: str) -> str:
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = hash_seed
        # Force UTF-8 IO so Rich on Windows can emit the panel's box
        # characters; the default cp1252 codec crashes on the Rich
        # output, which is a CI / subprocess concern only (interactive
        # terminals are typically UTF-8 capable).
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(  # noqa: S603 — argv list, no shell.
            [sys.executable, "-c", self._RENDER_SCRIPT],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            check=False,
            encoding="utf-8",
        )
        assert result.returncode == 0, f"subprocess render failed: {result.stderr}"
        return result.stdout

    def test_two_distinct_hash_seeds_produce_identical_output(self):
        """The classic ``PYTHONHASHSEED`` test: same input under two
        different seed values must produce identical output. A bug
        that orders by hash would surface here."""
        out_seed_1 = self._render_in_subprocess("1")
        out_seed_2 = self._render_in_subprocess("2")
        assert out_seed_1 == out_seed_2, (
            "render output differs under PYTHONHASHSEED=1 vs =2. "
            "This signals a dict / set iteration bug that the in-process "
            "test cannot catch."
        )

    def test_three_distinct_hash_seeds_produce_identical_output(self):
        """Three-seed variant tightens the cross-process check. Two
        seeds happening to collide on a hash bucket would slip past
        the two-seed test; three is the practical safety margin."""
        outs = [self._render_in_subprocess(seed) for seed in ("0", "12345", "99999999")]
        assert all(o == outs[0] for o in outs[1:])
