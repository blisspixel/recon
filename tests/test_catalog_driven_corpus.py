"""v1.9.9 — catalog-driven Hypothesis corpus.

The hand-curated synthetic corpus at
``validation/synthetic_corpus/fixtures/`` is consistency-checking by
design: the same person who wrote the trigger heuristics chose the
fixtures. A reviewer should ask "what about inputs the trigger
designer didn't think of?" — and the right answer is to draw inputs
from a source that is NOT under the trigger designer's curation.

These tests use Hypothesis to draw slugs and services directly from
the live fingerprint catalog (``recon_tool.fingerprints.load_fingerprints``),
combine them in arbitrary subsets, and run the resulting TenantInfo
through the renderer. The trigger discipline must hold:

  * Multi-cloud rollup never fires when there are zero distinct
    canonical cloud vendors across the input.
  * Multi-cloud rollup always fires when there are at least two
    distinct canonical cloud vendors.
  * Ceiling never fires when ``info.services`` is empty.
  * Ceiling never fires under ``--full`` mode.
  * Ceiling never fires when ``info.domain_count < 3``.

The Hypothesis strategy draws from the catalog, so the input space
is whatever the catalog publishes — not whatever the test author
wrote down. If the catalog gains a new slug shape that breaks the
trigger discipline, the property tests catch it on the next CI run
without anyone having to update fixtures.
"""

from __future__ import annotations

import io

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from rich.console import Console

from recon_tool.fingerprints import load_fingerprints
from recon_tool.formatter import (
    _CLOUD_VENDOR_BY_SLUG,
    canonical_cloud_vendor,
    render_tenant_panel,
)
from recon_tool.models import ConfidenceLevel, TenantInfo


def _render(info: TenantInfo, *, show_domains: bool = False) -> str:
    console = Console(no_color=True, record=True, width=120, file=io.StringIO())
    rendered = render_tenant_panel(info, show_domains=show_domains)
    console.print(rendered)
    return console.export_text()


# Catalog-derived strategies. The slug list is whatever the catalog
# currently publishes; new slugs added in a later release flow into
# the strategy automatically.
_catalog = load_fingerprints()
_catalog_slugs = sorted({fp.slug for fp in _catalog})
_catalog_names = sorted({fp.name for fp in _catalog})

# Cloud-categorized slugs that are in the rollup map. Used for the
# "always fires when ≥ 2 distinct vendors" property below.
_cloud_slugs_in_rollup = sorted(_CLOUD_VENDOR_BY_SLUG.keys())

# Non-cloud slugs from the catalog (anything not in the rollup map).
# Used for the "never fires when zero cloud vendors" property.
_non_cloud_slugs = [s for s in _catalog_slugs if s not in _CLOUD_VENDOR_BY_SLUG]


def _make_tenant(*, slugs, services, domain_count: int = 5, surface_count: int = 0) -> TenantInfo:
    domains = tuple(f"contoso-{i}.example" for i in range(domain_count))
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid",
        display_name="Contoso, Ltd",
        default_domain="contoso.example",
        queried_domain="contoso.example",
        confidence=ConfidenceLevel.HIGH,
        domain_count=domain_count,
        tenant_domains=domains,
        services=tuple(services),
        slugs=tuple(slugs),
    )


class TestMultiCloudInvariantsOnCatalogInputs:
    """Hypothesis-driven invariants on the multi-cloud rollup with
    inputs drawn from the live fingerprint catalog."""

    @given(slugs=st.lists(st.sampled_from(_non_cloud_slugs), min_size=0, max_size=8))
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_zero_cloud_vendors_never_fires_rollup(self, slugs):
        """Property: if every input slug is a non-cloud slug from the
        catalog, the rollup must NOT fire. The canonicalization
        returns None for these slugs; the vendor count is always 0;
        the trigger threshold (>= 2) is never met."""
        # Sanity that the strategy is constructed correctly:
        for slug in slugs:
            assert canonical_cloud_vendor(slug) is None, (
                f"non_cloud_slugs strategy contained {slug!r} which canonicalizes to a vendor"
            )

        info = _make_tenant(slugs=slugs, services=[s.title() for s in slugs])
        out = _render(info)
        assert "Multi-cloud" not in out, f"rollup fired on zero-cloud-vendor input. slugs={slugs}, render={out[:300]}"

    @given(
        cloud_slugs=st.lists(
            st.sampled_from(_cloud_slugs_in_rollup),
            min_size=2,
            max_size=6,
            unique=True,
        ),
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_two_or_more_distinct_vendors_always_fires_rollup(self, cloud_slugs):
        """Property: if the input contains slugs canonicalizing to at
        least 2 distinct cloud vendors, the rollup MUST fire. We
        filter inputs to ensure they actually produce ≥ 2 distinct
        vendors after canonicalization (otherwise multiple AWS-family
        slugs would still collapse to 1 vendor)."""
        vendors = {canonical_cloud_vendor(s) for s in cloud_slugs}
        vendors.discard(None)
        if len(vendors) < 2:
            # Strategy drew slugs that all canonicalize to the same
            # vendor (e.g. multiple AWS-family slugs). Skip.
            return

        info = _make_tenant(slugs=cloud_slugs, services=[s.title() for s in cloud_slugs])
        out = _render(info)
        assert "Multi-cloud" in out, (
            f"rollup did NOT fire on >= 2 distinct vendors. slugs={cloud_slugs}, vendors={vendors}, render={out[:400]}"
        )


class TestCeilingInvariantsOnCatalogInputs:
    """Hypothesis-driven invariants on the ceiling trigger with inputs
    drawn from the live catalog."""

    @given(slugs=st.lists(st.sampled_from(_catalog_slugs), min_size=0, max_size=10))
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_empty_services_never_fires_ceiling(self, slugs):
        """Property: regardless of slug content, if ``info.services``
        is empty the ceiling must not fire. The trigger has an
        explicit ``info.services`` short-circuit."""
        info = _make_tenant(slugs=slugs, services=[], domain_count=5)
        out = _render(info)
        assert "Passive-DNS ceiling" not in out

    @given(slugs=st.lists(st.sampled_from(_catalog_slugs), min_size=1, max_size=5))
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_full_mode_never_fires_ceiling(self, slugs):
        """Property: ``--full`` / ``--domains`` mode shows the long
        surface section and the ceiling becomes redundant. The
        trigger has an explicit ``not show_domains`` short-circuit."""
        info = _make_tenant(slugs=slugs, services=[s.title() for s in slugs], domain_count=5)
        out = _render(info, show_domains=True)
        assert "Passive-DNS ceiling" not in out

    @given(
        slugs=st.lists(st.sampled_from(_catalog_slugs), min_size=1, max_size=3),
        domain_count=st.integers(min_value=0, max_value=2),
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_low_domain_count_never_fires_ceiling(self, slugs, domain_count):
        """Property: domain_count < 3 must suppress regardless of how
        sparse the categorized services are. The conservative
        multi-domain gate respects genuinely-small organizations."""
        info = _make_tenant(
            slugs=slugs,
            services=[s.title() for s in slugs],
            domain_count=domain_count,
        )
        out = _render(info)
        assert "Passive-DNS ceiling" not in out
