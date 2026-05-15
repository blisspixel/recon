"""v1.9.9 — boundary tests on the passive-DNS ceiling trigger.

The ceiling footer fires only when all of:
    info.services and not show_domains
    info.domain_count >= 3
    ceiling_categorized_count < 5
    len(info.surface_attributions) < 5

The original test file (``test_formatter_ceiling.py``) covers
well-above and well-below cases for each condition. This file covers
the exact-threshold cases — the off-by-one slot where a heuristic
refactor most often introduces a regression.

For each numeric threshold the test pair pins the strict-inequality
boundary: the value that should fire, and the value that should
suppress.
"""

from __future__ import annotations

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _render_to_string(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


def _tenant_at_boundary(
    *,
    domain_count: int,
    categorized_proxy_services: int,
    surface_attribs: int,
) -> TenantInfo:
    """Build a TenantInfo positioned at a chosen point in the trigger's
    three-dimensional threshold space.

    The ``categorized_proxy_services`` parameter assumes one service per
    category, which holds for the test fixtures here because each
    service name selected falls under a distinct ``_CATEGORY_BY_SLUG``
    bucket. Surface attribs are filler subdomains with a known
    cloud-categorized slug.
    """
    # Service / slug pairs chosen so each one maps to a single
    # ``_CATEGORY_BY_SLUG`` bucket without round-tripping through pass 2
    # of ``_categorize_services``. Picking slugs whose fingerprint
    # display name diverges from the raw service string (Wiz → "Wiz
    # Security"; Crowdstrike → "CrowdStrike Falcon") causes the pass-2
    # heuristic to file the raw name under a second category, which
    # would push the categorized count above what the parameter
    # promises. The choices below all round-trip cleanly so
    # ``categorized_proxy_services == N`` produces exactly N categories.
    service_names = (
        "Microsoft 365",  # Email
        "Okta",  # Identity
        "Cloudflare",  # Cloud
        "Slack",  # Collaboration
        "OpenAI",  # AI
    )
    service_slugs = ("m365", "okta", "cloudflare", "slack", "openai")
    if categorized_proxy_services > len(service_names):
        raise ValueError(
            f"fixture supports at most {len(service_names)} distinct categories; requested {categorized_proxy_services}"
        )

    chosen_services = service_names[:categorized_proxy_services]
    chosen_slugs = service_slugs[:categorized_proxy_services]

    attribs = tuple(
        SurfaceAttribution(
            subdomain=f"sub{i}.contoso.com",
            primary_slug="aws-cloudfront",
            primary_name="AWS CloudFront",
            primary_tier="infrastructure",
        )
        for i in range(surface_attribs)
    )
    domains = tuple(f"contoso-{i}.com" for i in range(domain_count)) if domain_count else ()

    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-boundary",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.LOW,
        domain_count=domain_count,
        tenant_domains=domains,
        services=chosen_services,
        slugs=chosen_slugs,
        surface_attributions=attribs,
    )


class TestDomainCountBoundary:
    """Threshold: ``info.domain_count >= 3``."""

    def test_at_threshold_three_domains_fires(self):
        """Exactly three domains is the lowest count that should fire
        the ceiling. A strict ``> 3`` would silently drop this case."""
        info = _tenant_at_boundary(domain_count=3, categorized_proxy_services=1, surface_attribs=0)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" in out, "domain_count == 3 must fire; the gate is >= 3, not > 3"

    def test_just_below_threshold_two_domains_suppresses(self):
        info = _tenant_at_boundary(domain_count=2, categorized_proxy_services=1, surface_attribs=0)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out


class TestCategorizedCountBoundary:
    """Threshold: ``ceiling_categorized_count < 5``.

    Each fixture has exactly N service names from distinct categories so
    the categorized count maps to N. The N=4 case must fire (sparse);
    N=5 must suppress (the cutoff)."""

    def test_four_categorized_services_fires(self):
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=4, surface_attribs=0)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" in out, "4 categorized services is still sparse; the gate is < 5, so 4 must fire"

    def test_five_categorized_services_suppresses(self):
        """5 hits the strict-less-than cutoff and must suppress.
        Otherwise a refactor that flipped the comparator silently
        regresses the trigger."""
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=5, surface_attribs=0)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out


class TestSurfaceAttributionsBoundary:
    """Threshold: ``len(info.surface_attributions) < 5``."""

    def test_four_surface_attribs_fires(self):
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=1, surface_attribs=4)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" in out, "4 surface attributions is still sparse; the gate is < 5, so 4 must fire"

    def test_five_surface_attribs_suppresses(self):
        """5 hits the strict-less-than cutoff and must suppress. This is
        the case where a domain with a handful of subdomain attributions
        is no longer the architectural-limit picture the ceiling
        describes."""
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=1, surface_attribs=5)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out


class TestCompoundBoundary:
    """Both halves of the sparse check operate as AND. A fixture sparse
    on services but dense on surface attribs must suppress; the inverse
    must also suppress."""

    def test_sparse_services_dense_attribs_suppresses(self):
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=2, surface_attribs=10)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out

    def test_dense_services_sparse_attribs_suppresses(self):
        """5 categorized services hits the strict-less-than cutoff, so
        even with zero surface attributions the ceiling suppresses. The
        AND-gate is doing the right thing: dense in one dimension is
        enough."""
        info = _tenant_at_boundary(domain_count=4, categorized_proxy_services=5, surface_attribs=0)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out
