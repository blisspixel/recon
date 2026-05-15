"""v1.9.9 — render-time fuzz tests on render_tenant_panel.

Fixture and snapshot tests pin specific inputs. Property tests pin
specific function-level invariants. Fuzz tests exercise the full render
pipeline against random-but-structurally-valid TenantInfo inputs to
catch crashes, exceptions, and rendering edge cases that pre-canonical
fixtures miss.

The Hypothesis strategy below builds a TenantInfo from random choices
across the dimensions that interact with the v1.9.9 surfaces:

  * services / slugs (vary count, identity, cloud-vs-saas mix).
  * surface_attributions (vary count, vendor, tier).
  * tenant_domains and domain_count (vary multi-domain scale).
  * show_domains flag (toggle --full mode).

The single invariant under test is operational, not semantic: the
renderer must not raise on any input the data model accepts. v1.9.9
added two new branches with non-trivial conditions; a fuzz run is the
quickest way to catch a NoneType or KeyError lurking in either.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from rich.console import Console

from recon_tool.formatter import _CLOUD_VENDOR_BY_SLUG, render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo

_known_cloud_slugs = sorted(_CLOUD_VENDOR_BY_SLUG.keys())
_known_saas_slugs = ["slack", "okta", "auth0", "atlassian", "wiz", "salesforce", "hubspot"]
_all_slugs = _known_cloud_slugs + _known_saas_slugs

_service_names = st.sampled_from(
    [
        "Microsoft 365",
        "Google Workspace",
        "Okta",
        "Auth0",
        "Cloudflare",
        "AWS CloudFront",
        "Fastly",
        "Slack",
        "Atlassian",
        "Wiz",
        "Proofpoint",
        "Snowflake",
    ]
)

_slug_strategy = st.sampled_from(_all_slugs)


@st.composite
def _surface_attribution(draw: st.DrawFn) -> SurfaceAttribution:
    sub_n = draw(st.integers(min_value=0, max_value=99))
    slug = draw(_slug_strategy)
    return SurfaceAttribution(
        subdomain=f"sub{sub_n}.contoso.com",
        primary_slug=slug,
        primary_name=slug.replace("-", " ").title(),
        primary_tier=draw(st.sampled_from(["application", "infrastructure"])),
    )


@st.composite
def _fuzz_tenant(draw: st.DrawFn) -> TenantInfo:
    """Random-but-valid TenantInfo across the dimensions that touch
    v1.9.9 surfaces. Every drawn TenantInfo must round-trip through
    ``render_tenant_panel`` without raising."""
    n_domains = draw(st.integers(min_value=0, max_value=15))
    domains = tuple(f"contoso-{i}.example" for i in range(n_domains))
    slugs = tuple(draw(st.lists(_slug_strategy, min_size=0, max_size=10)))
    services = tuple(draw(st.lists(_service_names, min_size=0, max_size=10)))
    attribs = tuple(draw(st.lists(_surface_attribution(), min_size=0, max_size=12)))
    confidence = draw(st.sampled_from(list(ConfidenceLevel)))

    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-fuzz",
        display_name="Contoso Fuzz",
        default_domain="contoso.example",
        queried_domain="contoso.example",
        confidence=confidence,
        domain_count=n_domains,
        tenant_domains=domains,
        services=services,
        slugs=slugs,
        surface_attributions=attribs,
    )


def _render(info: TenantInfo, *, show_domains: bool) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, show_domains=show_domains)
    console.print(rendered)
    return console.export_text()


class TestRenderDoesNotRaise:
    """Operational invariant: any structurally-valid TenantInfo must
    render without raising. Catches NoneType bugs, KeyError lookups
    against unfamiliar slugs, format-string ordering issues, and the
    other failure modes that pre-canonical fixtures cannot exhaustively
    represent."""

    @given(info=_fuzz_tenant())
    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_default_panel_renders(self, info):
        _render(info, show_domains=False)

    @given(info=_fuzz_tenant())
    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_full_panel_renders(self, info):
        """``--full`` mode toggles surface sections that the default
        panel hides; fuzz both modes so a regression confined to one
        path surfaces."""
        _render(info, show_domains=True)


class TestRenderOutputIsString:
    """Beyond not raising, the render result must be a non-empty
    string. A renderer that silently returned the empty string on
    pathological inputs would pass the not-raise check while leaking
    a different failure into operator-facing surfaces."""

    @given(info=_fuzz_tenant())
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_default_render_is_non_empty(self, info):
        out = _render(info, show_domains=False)
        assert isinstance(out, str)
        # The display name "Contoso Fuzz" always appears in the hero
        # header, so a non-empty render is a load-bearing invariant.
        assert "Contoso Fuzz" in out
