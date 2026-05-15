"""v1.9.9 — passive-DNS ceiling phrasing in the default panel.

The default panel grew a one-line teaching footer that fires when the
panel looks sparse on a domain that probably has more public services
than we found. The line explains the architectural limit of passive DNS
collection so an operator does not read absence of finding as
absence of service. The trigger is conservative on purpose: it fires
only when both the categorized-service count and the
CNAME-chain-attribution count are below thresholds, and the apex has
enough tenant domains that a sparse result is genuinely surprising.

These tests pin the trigger heuristic:

  * Fires on a sparse-but-multi-domain apex (the surprising case).
  * Does not fire on a single-domain apex (genuinely-small org).
  * Does not fire when categorized services are dense.
  * Does not fire when CNAME-chain attributions are numerous (the
    subdomain footprint signals real scale even if apex-Services is
    short).
  * Does not fire under --full / --domains (those modes already show
    the long surface section; the footer would be redundant).
  * Does not fire when info.services is empty (a different message
    surface owns that case).
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


def _sparse_multi_domain_tenant(**overrides: object) -> TenantInfo:
    """Sparse panel on an apex with several tenant domains.

    Services intentionally count fewer than 5 categorized families and
    surface_attributions is empty so both halves of the trigger heuristic
    fire. domain_count ≥ 3 satisfies the multi-domain check.
    """
    base: dict[str, object] = {
        "tenant_id": "tid-sparse",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.LOW,
        "domain_count": 4,
        "tenant_domains": (
            "contoso.com",
            "contoso.net",
            "contoso.co.uk",
            "contoso-mail.com",
        ),
        # One short Email entry — categorized() will produce one or two
        # families which is well under the 5-floor.
        "services": ("Microsoft 365",),
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


def _dense_categorized_tenant() -> TenantInfo:
    """Many distinct service families across categories — not sparse."""
    return TenantInfo(  # type: ignore[arg-type]
        tenant_id="tid-dense",
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        domain_count=12,
        tenant_domains=("contoso.com", "contoso.net", "contoso.co.uk", "contoso-mail.com"),
        services=(
            "Microsoft 365",
            "Okta",
            "Slack",
            "Atlassian",
            "Cloudflare",
            "AWS CloudFront",
            "Wiz",
            "Proofpoint",
        ),
        slugs=(
            "m365",
            "okta",
            "slack",
            "atlassian",
            "cloudflare",
            "aws-cloudfront",
            "wiz",
            "proofpoint",
        ),
    )


class TestCeilingFires:
    def test_sparse_multi_domain_apex_shows_ceiling(self):
        info = _sparse_multi_domain_tenant()
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" in out, (
            "ceiling phrasing must fire on sparse-services + multi-domain apex; "
            "this is the surprising case the v1.9.9 footer was added for"
        )
        assert "Passive DNS surfaces" in out
        assert "not appear in public DNS records" in out


class TestCeilingSuppressed:
    def test_single_domain_apex_no_ceiling(self):
        """Genuinely-small orgs may have one tenant domain and few
        services — that is not architecturally surprising; the ceiling
        line would be alarmist."""
        info = _sparse_multi_domain_tenant(domain_count=1, tenant_domains=("contoso.com",))
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out

    def test_dense_categorized_no_ceiling(self):
        info = _dense_categorized_tenant()
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out

    def test_many_surface_attributions_no_ceiling(self):
        """The subdomain footprint signals scale even when apex-Services
        is short; the ceiling line would misread that picture."""
        many_attribs = tuple(
            SurfaceAttribution(
                subdomain=f"sub{i}.contoso.com",
                primary_slug="aws-cloudfront",
                primary_name="AWS CloudFront",
                primary_tier="infrastructure",
            )
            for i in range(8)
        )
        info = _sparse_multi_domain_tenant(surface_attributions=many_attribs)
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out

    def test_full_mode_no_ceiling(self):
        """``show_domains=True`` is --full / --domains; that surface
        already carries the long External-surface section so the
        teaching footer would be redundant."""
        info = _sparse_multi_domain_tenant()
        out = _render_to_string(info, show_domains=True)
        assert "Passive-DNS ceiling" not in out

    def test_no_services_no_ceiling(self):
        """An empty services tuple means the panel had nothing to
        categorize; the ceiling line is for sparse-but-non-empty
        cases."""
        info = _sparse_multi_domain_tenant(services=())
        out = _render_to_string(info)
        assert "Passive-DNS ceiling" not in out


class TestCeilingTone:
    def test_phrasing_avoids_alarmist_language(self):
        """The line teaches; it does not blame the tool or the target."""
        info = _sparse_multi_domain_tenant()
        out = _render_to_string(info)
        # No tool-blame: "could not" reads as a tool failure.
        assert "could not" not in out.lower().split("passive-dns ceiling")[1].split("\n\n")[0]
        # No target-blame either.
        assert "missing" not in out.lower().split("passive-dns ceiling")[1].split("\n\n")[0]
