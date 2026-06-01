"""Golden-output characterization tests for the user-facing renderers.

Purpose: pin the exact rendered output of ``render_tenant_panel`` (the main
panel, C901 ~96) and ``format_tenant_markdown`` (C901 ~25) so the complexity
decomposition of those functions cannot silently change what an operator
sees. These are characterization tests: the output is asserted byte-identical
to a committed golden snapshot under ``tests/golden_renders/``. When the
rendering is INTENTIONALLY changed, regenerate the snapshots by running the
suite once with ``RECON_REGEN_GOLDEN=1`` set, and review the diff before
committing.

Determinism: rendered through a ``no_color``, fixed-width Rich console, so the
snapshot is stable across machines.

Data: every fixture uses Microsoft fictional brands (Contoso, Northwind,
Fabrikam). No real company data appears here or in the golden files.
"""

from __future__ import annotations

import os
from pathlib import Path

from rich.console import Console

from recon_tool.formatter import format_tenant_markdown, render_tenant_panel
from recon_tool.models import (
    CertSummary,
    ConfidenceLevel,
    SurfaceAttribution,
    TenantInfo,
    UnclassifiedCnameChain,
)

_GOLDEN_DIR = Path(__file__).parent / "golden_renders"
_WIDTH = 120


def _render_panel(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=_WIDTH)
    console.print(render_tenant_panel(info, **kwargs))  # type: ignore[arg-type]
    return console.export_text()


def _check_golden(name: str, actual: str) -> None:
    """Compare ``actual`` to the committed snapshot, or regenerate it.

    Set ``RECON_REGEN_GOLDEN=1`` to (re)write the snapshot instead of
    asserting. Review the resulting diff before committing.
    """
    path = _GOLDEN_DIR / f"{name}.txt"
    if os.environ.get("RECON_REGEN_GOLDEN"):
        _GOLDEN_DIR.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    expected = path.read_text(encoding="utf-8")
    assert actual == expected, (
        f"golden mismatch for {name!r}. The renderer output changed. If this "
        "was intentional, regenerate with RECON_REGEN_GOLDEN=1 and review the diff."
    )


def _sparse_info() -> TenantInfo:
    """A thin result: a domain that publishes little. Northwind, fictional."""
    return TenantInfo(
        tenant_id=None,
        display_name="Northwind Traders",
        default_domain="northwindtraders.com",
        queried_domain="northwindtraders.com",
        confidence=ConfidenceLevel.LOW,
        sources=("dns_records",),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        domain_count=1,
        insights=("Passive DNS surfaces little for this apex.",),
    )


def _hardened_info() -> TenantInfo:
    """A hardened-looking target: wildcard certs, no identity. Fabrikam."""
    return TenantInfo(
        tenant_id=None,
        display_name="Fabrikam, Inc.",
        default_domain="fabrikam.com",
        queried_domain="fabrikam.com",
        confidence=ConfidenceLevel.LOW,
        sources=("dns_records", "cert_transparency"),
        services=(),
        slugs=(),
        domain_count=1,
        degraded_sources=("oidc_discovery",),
        cert_summary=CertSummary(
            cert_count=4,
            issuer_diversity=1,
            issuance_velocity=1,
            newest_cert_age_days=3,
            oldest_cert_age_days=20,
            top_issuers=("Let's Encrypt",),
            wildcard_sibling_clusters=(("*.fabrikam.com", "app.fabrikam.com"),),
        ),
        insights=("Wildcard-only certificate posture limits passive visibility.",),
    )


def _surface_rich_info() -> TenantInfo:
    """A tenant with a populated external surface: CNAME-chain attributions
    (a collapsed CDN group, layered app+infra rows, a standalone app) plus
    unclassified chains. Contoso, fictional.

    Pins the render branches the ``fully_populated_tenant_info`` fixture leaves
    dark: the Services subdomain summary, the Unclassified surface block, and
    the full-mode External surface section (individual rows, collapsed groups,
    apex stripping, layered service labels). Without this fixture those blocks
    have no golden snapshot, so a decomposition could change them unnoticed.
    """
    fastly = tuple(
        SurfaceAttribution(
            subdomain=f"cdn{i}.contoso.com",
            primary_slug="fastly",
            primary_name="Fastly",
            primary_tier="infrastructure",
        )
        for i in range(1, 7)  # 6 >= collapse threshold -> rendered as a group
    )
    auth0 = (
        SurfaceAttribution(
            subdomain="login.contoso.com",
            primary_slug="auth0",
            primary_name="Auth0",
            primary_tier="application",
            infra_slug="cloudflare",
            infra_name="Cloudflare",  # layered: "Auth0, Cloudflare"
        ),
        SurfaceAttribution(
            subdomain="sso.contoso.com",
            primary_slug="auth0",
            primary_name="Auth0",
            primary_tier="application",
        ),
    )
    zendesk = (
        SurfaceAttribution(
            subdomain="support.contoso.com",
            primary_slug="zendesk",
            primary_name="Zendesk",
            primary_tier="application",
        ),
    )
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Contoso Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("oidc_discovery", "dns_records", "cert_transparency"),
        services=("Microsoft 365", "Slack"),
        slugs=("microsoft365", "slack"),
        auth_type="Federated",
        domain_count=4,
        related_domains=("api.contoso.com", "login.contoso.com"),
        insights=("Email security 4/5 strong (DMARC reject, DKIM, SPF strict, MTA-STS)",),
        surface_attributions=fastly + auth0 + zendesk,
        unclassified_cname_chains=(
            UnclassifiedCnameChain(
                subdomain="weird.contoso.com",
                chain=("weird.contoso.com", "edge.example.net", "origin.unknown.net"),
            ),
            UnclassifiedCnameChain(
                subdomain="legacy.contoso.com",
                chain=("legacy.contoso.com", "old.vendor.net"),
            ),
            UnclassifiedCnameChain(
                subdomain="app.contoso.com",
                chain=("app.contoso.com",),
            ),
        ),
    )


class TestGoldenPanelRenders:
    """render_tenant_panel output is pinned across decomposition."""

    def test_panel_dense_default(self, fully_populated_tenant_info: TenantInfo) -> None:
        _check_golden("panel_dense_default", _render_panel(fully_populated_tenant_info))

    def test_panel_dense_full(self, fully_populated_tenant_info: TenantInfo) -> None:
        _check_golden(
            "panel_dense_full",
            _render_panel(fully_populated_tenant_info, show_services=True, show_domains=True),
        )

    def test_panel_dense_verbose(self, fully_populated_tenant_info: TenantInfo) -> None:
        _check_golden("panel_dense_verbose", _render_panel(fully_populated_tenant_info, verbose=True))

    def test_panel_dense_explain(self, fully_populated_tenant_info: TenantInfo) -> None:
        _check_golden("panel_dense_explain", _render_panel(fully_populated_tenant_info, explain=True))

    def test_panel_sparse_default(self) -> None:
        _check_golden("panel_sparse_default", _render_panel(_sparse_info()))

    def test_panel_hardened_default(self) -> None:
        _check_golden("panel_hardened_default", _render_panel(_hardened_info()))

    def test_panel_surface_default(self) -> None:
        # Default mode: exercises the Services subdomain summary and the
        # Unclassified surface block (both keyed on not-show_domains).
        _check_golden("panel_surface_default", _render_panel(_surface_rich_info()))

    def test_panel_surface_full(self) -> None:
        # Full mode: exercises the External surface section (individual rows,
        # collapsed CDN group, apex stripping, layered service labels) and the
        # unclassified-subdomain discovery hint.
        _check_golden(
            "panel_surface_full",
            _render_panel(_surface_rich_info(), show_services=True, show_domains=True),
        )


class TestGoldenMarkdownRenders:
    """format_tenant_markdown output is pinned across decomposition."""

    def test_markdown_dense(self, fully_populated_tenant_info: TenantInfo) -> None:
        _check_golden("markdown_dense", format_tenant_markdown(fully_populated_tenant_info))

    def test_markdown_sparse(self) -> None:
        _check_golden("markdown_sparse", format_tenant_markdown(_sparse_info()))
