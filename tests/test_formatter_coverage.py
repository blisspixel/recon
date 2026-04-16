"""Targeted coverage tests for formatter rendering paths.

Exercises panel render branches that weren't hit by the existing test
files: empty services, no cert_summary, degraded sources with and
without CT provider attribution, the v0.9.2 render_source_status_panel,
detect_provider edge cases, etc. No real company names.
"""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

from recon_tool.formatter import (
    detect_provider,
    get_console,
    render_source_status_panel,
    render_tenant_panel,
    render_verbose_sources,
    set_console,
)
from recon_tool.models import (
    CertSummary,
    ConfidenceLevel,
    SourceResult,
    TenantInfo,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip(s: str) -> str:
    return _ANSI_RE.sub("", s)


@pytest.fixture(autouse=True)
def _restore_console():
    """Each test in this file replaces the global console via set_console;
    restore the original on teardown so other test modules (CliRunner-based
    tests, etc.) get a clean console fixture instead of the StringIO buffer
    orphaned at the end of this file's last test."""
    original = get_console()
    yield
    set_console(original)


def _make_console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    c = Console(file=buf, force_terminal=True, width=200, no_color=True, highlight=False)
    set_console(c)
    return c, buf


def _minimal_info(**overrides: object) -> TenantInfo:
    defaults: dict[str, object] = dict(
        tenant_id=None,
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.MEDIUM,
        region="NA",
        sources=("dns_records",),
        services=(),
        slugs=(),
        auth_type=None,
        dmarc_policy=None,
        domain_count=1,
    )
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


class TestDetectProviderEdgeCases:
    def test_topology_all_none_slugs_empty_returns_hedged_unknown(self) -> None:
        result = detect_provider(
            services=(),
            slugs=(),
            primary_email_provider=None,
            email_gateway=None,
            likely_primary_email_provider=None,
        )
        assert "Unknown" in result

    def test_gateway_only_no_primary_no_likely(self) -> None:
        result = detect_provider(
            services=(),
            slugs=(),
            primary_email_provider=None,
            email_gateway="Proofpoint",
            likely_primary_email_provider=None,
        )
        # v0.9.3 format: "{gateway} gateway (no inferable downstream)"
        assert "Proofpoint" in result
        assert "gateway" in result
        assert "no inferable downstream" in result

    def test_likely_only_no_primary_no_gateway(self) -> None:
        """When only likely_primary is set (weird but possible), render it
        with the '(likely primary)' v0.9.3 qualifier."""
        result = detect_provider(
            services=(),
            slugs=(),
            primary_email_provider=None,
            email_gateway=None,
            likely_primary_email_provider="Google Workspace",
        )
        assert "Google Workspace" in result
        assert "likely primary" in result

    def test_secondary_providers_from_slugs_when_primary_set(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365", "google-workspace"),
            primary_email_provider="Microsoft 365",
            email_gateway=None,
        )
        assert "Microsoft 365" in result
        assert "Google Workspace" in result
        assert "secondary" in result

    def test_secondary_providers_when_no_primary_or_likely(self) -> None:
        result = detect_provider(
            services=(),
            slugs=("microsoft365",),
            primary_email_provider=None,
            email_gateway="Proofpoint",
        )
        # Microsoft 365 appears as secondary alongside the gateway
        assert "Proofpoint" in result
        assert "Microsoft 365" in result

    def test_zoho_slug_fallback(self) -> None:
        # v0.9.3 (second revision): default has_mx_records=True —
        # assumes custom MX unless the caller explicitly passes
        # has_mx_records=False. See TestBackwardCompatDetectProvider
        # for the full rationale.
        result = detect_provider(services=(), slugs=("zoho",))
        assert result == "Zoho Mail (account detected, custom MX)"

    def test_protonmail_slug_fallback(self) -> None:
        result = detect_provider(services=(), slugs=("protonmail",))
        assert result == "ProtonMail (account detected, custom MX)"

    def test_aws_ses_only_slug(self) -> None:
        result = detect_provider(services=(), slugs=("aws-ses",))
        assert result == "AWS SES (account detected, custom MX)"


class TestRenderTenantPanelEdgeCases:
    """Exercise render_tenant_panel branches that basic tests miss."""

    def test_empty_services_no_insights(self) -> None:
        _, buf = _make_console()
        info = _minimal_info()
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        assert "Contoso" in out

    def test_with_cert_summary(self) -> None:
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC", "BIMI"),
            cert_summary=CertSummary(
                cert_count=20,
                issuer_diversity=2,
                issuance_velocity=3,
                newest_cert_age_days=5,
                oldest_cert_age_days=100,
                top_issuers=("DigiCert", "Let's Encrypt"),
            ),
        )
        from recon_tool.formatter import get_console
        # v0.9.3: Certs section is shown only under --verbose to keep
        # the default view tight. Pass verbose=True to exercise it.
        get_console().print(render_tenant_panel(info, verbose=True))
        out = _strip(buf.getvalue())
        assert "Certs" in out
        assert "20 total" in out
        assert "DigiCert" in out

    def test_degraded_sources_without_ct_provider(self) -> None:
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC",),
            degraded_sources=("crt.sh", "certspotter"),
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        # v0.9.3 format: "Note" header + "Some sources unavailable (...)"
        assert "Note" in out
        assert "crt.sh" in out
        assert "unavailable" in out

    def test_ct_provider_without_degraded_suppresses_note(self) -> None:
        """v0.9.2 Phase 2d: when CT succeeded cleanly (no degraded sources),
        the panel does NOT show a Note line. The CT provenance is still
        available via --json and --verbose for users who need it; the
        panel stays uncluttered on the happy path."""
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC",),
            ct_provider_used="crt.sh",
            ct_subdomain_count=42,
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        assert "Note:" not in out

    def test_degraded_plus_ct_provider_fallback(self) -> None:
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC",),
            degraded_sources=("crt.sh",),
            ct_provider_used="certspotter",
            ct_subdomain_count=87,
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        assert "crt.sh" in out
        assert "certspotter" in out
        assert "87" in out

    def test_related_domains_truncation(self) -> None:
        """v0.9.3: more than 8 related domains shows a compact
        '(N total — M more, use --full to see all)' footer."""
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC",),
            related_domains=tuple(f"sub{i}.contoso.com" for i in range(25)),
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        assert "sub0.contoso.com" in out
        assert "25 total" in out
        assert "more" in out
        assert "--full" in out

    def test_related_domains_full_list_when_show_domains(self) -> None:
        """show_domains=True renders the complete related list."""
        _, buf = _make_console()
        info = _minimal_info(
            services=("DMARC",),
            related_domains=tuple(f"sub{i}.contoso.com" for i in range(15)),
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info, show_domains=True))
        out = _strip(buf.getvalue())
        assert "sub14.contoso.com" in out
        assert "and " not in out or "more" not in out.split("sub14.contoso.com")[1]

    def test_m365_panel_with_tenant_id(self) -> None:
        _, buf = _make_console()
        info = _minimal_info(
            tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            display_name="Contoso Ltd",
            services=("Microsoft 365",),
            slugs=("microsoft365",),
            auth_type="Federated",
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info))
        out = _strip(buf.getvalue())
        # v0.9.3 format: the label is "Tenant" (no " ID:" suffix) and
        # the tenant UUID appears on the same line.
        assert "Tenant" in out
        assert "a1b2c3d4" in out

    def test_explain_flag_renders_classification(self) -> None:
        _, buf = _make_console()
        info = _minimal_info(
            services=("Microsoft 365", "Google Workspace"),
            slugs=("microsoft365", "google-workspace"),
            primary_email_provider="Microsoft 365",
            email_gateway="Proofpoint",
        )
        from recon_tool.formatter import get_console
        get_console().print(render_tenant_panel(info, explain=True))
        out = _strip(buf.getvalue())
        # v0.9.3 format: the Provider line carries the primary/gateway
        # classification inline. No separate "[Primary (MX): …]"
        # classification block.
        assert "Microsoft 365 (primary)" in out
        assert "Proofpoint gateway" in out


class TestRenderSourceStatusPanel:
    """v0.9.2 render_source_status_panel for --explain output."""

    def test_empty_results_returns_none(self) -> None:
        assert render_source_status_panel([]) is None

    def test_mixed_success_and_failure(self) -> None:
        _, buf = _make_console()
        results = [
            SourceResult(
                source_name="oidc_discovery",
                tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                region="NA",
            ),
            SourceResult(source_name="google_workspace", error="No Google Workspace configuration found"),
            SourceResult(source_name="dns_records", m365_detected=True, dmarc_policy="reject"),
        ]
        panel = render_source_status_panel(results)
        assert panel is not None
        from recon_tool.formatter import get_console
        get_console().print(panel)
        out = _strip(buf.getvalue())
        assert "oidc_discovery" in out
        assert "google_workspace" in out
        assert "No Google Workspace" in out
        assert "dns_records" in out
        assert "DMARC: reject" in out

    def test_all_failure(self) -> None:
        results = [
            SourceResult(source_name="oidc_discovery", error="HTTP 429"),
            SourceResult(source_name="dns_records", error="DNS error"),
        ]
        panel = render_source_status_panel(results)
        assert panel is not None


class TestRenderVerboseSources:
    def test_verbose_renders_success_and_failure(self) -> None:
        _, buf = _make_console()
        results = [
            SourceResult(
                source_name="oidc_discovery",
                tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                region="NA",
            ),
            SourceResult(source_name="user_realm", error="HTTP 403"),
        ]
        render_verbose_sources(results)
        out = _strip(buf.getvalue())
        assert "oidc_discovery" in out
        assert "tenant ID found" in out
        assert "user_realm" in out
        assert "HTTP 403" in out
