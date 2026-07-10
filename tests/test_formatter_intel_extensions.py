"""Tests for intelligence-layer-v2 formatter extensions."""

import json

from rich.console import Console

from recon_tool.formatter import (
    format_chain_dict,
    format_chain_json,
    format_delta_dict,
    format_delta_json,
    format_posture_observations,
    format_tenant_dict,
    render_chain_panel,
    render_delta_panel,
    render_posture_panel,
)
from recon_tool.models import (
    CertSummary,
    ChainReport,
    ChainResult,
    ConfidenceLevel,
    DeltaReport,
    Observation,
    TenantInfo,
)


def _make_info(**overrides) -> TenantInfo:
    defaults = {
        "tenant_id": "tid",
        "display_name": "Test",
        "default_domain": "test.com",
        "queried_domain": "test.com",
        "confidence": ConfidenceLevel.HIGH,
        "services": ("Svc",),
        "sources": ("dns_records",),
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)


class TestCertSummaryRendering:
    def test_cert_summary_in_json(self):
        cs = CertSummary(
            cert_count=10,
            issuer_diversity=2,
            issuance_velocity=5,
            newest_cert_age_days=3,
            oldest_cert_age_days=100,
            top_issuers=("LE", "DigiCert"),
        )
        info = _make_info(cert_summary=cs)
        d = format_tenant_dict(info)
        assert "cert_summary" in d
        assert d["cert_summary"]["cert_count"] == 10
        assert d["cert_summary"]["issuance_velocity"] == 5

    def test_no_cert_summary_when_none(self):
        """v1.0 schema: cert_summary is always present, null when no CT data."""
        info = _make_info()
        d = format_tenant_dict(info)
        assert d["cert_summary"] is None


class TestPostureRendering:
    def test_format_observations(self):
        obs = (Observation(category="email", salience="high", statement="Test", related_slugs=("a",)),)
        result = format_posture_observations(obs)
        assert len(result) == 1
        assert result[0]["category"] == "email"
        assert result[0]["salience"] == "high"

    def test_render_panel_empty(self):
        assert render_posture_panel(()) is None

    def test_render_panel_nonempty(self):
        obs = (Observation(category="email", salience="high", statement="Test obs", related_slugs=()),)
        panel = render_posture_panel(obs)
        assert panel is not None


class TestDeltaRendering:
    def test_format_delta_no_changes(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=(),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
        )
        d = format_delta_dict(delta)
        assert d["has_changes"] is False
        assert d["domain"] == "test.com"

    def test_format_delta_with_changes(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=("New",),
            removed_services=("Old",),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
            changed_dmarc_policy=("none", "reject"),
        )
        d = format_delta_dict(delta)
        assert d["has_changes"] is True
        assert "New" in d["added_services"]
        assert d["changed_dmarc_policy"]["from"] == "none"

    def test_format_delta_json(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=(),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
        )
        j = format_delta_json(delta)
        parsed = json.loads(j)
        assert parsed["domain"] == "test.com"

    def test_render_delta_panel(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=("New",),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
        )
        panel = render_delta_panel(delta)
        assert panel is not None


class TestChainRendering:
    def test_format_chain_dict(self):
        info = _make_info()
        report = ChainReport(
            results=(ChainResult(domain="test.com", info=info, chain_depth=0),),
            max_depth_reached=0,
            truncated=False,
        )
        d = format_chain_dict(report)
        assert d["total_domains"] == 1
        assert d["truncated"] is False
        assert len(d["domains"]) == 1
        assert d["domains"][0]["chain_depth"] == 0

    def test_format_chain_json(self):
        info = _make_info()
        report = ChainReport(
            results=(ChainResult(domain="test.com", info=info, chain_depth=0),),
            max_depth_reached=0,
            truncated=False,
        )
        j = format_chain_json(report)
        parsed = json.loads(j)
        assert parsed["total_domains"] == 1

    def test_render_chain_panel(self):
        info = _make_info()
        report = ChainReport(
            results=(ChainResult(domain="test.com", info=info, chain_depth=0),),
            max_depth_reached=0,
            truncated=False,
        )
        panel = render_chain_panel(report)
        assert panel is not None

        console = Console(no_color=True, record=True, width=120)
        console.print(panel)
        rendered = console.export_text()
        assert "Unknown (no known provider pattern matched)" not in rendered

    def test_render_chain_truncated(self):
        info = _make_info()
        report = ChainReport(
            results=(ChainResult(domain="test.com", info=info, chain_depth=0),),
            max_depth_reached=1,
            truncated=True,
        )
        panel = render_chain_panel(report)
        assert panel is not None


class TestDeltaRenderingBranches:
    """Cover all scalar-change branches in render_delta_panel."""

    def test_render_delta_no_changes(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=(),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
        )
        panel = render_delta_panel(delta)
        assert panel is not None

    def test_render_delta_all_change_types(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=("NewSvc",),
            removed_services=("OldSvc",),
            added_slugs=("new-slug",),
            removed_slugs=("old-slug",),
            added_signals=("NewSig",),
            removed_signals=("OldSig",),
            changed_auth_type=("Federated", "Managed"),
            changed_dmarc_policy=("none", "reject"),
            changed_email_security_score=(1, 4),
            changed_confidence=("low", "high"),
            changed_domain_count=(3, 10),
        )
        panel = render_delta_panel(delta)
        assert panel is not None

    def test_format_delta_all_scalar_changes(self):
        delta = DeltaReport(
            domain="test.com",
            added_services=(),
            removed_services=(),
            added_slugs=(),
            removed_slugs=(),
            added_signals=(),
            removed_signals=(),
            changed_auth_type=("Federated", "Managed"),
            changed_dmarc_policy=("none", "reject"),
            changed_email_security_score=(2, 5),
            changed_confidence=("low", "high"),
            changed_domain_count=(1, 20),
        )
        d = format_delta_dict(delta)
        assert d["changed_auth_type"]["from"] == "Federated"
        assert d["changed_auth_type"]["to"] == "Managed"
        assert d["changed_email_security_score"]["from"] == 2
        assert d["changed_confidence"]["from"] == "low"
        assert d["changed_domain_count"]["to"] == 20


class TestMarkdownRendering:
    """Cover format_tenant_markdown branches."""

    def test_markdown_basic(self):
        from recon_tool.formatter import format_tenant_markdown

        info = _make_info()
        md = format_tenant_markdown(info)
        assert "# Tenant Report:" in md
        assert r"test\.com" in md

    def test_markdown_with_cert_summary(self):
        from recon_tool.formatter import format_tenant_markdown

        cs = CertSummary(
            cert_count=10,
            issuer_diversity=2,
            issuance_velocity=5,
            newest_cert_age_days=3,
            oldest_cert_age_days=100,
            top_issuers=("LE", "DigiCert"),
        )
        info = _make_info(cert_summary=cs, tenant_id="tid", region="US")
        md = format_tenant_markdown(info)
        assert "Certificate Intelligence" in md
        assert "10" in md

    def test_markdown_with_domains_and_related(self):
        from recon_tool.formatter import format_tenant_markdown

        info = _make_info(
            tenant_domains=("a.com", "b.com"),
            related_domains=("c.com",),
            domain_count=2,
            insights=("Some insight",),
            auth_type="Federated",
            degraded_sources=("crt.sh",),
        )
        md = format_tenant_markdown(info)
        assert "Tenant Domains" in md
        assert "Related Domains" in md
        assert r"crt\.sh" in md

    def test_markdown_m365_and_other_services(self):
        from recon_tool.formatter import format_tenant_markdown

        info = _make_info(
            services=("Exchange Online", "Cloudflare", "Microsoft Teams"),
        )
        md = format_tenant_markdown(info)
        assert "Microsoft 365 Services" in md
        assert "Tech Stack" in md

    def test_markdown_service_groups_are_mutually_exclusive(self):
        from recon_tool.formatter import format_tenant_markdown

        info = _make_info(
            services=(
                "Microsoft Teams",
                "Google Workspace: DKIM",
                "DKIM (Google Workspace)",
                "DKIM",
                "AutoGen (Microsoft)",
                "Microsoft Edge (Front Door)",
            ),
        )

        md = format_tenant_markdown(info)
        m365_section = md.split("## Microsoft 365 Services", 1)[1].split("##", 1)[0]
        gws_section = md.split("## Google Workspace Services", 1)[1].split("##", 1)[0]
        tech_section = md.split("## Tech Stack", 1)[1].split("##", 1)[0]

        assert "- Microsoft Teams" in m365_section
        assert r"- Google Workspace\: DKIM" in gws_section
        assert r"- DKIM \(Google Workspace\)" in gws_section
        assert "- DKIM" in tech_section
        assert r"- AutoGen \(Microsoft\)" in tech_section
        assert r"- Microsoft Edge \(Front Door\)" in tech_section
        assert md.count(r"- Google Workspace\: DKIM") == 1
        assert md.count(r"- DKIM \(Google Workspace\)") == 1

    def test_m365_fallbacks_are_exact_source_labels(self):
        from recon_tool.formatter import _is_m365_service

        expected = {
            "DKIM (Exchange Online)": True,
            "Exchange Autodiscover": True,
            "Exchange Online": True,
            "Intune / MDM": True,
            "Microsoft 365": True,
            "Microsoft 365 (US Government cloud)": True,
            "Microsoft Teams": True,
            "Office ProPlus (msoid)": True,
            "DKIM": False,
            "AutoGen (Microsoft)": False,
            "Microsoft Edge (Front Door)": False,
            "Google Workspace: DKIM": False,
            "DKIM (Google Workspace)": False,
        }

        assert {service: _is_m365_service(service) for service in expected} == expected

    def test_all_catalog_m365_names_classify_as_m365(self):
        from recon_tool.fingerprints import load_fingerprints
        from recon_tool.formatter import _is_m365_service

        names = {fp.name for fp in load_fingerprints() if fp.slug.startswith("microsoft365")}

        assert names
        assert all(_is_m365_service(name) for name in names)


class TestChainRenderingMultiDepth:
    def test_chain_multiple_depths(self):
        info1 = _make_info()
        info2 = _make_info(display_name="Related")
        report = ChainReport(
            results=(
                ChainResult(domain="test.com", info=info1, chain_depth=0),
                ChainResult(domain="related.com", info=info2, chain_depth=1),
            ),
            max_depth_reached=1,
            truncated=False,
        )
        d = format_chain_dict(report)
        assert d["total_domains"] == 2
        assert d["domains"][1]["chain_depth"] == 1

        panel = render_chain_panel(report)
        assert panel is not None
