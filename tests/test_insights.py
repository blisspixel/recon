"""Tests for insight generation and tiered output."""

from __future__ import annotations

import io
import json
import re

from rich.console import Console

from recon_tool.formatter import format_tenant_json, render_tenant_panel
from recon_tool.insights import generate_insights
from recon_tool.models import ConfidenceLevel, TenantInfo

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


class TestInsightGeneration:
    """Tests for generate_insights(services, slugs, auth_type, dmarc_policy, domain_count)."""

    def test_federated_auth(self):
        insights = generate_insights(set(), set(), "Federated", None, 0)
        assert any("Federated" in i for i in insights)

    def test_managed_auth(self):
        # "Managed" only shows Entra ID insight when M365 is detected
        insights = generate_insights(set(), {"microsoft365"}, "Managed", None, 0)
        assert any("Cloud-managed" in i for i in insights)

    def test_managed_auth_without_m365(self):
        # "Managed" without M365 evidence produces no auth insight
        insights = generate_insights(set(), set(), "Managed", None, 0)
        assert not any("Cloud-managed" in i for i in insights)

    def test_dmarc_reject(self):
        insights = generate_insights(set(), set(), None, "reject", 0)
        assert any("reject" in i for i in insights)

    def test_dmarc_quarantine(self):
        insights = generate_insights(set(), set(), None, "quarantine", 0)
        assert any("quarantine" in i for i in insights)

    def test_dmarc_none(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365"}
        insights = generate_insights(services, slugs, None, "none", 0)
        assert any("not enforced" in i for i in insights)

    def test_no_dmarc_with_exchange(self):
        """v0.9.3: a domain with MX-backed M365 (primary_email_provider
        set from MX evidence) but no DMARC record should emit the
        "No DMARC" gap insight. Passing primary_email_provider here
        represents "MX actually points to Microsoft 365" — without
        it the email-security scorer refuses to score, to avoid the
        bug where a dormant Google Workspace account registration
        produced an "Email security 0/5 weak" line on a domain with
        zero email infrastructure."""
        services = {"Exchange Online"}
        slugs = {"microsoft365"}
        insights = generate_insights(
            services,
            slugs,
            None,
            None,
            0,
            primary_email_provider="Microsoft 365",
        )
        assert any("No DMARC" in i for i in insights)

    def test_large_enterprise_domains(self):
        insights = generate_insights(set(), set(), None, None, 25)
        assert any("large enterprise" in i for i in insights)

    def test_midsize_domains(self):
        insights = generate_insights(set(), set(), None, None, 8)
        assert any("mid-size" in i for i in insights)

    def test_small_domain_count(self):
        insights = generate_insights(set(), set(), None, None, 3)
        assert any("3 domains" in i for i in insights)

    def test_proofpoint_gateway(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365", "proofpoint"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert any("Proofpoint" in i and "gateway" in i.lower() for i in insights)

    def test_mimecast_gateway(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365", "mimecast"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert any("Mimecast" in i for i in insights)

    def test_google_mx_microsoft_txt_migration(self):
        slugs = {"google-workspace", "microsoft365"}
        insights = generate_insights(set(), slugs, None, None, 0)
        assert any("dual provider" in i.lower() for i in insights)

    def test_exchange_mx_google_spf_migration(self):
        slugs = {"microsoft365", "google-workspace"}
        insights = generate_insights(set(), slugs, None, None, 0)
        assert any("dual provider" in i.lower() for i in insights)

    def test_google_site_verified_no_migration(self):
        """google-site-verification alone should NOT trigger migration signal."""
        services = {"Exchange Online", "Google (site verified)"}
        slugs = {"microsoft365", "google-site-verified"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert not any("migration" in i.lower() or "hybrid" in i.lower() for i in insights)

    def test_knowbe4_insight(self):
        insights = generate_insights(set(), {"knowbe4"}, None, None, 0)
        assert any("KnowBe4" in i for i in insights)

    def test_crowdstrike_insight(self):
        insights = generate_insights(set(), {"crowdstrike"}, None, None, 0)
        assert any("CrowdStrike" in i for i in insights)

    def test_duo_insight(self):
        insights = generate_insights(set(), {"duo"}, None, None, 0)
        assert any("Duo" in i for i in insights)

    def test_okta_insight(self):
        insights = generate_insights(set(), {"okta"}, None, None, 0)
        assert any("Okta" in i for i in insights)

    def test_dual_mdm(self):
        services = {"Intune / MDM"}
        slugs = {"microsoft365", "jamf"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert any("Dual MDM" in i for i in insights)

    def test_jamf_only(self):
        insights = generate_insights(set(), {"jamf"}, None, None, 0)
        assert any("Jamf" in i for i in insights)

    def test_no_dkim_with_exchange(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365"}
        insights = generate_insights(services, slugs, None, "reject", 0)
        assert any("No DKIM" in i for i in insights)

    def test_sophos_insight(self):
        insights = generate_insights(set(), {"sophos"}, None, None, 0)
        assert any("Sophos" in i for i in insights)

    def test_barracuda_gateway(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365", "barracuda"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert any("Barracuda" in i for i in insights)

    def test_cisco_email_gateway(self):
        services = {"Exchange Online"}
        slugs = {"microsoft365", "cisco-ironport"}
        insights = generate_insights(services, slugs, None, None, 0)
        assert any("Cisco" in i for i in insights)

    def test_gateway_without_exchange(self):
        slugs = {"proofpoint"}
        insights = generate_insights(set(), slugs, None, None, 0)
        assert any("Proofpoint" in i for i in insights)


class TestTieredOutput:
    def _make_info(self, **kwargs) -> TenantInfo:
        defaults = {
            "tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "display_name": "TestCo",
            "default_domain": "testco.com",
            "queried_domain": "testco.com",
            "confidence": ConfidenceLevel.HIGH,
            "region": "NA",
            "auth_type": "Federated",
            "dmarc_policy": "reject",
            "domain_count": 5,
            "sources": ("oidc_discovery", "user_realm"),
            "services": ("Exchange Online", "Google Workspace", "Slack"),
            "insights": ("Federated identity", "DMARC: reject"),
            "tenant_domains": ("testco.com", "testco.onmicrosoft.com"),
        }
        defaults.update(kwargs)
        return TenantInfo(**defaults)

    def _render(self, panel) -> str:
        c = Console(file=io.StringIO(), force_terminal=True, width=200, no_color=True, highlight=False)
        c.print(panel)
        # Strip ANSI escape sequences so substring assertions match across
        # styled segments (B3 splits insight labels and values into separate
        # styled appends, which would otherwise break "in output" checks).
        return _strip_ansi(c.file.getvalue())

    def test_default_shows_insights_not_services(self):
        info = self._make_info()
        output = self._render(render_tenant_panel(info))
        assert "Federated identity" in output
        assert "DMARC: reject" in output
        assert "Tech Stack:" not in output
        assert "M365:" not in output

    def test_services_flag_shows_services(self):
        info = self._make_info()
        output = self._render(render_tenant_panel(info, show_services=True))
        assert "Exchange Online" in output
        assert "Slack" in output

    def test_domains_flag_shows_domains(self):
        info = self._make_info()
        output = self._render(render_tenant_panel(info, show_domains=True))
        assert "testco.com" in output
        assert "testco.onmicrosoft.com" in output
        assert "Domains (5)" in output

    def test_full_shows_everything(self):
        info = self._make_info()
        output = self._render(render_tenant_panel(info, show_services=True, show_domains=True))
        assert "Federated identity" in output
        assert "Exchange Online" in output
        assert "testco.onmicrosoft.com" in output

    def test_json_includes_all_fields(self):
        info = self._make_info()
        data = json.loads(format_tenant_json(info))
        assert data["auth_type"] == "Federated"
        assert data["dmarc_policy"] == "reject"
        assert data["domain_count"] == 5
        assert "Federated identity" in data["insights"]
        assert "testco.onmicrosoft.com" in data["tenant_domains"]
        assert "Exchange Online" in data["services"]

    def test_auth_type_shown_in_panel(self):
        info = self._make_info()
        output = self._render(render_tenant_panel(info))
        assert "Federated" in output

    def test_no_insights_no_crash(self):
        info = self._make_info(insights=(), services=(), tenant_domains=())
        output = self._render(render_tenant_panel(info, show_services=True, show_domains=True))
        assert "TestCo" in output

    def test_gap_insight_colored_red(self):
        """Insights with 'gap' or 'not enforced' should still render."""
        info = self._make_info(insights=("No DMARC record — potential email security gap",))
        output = self._render(render_tenant_panel(info))
        assert "email security gap" in output
