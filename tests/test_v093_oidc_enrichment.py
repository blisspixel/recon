"""Tests for v0.9.3 OIDC tenant metadata enrichment.

Covers:
- parse_tenant_info_from_oidc extracts cloud_instance_name,
  tenant_region_sub_scope, and msgraph_host when present in the
  discovery response
- Fields are None when the discovery response omits them (backward
  compatible with v0.9.2 and earlier)
- Sovereignty insights fire in generate_insights for gov-cloud,
  GCC High, China 21Vianet, and B2C tenants
- Commercial M365 tenants produce no sovereignty insight
- Hedged language in every insight (never "is", always "likely" or
  "observed")
"""

from __future__ import annotations

from recon_tool.insights import generate_insights
from recon_tool.sources.oidc import parse_tenant_info_from_oidc

_VALID_TENANT_ID = "11111111-2222-3333-4444-555555555555"


def _auth_endpoint(tenant_id: str = _VALID_TENANT_ID) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"


# ── parse_tenant_info_from_oidc ─────────────────────────────────────────


class TestOIDCParsing:
    def test_commercial_tenant_has_no_cloud_extensions(self):
        """A typical commercial tenant discovery response does not
        carry cloud_instance_name — all three fields should be None."""
        resp = {"authorization_endpoint": _auth_endpoint()}
        result = parse_tenant_info_from_oidc(resp)
        assert result.tenant_id == _VALID_TENANT_ID
        assert result.cloud_instance is None
        assert result.tenant_region_sub_scope is None
        assert result.msgraph_host is None

    def test_commercial_with_instance_name(self):
        resp = {
            "authorization_endpoint": _auth_endpoint(),
            "cloud_instance_name": "microsoftonline.com",
            "msgraph_host": "graph.microsoft.com",
        }
        result = parse_tenant_info_from_oidc(resp)
        assert result.cloud_instance == "microsoftonline.com"
        assert result.msgraph_host == "graph.microsoft.com"

    def test_gcc_tenant(self):
        resp = {
            "authorization_endpoint": _auth_endpoint(),
            "cloud_instance_name": "microsoftonline.us",
            "msgraph_host": "graph.microsoft.us",
            "tenant_region_sub_scope": "GCC",
        }
        result = parse_tenant_info_from_oidc(resp)
        assert result.cloud_instance == "microsoftonline.us"
        assert result.tenant_region_sub_scope == "GCC"
        assert result.msgraph_host == "graph.microsoft.us"

    def test_gcch_dod_tenant(self):
        resp = {
            "authorization_endpoint": _auth_endpoint(),
            "cloud_instance_name": "microsoftonline.us",
            "tenant_region_sub_scope": "DOD",
        }
        result = parse_tenant_info_from_oidc(resp)
        assert result.cloud_instance == "microsoftonline.us"
        assert result.tenant_region_sub_scope == "DOD"

    def test_china_21vianet(self):
        resp = {
            "authorization_endpoint": _auth_endpoint(),
            "cloud_instance_name": "partner.microsoftonline.cn",
            "msgraph_host": "microsoftgraphchina.cn",
        }
        result = parse_tenant_info_from_oidc(resp)
        assert result.cloud_instance == "partner.microsoftonline.cn"

    def test_empty_string_becomes_none(self):
        """An empty-string extension should normalize to None."""
        resp = {
            "authorization_endpoint": _auth_endpoint(),
            "cloud_instance_name": "",
            "msgraph_host": "   ",
            "tenant_region_sub_scope": "",
        }
        result = parse_tenant_info_from_oidc(resp)
        assert result.cloud_instance is None
        assert result.tenant_region_sub_scope is None
        assert result.msgraph_host is None


# ── Insight generation ─────────────────────────────────────────────────


def _insights(**kwargs: object) -> list[str]:
    defaults: dict[str, object] = {
        "services": set(),
        "slugs": set(),
        "auth_type": None,
        "dmarc_policy": None,
        "domain_count": 0,
    }
    defaults.update(kwargs)
    return generate_insights(**defaults)  # pyright: ignore[reportArgumentType]


class TestSovereigntyInsights:
    def test_commercial_emits_nothing(self):
        out = _insights(cloud_instance="microsoftonline.com")
        assert not any("government" in i.lower() for i in out)
        assert not any("china" in i.lower() for i in out)

    def test_gcc_emits_hedged_insight(self):
        out = _insights(cloud_instance="microsoftonline.us")
        gov_lines = [i for i in out if "government" in i.lower() or "gcc" in i.lower()]
        assert gov_lines
        assert any("likely" in i.lower() or "observed" in i.lower() for i in gov_lines)

    def test_gcch_dod_emits_distinct_insight(self):
        out = _insights(
            cloud_instance="microsoftonline.us",
            tenant_region_sub_scope="DOD",
        )
        dod_lines = [i for i in out if "dod" in i.lower() or "gcc high" in i.lower()]
        assert dod_lines

    def test_china_emits_hedged_insight(self):
        out = _insights(cloud_instance="partner.microsoftonline.cn")
        china_lines = [i for i in out if "china" in i.lower()]
        assert china_lines
        assert any("likely" in i.lower() or "observed" in i.lower() for i in china_lines)

    def test_b2c_emits_b2c_insight(self):
        out = _insights(cloud_instance="fabrikam.b2clogin.com")
        assert any("b2c" in i.lower() for i in out)

    def test_no_instance_no_insight(self):
        out = _insights()
        assert not any("government" in i.lower() or "china" in i.lower() or "b2c" in i.lower() for i in out)

    def test_never_uses_confident_is(self):
        """Every sovereignty insight must be hedged."""
        for ci in ("microsoftonline.us", "partner.microsoftonline.cn"):
            out = _insights(cloud_instance=ci)
            gov_lines = [
                i for i in out
                if "government" in i.lower()
                or "china" in i.lower()
                or "gcc" in i.lower()
            ]
            for line in gov_lines:
                lower = line.lower()
                # No confident "IS a X tenant" claims
                assert " is a " not in lower
                assert " is an " not in lower
                assert "likely" in lower or "observed" in lower
