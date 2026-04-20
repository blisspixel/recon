"""Unit tests for the decomposed insight generators."""

from __future__ import annotations

from recon_tool.insights import (
    InsightContext,
    _auth_insights,
    _email_security_insights,
    _gateway_insights,
    _infrastructure_insights,
    _license_insights,
    _mdm_insights,
    _migration_insights,
    _org_size_insights,
    _pki_insights,
    _sase_insights,
    _security_stack_insights,
    generate_insights,
)


def _ctx(**kwargs) -> InsightContext:
    defaults = dict(services=set(), slugs=set(), auth_type=None, dmarc_policy=None, domain_count=0)
    defaults.update(kwargs)
    return InsightContext.from_sets(**defaults)


class TestAuthInsights:
    def test_federated(self):
        assert any("Federated" in i for i in _auth_insights(_ctx(auth_type="Federated")))

    def test_managed(self):
        # "Managed" only shows Entra ID insight when M365 slug is present
        assert any("Cloud-managed" in i for i in _auth_insights(_ctx(auth_type="Managed", slugs={"microsoft365"})))

    def test_managed_without_m365(self):
        # "Managed" without M365 evidence produces nothing — GetUserRealm
        # returns "Managed" for non-Microsoft domains too
        assert _auth_insights(_ctx(auth_type="Managed")) == []

    def test_none(self):
        assert _auth_insights(_ctx()) == []


class TestEmailSecurityInsights:
    def test_full_score(self):
        ctx = _ctx(
            services={"DKIM (Exchange Online)", "SPF: strict (-all)", "MTA-STS", "BIMI"},
            slugs={"microsoft365"},
            dmarc_policy="reject",
        )
        insights = _email_security_insights(ctx)
        assert any("5/5" in i for i in insights)

    def test_no_email_no_insights(self):
        assert _email_security_insights(_ctx()) == []

    def test_dmarc_none_warns(self):
        ctx = _ctx(slugs={"microsoft365"}, dmarc_policy="none")
        insights = _email_security_insights(ctx)
        assert any("not enforced" in i for i in insights)


class TestOrgSizeInsights:
    def test_large(self):
        assert any("large" in i for i in _org_size_insights(_ctx(domain_count=25)))

    def test_mid(self):
        assert any("mid-size" in i for i in _org_size_insights(_ctx(domain_count=8)))

    def test_small(self):
        assert any("3 domains" in i for i in _org_size_insights(_ctx(domain_count=3)))

    def test_zero(self):
        assert _org_size_insights(_ctx(domain_count=0)) == []


class TestGatewayInsights:
    def test_proofpoint_with_exchange(self):
        ctx = _ctx(slugs={"microsoft365", "proofpoint"})
        insights = _gateway_insights(ctx)
        assert any("Proofpoint" in i and "Exchange" in i for i in insights)

    def test_proofpoint_without_exchange(self):
        ctx = _ctx(slugs={"proofpoint"})
        insights = _gateway_insights(ctx)
        assert any("Proofpoint" in i for i in insights)
        assert not any("Exchange" in i for i in insights)


class TestMigrationInsights:
    def test_google_and_microsoft(self):
        ctx = _ctx(slugs={"google-workspace", "microsoft365"})
        assert len(_migration_insights(ctx)) == 1

    def test_no_migration(self):
        assert _migration_insights(_ctx()) == []


class TestLicenseInsights:
    def test_intune_federated(self):
        ctx = _ctx(services={"Intune / MDM"}, auth_type="Federated")
        assert any("E3/E5" in i for i in _license_insights(ctx))

    def test_intune_managed(self):
        ctx = _ctx(services={"Intune / MDM"}, auth_type="Managed")
        assert any("E3+" in i for i in _license_insights(ctx))


class TestSecurityStackInsights:
    def test_multiple_tools(self):
        ctx = _ctx(slugs={"crowdstrike", "okta"})
        insights = _security_stack_insights(ctx)
        assert any("CrowdStrike" in i and "Okta" in i for i in insights)


class TestMdmInsights:
    def test_dual_mdm(self):
        ctx = _ctx(services={"Intune / MDM"}, slugs={"jamf"})
        assert any("Dual MDM" in i for i in _mdm_insights(ctx))

    def test_dual_mdm_kandji(self):
        ctx = _ctx(services={"Intune / MDM"}, slugs={"kandji"})
        insights = _mdm_insights(ctx)
        assert any("Dual MDM" in i and "Kandji" in i for i in insights)

    def test_jamf_only(self):
        ctx = _ctx(slugs={"jamf"})
        assert any("Jamf" in i for i in _mdm_insights(ctx))

    def test_kandji_only(self):
        ctx = _ctx(slugs={"kandji"})
        assert any("Kandji" in i for i in _mdm_insights(ctx))


class TestInfrastructureInsights:
    def test_dns_and_cdn(self):
        ctx = _ctx(services={"DNS: Cloudflare", "CDN: Akamai"})
        insights = _infrastructure_insights(ctx)
        assert any("Cloudflare" in i for i in insights)


class TestGenerateInsightsIntegration:
    def test_combines_all_generators(self):
        insights = generate_insights(
            services={"Intune / MDM", "DKIM (Exchange Online)"},
            slugs={"microsoft365", "proofpoint", "crowdstrike"},
            auth_type="Federated",
            dmarc_policy="reject",
            domain_count=25,
        )
        # Should have auth, email security, org size, gateway, license, security stack
        assert len(insights) >= 5


class TestAuthInsightsWithIdP:
    def test_federated_with_okta_detected(self):
        ctx = _ctx(auth_type="Federated", slugs={"okta"})
        insights = _auth_insights(ctx)
        assert any("Okta" in i for i in insights)
        # Should say "indicators observed (likely Okta)" — not the generic ADFS/Okta/Ping fallback
        assert any("indicators observed" in i for i in insights)

    def test_federated_with_duo_detected(self):
        ctx = _ctx(auth_type="Federated", slugs={"duo"})
        insights = _auth_insights(ctx)
        assert any("Duo" in i for i in insights)

    def test_federated_without_idp_is_generic(self):
        ctx = _ctx(auth_type="Federated")
        insights = _auth_insights(ctx)
        assert any("likely" in i for i in insights)

    def test_federated_with_cisco_identity_does_not_claim_cisco_idp(self):
        # cisco-identity matches any TXT of the form cisco-ci-domain-verification=*.
        # That token is used by many Cisco products (Duo, Customer Identity,
        # Secure Email, Intersight), not specifically the org's SSO IdP.
        # The federated-auth insight must fall back to the generic line, not
        # name Cisco as the likely IdP.
        ctx = _ctx(auth_type="Federated", slugs={"cisco-identity"})
        insights = _auth_insights(ctx)
        assert not any("Cisco" in i for i in insights)
        assert any("ADFS/Okta/Ping" in i for i in insights)


class TestSaseInsights:
    def test_zscaler_detected(self):
        ctx = _ctx(slugs={"zscaler"})
        insights = _sase_insights(ctx)
        assert any("Zscaler" in i for i in insights)

    def test_netskope_detected(self):
        ctx = _ctx(slugs={"netskope"})
        insights = _sase_insights(ctx)
        assert any("Netskope" in i for i in insights)

    def test_multi_vendor_sase(self):
        ctx = _ctx(slugs={"zscaler", "netskope"})
        insights = _sase_insights(ctx)
        assert any("multi-vendor" in i for i in insights)

    def test_no_sase(self):
        ctx = _ctx(slugs={"crowdstrike"})
        assert _sase_insights(ctx) == []


class TestPkiInsights:
    def test_letsencrypt(self):
        ctx = _ctx(slugs={"letsencrypt"})
        insights = _pki_insights(ctx)
        assert any("Let's Encrypt" in i for i in insights)

    def test_multiple_cas(self):
        ctx = _ctx(slugs={"letsencrypt", "digicert"})
        insights = _pki_insights(ctx)
        assert any("Let's Encrypt" in i and "DigiCert" in i for i in insights)

    def test_no_caa(self):
        assert _pki_insights(_ctx()) == []


class TestExpandedSecurityStack:
    def test_sentinelone_in_stack(self):
        ctx = _ctx(slugs={"sentinelone", "okta"})
        insights = _security_stack_insights(ctx)
        assert any("SentinelOne" in i for i in insights)

    def test_netskope_in_stack(self):
        ctx = _ctx(slugs={"netskope", "crowdstrike"})
        insights = _security_stack_insights(ctx)
        assert any("Netskope" in i for i in insights)

    def test_1password_in_stack(self):
        ctx = _ctx(slugs={"1password", "okta"})
        insights = _security_stack_insights(ctx)
        assert any("1Password" in i for i in insights)


class TestExpandedGateway:
    def test_symantec_gateway(self):
        ctx = _ctx(slugs={"symantec", "microsoft365"})
        insights = _gateway_insights(ctx)
        assert any("Symantec" in i for i in insights)

    def test_trellix_gateway(self):
        ctx = _ctx(slugs={"trellix"})
        insights = _gateway_insights(ctx)
        assert any("Trellix" in i for i in insights)

    def test_cisco_email_gateway(self):
        ctx = _ctx(slugs={"cisco-email", "microsoft365"})
        insights = _gateway_insights(ctx)
        assert any("Cisco Secure Email" in i for i in insights)
