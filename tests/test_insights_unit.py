"""Unit tests for the decomposed insight generators."""

from __future__ import annotations

from typing import Any, cast

from recon_tool.constants import SVC_BIMI, SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE, SVC_MTA_STS, SVC_SPF_STRICT
from recon_tool.insights import (
    InsightContext,
    _auth_insights,
    _device_management_insights,
    _email_security_insights,
    _gateway_insights,
    _google_modules_insights,
    _infrastructure_insights,
    _network_security_insights,
    _pki_insights,
    _provider_overlap_insights,
    _security_vendor_insights,
    _sparse_signal_insights,
    _tenant_domain_insights,
    generate_insights,
)
from recon_tool.models import EvidenceRecord


def _ctx(**kwargs) -> InsightContext:
    defaults: dict[str, Any] = {
        "services": set(),
        "slugs": set(),
        "auth_type": None,
        "dmarc_policy": None,
        "domain_count": 0,
    }
    defaults.update(kwargs)
    if "evidence" not in defaults:
        evidence: list[EvidenceRecord] = []
        for service in cast(set[str], defaults["services"]):
            if service in {SVC_DKIM, SVC_DKIM_EXCHANGE, SVC_DKIM_GOOGLE}:
                evidence.append(EvidenceRecord("DKIM", "selector response", service, "dkim"))
            elif service == SVC_SPF_STRICT:
                evidence.append(EvidenceRecord("SPF", "v=spf1 -all", service, "spf-strict"))
            elif service == SVC_MTA_STS:
                evidence.append(EvidenceRecord("MTA_STS", "v=STSv1", service, "mta-sts"))
            elif service == SVC_BIMI:
                evidence.append(EvidenceRecord("BIMI", "v=BIMI1", service, "bimi"))
            elif service.startswith("DNS:"):
                evidence.append(EvidenceRecord("NS", "ns.example.net", service, "test-dns"))
            elif service.startswith(("CDN:", "Hosting:", "WAF:", "Google Workspace: ")):
                evidence.append(EvidenceRecord("CNAME", "edge.example.net", service, "test-endpoint"))
        defaults["evidence"] = tuple(evidence)
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
    def test_full_inventory(self):
        # Score line is inventory, not fraction. All five controls
        # should appear in a single "Email security: ..." line when present.
        ctx = _ctx(
            services={"DKIM (Exchange Online)", "SPF: strict (-all)", "MTA-STS", "BIMI"},
            slugs={"microsoft365"},
            dmarc_policy="reject",
        )
        insights = _email_security_insights(ctx)
        score_line = next((i for i in insights if i.startswith("Email security:")), None)
        assert score_line is not None
        for expected in ("DMARC reject", "DKIM", "SPF strict", "MTA-STS", "BIMI"):
            assert expected in score_line, f"expected {expected!r} in {score_line!r}"

    def test_no_email_no_insights(self):
        assert _email_security_insights(_ctx()) == []

    def test_dmarc_none_warns(self):
        ctx = _ctx(slugs={"microsoft365"}, dmarc_policy="none")
        insights = _email_security_insights(ctx)
        assert any("not enforced" in i for i in insights)

    def test_gateway_does_not_substitute_for_observed_dkim(self):
        ctx = _ctx(
            slugs={"microsoft365"},
            dmarc_policy="reject",
            email_gateway="Proofpoint",
        )
        insights = _email_security_insights(ctx)
        score_line = next(i for i in insights if i.startswith("Email security:"))

        assert "DMARC reject" in score_line
        assert "DKIM (inferred" not in score_line
        assert "No DKIM at common selectors observed (other selector names may exist)" in insights

    def test_google_workspace_dkim_is_recognized_as_observed(self):
        ctx = _ctx(
            services={"DKIM (Google Workspace)"},
            slugs={"google-workspace"},
            dmarc_policy="reject",
        )

        insights = _email_security_insights(ctx)

        assert "DKIM" in next(i for i in insights if i.startswith("Email security:"))
        assert not any(i.startswith("No DKIM") for i in insights)

    def test_extensible_email_name_does_not_make_email_scoreable(self):
        ctx = _ctx(
            services={"Synthetic Delta Email"},
            slugs={"delta-email"},
            evidence=(EvidenceRecord("TXT", "delta=token", "Synthetic Delta Email", "delta-email"),),
        )

        assert _email_security_insights(ctx) == []

    def test_extensible_spf_prefix_does_not_claim_spf_policy(self):
        ctx = _ctx(
            services={"SPF: neutral"},
            slugs={"delta-spf"},
            evidence=(EvidenceRecord("TXT", "delta=token", "SPF: neutral", "delta-spf"),),
            has_mx_records=True,
        )

        summary = next(line for line in _email_security_insights(ctx) if line.startswith("Email security:"))
        assert "SPF" not in summary

    def test_dmarc_effective_policy_used_in_score_line(self):
        ctx = _ctx(dmarc_policy="reject", dmarc_effective_policy="quarantine")
        insights = _email_security_insights(ctx)
        score_line = next(i for i in insights if i.startswith("Email security:"))
        assert "DMARC quarantine" in score_line
        assert "DMARC reject" not in score_line


class TestTenantDomainInsights:
    def test_domain_count_is_reported_without_inferring_organization_size(self):
        insights = _tenant_domain_insights(_ctx(domain_count=25))

        assert insights == ["Microsoft tenant discovery returned 25 domains"]
        assert not any("enterprise" in insight.lower() or "organization" in insight.lower() for insight in insights)

    def test_spf_complexity_does_not_infer_organization_size(self):
        insights = _tenant_domain_insights(_ctx(services={"SPF complexity: large (12 includes)"}, domain_count=0))

        assert insights == []

    def test_multiple_tenant_domains_are_reported_exactly(self):
        assert _tenant_domain_insights(_ctx(domain_count=3)) == ["Microsoft tenant discovery returned 3 domains"]

    def test_zero(self):
        assert _tenant_domain_insights(_ctx(domain_count=0)) == []


class TestGatewayInsights:
    def test_mx_backed_gateway_is_reported_as_observed(self):
        insights = _gateway_insights(_ctx(email_gateway="Proofpoint"))

        assert insights == ["MX gateway observed: Proofpoint"]

    def test_generic_vendor_slugs_do_not_establish_email_routing(self):
        ctx = _ctx(slugs={"microsoft365", "proofpoint"})

        assert _gateway_insights(ctx) == []


class TestProviderOverlapInsights:
    def test_google_and_microsoft(self):
        ctx = _ctx(slugs={"google-workspace", "microsoft365"})
        insights = _provider_overlap_insights(ctx)

        assert insights == ["Provider indicators co-observed: Google Workspace, Microsoft 365"]
        assert not any("migration" in insight.lower() or "coexistence" in insight.lower() for insight in insights)

    def test_no_overlap(self):
        assert _provider_overlap_insights(_ctx()) == []


class TestSecurityVendorInsights:
    def test_multiple_tools(self):
        ctx = _ctx(slugs={"crowdstrike", "okta"})
        insights = _security_vendor_insights(ctx)

        assert insights == ["Security-vendor indicators observed: CrowdStrike (endpoint), Okta (identity)"]
        assert any("CrowdStrike" in i and "Okta" in i for i in insights)


class TestDeviceManagementInsights:
    def test_multiple_vendor_indicators_do_not_infer_fleet_composition(self):
        ctx = _ctx(services={"Intune / MDM"}, slugs={"jamf"})
        insights = _device_management_insights(ctx)

        assert insights == ["Device-management vendor indicators observed: Intune, Jamf"]
        assert not any("fleet" in insight.lower() or "windows" in insight.lower() for insight in insights)

    def test_intune_and_kandji(self):
        ctx = _ctx(services={"Intune / MDM"}, slugs={"kandji"})
        assert _device_management_insights(ctx) == ["Device-management vendor indicators observed: Intune, Kandji"]

    def test_jamf_only(self):
        ctx = _ctx(slugs={"jamf"})
        assert _device_management_insights(ctx) == ["Device-management vendor indicator observed: Jamf"]

    def test_kandji_only(self):
        ctx = _ctx(slugs={"kandji"})
        assert _device_management_insights(ctx) == ["Device-management vendor indicator observed: Kandji"]

    def test_intune_only(self):
        ctx = _ctx(services={"Intune / MDM"})
        assert _device_management_insights(ctx) == ["Device-management vendor indicator observed: Intune"]


class TestInfrastructureInsights:
    def test_dns_and_cdn(self):
        ctx = _ctx(services={"DNS: Cloudflare", "CDN: Akamai"})
        insights = _infrastructure_insights(ctx)
        assert any("Cloudflare" in i for i in insights)


class TestSparseSignalInsights:
    def test_edge_heavy_sparse_domain_gets_specific_diagnosis(self):
        ctx = _ctx(services={"DNS: Cloudflare", "CDN: Cloudflare", "DMARC"})
        insights = _sparse_signal_insights(ctx)
        assert any("edge-heavy footprint" in i for i in insights)
        assert any("docs/weak-areas.md" in i for i in insights)
        assert any("recon <domain> --chain --depth 2" in i for i in insights)
        assert not any("DNS-only" in i or "passive DNS" in i for i in insights)

    def test_custom_mail_sparse_domain_gets_unclassified_mx_diagnosis(self):
        ctx = _ctx(
            services={"Custom or unclassified MX", "DMARC"},
            slugs={"self-hosted-mail"},
            has_mx_records=True,
        )
        insights = _sparse_signal_insights(ctx)
        assert any("custom or unclassified MX" in i for i in insights)
        assert not any("self-hosted" in i.lower() or "hybrid" in i.lower() for i in insights)

    def test_minimal_public_dns_domain_gets_minimal_dns_diagnosis(self):
        ctx = _ctx(services={"DMARC"})
        insights = _sparse_signal_insights(ctx)
        assert any("minimal public DNS footprint" in i for i in insights)
        assert not any("small" in i.lower() or "holding" in i.lower() or "portfolio" in i.lower() for i in insights)

    def test_dense_domain_does_not_get_sparse_diagnosis(self):
        ctx = _ctx(
            services={
                "Exchange Online",
                "Slack",
                "Atlassian",
                "Okta",
                "DNS: Cloudflare",
            },
            slugs={"microsoft365", "okta"},
            auth_type="Federated",
        )
        assert _sparse_signal_insights(ctx) == []


class TestGenerateInsightsIntegration:
    def test_combines_all_generators(self):
        insights = generate_insights(
            services={"Intune / MDM", "DKIM (Exchange Online)"},
            slugs={"microsoft365", "proofpoint", "crowdstrike"},
            auth_type="Federated",
            dmarc_policy="reject",
            domain_count=25,
        )
        assert any(insight == "Microsoft tenant discovery returned 25 domains" for insight in insights)
        assert any(insight == "MX gateway observed: Proofpoint" for insight in insights) is False
        assert any("Security-vendor indicators observed:" in insight for insight in insights)
        assert any(insight == "Device-management vendor indicator observed: Intune" for insight in insights)
        assert not any("E3" in insight or "E5" in insight or "license" in insight.lower() for insight in insights)


class TestAuthInsightsWithIdP:
    def test_federated_with_okta_detected(self):
        ctx = _ctx(auth_type="Federated", slugs={"okta"})
        insights = _auth_insights(ctx)

        assert insights == ["Federated identity observed; identity-vendor indicators: Okta"]
        assert not any("likely" in insight.lower() or " via " in insight.lower() for insight in insights)

    def test_federated_with_duo_detected(self):
        ctx = _ctx(auth_type="Federated", slugs={"duo"})
        insights = _auth_insights(ctx)

        assert insights == ["Federated identity observed; identity-vendor indicators: Duo"]

    def test_federated_without_idp_vendor_does_not_guess(self):
        ctx = _ctx(auth_type="Federated")
        insights = _auth_insights(ctx)

        assert insights == ["Federated identity observed; external IdP not identified"]
        assert not any(vendor in insight for insight in insights for vendor in ("ADFS", "Okta", "Ping"))

    def test_federated_with_cisco_identity_does_not_claim_cisco_idp(self):
        # cisco-identity matches any TXT of the form cisco-ci-domain-verification=*.
        # That token is used by many Cisco products (Duo, Customer Identity,
        # Secure Email, Intersight), not specifically the org's SSO IdP.
        # The federated-auth insight must fall back to the generic line, not
        # name Cisco as the likely IdP.
        ctx = _ctx(auth_type="Federated", slugs={"cisco-identity"})
        insights = _auth_insights(ctx)
        assert not any("Cisco" in i for i in insights)
        assert insights == ["Federated identity observed; external IdP not identified"]


class TestGoogleModuleInsights:
    def test_module_names_remain_observed_indicators(self):
        ctx = _ctx(services={"Google Workspace: Drive", "Google Workspace: Groups"})

        insights = _google_modules_insights(ctx)

        assert insights == ["Google Workspace module indicators observed: Drive, Groups"]
        assert not any("active" in insight.lower() or "enabled" in insight.lower() for insight in insights)


class TestNetworkSecurityInsights:
    def test_zscaler_detected(self):
        ctx = _ctx(slugs={"zscaler"})
        insights = _network_security_insights(ctx)
        assert insights == ["Network-security vendor indicator observed: Zscaler"]

    def test_netskope_detected(self):
        ctx = _ctx(slugs={"netskope"})
        insights = _network_security_insights(ctx)
        assert insights == ["Network-security vendor indicator observed: Netskope"]

    def test_multiple_vendor_indicators_do_not_infer_deployment(self):
        ctx = _ctx(slugs={"zscaler", "netskope"})
        insights = _network_security_insights(ctx)

        assert insights == ["Network-security vendor indicators observed: Zscaler, Netskope"]
        assert not any("SASE" in insight or "ZTNA" in insight or "deployment" in insight for insight in insights)

    def test_no_vendor_indicator(self):
        ctx = _ctx(slugs={"crowdstrike"})
        assert _network_security_insights(ctx) == []


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

    def test_globalsign_txt_verification_is_not_a_caa_choice(self):
        assert _pki_insights(_ctx(slugs={"globalsign"})) == []


class TestExpandedSecurityStack:
    def test_sentinelone_in_stack(self):
        ctx = _ctx(slugs={"sentinelone", "okta"})
        insights = _security_vendor_insights(ctx)
        assert any("SentinelOne" in i for i in insights)

    def test_netskope_in_stack(self):
        ctx = _ctx(slugs={"netskope", "crowdstrike"})
        insights = _security_vendor_insights(ctx)
        assert any("Netskope" in i for i in insights)

    def test_1password_in_stack(self):
        ctx = _ctx(slugs={"1password", "okta"})
        insights = _security_vendor_insights(ctx)
        assert any("1Password" in i for i in insights)


class TestExpandedGateway:
    def test_symantec_gateway(self):
        ctx = _ctx(email_gateway="Symantec/Broadcom")
        insights = _gateway_insights(ctx)
        assert any("Symantec" in i for i in insights)

    def test_trellix_gateway(self):
        ctx = _ctx(email_gateway="Trellix (FireEye)")
        insights = _gateway_insights(ctx)
        assert any("Trellix" in i for i in insights)

    def test_cisco_email_gateway(self):
        ctx = _ctx(email_gateway="Cisco Secure Email")
        insights = _gateway_insights(ctx)
        assert any("Cisco Secure Email" in i for i in insights)
