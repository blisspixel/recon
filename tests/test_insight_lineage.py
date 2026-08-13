"""Exact generation-time lineage for the bounded insight generators."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
from recon_tool.collection_view import (
    collection_observable_evidence,
    collection_observable_info,
    collection_observable_result,
)
from recon_tool.explanation import explain_insights
from recon_tool.insight_explanation import InsightExplanationContext
from recon_tool.insight_scopes import (
    INSIGHT_OBSERVATION_SCOPES,
    observation_scopes_available,
    unavailable_observation_scopes,
)
from recon_tool.insights import _INSIGHT_GENERATORS, InsightContext, generate_insight_claims, generate_insights
from recon_tool.merger import merge_results
from recon_tool.models import ConfidenceLevel, EvidenceRecord, InsightClaim, SourceResult, TenantInfo


def _info(**overrides: object) -> TenantInfo:
    values: dict[str, object] = {
        "tenant_id": None,
        "display_name": "example.test",
        "default_domain": "example.test",
        "queried_domain": "example.test",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    values.update(overrides)
    return TenantInfo(**values)  # type: ignore[arg-type]


def _claims(*args: Any, **kwargs: Any) -> list[InsightClaim]:
    """Build the immutable generator context used by the lineage API."""
    return generate_insight_claims(InsightContext.from_sets(*args, **kwargs))


def test_public_string_projection_is_derived_from_exact_claims() -> None:
    kwargs = {
        "services": {"DKIM"},
        "slugs": {"microsoft365", "okta"},
        "auth_type": "Federated",
        "dmarc_policy": "reject",
        "domain_count": 3,
        "evidence": (
            EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365"),
            EvidenceRecord("TXT", "okta-domain-verification=x", "Okta", "okta"),
            EvidenceRecord("DKIM", "selector response", "DKIM", "dkim"),
            EvidenceRecord("DMARC", "v=DMARC1; p=reject", "DMARC", "dmarc"),
        ),
    }

    claims = _claims(**kwargs)

    assert generate_insights(**kwargs) == [claim.text for claim in claims]
    assert all(claim.generator_rule_id.startswith("_") for claim in claims)
    assert all(claim.supporting_evidence or claim.observation_scope for claim in claims)
    assert all(not claim.evidence_required or claim.supporting_evidence for claim in claims)


def test_every_registered_generator_emits_at_least_one_attributed_claim() -> None:
    scenarios = (
        {
            "services": set(),
            "slugs": {"microsoft365", "okta"},
            "auth_type": "Federated",
            "dmarc_policy": None,
            "domain_count": 2,
            "cloud_instance": "microsoftonline.us",
            "google_auth_type": None,
            "google_idp_name": None,
            "email_gateway": "Proofpoint",
            "evidence": (
                EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365"),
                EvidenceRecord("HTTP", "tenant_domain_count=2", "Autodiscover", "microsoft365"),
                EvidenceRecord(
                    "HTTP",
                    "cloud_instance_name=microsoftonline.us",
                    "OIDC Discovery metadata",
                    "microsoft365",
                ),
                EvidenceRecord("TXT", "okta-domain-verification=x", "Okta", "okta"),
                EvidenceRecord("MX", "10 mx.proofpoint.com", "Proofpoint", "proofpoint"),
            ),
        },
        {
            "services": {"Intune / MDM", "Google Workspace: Drive", "CDN: Fastly"},
            "slugs": {
                "google-federated",
                "google-workspace",
                "microsoft365",
                "crowdstrike",
                "zscaler",
                "jamf",
                "letsencrypt",
            },
            "auth_type": None,
            "dmarc_policy": "reject",
            "domain_count": 0,
            "google_auth_type": "Federated",
            "google_idp_name": "Okta",
            "evidence": (
                EvidenceRecord("HTTP", "Federated redirect to Okta", "Google Identity Routing", "google-federated"),
                EvidenceRecord("MX", "aspmx.l.google.com", "Google Workspace", "google-workspace"),
                EvidenceRecord("HTTP", "tenant_id=x", "OIDC Discovery", "microsoft365"),
                EvidenceRecord("TXT", "crowdstrike=x", "CrowdStrike", "crowdstrike"),
                EvidenceRecord("TXT", "zscaler=x", "Zscaler", "zscaler"),
                EvidenceRecord("TXT", "jamf=x", "Jamf", "jamf"),
                EvidenceRecord("TXT", "intune=x", "Intune / MDM", "intune"),
                EvidenceRecord("CAA", "0 issue letsencrypt.org", "Let's Encrypt", "letsencrypt"),
                EvidenceRecord("CNAME", "drive.googlehosted.com", "Google Workspace: Drive", "gws-drive"),
                EvidenceRecord("CNAME", "edge.fastly.net", "CDN: Fastly", "fastly"),
                EvidenceRecord("DMARC", "v=DMARC1; p=reject", "DMARC", "dmarc"),
            ),
        },
        {
            "services": set(),
            "slugs": set(),
            "auth_type": None,
            "dmarc_policy": None,
            "domain_count": 0,
        },
        {
            "services": set(),
            "slugs": {"null-mx"},
            "auth_type": None,
            "dmarc_policy": None,
            "domain_count": 0,
            "has_mx_records": True,
            "evidence": (EvidenceRecord("MX", "0 .", "Null MX", "null-mx"),),
        },
    )

    claims = [claim for scenario in scenarios for claim in _claims(**scenario)]

    assert {claim.generator_rule_id for claim in claims} == {generator.__name__ for generator in _INSIGHT_GENERATORS}
    assert all(claim.supporting_evidence or claim.observation_scope for claim in claims)
    assert all(not claim.evidence_required or claim.supporting_evidence for claim in claims)


def test_auth_lineage_selects_only_evidence_consumed_by_the_generator() -> None:
    auth_evidence = EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365")
    okta_evidence = EvidenceRecord("TXT", "okta-domain-verification=x", "Okta", "okta")
    unrelated = EvidenceRecord("TXT", "unrelated=x", "Unrelated", "other")

    claims = _claims(
        set(),
        {"microsoft365", "okta", "other"},
        "Federated",
        None,
        0,
        evidence=(auth_evidence, okta_evidence, unrelated),
    )

    claim = next(item for item in claims if item.generator_rule_id == "_auth_insights")
    assert claim.supporting_evidence == (auth_evidence, okta_evidence)
    assert claim.observation_scope == ("identity:user_realm",)


def test_managed_auth_lineage_excludes_unread_vendor_evidence() -> None:
    realm = EvidenceRecord("HTTP", "NameSpaceType=Managed", "GetUserRealm", "microsoft365")
    mx = EvidenceRecord("MX", "10 example.mail.protection.outlook.com", "Microsoft 365", "microsoft365")
    okta = EvidenceRecord("TXT", "okta-domain-verification=x", "Okta", "okta")

    claims = _claims(
        set(),
        {"microsoft365", "okta"},
        "Managed",
        None,
        0,
        evidence=(realm, mx, okta),
    )

    claim = next(item for item in claims if item.generator_rule_id == "_auth_insights")
    assert claim.supporting_evidence == (realm, mx)
    assert okta not in claim.supporting_evidence


def test_positive_catalog_claim_abstains_without_matching_evidence() -> None:
    unrelated = EvidenceRecord("A", "192.0.2.1", "Apex address", "apex-address")

    claims = _claims(
        set(),
        {"crowdstrike"},
        None,
        None,
        0,
        evidence=(unrelated,),
    )

    assert not any(item.generator_rule_id == "_security_vendor_insights" for item in claims)


def test_absence_shaped_insights_carry_bounded_observation_scope() -> None:
    claims = _claims(set(), set(), None, None, 0)

    no_email = next(item for item in claims if item.generator_rule_id == "_no_email_infrastructure_insights")
    assert no_email.supporting_evidence == ()
    assert no_email.observation_scope == (
        "dns:mx",
        "dns:apex_txt",
        "dns:dmarc",
        "dns:dkim_common_selectors",
    )


def test_exact_claim_bypasses_legacy_text_reconstruction_in_explanations() -> None:
    metadata = EvidenceRecord(
        "HTTP",
        "cloud_instance_name=microsoftonline.us",
        "OIDC Discovery metadata",
        "microsoft365",
    )
    claims = _claims(
        set(),
        {"microsoft365"},
        None,
        None,
        0,
        cloud_instance="microsoftonline.us",
        evidence=(metadata,),
    )
    sovereignty = next(item for item in claims if item.generator_rule_id == "_sovereignty_insights")

    record = explain_insights(
        [sovereignty.text],
        frozenset({"microsoft365"}),
        frozenset(),
        (metadata,),
        InsightExplanationContext((), (sovereignty,)),
    )[0]

    assert record.fired_rules == ("_sovereignty_insights",)
    assert record.matched_evidence == (metadata,)
    assert record.confidence_derivation.startswith("Exact generation-time association")
    assert "not reconstructed" not in record.confidence_derivation


def test_sovereignty_lineage_renders_only_observed_metadata_fields() -> None:
    metadata = EvidenceRecord(
        "HTTP",
        "msgraph_host=graph.microsoft.us",
        "OIDC Discovery metadata",
        "microsoft365",
    )

    claim = next(
        item
        for item in _claims(
            set(),
            {"microsoft365"},
            None,
            None,
            0,
            msgraph_host="graph.microsoft.us",
            evidence=(metadata,),
        )
        if item.generator_rule_id == "_sovereignty_insights"
    )

    assert "observed msgraph_host=graph.microsoft.us" in claim.text
    assert "cloud_instance" not in claim.text
    assert claim.supporting_evidence == (metadata,)


def test_degraded_oidc_projection_removes_metadata_evidence_and_claims() -> None:
    metadata = (
        EvidenceRecord(
            "HTTP",
            "cloud_instance_name=microsoftonline.us",
            "OIDC Discovery metadata",
            "microsoft365",
        ),
        EvidenceRecord(
            "HTTP",
            "tenant_region_sub_scope=GCCH",
            "OIDC Discovery metadata",
            "microsoft365",
        ),
        EvidenceRecord(
            "HTTP",
            "msgraph_host=graph.microsoft.us",
            "OIDC Discovery metadata",
            "microsoft365",
        ),
    )
    claim = next(
        item
        for item in _claims(
            set(),
            {"microsoft365"},
            None,
            None,
            0,
            cloud_instance="microsoftonline.us",
            tenant_region_sub_scope="GCCH",
            msgraph_host="graph.microsoft.us",
            evidence=metadata,
        )
        if item.generator_rule_id == "_sovereignty_insights"
    )
    info = _info(
        slugs=("microsoft365",),
        evidence=metadata,
        region="US",
        cloud_instance="microsoftonline.us",
        tenant_region_sub_scope="GCCH",
        msgraph_host="graph.microsoft.us",
        insights=(claim.text,),
        insight_claims=(claim,),
        degraded_sources=("source:oidc_discovery",),
    )

    projected = collection_observable_info(info)

    assert collection_observable_evidence(info) == ()
    assert projected.region is None
    assert projected.cloud_instance is None
    assert projected.tenant_region_sub_scope is None
    assert projected.msgraph_host is None
    assert claim.text not in projected.insights
    assert not any(item.generator_rule_id == "_sovereignty_insights" for item in projected.insight_claims)


@pytest.mark.parametrize("marker", ["identity:autodiscover", "source:user_realm", "user_realm"])
def test_degraded_autodiscover_projection_removes_domain_evidence(marker: str) -> None:
    evidence = EvidenceRecord("HTTP", "tenant_domain_count=2", "Autodiscover", "microsoft365")
    result = SourceResult(
        source_name="user_realm",
        tenant_domains=("example.test", "example.onmicrosoft.com"),
        detected_services=("Microsoft 365",),
        detected_slugs=("microsoft365",),
        evidence=(evidence,),
        degraded_sources=(marker,),
    )

    projected = collection_observable_result(result)

    assert projected.tenant_domains == ()
    assert evidence not in projected.evidence


def test_degraded_oidc_source_result_masks_every_metadata_scalar() -> None:
    evidence = EvidenceRecord(
        "HTTP",
        "cloud_instance_name=microsoftonline.us",
        "OIDC Discovery metadata",
        "microsoft365",
    )
    result = SourceResult(
        source_name="oidc_discovery",
        tenant_id="00000000-0000-0000-0000-000000000001",
        region="US",
        cloud_instance="microsoftonline.us",
        tenant_region_sub_scope="GCCH",
        msgraph_host="graph.microsoft.us",
        detected_services=("Microsoft 365",),
        detected_slugs=("microsoft365",),
        evidence=(evidence,),
        degraded_sources=("source:oidc_discovery",),
    )

    projected = collection_observable_result(result)

    assert projected.tenant_id is None
    assert projected.region is None
    assert projected.cloud_instance is None
    assert projected.tenant_region_sub_scope is None
    assert projected.msgraph_host is None
    assert evidence not in projected.evidence


_SCOPE_DEGRADATION_CASES = (
    ("dns:mx", "dns:mx"),
    ("dns:apex_txt", "dns:apex_txt"),
    ("dns:cname", "dns:cname"),
    ("dns:dmarc", "dns:dmarc"),
    ("dns:dkim_common_selectors", "dns:dkim"),
    ("http:mta_sts_policy", "http:mta_sts_policy"),
    ("dns:bimi", "dns:bimi"),
    ("dns:caa", "dns:caa"),
    ("dns:catalog", "dns:subdomain_txt"),
    ("public_metadata:service_catalog", "dns:ns"),
    ("dns:bounded_service_records", "dns:a"),
    ("identity:user_realm", "identity:user_realm"),
    ("identity:autodiscover", "identity:autodiscover"),
    ("identity:oidc_discovery", "source:oidc_discovery"),
    ("identity:google_routing", "source:google_identity"),
    ("public_metadata:bounded_collection", "source:google_workspace"),
)


@pytest.mark.parametrize(("scope", "marker"), _SCOPE_DEGRADATION_CASES)
def test_every_observation_scope_has_fail_closed_availability_semantics(scope: str, marker: str) -> None:
    assert unavailable_observation_scopes((scope,), (marker,)) == (scope,)
    assert not observation_scopes_available((scope,), (marker,))


def test_scope_degradation_cases_cover_the_complete_vocabulary() -> None:
    assert {scope for scope, _marker in _SCOPE_DEGRADATION_CASES} == INSIGHT_OBSERVATION_SCOPES
    assert unavailable_observation_scopes(("unknown:scope",), ()) == ("unknown:scope",)


@pytest.mark.parametrize("marker", ["dns:apex_txt", "dns:cname"])
def test_generic_federated_absence_claim_requires_every_declared_scope(marker: str) -> None:
    evidence = EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365")
    claim = next(
        item
        for item in _claims(set(), {"microsoft365"}, "Federated", None, 0, evidence=(evidence,))
        if item.generator_rule_id == "_auth_insights"
    )
    info = _info(
        auth_type="Federated",
        slugs=("microsoft365",),
        evidence=(evidence,),
        insights=(claim.text,),
        insight_claims=(claim,),
        degraded_sources=(marker,),
    )

    projected = collection_observable_info(info)

    assert claim.text not in projected.insights
    assert claim not in projected.insight_claims


def test_sparse_claim_requires_a_complete_bounded_collection() -> None:
    claims = tuple(_claims(set(), set(), None, None, 0))
    info = _info(
        insights=tuple(claim.text for claim in claims),
        insight_claims=claims,
        degraded_sources=("crt.sh",),
    )

    projected = collection_observable_info(info)

    assert not any(
        "public_metadata:bounded_collection" in claim.observation_scope for claim in projected.insight_claims
    )


def test_cache_round_trip_preserves_exact_insight_claims() -> None:
    evidence = EvidenceRecord("MX", "10 mx.proofpoint.com", "Proofpoint", "proofpoint")
    claim = next(
        item
        for item in _claims(
            set(),
            {"proofpoint"},
            None,
            None,
            0,
            email_gateway="Proofpoint",
            has_mx_records=True,
            evidence=(evidence,),
        )
        if item.generator_rule_id == "_gateway_insights"
    )
    info = _info(
        insights=(claim.text,),
        insight_claims=(claim,),
        evidence=(evidence,),
        email_gateway="Proofpoint",
    )

    restored = tenant_info_from_dict(tenant_info_to_dict(info))

    assert replace(restored.insight_claims[0], supporting_evidence=()) == replace(
        claim,
        supporting_evidence=(),
    )
    assert restored.insight_claims[0].supporting_evidence == (evidence,)


def test_cache_round_trip_preserves_claim_evidence_without_catalog_slug() -> None:
    evidence = EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "")
    claim = InsightClaim(
        text="Federated identity observed",
        generator_rule_id="_auth_insights",
        supporting_evidence=(evidence,),
    )
    info = _info(
        insights=(claim.text,),
        insight_claims=(claim,),
        evidence=(evidence,),
    )

    restored = tenant_info_from_dict(tenant_info_to_dict(info))

    assert restored.insight_claims == (claim,)


def test_gateway_claim_attaches_only_gateway_mx_evidence() -> None:
    gateway = EvidenceRecord("MX", "10 mx.proofpoint.invalid", "Proofpoint", "proofpoint")
    provider = EvidenceRecord(
        "MX",
        "20 aspmx.l.google.invalid",
        "Google Workspace",
        "google-workspace",
    )

    claim = next(
        item
        for item in _claims(
            set(),
            {"proofpoint", "google-workspace"},
            None,
            None,
            0,
            email_gateway="Proofpoint",
            primary_email_provider="Google Workspace",
            has_mx_records=True,
            evidence=(gateway, provider),
        )
        if item.generator_rule_id == "_gateway_insights"
    )

    assert claim.supporting_evidence == (gateway,)


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("unknown_rule", "unknown generator rule"),
        ("absent_insight", "references an absent insight"),
        ("foreign_evidence", "references evidence absent"),
        ("unknown_scope", "unknown observation scopes"),
        ("positive_scope_only", "requires supporting evidence"),
        ("unsupported_claim", "has no evidence or bounded observation scope"),
    ],
)
def test_cache_rejects_corrupt_or_unbound_insight_lineage(corruption: str, message: str) -> None:
    evidence = EvidenceRecord("TXT", "crowdstrike=x", "CrowdStrike", "crowdstrike")
    claim = next(
        item
        for item in _claims(
            set(),
            {"crowdstrike"},
            None,
            None,
            0,
            evidence=(evidence,),
        )
        if item.generator_rule_id == "_security_vendor_insights"
    )
    payload = tenant_info_to_dict(
        _info(
            insights=(claim.text,),
            insight_claims=(claim,),
            evidence=(evidence,),
        )
    )
    corrupted = deepcopy(payload)
    cached_claim = corrupted["insight_claims"][0]
    if corruption == "unknown_rule":
        cached_claim["generator_rule_id"] = "_invented_insights"
    elif corruption == "absent_insight":
        cached_claim["text"] = "A string not present in insights"
    elif corruption == "foreign_evidence":
        cached_claim["supporting_evidence"][0]["raw_value"] = "10 unrelated.invalid"
    elif corruption == "unknown_scope":
        cached_claim["observation_scope"] = ["unknown:scope"]
    elif corruption == "positive_scope_only":
        cached_claim["supporting_evidence"] = []
    else:
        cached_claim["supporting_evidence"] = []
        cached_claim["observation_scope"] = []
        cached_claim["evidence_required"] = False

    with pytest.raises(ValueError, match=message):
        tenant_info_from_dict(corrupted)


def test_merge_attaches_claims_and_collection_projection_preserves_them() -> None:
    auth_evidence = EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365")
    info = merge_results(
        [
            SourceResult(
                source_name="user_realm",
                display_name="Example",
                default_domain="example.test",
                auth_type="Federated",
                detected_slugs=("microsoft365",),
                evidence=(auth_evidence,),
            )
        ],
        queried_domain="example.test",
    )

    projected = collection_observable_info(info)
    claim = next(item for item in projected.insight_claims if item.generator_rule_id == "_auth_insights")
    assert claim.text in projected.insights
    assert claim.supporting_evidence == (auth_evidence,)


def test_degraded_projection_regenerates_claims_only_from_observable_evidence() -> None:
    mx_evidence = EvidenceRecord("MX", "10 mx.proofpoint.com", "Proofpoint", "proofpoint")
    claim = _claims(
        set(),
        {"proofpoint"},
        None,
        None,
        0,
        email_gateway="Proofpoint",
        has_mx_records=True,
        evidence=(mx_evidence,),
    )[0]
    info = _info(
        services=("Proofpoint",),
        slugs=("proofpoint",),
        insights=(claim.text,),
        insight_claims=(claim,),
        evidence=(mx_evidence,),
        email_gateway="Proofpoint",
        degraded_sources=("dns:mx",),
    )

    projected = collection_observable_info(info)

    assert claim.text not in projected.insights
    assert all(item.text in projected.insights for item in projected.insight_claims)
    assert all(mx_evidence not in item.supporting_evidence for item in projected.insight_claims)
