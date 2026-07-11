"""Collection-marker precedence across user-facing tenant surfaces."""

from __future__ import annotations

import io
from dataclasses import replace

import pytest
from rich.console import Console

from recon_tool.bayesian import infer_from_tenant_info
from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
from recon_tool.cli.lookup import _build_explanations
from recon_tool.collection_view import collection_observable_evidence, collection_observable_info
from recon_tool.constants import SVC_BIMI, SVC_DMARC, SVC_MTA_STS, SVC_SPF_STRICT
from recon_tool.email_security import signal_context_from_tenant_info
from recon_tool.explanation import build_explanation_dag
from recon_tool.formatter import format_tenant_dict, format_tenant_markdown, render_tenant_panel
from recon_tool.formatter.classify import provider_line
from recon_tool.insights import generate_insights
from recon_tool.merger import merge_results
from recon_tool.models import ConfidenceLevel, EvidenceRecord, PosteriorObservation, SourceResult, TenantInfo
from recon_tool.posture import analyze_posture
from recon_tool.server.lookup import _format_lookup_tenant
from recon_tool.signals import evaluate_signals


def _info(*, degraded_sources: tuple[str, ...]) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Example",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records",),
        services=(SVC_DMARC, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI, "Proofpoint"),
        slugs=("dmarc", "spf-strict", "mta-sts", "mta-sts-enforce", "bimi", "proofpoint"),
        insights=("Email security: DMARC reject, SPF strict, MTA-STS, BIMI",),
        dmarc_policy="reject",
        mta_sts_mode="enforce",
        email_gateway="Proofpoint",
        evidence=(
            EvidenceRecord(
                source_type="MX",
                raw_value="10 mx1.example.net",
                rule_name="Proofpoint",
                slug="proofpoint",
            ),
        ),
        degraded_sources=degraded_sources,
        slug_confidences=(("dmarc", 3.0), ("proofpoint", 2.0)),
        detection_scores=(("dmarc", "high"), ("proofpoint", "medium")),
    )


def _empty_dns_insights() -> tuple[str, ...]:
    """Return the real generator output for a domain with no email evidence."""
    return tuple(generate_insights(set(), set(), None, None, 0))


_RETIRED_INSIGHTS = (
    "25 domains \N{EM DASH} large enterprise",
    "8 domains \N{EM DASH} mid-size organization",
    "3 domains in tenant",
    "Large org signal: SPF complexity: 12 includes",
    "M365 E3/E5 indicators (Intune + federated auth)",
    "M365 E3+ indicators (Intune enrolled)",
    "Office ProPlus indicators (E3+ or Apps for Enterprise)",
    "Dual MDM: Intune + Jamf (Windows + Mac fleet)",
    "Mac management (Jamf)",
    "Dual provider: Google + Microsoft coexistence",
    "SASE/ZTNA: Zscaler (multi-vendor edge security)",
    "Security stack: CrowdStrike (endpoint)",
    "Email gateway: Proofpoint in front of Exchange",
    "Email delivery path: Proofpoint gateway to Microsoft 365",
    "Federated identity indicators (likely ADFS/Okta/Ping \N{EM DASH} enterprise SSO)",
    "Federated identity indicators observed (likely Okta)",
    "Email security: DMARC reject, DKIM (inferred via Proofpoint)",
    "Google Workspace modules: Drive, Meet",
    "Sparse public signal: consistent with a small organization or holding / portfolio company",
)


@pytest.mark.parametrize("legacy_insight", _RETIRED_INSIGHTS)
def test_removed_legacy_claims_are_hidden_without_mutating_raw_info(legacy_insight: str) -> None:
    raw = replace(
        _info(degraded_sources=()),
        insights=(legacy_insight, "Operational note"),
    )

    visible = collection_observable_info(raw)

    assert visible.insights == ("Operational note",)
    assert raw.insights == (legacy_insight, "Operational note")


def test_current_observational_insights_remain_visible() -> None:
    current = (
        "Microsoft tenant discovery returned 25 domains",
        "Provider indicators co-observed: Google Workspace, Microsoft 365",
        "Network-security vendor indicator observed: Zscaler",
        "MX gateway observed: Proofpoint",
    )
    raw = replace(_info(degraded_sources=()), insights=current)

    assert collection_observable_info(raw).insights == current


def test_same_version_cache_round_trip_preserves_raw_but_reporting_suppresses_legacy_claim() -> None:
    legacy = "M365 E3/E5 indicators (Intune + federated auth)"
    raw = replace(_info(degraded_sources=()), insights=(legacy,))

    cached = tenant_info_from_dict(tenant_info_to_dict(raw))
    visible = collection_observable_info(cached)

    assert cached.insights == (legacy,)
    assert visible.insights == ()
    assert legacy not in format_tenant_dict(cached)["insights"]
    assert legacy not in format_tenant_markdown(cached)
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(cached))
    assert legacy not in output.getvalue()


def test_same_version_legacy_cache_is_suppressed_across_panel_and_mcp_formats() -> None:
    raw = replace(_info(degraded_sources=()), insights=_RETIRED_INSIGHTS)
    cached = tenant_info_from_dict(tenant_info_to_dict(raw))
    panel = io.StringIO()
    Console(file=panel, width=100, force_terminal=False).print(render_tenant_panel(cached))
    surfaces = {
        "panel": panel.getvalue(),
        "mcp-text": _format_lookup_tenant(cached, (), "text", False),
        "mcp-json": _format_lookup_tenant(cached, (), "json", False),
        "mcp-markdown": _format_lookup_tenant(cached, (), "markdown", False),
    }

    assert cached.insights == _RETIRED_INSIGHTS
    for surface, rendered in surfaces.items():
        for legacy in _RETIRED_INSIGHTS:
            assert legacy not in rendered, f"{surface} leaked {legacy!r}"


def test_failed_email_detector_masks_partial_control_assertions() -> None:
    raw = _info(degraded_sources=("detector:email_security",))

    visible = collection_observable_info(raw)

    assert visible.dmarc_policy is None
    assert visible.mta_sts_mode is None
    assert SVC_DMARC not in visible.services
    assert SVC_MTA_STS not in visible.services
    assert SVC_BIMI not in visible.services
    assert visible.insights == ()
    assert visible.degraded_sources == raw.degraded_sources
    assert visible.evidence == raw.evidence


def test_failed_mx_channel_masks_gateway_but_preserves_raw_evidence() -> None:
    raw = _info(degraded_sources=("dns:mx",))

    visible = collection_observable_info(raw)

    assert visible.email_gateway is None
    assert visible.primary_email_provider is None
    assert visible.likely_primary_email_provider is None
    assert "Proofpoint" not in visible.services
    assert "proofpoint" not in visible.slugs
    assert visible.evidence == raw.evidence


@pytest.mark.parametrize("marker", ["dns:mx", "dns:dmarc", "dns:dkim", "dns:apex_txt"])
def test_no_email_absence_requires_every_contributing_channel(marker: str) -> None:
    no_email = next(
        insight for insight in _empty_dns_insights() if insight.startswith("No observable email infrastructure")
    )
    raw = replace(
        _info(degraded_sources=(marker,)),
        insights=(no_email,),
    )

    visible = collection_observable_info(raw)

    assert visible.insights == ()


def test_dmarc_failure_masks_rua_evidence_from_the_same_record_response() -> None:
    rua = EvidenceRecord(
        source_type="DMARC_RUA",
        raw_value="mailto:reports@example.net",
        rule_name="DMARC aggregate reporting",
        slug="dmarc-reporting",
    )
    raw = replace(_info(degraded_sources=("dns:dmarc",)), evidence=(rua,))

    assert collection_observable_evidence(raw) == ()


def test_apex_txt_failure_masks_typed_spf_include_count() -> None:
    raw = replace(_info(degraded_sources=("dns:apex_txt",)), spf_include_count=9)

    assert collection_observable_info(raw).spf_include_count == 0


def test_a_channel_failure_masks_ptr_evidence() -> None:
    ptr = EvidenceRecord(
        source_type="PTR",
        raw_value="edge.example.net",
        rule_name="Example hosting",
        slug="example-hosting",
    )
    raw = replace(
        _info(degraded_sources=("dns:a",)),
        services=("Example hosting",),
        slugs=("example-hosting",),
        evidence=(ptr,),
    )

    visible = collection_observable_info(raw)

    assert collection_observable_evidence(raw) == ()
    assert visible.services == ()
    assert visible.slugs == ()


@pytest.mark.parametrize(
    ("marker", "evidence"),
    [
        (
            "detector:m365_cnames",
            EvidenceRecord(
                source_type="SRV",
                raw_value="100 1 5061 sipfed.online.lync.com",
                rule_name="Microsoft Teams",
                slug="microsoft365",
            ),
        ),
        (
            "detector:idp_hub",
            EvidenceRecord(
                source_type="A",
                raw_value="adfs.example.com",
                rule_name="ADFS SSO hub",
                slug="adfs-sso-hub",
            ),
        ),
        (
            "detector:exchange_endpoints",
            EvidenceRecord(
                source_type="A",
                raw_value="owa.example.com",
                rule_name="Exchange-style endpoint indicator",
                slug="exchange-onprem",
            ),
        ),
    ],
)
def test_detector_failure_masks_partial_contributions_from_every_owned_channel(
    marker: str,
    evidence: EvidenceRecord,
) -> None:
    raw = replace(
        _info(degraded_sources=(marker,)),
        services=(evidence.rule_name,),
        slugs=(evidence.slug,),
        evidence=(evidence,),
    )

    visible = collection_observable_info(raw)

    assert collection_observable_evidence(raw) == ()
    assert visible.services == ()
    assert visible.slugs == ()


@pytest.mark.parametrize(
    ("marker", "insight"),
    [
        ("dns:dmarc", "No DMARC record at apex"),
        ("dns:dkim", "No DKIM at common selectors (custom selectors possible)"),
        ("dns:caa", "PKI: Example CA"),
        ("dns:mx", "MX gateway observed: Example gateway"),
        ("dns:mx", "Email delivery path: Example gateway to Microsoft 365"),
        (
            "dns:mx",
            "Sparse public signal \N{EM DASH} custom or self-hosted mail infrastructure.",
        ),
        (
            "dns:mx",
            "Sparse public signal \N{EM DASH} few observable records beyond MX and identity.",
        ),
        ("dns:apex_txt", "Large org signal: SPF complexity: 12 includes"),
    ],
)
def test_generator_owned_insight_prefixes_require_their_channel(marker: str, insight: str) -> None:
    raw = replace(
        _info(degraded_sources=(marker,)),
        insights=(insight,),
    )

    visible = collection_observable_info(raw)

    assert visible.insights == ()


def test_unavailable_mx_preserves_non_mx_sparse_observation() -> None:
    edge_observation = "Sparse public signal \N{EM DASH} edge-heavy footprint. Cloudflare sits in front of the apex."
    raw = replace(
        _info(degraded_sources=("dns:mx",)),
        insights=(edge_observation,),
    )

    visible = collection_observable_info(raw)

    assert visible.insights == (edge_observation,)


def test_failed_apex_txt_masks_tokens_and_catalog_detections() -> None:
    baseline = _info(degraded_sources=())
    raw = replace(
        _info(degraded_sources=("dns:apex_txt",)),
        services=(*baseline.services, "Microsoft 365"),
        slugs=(*baseline.slugs, "microsoft365"),
        site_verification_tokens=("opaque-token",),
    )

    visible = collection_observable_info(raw)

    assert visible.site_verification_tokens == ()
    assert "Microsoft 365" not in visible.services
    assert "microsoft365" not in visible.slugs


def test_failed_apex_txt_preserves_catalog_detection_corroborated_by_mx() -> None:
    raw = replace(
        _info(degraded_sources=("dns:apex_txt",)),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        primary_email_provider="Microsoft 365",
        evidence=(
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
        ),
    )

    visible = collection_observable_info(raw)

    assert visible.services == ("Microsoft 365",)
    assert visible.slugs == ("microsoft365",)
    assert visible.primary_email_provider == "Microsoft 365"


def test_whole_dns_failure_cannot_cross_corroborate_unavailable_sources() -> None:
    raw = replace(
        _info(degraded_sources=("dns_records",)),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        evidence=(
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="DKIM",
                raw_value="selector1-example-com._domainkey.example.onmicrosoft.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
        ),
    )

    visible = collection_observable_info(raw)

    assert visible.services == ()
    assert visible.slugs == ()


def test_unavailable_channels_cannot_fire_signal_or_posture_rules() -> None:
    raw = _info(degraded_sources=("detector:email_security",))

    signal_names = {match.name for match in evaluate_signals(signal_context_from_tenant_info(raw))}
    observation_sources = {observation.source_name for observation in analyze_posture(raw)}

    assert "Google MTA-STS Enforcing" not in signal_names
    assert not any("Gateway Without DMARC Enforcement" in name for name in signal_names)
    assert "gateway_without_dmarc" not in observation_sources


def test_unavailable_mx_cannot_support_gateway_posterior() -> None:
    raw = _info(degraded_sources=("dns:mx",))

    result = infer_from_tenant_info(raw, priors_override={})
    gateway = next(node for node in result.posteriors if node.name == "email_gateway_present")

    assert "slug:proofpoint" not in gateway.evidence_used


def test_unavailable_dkim_cannot_support_m365_posterior() -> None:
    raw = replace(
        _info(degraded_sources=("detector:dkim",)),
        services=("DKIM (Exchange Online)",),
        slugs=("microsoft365",),
        evidence=(
            EvidenceRecord(
                source_type="DKIM",
                raw_value="selector1._domainkey.example.com",
                rule_name="DKIM (Exchange Online)",
                slug="microsoft365",
            ),
        ),
    )

    result = infer_from_tenant_info(raw, priors_override={})
    m365 = next(node for node in result.posteriors if node.name == "m365_tenant")

    assert "slug:microsoft365" not in m365.evidence_used


def test_structured_and_panel_outputs_use_collection_view() -> None:
    raw = _info(degraded_sources=("detector:email_security",))

    data = format_tenant_dict(raw)
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(raw))
    rendered = output.getvalue()

    assert data["dmarc_policy"] is None
    assert data["mta_sts_mode"] is None
    assert data["email_security_score"] == 0
    assert "DMARC reject" not in rendered
    assert "MTA-STS enforce" not in rendered
    assert "Email security:" not in rendered
    assert "detector:email_security" in data["degraded_sources"]


def test_degraded_mx_outputs_do_not_surface_mx_absence_claims() -> None:
    mx_absence_insights = tuple(
        insight
        for insight in _empty_dns_insights()
        if insight.startswith("No observable email infrastructure") or "minimal public DNS footprint" in insight
    )
    assert len(mx_absence_insights) == 2
    raw = replace(
        _info(degraded_sources=("dns:mx",)),
        insights=mx_absence_insights,
    )

    data = format_tenant_dict(raw)
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(raw))
    rendered = output.getvalue()

    assert all(insight not in data["insights"] for insight in mx_absence_insights)
    assert "No observable email infrastructure" not in rendered
    assert "minimal public DNS footprint" not in rendered


def test_degraded_mx_cannot_qualify_txt_account_from_preserved_raw_evidence() -> None:
    raw = replace(
        _info(degraded_sources=("dns:mx",)),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="MS=ms12345678",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
        ),
    )

    visible = collection_observable_info(raw)
    data = format_tenant_dict(raw)
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(raw))
    rendered = output.getvalue()

    assert provider_line(visible) == "Microsoft 365 (account indicator; MX collection unavailable)"
    assert data["provider"] == "Microsoft 365 (account indicator; MX collection unavailable)"
    assert len(data["evidence"]) == 2
    assert "Provider     Microsoft 365 (account indicator; MX collection" in rendered
    assert "custom MX" not in rendered
    assert "no MX" not in rendered


def test_degraded_dkim_cannot_promote_txt_account_to_provider_secondary() -> None:
    raw = replace(
        _info(degraded_sources=("detector:dkim",)),
        services=("Microsoft 365", "Google Workspace"),
        slugs=("microsoft365", "google-workspace"),
        primary_email_provider="Microsoft 365",
        email_gateway=None,
        evidence=(
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="TXT",
                raw_value="google-site-verification=opaque",
                rule_name="Google Workspace",
                slug="google-workspace",
            ),
            EvidenceRecord(
                source_type="DKIM",
                raw_value="google._domainkey.example.com",
                rule_name="Google Workspace",
                slug="google-workspace",
            ),
        ),
    )

    visible = collection_observable_info(raw)
    data = format_tenant_dict(raw)
    output = io.StringIO()
    Console(file=output, width=100, force_terminal=False).print(render_tenant_panel(raw))
    rendered = output.getvalue()

    assert provider_line(visible) == "Microsoft 365 (MX delivery path)"
    assert data["provider"] == "Microsoft 365 (MX delivery path)"
    assert len(data["evidence"]) == 3
    assert "Provider     Microsoft 365 (MX delivery path)" in rendered
    assert "Google Workspace (secondary)" not in rendered


def test_explanation_summary_uses_available_evidence_and_preserves_raw_provenance() -> None:
    raw = replace(
        _info(degraded_sources=("dns:mx", "detector:dkim")),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        insights=("Observed provider: microsoft365",),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="MS=ms12345678",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="DKIM",
                raw_value="selector1._domainkey.example.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
        ),
    )

    explanations = _build_explanations(raw, [])
    record = next(item for item in explanations if item.item_name == "Observed provider: microsoft365")
    data = format_tenant_dict(raw)

    assert [evidence.source_type for evidence in collection_observable_evidence(raw)] == ["TXT"]
    assert [evidence.source_type for evidence in record.matched_evidence] == ["TXT"]
    assert [evidence["source_type"] for evidence in data["evidence"]] == ["TXT", "MX", "DKIM"]


def test_apex_txt_failure_removes_only_txt_support_from_a_corroborated_claim() -> None:
    raw = replace(
        _info(degraded_sources=("dns:apex_txt",)),
        services=("Microsoft 365",),
        slugs=("microsoft365",),
        insights=("Observed provider: microsoft365",),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="MS=ms12345678",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="MX",
                raw_value="10 example-com.mail.protection.outlook.com",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
        ),
    )

    visible = collection_observable_info(raw)
    explanations = _build_explanations(raw, [])
    record = next(item for item in explanations if item.item_name == "Observed provider: microsoft365")

    assert visible.services == ("Microsoft 365",)
    assert visible.slugs == ("microsoft365",)
    assert [evidence.source_type for evidence in collection_observable_evidence(raw)] == ["MX"]
    assert [evidence.source_type for evidence in record.matched_evidence] == ["MX"]
    assert [evidence["source_type"] for evidence in format_tenant_dict(raw)["evidence"]] == ["TXT", "MX"]


def test_dmarc_failure_cannot_seed_an_unavailable_evidence_node() -> None:
    raw = replace(
        _info(degraded_sources=("dns:dmarc",)),
        services=(SVC_DMARC,),
        slugs=("dmarc",),
        insights=("DMARC: reject",),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="v=DMARC1; p=reject",
                rule_name=SVC_DMARC,
                slug="dmarc",
            ),
        ),
    )

    observable_evidence = collection_observable_evidence(raw)
    dag = build_explanation_dag(_build_explanations(raw, []), observable_evidence)

    assert observable_evidence == ()
    assert not any(node["type"] == "evidence" for node in dag["nodes"])


@pytest.mark.parametrize(
    ("marker", "service", "slug"),
    [
        ("dns:mx", "Proofpoint", "proofpoint"),
        ("dns:dkim", "DKIM (Exchange Online)", "microsoft365"),
        ("dns:caa", "Let's Encrypt", "letsencrypt"),
    ],
)
def test_legacy_role_value_without_lineage_is_masked_when_its_channel_failed(
    marker: str,
    service: str,
    slug: str,
) -> None:
    visible = collection_observable_info(
        replace(
            _info(degraded_sources=(marker,)),
            services=(service,),
            slugs=(slug,),
            evidence=(),
        )
    )

    assert visible.services == ()
    assert visible.slugs == ()


def test_masked_signal_insight_and_cached_posterior_cannot_survive_without_units() -> None:
    raw = replace(
        _info(degraded_sources=("dns:apex_txt",)),
        services=("CrowdStrike Falcon", "Okta"),
        slugs=("crowdstrike", "okta"),
        insights=("Enterprise Security Stack: CrowdStrike, Okta",),
        evidence=(
            EvidenceRecord("TXT", "crowdstrike-token", "CrowdStrike Falcon", "crowdstrike"),
            EvidenceRecord("TXT", "okta-token", "Okta", "okta"),
        ),
        slug_confidences=(("crowdstrike", 0.99),),
        posterior_observations=(
            PosteriorObservation(
                name="security_stack",
                description="fixture",
                posterior=0.99,
                interval_low=0.9,
                interval_high=1.0,
                evidence_used=("slug:crowdstrike",),
                n_eff=8.0,
                sparse=False,
            ),
        ),
    )

    visible = collection_observable_info(raw)

    assert visible.slugs == ()
    assert visible.insights == ()
    assert visible.slug_confidences == ()
    assert visible.posterior_observations == ()


def test_unavailable_source_evidence_cannot_raise_or_explain_inference_confidence() -> None:
    stale = EvidenceRecord("TXT", "MS=stale", "Microsoft 365", "microsoft365")
    result = SourceResult(
        source_name="dns_records",
        detected_services=("Microsoft 365",),
        detected_slugs=("microsoft365",),
        evidence=(stale,),
        degraded_sources=("dns:apex_txt",),
    )

    info = merge_results([result], "example.com")
    confidence = next(record for record in _build_explanations(info, [result]) if record.item_type == "confidence")

    assert info.inference_confidence == ConfidenceLevel.LOW
    assert collection_observable_info(info).slugs == ()
    assert confidence.matched_evidence == ()
