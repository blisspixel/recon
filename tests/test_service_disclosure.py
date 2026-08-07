"""Service disclosure stays additive across stable human-output modes."""

from __future__ import annotations

import io
from dataclasses import replace

import pytest
from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.classify import categorize_services, role_aware_service_label
from recon_tool.models import EvidenceRecord, TenantInfo


def _render(
    info: TenantInfo,
    *,
    show_services: bool = False,
    show_domains: bool = False,
    verbose: bool = False,
) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, no_color=True, width=120)
    console.print(
        render_tenant_panel(
            info,
            show_services=show_services,
            show_domains=show_domains,
            verbose=verbose,
        )
    )
    return buffer.getvalue()


def _with_secondary_mail_service(info: TenantInfo) -> TenantInfo:
    return replace(
        info,
        services=(*info.services, "SendGrid"),
        slugs=(*info.slugs, "sendgrid"),
        evidence=(
            *info.evidence,
            EvidenceRecord(
                source_type="CNAME",
                raw_value="email.alpha.invalid -> u123.wl.sendgrid.net",
                rule_name="SendGrid",
                slug="sendgrid",
            ),
        ),
    )


def _services_block(output: str) -> str:
    return output.split("Services\n", 1)[1].split("\n\n", 1)[0]


@pytest.mark.parametrize(
    ("source_type", "expected_role"),
    [
        ("MX", "MX delivery path"),
        ("CNAME", "CNAME endpoint binding"),
        ("CNAME_TARGET", "CNAME endpoint binding"),
        ("SPF", "SPF sender authorization"),
        ("DMARC_RUA", "DMARC aggregate-report destination"),
        ("SRV", "SRV service-discovery reference"),
        ("NS", "authoritative DNS delegation"),
    ],
)
def test_catalog_service_label_states_retained_evidence_role(
    source_type: str,
    expected_role: str,
) -> None:
    evidence = (EvidenceRecord(source_type, "public-record", "Synthetic Service", "synthetic-service"),)

    assert role_aware_service_label("Synthetic Service", evidence) == f"Synthetic Service ({expected_role})"


def test_catalog_service_without_matching_lineage_states_role_unavailable() -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        services=("Synthetic Service",),
    )

    assert role_aware_service_label("Synthetic Service", ()) == "Synthetic Service (role unavailable)"
    assert categorize_services(info) == {"Business Apps": ["Synthetic Service (role unavailable)"]}


def test_explicit_email_control_label_does_not_require_catalog_lineage() -> None:
    assert role_aware_service_label("DMARC", ()) == "DMARC"
    assert role_aware_service_label("DMARC", (EvidenceRecord("DMARC", "v=DMARC1; p=reject", "DMARC", "dmarc"),)) == (
        "DMARC"
    )


def test_catalog_name_that_begins_with_control_name_still_requires_lineage() -> None:
    evidence = (EvidenceRecord("DMARC_RUA", "mailto:reports@vendor.invalid", "DMARC Digests", "dmarc-digests"),)

    assert role_aware_service_label("DMARC Digests", evidence) == ("DMARC Digests (DMARC aggregate-report destination)")
    assert role_aware_service_label("DMARC Digests", ()) == "DMARC Digests (role unavailable)"


def test_catalog_role_follows_record_type_not_incompatible_slug_identity() -> None:
    route53 = TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        services=("AWS Route 53",),
        slugs=("aws-route53",),
        evidence=(EvidenceRecord("CNAME", "app.alpha.invalid -> target.invalid", "AWS Route 53", "aws-route53"),),
    )

    assert categorize_services(route53) == {"Cloud": ["AWS Route 53 (CNAME endpoint binding)"]}
    assert (
        role_aware_service_label(
            "Null MX (domain does not accept email)",
            (EvidenceRecord("TXT", "unrelated", "Null MX (domain does not accept email)", "null-mx"),),
        )
        == "Unclassified observation (role unavailable)"
    )
    assert (
        role_aware_service_label(
            "Synthetic Null-MX label",
            (EvidenceRecord("TXT", "unrelated", "Synthetic Null-MX label", "null-mx"),),
        )
        == "Unclassified observation (role unavailable)"
    )


@pytest.mark.parametrize(
    ("service", "source_type"),
    [
        ("BIMI", "MX"),
        ("MTA-STS", "SPF"),
        ("TLS-RPT", "CNAME"),
        ("Exchange-style endpoint indicator", "TXT"),
    ],
)
def test_intrinsic_observation_with_incompatible_evidence_fails_closed(
    service: str,
    source_type: str,
) -> None:
    evidence = (EvidenceRecord(source_type, "incompatible", service, "synthetic"),)

    assert role_aware_service_label(service, evidence) == "Unclassified observation (role unavailable)"


@pytest.mark.parametrize(
    ("service", "slug"),
    [
        ("Null MX (domain does not accept email)", "null-mx"),
        ("Exchange-style endpoint indicator", "exchange-onprem"),
    ],
)
def test_special_slug_with_incompatible_caa_evidence_fails_closed(
    service: str,
    slug: str,
) -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
        services=(service,),
        slugs=(slug,),
        evidence=(EvidenceRecord("CAA", "0 issue ca.invalid", service, slug),),
    )

    categorized = categorize_services(info)

    assert categorized["Email"] == ["Unclassified observation (role unavailable)"]
    assert not any("CAA:" in item for items in categorized.values() for item in items)


def test_services_flag_remains_backward_compatible(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = _with_secondary_mail_service(fully_populated_tenant_info)

    assert _render(info, show_services=True) == _render(info)


def test_detail_modes_retain_compact_and_secondary_email_facts(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = _with_secondary_mail_service(fully_populated_tenant_info)
    # Every mode keeps the same email facts in the same order; the detail modes
    # additionally keep the record role inline (ADR-0012).
    qualified = (
        "Email Microsoft 365 (MX delivery path), Proofpoint (MX delivery path), "
        "DMARC reject, MTA-STS enforce, SendGrid (CNAME endpoint binding)"
    )
    compact = "Email Microsoft 365, Proofpoint, DMARC reject, MTA-STS enforce, SendGrid"
    cases = (
        (_render(info), compact),
        (_render(info, verbose=True), qualified),
        (_render(info, show_services=True, show_domains=True, verbose=True), qualified),
    )

    for output, expected_email in cases:
        collapsed = " ".join(_services_block(output).split())
        assert expected_email in collapsed
        for fact in ("Microsoft 365", "Proofpoint", "DMARC reject", "MTA-STS enforce", "SendGrid"):
            assert collapsed.count(fact) == 1


def test_full_panel_adds_verbose_and_domain_sections(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    output = _render(
        _with_secondary_mail_service(fully_populated_tenant_info),
        show_services=True,
        show_domains=True,
        verbose=True,
    )

    assert "Domains (3)" in output
    assert "Certs" in output
    assert "Evidence Detail" in output


def test_gateway_does_not_promote_or_duplicate_txt_only_downstream(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = replace(
        fully_populated_tenant_info,
        services=("Proofpoint", "Microsoft 365"),
        slugs=("proofpoint", "microsoft365"),
        evidence=(
            EvidenceRecord("MX", "mx1.proofpoint.example", "Proofpoint", "proofpoint"),
            EvidenceRecord("TXT", "MS=ms12345", "Microsoft 365", "microsoft365"),
        ),
        primary_email_provider=None,
        email_gateway="Proofpoint",
        likely_primary_email_provider="Microsoft 365",
        dmarc_policy=None,
        mta_sts_mode=None,
    )
    output = _render(info)
    collapsed = " ".join(_services_block(output).split())
    header = " ".join(output.split("Services\n", 1)[0].split())

    # The TXT-only downstream is listed after the MX gateway and is never
    # promoted into a delivery path. The default view carries the roles in the
    # evidence trail but keeps the provider row's downstream hedge (ADR-0012).
    assert "Email Proofpoint, Microsoft 365" in collapsed
    assert collapsed.count("Microsoft 365") == 1
    assert "Microsoft 365 (likely downstream)" in header


def test_gateway_fingerprint_alias_is_not_duplicated(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = replace(
        fully_populated_tenant_info,
        services=("Symantec Email Security",),
        slugs=("symantec",),
        evidence=(EvidenceRecord("MX", "mx1.messagelabs.example", "Symantec Email Security", "symantec"),),
        primary_email_provider=None,
        email_gateway="Symantec/Broadcom",
        likely_primary_email_provider=None,
        dmarc_policy=None,
        mta_sts_mode=None,
    )
    collapsed = " ".join(_services_block(_render(info)).split())

    assert "Email Symantec/Broadcom" in collapsed
    assert collapsed.count("Symantec") == 1
    assert "Symantec Email Security" not in collapsed
    # The MX role is established, so the label is compacted rather than dropped
    # and no unattributed-match note appears (ADR-0012).
    assert "Email Symantec/Broadcom" in collapsed
    assert "role unavailable" not in collapsed
    assert "unattributed" not in collapsed


def test_degraded_mx_preserves_surviving_txt_indicator(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = replace(
        fully_populated_tenant_info,
        services=("Symantec Email Security",),
        slugs=("symantec",),
        evidence=(
            EvidenceRecord("MX", "mx1.messagelabs.example", "Symantec Email Security", "symantec"),
            EvidenceRecord("TXT", "symantec-verification=opaque", "Symantec Email Security", "symantec"),
        ),
        degraded_sources=("dns:mx",),
        primary_email_provider=None,
        email_gateway="Symantec/Broadcom",
        likely_primary_email_provider=None,
        dmarc_policy=None,
        mta_sts_mode=None,
    )
    collapsed = " ".join(_services_block(_render(info)).split())

    # The TXT indicator survives the degraded MX channel and is not dropped as
    # unattributed; its role stays available on the detail views (ADR-0012).
    assert "Email Symantec Email Security" in collapsed
    assert "unattributed" not in collapsed
    assert "Symantec/Broadcom" not in collapsed
