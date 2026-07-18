"""Service disclosure stays additive across stable human-output modes."""

from __future__ import annotations

import io
from dataclasses import replace

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
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


def test_services_flag_remains_backward_compatible(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = _with_secondary_mail_service(fully_populated_tenant_info)

    assert _render(info, show_services=True) == _render(info)


def test_detail_modes_retain_compact_and_secondary_email_facts(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = _with_secondary_mail_service(fully_populated_tenant_info)
    outputs = (
        _render(info),
        _render(info, verbose=True),
        _render(info, show_services=True, show_domains=True, verbose=True),
    )
    expected_email = "Email Microsoft 365, Proofpoint, DMARC reject, MTA-STS enforce, SendGrid"

    for output in outputs:
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

    assert "Email Proofpoint, Microsoft 365 (public TXT account indicator)" in collapsed
    assert collapsed.count("Microsoft 365") == 1
    assert "Microsoft 365 (possible downstream indicator)" in header


def test_gateway_fingerprint_alias_is_not_duplicated(
    fully_populated_tenant_info: TenantInfo,
) -> None:
    info = replace(
        fully_populated_tenant_info,
        services=("Symantec Email Security",),
        slugs=("symantec",),
        evidence=(
            EvidenceRecord("MX", "mx1.messagelabs.example", "Symantec Email Security", "symantec"),
        ),
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

    assert "Email Symantec Email Security (public TXT account indicator)" in collapsed
    assert "Symantec/Broadcom" not in collapsed
