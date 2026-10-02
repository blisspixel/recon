"""Adobe's domain-verification marker does not identify a corporate IdP."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from recon_tool.fingerprints import get_txt_patterns, match_txt_all
from recon_tool.formatter import format_tenant_markdown, format_tenant_plain, render_tenant_panel
from recon_tool.formatter.classify import categorize_services, compact_categorized_services
from recon_tool.formatter.roles import identity_role_vendors
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.server.lookup import _lookup_tenant_text
from recon_tool.sources import dns_base, dns_email

_NAME = "Adobe Admin Console"
_SLUG = "adobe-idp"
_RECORD = "adobe-idp-site-verification=synthetic-fixture"


def _info(name: str = _NAME, *, evidence: bool = True, degraded: bool = False) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="example.com",
        queried_domain="example.com",
        services=(name,),
        slugs=(_SLUG,),
        evidence=(EvidenceRecord("TXT", _RECORD, name, _SLUG),) if evidence else (),
        degraded_sources=("dns:apex_txt",) if degraded else (),
    )


@pytest.mark.asyncio
async def test_adobe_txt_uses_account_name_and_preserves_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        assert (domain, record_type) == ("example.com", "TXT")
        return [_RECORD]

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_txt(ctx, "example.com")

    assert ctx.services == {_NAME}
    assert ctx.slugs == {_SLUG}
    assert ctx.evidence == [EvidenceRecord("TXT", _RECORD, _NAME, _SLUG)]
    assert (_SLUG, "txt", "^adobe-idp-site-verification=") in ctx._matched_fp_detections
    assert ctx.raw_dns_records["TXT"] == [_RECORD]


@pytest.mark.parametrize("name", [_NAME, "Adobe (IDP)"])
def test_current_and_cached_adobe_labels_stay_out_of_identity(name: str) -> None:
    info = _info(name)
    categorized = categorize_services(info)

    assert categorized == {"Business Apps": [f"{_NAME} (public TXT account indicator)"]}
    assert compact_categorized_services(categorized)[0] == {"Business Apps": [_NAME]}
    assert identity_role_vendors(info) == ()
    assert info.auth_type is None

    buffer = io.StringIO()
    Console(file=buffer, color_system=None, width=100).print(render_tenant_panel(info))
    for output in (
        buffer.getvalue(),
        format_tenant_plain(info),
        format_tenant_markdown(info),
        _lookup_tenant_text(info),
    ):
        assert _NAME in output
        assert "Adobe (IDP)" not in output
        assert "Identity:" not in output
    assert "Business Apps" in buffer.getvalue()


@pytest.mark.parametrize("options", [{"evidence": False}, {"degraded": True}])
def test_adobe_label_needs_available_txt_evidence(options: dict[str, bool]) -> None:
    info = _info(**options)
    compact, _, _ = compact_categorized_services(categorize_services(info))

    assert not compact
    assert identity_role_vendors(info) == ()


@pytest.mark.parametrize(
    "record", ["", "not-adobe-idp-site-verification=fixture", "adobe-idp-site-verification2=fixture"]
)
def test_adobe_prefix_lookalikes_do_not_match(record: str) -> None:
    assert _SLUG not in {detection.slug for detection in match_txt_all(record, get_txt_patterns())}
