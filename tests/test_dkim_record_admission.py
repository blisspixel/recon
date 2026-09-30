"""DKIM TXT observation admission at the existing selector boundaries."""

from __future__ import annotations

import pytest
from rich.console import Console

from recon_tool.constants import SVC_DKIM, SVC_DKIM_GOOGLE
from recon_tool.email_security import compute_email_security_score
from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.merger import merge_results
from recon_tool.sources import dns_base, dns_email
from recon_tool.sources.dns import DNSSource
from recon_tool.sources.dns_base import DetectionCtx
from recon_tool.sources.dns_tables import is_dkim_key_record


@pytest.mark.parametrize("google", [False, True], ids=["generic", "google"])
@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM10; p=AQID",
        "v=DKIM1.0; p=AQID",
        "n=v=DKIM1; p=AQID; v=OTHER",
        "v=dkim1; p=AQID",
        "v=DKIM1",
        "v=DKIM1; p=",
        "v=DKIM1; p= \t",
        "v=DKIM1; p=AQID; p=",
        "v=DKIM1; p=; p=AQID",
        "p=AQID; v=DKIM1",
        "v=DKIM1; P=AQID",
        "v=DKIM1; p=not-base64",
        "v=DKIM1; p=A===",
        "v=DKIM1; p=AQID; malformed",
        "v=DKIM1;; p=AQID",
        "v=DKIM1; p=AQ\nID",
        "v=DKIM1; p=AQ\r\nID",
        "v=DKIM1; p=AQ\x00ID",
        "v=DKIM1; p=AQ\u00a0ID",
        "v=DKIM1; p=AQID====",
        "v=DKIM1; p=AQID; x=one; x=two",
        "v=DKIM1; p=AQID; bad-name=value",
        "v=DKIM1; p=AQID; 1bad=value",
    ],
)
def test_invalid_or_revoked_txt_does_not_create_dkim_control(record: str, google: bool) -> None:
    ctx = DetectionCtx()
    if google:
        dns_email._apply_google_dkim(ctx, [record], [])
    else:
        dns_email._apply_generic_dkim(ctx, [[record]])

    assert not ctx.services
    assert not ctx.slugs
    assert not ctx.evidence


@pytest.mark.parametrize("google", [False, True], ids=["generic", "google"])
@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM1; k=rsa; p=AQID",
        "k=rsa; p=AQID",
        "p=AQID",
        " v = DKIM1 ; p = AQ ID ; ",
        "v=DKIM1; p=AQ\r\n\tID",
        "v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "v=DKIM1; n=synthetic note; x_extension=ignored; p=AQID",
        "v=DKIM1; p=AQ==",
        "v=DKIM1; p=AQI=",
        "V=UNKNOWN; P=ignored; p=AQID",
    ],
)
def test_key_record_shape_preserves_exact_provenance(record: str, google: bool) -> None:
    ctx = DetectionCtx()
    if google:
        dns_email._apply_google_dkim(ctx, [record], [])
    else:
        dns_email._apply_generic_dkim(ctx, [[record]])

    assert SVC_DKIM in ctx.services
    assert len(ctx.evidence) == 1
    assert ctx.evidence[0].raw_value == record
    assert ctx.evidence[0].source_type == "DKIM"
    assert ctx.evidence[0].rule_name == (SVC_DKIM_GOOGLE if google else SVC_DKIM)


@pytest.mark.parametrize(
    "record",
    ["", " ", ";", "v=DKIM1; p=" + "A" * 65_535],
    ids=["empty", "whitespace", "empty-tag", "oversized"],
)
def test_empty_or_oversized_input_is_not_a_key_record(record: str) -> None:
    assert not is_dkim_key_record(record)


def test_valid_later_selector_survives_revocation_and_other_txt_records() -> None:
    ctx = DetectionCtx()
    dns_email._apply_generic_dkim(ctx, [["v=DKIM1; p=", "unrelated"], ["p=AQID"]])
    assert ctx.services == {SVC_DKIM}
    assert [item.raw_value for item in ctx.evidence] == ["p=AQID"]


def test_google_cname_delegation_remains_observable_when_txt_is_not_a_key() -> None:
    ctx = DetectionCtx()
    target = "selector._domainkey.google.com."
    dns_email._apply_google_dkim(ctx, ["v=DKIM1; p="], [target])
    assert ctx.services == {SVC_DKIM, SVC_DKIM_GOOGLE}
    assert [item.raw_value for item in ctx.evidence] == [target]


@pytest.mark.asyncio
@pytest.mark.parametrize("selector", ["google", "dkim"])
@pytest.mark.parametrize(("record", "observed"), [("v=DKIM1; p=", False), ("p=AQID", True)])
async def test_source_merge_json_and_panel_agree_on_dkim_observation(
    monkeypatch: pytest.MonkeyPatch, selector: str, record: str, observed: bool
) -> None:
    queries: list[tuple[str, str]] = []

    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        queries.append((domain, record_type))
        return [record] if (domain, record_type) == (f"{selector}._domainkey.example.com", "TXT") else []

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    result = await DNSSource().lookup("example.com", skip_ct=True)
    info = merge_results([result], "example.com")
    payload = format_tenant_dict(info)
    console = Console(record=True, no_color=True, width=100)
    with console.capture() as captured:
        console.print(render_tenant_panel(info))

    assert (SVC_DKIM in info.services) is observed
    assert compute_email_security_score(info) == int(observed)
    assert payload["email_security_score"] == int(observed)
    services_section = captured.get().partition("Services\n")[2].split("\n\n", 1)[0]
    assert ("DKIM" in services_section) is observed
    assert {item.raw_value for item in info.evidence if item.source_type == "DKIM"} == ({record} if observed else set())
    assert (f"{selector}._domainkey.example.com", "TXT") in queries
    assert not result.degraded_sources
