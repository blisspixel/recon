"""Public email-policy declarations must survive protocol record admission."""

from __future__ import annotations

import pytest
from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.merger import merge_results
from recon_tool.sources import dns_base, dns_email
from recon_tool.sources.dns import DNSSource
from recon_tool.sources.dns_base import DetectionCtx
from recon_tool.sources.dns_tables import extract_bimi_vmc_url, select_bimi_record, select_tls_rpt_record


@pytest.mark.parametrize(
    "record",
    [
        "v=BIMI10; l=https://assets.example.com/logo.svg",
        "v=bimi1; l=https://assets.example.com/logo.svg",
        "note=v=BIMI1; l=https://assets.example.com/logo.svg",
        "l=https://assets.example.com/logo.svg; v=BIMI1",
        "v=BIMI1",
        "v=BIMI1; a=https://assets.example.com/vmc.pem",
        "v=BIMI1; l=; a=;",
        "v=BIMI1; l=;",
        "v=BIMI1; L=https://assets.example.com/logo.svg",
        "v=BIMI1; l=http://assets.example.com/logo.svg",
        "v=BIMI1; l=https://",
        "v=BIMI1; l=https://assets.example.com/logo%GG.svg",
        "v=BIMI1; l=https://assets.example.com/a,b.svg",
        "v=BIMI1; l=https://assets.example.com/logo.svg; l=",
        "v=BIMI1; l=; l=https://assets.example.com/logo.svg",
        "v=BIMI1; l=https://assets.example.com/logo.svg; a=http://assets.example.com/vmc.pem",
        "v=BIMI1; l=https://assets.example.com/logo.svg; a=https://192.0.2.1/vmc.pem",
        "v=BIMI1; l=https://assets.example.com/logo.svg; a=https://localhost/vmc.pem",
        "v=BIMI1;; l=https://assets.example.com/logo.svg",
        "v=BIMI1; l=https://assets.example.com/logo.svg; malformed",
        "v=BIMI1; l=https://assets.example.com/lo\ngo.svg",
        "v=BIMI1; l=https://assets.example.com/logo.svg; lps=bad_prefix",
    ],
)
@pytest.mark.asyncio
async def test_invalid_or_declined_bimi_does_not_create_control(record: str) -> None:
    ctx = DetectionCtx()
    await dns_email._apply_bimi(ctx, [record], "example.com")
    assert not ctx.services
    assert not ctx.slugs
    assert not ctx.evidence


@pytest.mark.parametrize(
    "record",
    [
        "v=TLSRPTv10; rua=mailto:reports@example.com",
        "v=tlsrptv1; rua=mailto:reports@example.com",
        "note=v=TLSRPTv1; rua=mailto:reports@example.com",
        "rua=mailto:reports@example.com; v=TLSRPTv1",
        "v=TLSRPTv1",
        "v=TLSRPTv1; x=anything",
        "v=TLSRPTv1; RUA=mailto:reports@example.com",
        "v=TLSRPTv1; rua=",
        "v=TLSRPTv1; rua=reports@example.com",
        "v=TLSRPTv1; rua=mailto:reports@example.com,",
        "v=TLSRPTv1; rua=,mailto:reports@example.com",
        "v=TLSRPTv1; rua=mailto:reports@example.com!10m",
        "v=TLSRPTv1; rua=https://reports.example.com/%GG",
        "v=TLSRPTv1; rua=mailto:reports@example.com; malformed",
        "v=TLSRPTv1;; rua=mailto:reports@example.com",
        "v=TLSRPTv1; rua=mailto:reports@example.com; x=two words",
        "v=TLSRPTv1; rua=mailto:reports@example.com; x=bad=value",
        "v=TLSRPTv1; rua=mailto:reports@example.com\n",
        "v=TLSRPTv1; rua=mailto:reports@example.com\u00a0",
        "v=TLSRPTv1; rua =mailto:reports@example.com",
        "v=TLSRPTv1; rua=mailto:reports@example.com ",
    ],
)
def test_invalid_tls_rpt_does_not_create_control(record: str) -> None:
    ctx = DetectionCtx()
    dns_email._apply_tls_rpt(ctx, [record])
    assert not ctx.services
    assert not ctx.slugs
    assert not ctx.evidence


@pytest.mark.parametrize("bimi", [False, True], ids=["tls-rpt", "bimi"])
@pytest.mark.parametrize("duplicate", [False, True], ids=["conflicting", "repeated"])
@pytest.mark.asyncio
async def test_multiple_candidate_records_do_not_create_control(bimi: bool, duplicate: bool) -> None:
    first = "v=BIMI1; l=https://assets.example.com/a.svg" if bimi else "v=TLSRPTv1; rua=mailto:a@example.com"
    second = first if duplicate else first.replace("a.svg", "b.svg").replace("a@example", "b@example")
    ctx = DetectionCtx()
    if bimi:
        await dns_email._apply_bimi(ctx, [first, second], "example.com")
    else:
        dns_email._apply_tls_rpt(ctx, [first, second])
    assert not ctx.services
    assert not ctx.evidence


@pytest.mark.parametrize("bimi", [False, True], ids=["tls-rpt", "bimi"])
@pytest.mark.asyncio
async def test_valid_policy_preserves_raw_evidence(bimi: bool) -> None:
    record = "v=BIMI1; l=https://assets.example.com/logo.svg" if bimi else "v=TLSRPTv1; rua=mailto:a@example.com"
    ctx = DetectionCtx()
    if bimi:
        await dns_email._apply_bimi(ctx, ["unrelated TXT", record], "example.com")
    else:
        dns_email._apply_tls_rpt(ctx, ["unrelated TXT", record])
    assert ctx.services == ({"BIMI"} if bimi else {"TLS-RPT"})
    assert [item.raw_value for item in ctx.evidence] == [record]


@pytest.mark.parametrize(
    "record",
    [
        " v = BIMI1 ; l = https://assets.example.com/logo.svg ; ",
        "v=BIMI1;\r\n\tl=https://assets.example.com/logo.svg",
        "v=BIMI1; l=https://assets.example.com/logo%2c.svg",
        "v=BIMI1; l=https://assets.example.com/logo!wide.svg",
        "v=BIMI1; l=; a=https://assets.example.com/vmc.pem",
        "v=BIMI1; l=https://assets.example.com/logo.svg; a=;",
        "v=BIMI1; x_extension=ignored note; l=https://assets.example.com/logo.svg",
        "v=BIMI1; l=https://assets.example.com/logo.svg; lps=;",
        "v=BIMI1; l=https://assets.example.com/logo.svg; lps=help, team-; avp=brand",
        "v=BIMI1; l=https://assets.example.com/logo.svg; avp=unknown",
        "v=BIMI1; l=HTTPS://assets.example.com/logo.svg; A=ignored",
    ],
)
def test_bimi_supported_syntax_extensions_and_nonempty_authority(record: str) -> None:
    assert select_bimi_record([record]) == record


@pytest.mark.parametrize(
    "record",
    [
        "v=TLSRPTv1;rua=mailto:reports@example.com;",
        "v=TLSRPTv1;\trua=https://reports.example.com/tls \t; \t",
        "v=TLSRPTv1;rua=mailto:a@example.com \t,\t https://reports.example.com/tls",
        "v=TLSRPTv1;rua=mailto:a@example.com;rua=https://reports.example.com/tls",
        "v=TLSRPTv1;rua=https://reports.example.com/a%2Cb%21c%3Bd",
        "v=TLSRPTv1;rua=https://reports.example.com/tls;0.x-test=ignored;0.x-test=again",
        "v=TLSRPTv1;RUA=ignored;rua=MAILTO:a@example.com",
        "v=TLSRPTv1;rua=urn:example:report",
        "v=TLSRPTv1 \t;rua=mailto:a@example.com",
    ],
)
def test_tls_rpt_declared_uri_syntax_does_not_imply_delivery(record: str) -> None:
    assert select_tls_rpt_record([record]) == record


def test_tls_rpt_multiple_txt_records_use_the_specified_literal_prefix_filter() -> None:
    spaced = "v=TLSRPTv1 \t;rua=mailto:a@example.com"
    literal = "v=TLSRPTv1;rua=mailto:b@example.com"
    assert select_tls_rpt_record([spaced, "unrelated TXT"]) is None
    assert select_tls_rpt_record([spaced, literal]) == literal
    assert select_tls_rpt_record([literal, spaced]) == literal


@pytest.mark.parametrize("bimi", [False, True], ids=["tls-rpt", "bimi"])
@pytest.mark.parametrize(
    "tail",
    ["", "; malformed", ";" + "x" * 65_535],
    ids=["missing-required-tag", "malformed", "oversized"],
)
def test_invalid_current_version_candidate_still_blocks_other_valid_record(bimi: bool, tail: str) -> None:
    valid = "v=BIMI1; l=https://assets.example.com/logo.svg" if bimi else "v=TLSRPTv1;rua=mailto:a@example.com"
    invalid = ("v=BIMI1" if bimi else "v=TLSRPTv1;") + tail
    select = select_bimi_record if bimi else select_tls_rpt_record
    assert select([valid, invalid]) is None
    assert select([invalid, valid]) is None
    assert select([invalid]) is None


@pytest.mark.parametrize("bimi", [False, True], ids=["tls-rpt", "bimi"])
@pytest.mark.parametrize("record", ["", " ", "not a policy"])
def test_empty_or_unrelated_txt_is_not_a_policy(bimi: bool, record: str) -> None:
    select = select_bimi_record if bimi else select_tls_rpt_record
    assert select([]) is None
    assert select([record]) is None


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("a = https://assets.example.com/vmc.pem", "https://assets.example.com/vmc.pem"),
        ("A=https://assets.example.com/vmc.pem", None),
        ("a=https://assets.example.com/vmc.pem; a=https://other.example.com/vmc.pem", None),
        ("a=https://assets.example.com/vmc.der", None),
        ("a=https://assets.example.com:bad/vmc.pem", None),
        ("a=", None),
    ],
)
def test_authority_extraction_uses_the_same_admitted_tags(authority: str, expected: str | None) -> None:
    assert extract_bimi_vmc_url(f"v=BIMI1; l=https://assets.example.com/logo.svg; {authority}") == expected


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("valid", [False, True])
@pytest.mark.asyncio
async def test_only_admitted_bimi_can_reach_opt_in_enrichment(
    monkeypatch: pytest.MonkeyPatch, active: bool, valid: bool
) -> None:
    attempted: list[str] = []

    async def enrich(_ctx: DetectionCtx, txt: str) -> None:
        attempted.append(txt)

    monkeypatch.setattr(dns_email, "_parse_bimi_vmc", enrich)
    record = f"v={'BIMI1' if valid else 'BIMI10'}; l=; a=https://assets.example.com/vmc.pem"
    ctx = DetectionCtx()
    ctx.active_probes = active
    await dns_email._apply_bimi(ctx, [record], "example.com")
    assert attempted == ([record] if valid and active else [])


@pytest.mark.parametrize("bimi", [False, True], ids=["tls-rpt", "bimi"])
@pytest.mark.parametrize("state", ["valid", "invalid", "conflict", "missing", "failed"])
@pytest.mark.asyncio
async def test_source_json_and_compact_panel_agree(monkeypatch: pytest.MonkeyPatch, bimi: bool, state: str) -> None:
    prefix, service, slug = ("default._bimi", "BIMI", "bimi") if bimi else ("_smtp._tls", "TLS-RPT", "tls-rpt")
    valid = "v=BIMI1; l=https://assets.example.com/logo.svg" if bimi else "v=TLSRPTv1;rua=mailto:a@example.com"
    invalid = "v=BIMI1; l=; a=" if bimi else "v=TLSRPTv1; rua="
    records = {"valid": [valid], "invalid": [invalid], "conflict": [valid, invalid], "missing": [], "failed": []}

    async def resolve(
        domain: str, record_type: str, *, degraded_sources: set[str] | None = None, **_kwargs: object
    ) -> list[str]:
        if (domain, record_type) != (f"{prefix}.example.com", "TXT"):
            return []
        if state == "failed" and degraded_sources is not None:
            degraded_sources.add(f"dns:{'bimi' if bimi else 'tls_rpt'}")
        return records[state]

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    result = await DNSSource().lookup("example.com", skip_ct=True)
    info = merge_results([result], "example.com")
    payload = format_tenant_dict(info)
    console = Console(record=True, no_color=True, width=100)
    with console.capture() as captured:
        console.print(render_tenant_panel(info))
    services_section = captured.get().partition("Services\n")[2].split("\n\n", 1)[0]
    observed = state == "valid"
    assert (service in info.services) is observed
    assert (service in payload["services"]) is observed
    # The compact Email row deliberately omits TLS-RPT. Detailed service
    # evidence still carries it; rejected BIMI must not survive in the row.
    assert (service in services_section) is (observed and bimi)
    assert payload["email_security_score"] == int(observed and bimi)
    assert [item.raw_value for item in info.evidence if item.slug == slug] == ([valid] if observed else [])
    assert bool(result.degraded_sources) is (state == "failed")
