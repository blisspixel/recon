"""Offline declaration, lookalike and cross-surface mail applicability checks."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from jsonschema import Draft202012Validator
from jsonschema.protocols import Validator
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.email_applicability import mail_applicability
from recon_tool.exposure import assess_exposure_from_info, compare_postures_from_infos, find_gaps_from_info
from recon_tool.exposure_models import EXPOSURE_COMPONENT_SPECS, ExposureIndex
from recon_tool.formatter.exposure import format_exposure_dict
from recon_tool.mcp_client.sdk_compat import call_tool_parts
from recon_tool.merger import merge_results
from recon_tool.models import EvidenceRecord, SourceResult, TenantInfo
from recon_tool.review_bundle import ReviewCollectionContext, build_review_bundle
from recon_tool.server.app import mcp
from recon_tool.server.posture import assess_exposure, find_hardening_gaps, simulate_hardening
from recon_tool.sources import dns_base, dns_email
from recon_tool.sources.dns_tables import is_null_mx_set

_NULL_MX = EvidenceRecord("MX", "0 .", "Null MX (domain does not accept email)", "null-mx")
_SPF = EvidenceRecord("SPF", "v=spf1 -all", "SPF: strict (-all)", "spf-strict")
_DMARC = EvidenceRecord("DMARC", "v=DMARC1; p=reject", "DMARC", "dmarc")
_INBOUND = {"MTA-STS", "TLS-RPT", "Email gateway"}
_OUTBOUND = {"DKIM", "BIMI"}


def _info() -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="example.com",
        queried_domain="example.com",
        dmarc_policy="reject",
        evidence=(_NULL_MX, _SPF, _DMARC),
        slugs=("null-mx", "spf-strict", "dmarc"),
    )


def _inapplicable(info: TenantInfo) -> set[str]:
    return {
        component.control
        for component in assess_exposure_from_info(info).index_components
        if component.applicability is not None
    }


@pytest.mark.parametrize("mx", [("0 .",), ("0 .", "0 ."), (" 0\t. ",)])
def test_null_mx_grammar_shares_the_live_detector_rule(mx: tuple[str, ...]) -> None:
    assert is_null_mx_set(mx)
    info = replace(_info(), evidence=(*(replace(_NULL_MX, raw_value=value) for value in mx), _SPF, _DMARC))
    assert _inapplicable(info) == _INBOUND | _OUTBOUND


@pytest.mark.parametrize("mx", [(), ("10 .",), ("0",), ("0 .", "10 mx.example.com"), ("0 .", "bad")])
def test_mixed_empty_and_malformed_mx_never_establish_no_mail(mx: tuple[str, ...]) -> None:
    assert not is_null_mx_set(mx)
    info = replace(_info(), evidence=(*(replace(_NULL_MX, raw_value=value) for value in mx), _SPF, _DMARC))
    assert not _inapplicable(info)
    assert any("mta-sts" in gap.generator_rule_id for gap in find_gaps_from_info(info).gaps)


@pytest.mark.parametrize("raw", ["v=spf1 -all", "V=SPF1 -ALL", "v=spf1  -all "])
def test_only_an_explicit_deny_all_policy_supports_sender_suppression(raw: str) -> None:
    assert _inapplicable(replace(_info(), evidence=(_NULL_MX, replace(_SPF, raw_value=raw), _DMARC))) == (
        _INBOUND | _OUTBOUND
    )


@pytest.mark.parametrize(
    "raw",
    [
        "v=spf1 include:mail.example.com -all",
        "v=spf1 ip4:192.0.2.1 -all",
        "v=spf1 redirect=mail.example.com",
        "v=spf1 ~all",
        "v=spf1 +all",
        "v=spf1 -all unknown=modifier",
        "v=spf1\t-all",
    ],
)
def test_strict_spf_and_malformed_or_broader_policies_do_not_mean_no_sending(raw: str) -> None:
    info = replace(_info(), evidence=(_NULL_MX, replace(_SPF, raw_value=raw), _DMARC))
    assert _inapplicable(info) == _INBOUND
    assert any("dkim" in gap.generator_rule_id for gap in find_gaps_from_info(info).gaps)


def test_competing_or_unadmitted_spf_and_wrong_evidence_roles_cannot_suppress_sender_controls() -> None:
    for evidence in (
        (_NULL_MX, _SPF, replace(_SPF, raw_value="v=spf1 +all", slug="spf"), _DMARC),
        (_NULL_MX, replace(_SPF, slug="spf"), _DMARC),
        (_NULL_MX, replace(_SPF, source_type="TXT"), _DMARC),
    ):
        assert _inapplicable(replace(_info(), evidence=evidence)) == _INBOUND
    for mx in (replace(_NULL_MX, source_type="TXT"), replace(_NULL_MX, slug="custom-mx")):
        assert not _inapplicable(replace(_info(), evidence=(mx, _SPF, _DMARC)))


@pytest.mark.parametrize(
    ("raw", "policy", "outbound"),
    [
        ("v=DMARC1; p=reject", "reject", True),
        ("v=DMARC1; p=quarantine", "quarantine", True),
        ("v=DMARC1; p=none", "none", False),
        ("v=DMARC1; p=reject; pct=0", "reject", False),
        ("v=DMARC1; p=quarantine; t=y", "quarantine", False),
        ("v=DMARC1; p=none", "reject", False),
        ("v=DMARC1; p=invalid", "reject", False),
    ],
)
def test_sender_applicability_uses_raw_bound_effective_dmarc(raw: str, policy: str, outbound: bool) -> None:
    info = replace(_info(), dmarc_policy=policy, evidence=(_NULL_MX, _SPF, replace(_DMARC, raw_value=raw)))
    assert mail_applicability(info).outbound_not_applicable is outbound


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("dns", set[str]()),
        ("dns:mx", set[str]()),
        ("detector:mx", set[str]()),
        ("dns:apex_txt", _INBOUND),
        ("dns:dmarc", _INBOUND),
        ("detector:email_security", _INBOUND),
        ("dns:dkim", _INBOUND | _OUTBOUND),
        ("dns:mta_sts", _INBOUND | _OUTBOUND),
    ],
)
def test_failed_sources_cannot_supply_applicability_proof(marker: str, expected: set[str]) -> None:
    info = replace(_info(), degraded_sources=(marker,))
    assert _inapplicable(info) == expected
    unavailable = set(find_gaps_from_info(info).unavailable_controls)
    assert unavailable.isdisjoint(expected)
    assert info.degraded_sources == (marker,)
    if marker in {"dns:dkim", "dns:mta_sts"}:
        control = "DKIM" if marker == "dns:dkim" else "MTA-STS"
        component = next(item for item in assess_exposure_from_info(info).index_components if item.control == control)
        assert component.state == "unavailable"
        assert component.evidence == ()
        assert component.applicability is not None


def test_inapplicable_components_retain_proof_without_credit_or_unresolved_capacity() -> None:
    info = _info()
    assessment = assess_exposure_from_info(info)
    index = ExposureIndex(assessment.index_components)
    assert index.model_maximum_points == 45
    assert index.score_floor == 30
    assert index.score_ceiling == 40
    assert [(item.component_id, item.control, item.maximum_points) for item in index.components] == list(
        EXPOSURE_COMPONENT_SPECS
    )
    for component in index.components:
        if component.control not in _INBOUND | _OUTBOUND:
            continue
        proof = component.applicability
        assert proof is not None
        assert proof.state == "not_applicable"
        assert component.awarded_points == component.unconfirmable_points == 0
        assert proof.evidence
        assert proof.metadata_dependencies[0].field == "mail_applicability"
        assert "dns:mx" in proof.observation_scope
        assert any(item.raw_value == "0 ." for item in proof.evidence)
    assert info.evidence == (_NULL_MX, _SPF, _DMARC)
    assert all(
        "not applicable:" in ctrl.detail
        for ctrl in assessment.hardening_status.controls
        if ctrl.name != "DMARC" and ctrl.name != "CAA"
    )
    with pytest.raises(ValueError, match="cannot award points"):
        replace(index.components[1], awarded_points=1)
    proof = index.components[1].applicability
    assert proof is not None
    with pytest.raises(ValueError, match="requires retained evidence"):
        replace(proof, evidence=())


@pytest.mark.parametrize("marker", [None, "dns:dkim", "dns:mta_sts", "dns:mx"])
def test_applicability_is_additive_to_the_released_mcp_output_schema(marker: str | None) -> None:
    # Captured from the v2.23.0 TypedDict declarations using MCP 2.3.0.
    # Their source is identical at 114aaa670c2eea8e0e9f06ea0f0dbb069fe2de58
    # and c05089d51f74aca1906f798586352c6192caa3a7. Keep this fixture frozen.
    schema = json.loads((Path(__file__).parent / "fixtures" / "exposure-output-schema-2.23.0.json").read_text())
    info = replace(_info(), degraded_sources=(marker,) if marker is not None else ())
    payload = format_exposure_dict(assess_exposure_from_info(info))
    validator = cast(Validator, Draft202012Validator(schema))
    validator.validate(payload)
    states = {component["state"] for component in payload["observability"]["components"]}
    assert states <= {"observed_value", "observed_empty", "unresolved", "unavailable", "hypothetical_value"}


def test_retained_sender_residue_is_not_erased_or_credited_as_applicable() -> None:
    dkim = EvidenceRecord("DKIM", "v=DKIM1; p=opaque", "DKIM", "dkim")
    info = replace(_info(), evidence=(*_info().evidence, dkim))
    assessment = assess_exposure_from_info(info)
    control = next(item for item in assessment.hardening_status.controls if item.name == "DKIM")
    assert control.present
    assert control.detail.startswith("not applicable:")
    assert any(item.raw_value == dkim.raw_value for item in control.evidence)
    assert _inapplicable(info) == _INBOUND | _OUTBOUND
    component = next(item for item in assessment.index_components if item.control == "DKIM")
    assert component.state == "observed_value"
    assert component.awarded_points == 0
    assert any(item.raw_value == dkim.raw_value for item in component.evidence)


@pytest.mark.parametrize("mode", ["none", "testing", "enforce"])
def test_null_mx_suppresses_both_missing_and_weak_transport_prompts(mode: str) -> None:
    info = replace(
        _info(),
        mta_sts_mode=mode,
        evidence=(
            *_info().evidence,
            EvidenceRecord("MTA_STS", "v=STSv1; id=synthetic", "MTA-STS", "mta-sts"),
            EvidenceRecord(
                "MTA_STS_POLICY", f"mode: {mode}", "MTA-STS", "mta-sts-enforce" if mode == "enforce" else "mta-sts"
            ),
        ),
    )
    assert not any("mta-sts" in gap.generator_rule_id for gap in find_gaps_from_info(info).gaps)
    component = next(item for item in assess_exposure_from_info(info).index_components if item.control == "MTA-STS")
    assert component.applicability is not None


def test_missing_or_conflicting_dmarc_never_establishes_sender_inapplicability() -> None:
    for info in (
        replace(_info(), dmarc_policy=None, evidence=(_NULL_MX, _SPF)),
        replace(_info(), evidence=(*_info().evidence, replace(_DMARC, raw_value="v=DMARC1; p=none"))),
    ):
        assert _inapplicable(info) == _INBOUND


@pytest.mark.asyncio
async def test_detector_and_merge_pipeline_reaches_the_same_applicability(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(domain: str, record_type: str, **_kwargs: object) -> list[str]:
        return {
            ("example.com", "MX"): ["0 ."],
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        }.get((domain, record_type), [])

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    ctx = dns_base.DetectionCtx()
    await dns_email.detect_mx(ctx, "example.com")
    await dns_email.detect_txt(ctx, "example.com")
    with patch("recon_tool.sources.dns_email._http_client") as http:
        await dns_email.detect_email_security(ctx, "example.com")
        http.assert_not_called()
    result = SourceResult(
        source_name="dns_records",
        evidence=tuple(ctx.evidence),
        detected_services=tuple(sorted(ctx.services)),
        detected_slugs=tuple(sorted(ctx.slugs)),
        dmarc_policy=ctx.dmarc_policy,
    )
    assert _inapplicable(merge_results([result], "example.com")) == _INBOUND | _OUTBOUND


@pytest.mark.asyncio
async def test_mcp_gap_and_exposure_tools_share_the_declaration_decision() -> None:
    with patch("recon_tool.server.app.resolve_single_for_tool", new=AsyncMock(return_value=_info())):
        exposure = await assess_exposure("example.com")
        gaps = await find_hardening_gaps("example.com")
        _content, dispatched = call_tool_parts(await mcp.call_tool("assess_exposure", {"domain": "example.com"}))
    assert dispatched == exposure
    assert exposure["observability"]["model_maximum_points"] == 45
    assert [gap["generator_rule_id"] for gap in gaps["gaps"]] == ["guidance.infrastructure.caa.missing.v1"]


@pytest.mark.parametrize("fixes", [[], ["MTA-STS enforce", "DKIM"], ["BIMI", "TLS-RPT", "DKIM", "MTA-STS"]])
@pytest.mark.asyncio
async def test_simulation_does_not_award_inapplicable_control_points(fixes: list[str]) -> None:
    with patch("recon_tool.server.app.resolve_or_cache", new=AsyncMock(return_value=(_info(), []))):
        result = await simulate_hardening("example.com", fixes)
    assert result["score_delta"] == 0
    assert result["applied_fixes"] == []
    assert result["current_observability"] == result["simulated_observability"]
    assert result["simulated_observability"]["model_maximum_points"] == 45


@pytest.mark.asyncio
async def test_simulation_preserves_original_applicability_and_allows_other_fixes() -> None:
    with patch("recon_tool.server.app.resolve_or_cache", new=AsyncMock(return_value=(_info(), []))):
        result = await simulate_hardening("example.com", ["DKIM", "CAA"])
    assert result["score_delta"] == 5
    assert result["applied_fixes"] == ["CAA records configured"]
    info = replace(_info(), dmarc_policy=None, evidence=(_NULL_MX, _SPF))
    with patch("recon_tool.server.app.resolve_or_cache", new=AsyncMock(return_value=(info, []))):
        result = await simulate_hardening("example.com", ["DMARC reject", "DKIM"])
    components = {item["control"]: item for item in result["simulated_observability"]["components"]}
    assert components["DKIM"]["state"] == "hypothetical_value"
    assert components["DKIM"]["awarded_points"] == 15
    applicability = components["MTA-STS"].get("applicability")
    assert applicability is not None
    assert applicability["state"] == "not_applicable"


def test_review_candidates_and_comparisons_share_applicability() -> None:
    now = datetime(2026, 10, 24, tzinfo=UTC)
    bundle = build_review_bundle(
        _info(),
        [SourceResult(source_name="dns_records", evidence=_info().evidence)],
        "example.com",
        ReviewCollectionContext(now, now, False, 120),
        generated_at=now,
    )
    candidates = bundle["result"]["review_candidates"]["candidates"]
    assert [item["generator_rule_id"] for item in candidates] == ["guidance.infrastructure.caa.missing.v1"]
    peer = replace(
        _info(), queried_domain="example.org", evidence=(_SPF, _DMARC, EvidenceRecord("DKIM", "key", "DKIM", "dkim"))
    )
    comparison = compare_postures_from_infos(_info(), peer)
    assert not any("DKIM" in difference.description for difference in comparison.differences)


@pytest.mark.parametrize("mode", ["--gaps", "--exposure", "review"])
def test_cli_surfaces_use_the_same_declaration_decision(mode: str) -> None:
    args = ["review", "example.com", "--json"] if mode == "review" else ["example.com", mode, "--json", "--no-cache"]
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(_info(), []))):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    if mode == "--exposure":
        assert payload["observability"]["model_maximum_points"] == 45
    else:
        gaps = payload["result"]["review_candidates"]["candidates"] if mode == "review" else payload["gaps"]
        assert all(
            "mta-sts" not in item["generator_rule_id"]
            and "dkim" not in item["generator_rule_id"]
            and "tls-rpt" not in item["generator_rule_id"]
            for item in gaps
        )
