"""Exact generation-time lineage for public hardening guidance."""

from __future__ import annotations

import io
from dataclasses import replace

import pytest
from rich.console import Console

from recon_tool.constants import SVC_DMARC, SVC_MTA_STS, SVC_SPF_SOFTFAIL
from recon_tool.exposure import find_gaps_from_info
from recon_tool.exposure_gaps import hardening_scopes_available
from recon_tool.exposure_models import hardening_metadata_predicate_satisfied
from recon_tool.formatter.exposure import format_gaps_dict, render_gaps_panel
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo


def _info(**changes: object) -> TenantInfo:
    base = TenantInfo(
        tenant_id=None,
        display_name=None,
        default_domain=None,
        queried_domain="lineage.invalid",
        confidence=ConfidenceLevel.LOW,
        sources=("dns_records",),
    )
    return replace(base, **changes)


def _gap(info: TenantInfo, rule_id: str):
    return next(gap for gap in find_gaps_from_info(info).gaps if gap.generator_rule_id == rule_id)


def _assert_exact_lineage(info: TenantInfo) -> None:
    report = find_gaps_from_info(info)
    rule_ids = [gap.generator_rule_id for gap in report.gaps]
    assert len(rule_ids) == len(set(rule_ids))
    for gap in report.gaps:
        assert gap.generator_rule_id.startswith("guidance.")
        assert gap.observation_state
        assert gap.observation_scope
        assert hardening_scopes_available(gap.observation_scope, info.degraded_sources)
        assert gap.metadata_dependencies
        assert all(hardening_metadata_predicate_satisfied(item) for item in gap.metadata_dependencies)


def test_bounded_non_observations_retain_exact_rule_scope_and_state() -> None:
    report = find_gaps_from_info(_info())
    by_rule = {gap.generator_rule_id: gap for gap in report.gaps}

    assert set(by_rule) == {
        "guidance.email.dmarc.missing.v1",
        "guidance.email.dkim.common-selectors-not-observed.v1",
        "guidance.email.mta-sts.missing.v1",
        "guidance.email.tls-rpt.missing.v1",
        "guidance.infrastructure.caa.missing.v1",
    }
    assert by_rule["guidance.email.dkim.common-selectors-not-observed.v1"].observation_state == (
        "unresolved_hideable_state"
    )
    assert not by_rule["guidance.email.dkim.common-selectors-not-observed.v1"].absence_confirmable
    assert by_rule["guidance.email.dkim.common-selectors-not-observed.v1"].observation_scope == (
        "dns:dkim_common_selectors",
    )
    for rule_id, gap in by_rule.items():
        if ".dkim." not in rule_id:
            assert gap.observation_state == "bounded_non_observation"
            assert gap.absence_confirmable
        assert not gap.evidence

    _assert_exact_lineage(_info())


@pytest.mark.parametrize(
    ("info", "rule_id", "scope"),
    [
        (
            _info(
                dmarc_policy="none",
                services=(SVC_DMARC,),
                slugs=("dmarc",),
                evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=none", SVC_DMARC, "dmarc"),),
            ),
            "guidance.email.dmarc.monitoring.v1",
            ("dns:dmarc",),
        ),
        (
            _info(
                dmarc_policy="reject",
                dmarc_pct=0,
                services=(SVC_DMARC,),
                slugs=("dmarc",),
                evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=reject; pct=0", SVC_DMARC, "dmarc"),),
            ),
            "guidance.email.dmarc.not-effectively-enforcing.v1",
            ("dns:dmarc",),
        ),
        (
            _info(
                dmarc_policy="quarantine",
                services=(SVC_DMARC,),
                slugs=("dmarc",),
                evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=quarantine", SVC_DMARC, "dmarc"),),
            ),
            "guidance.email.dmarc.quarantine.v1",
            ("dns:dmarc",),
        ),
        (
            _info(
                services=(SVC_SPF_SOFTFAIL,),
                slugs=("spf-softfail",),
                evidence=(EvidenceRecord("SPF", "v=spf1 ~all", SVC_SPF_SOFTFAIL, "spf-softfail"),),
            ),
            "guidance.email.spf.softfail.v1",
            ("dns:apex_txt",),
        ),
        (
            _info(
                mta_sts_mode="none",
                services=(SVC_MTA_STS,),
                slugs=("mta-sts",),
                evidence=(
                    EvidenceRecord("MTA_STS", "v=STSv1; id=lineage1", SVC_MTA_STS, "mta-sts"),
                    EvidenceRecord("MTA_STS_POLICY", "mode: none", SVC_MTA_STS, "mta-sts"),
                ),
            ),
            "guidance.email.mta-sts.mode-none.v1",
            ("dns:mta_sts", "http:mta_sts_policy"),
        ),
        (
            _info(
                mta_sts_mode="testing",
                services=(SVC_MTA_STS,),
                slugs=("mta-sts",),
                evidence=(
                    EvidenceRecord("MTA_STS", "v=STSv1; id=lineage2", SVC_MTA_STS, "mta-sts"),
                    EvidenceRecord("MTA_STS_POLICY", "mode: testing", SVC_MTA_STS, "mta-sts"),
                ),
            ),
            "guidance.email.mta-sts.testing.v1",
            ("dns:mta_sts", "http:mta_sts_policy"),
        ),
    ],
)
def test_observed_weak_configurations_retain_exact_evidence_and_dependencies(
    info: TenantInfo,
    rule_id: str,
    scope: tuple[str, ...],
) -> None:
    gap = _gap(info, rule_id)

    assert gap.observation_state == "observed_weak_configuration"
    assert gap.observation_scope == scope
    assert gap.evidence
    assert gap.metadata_dependencies
    assert all(hardening_metadata_predicate_satisfied(item) for item in gap.metadata_dependencies)
    _assert_exact_lineage(info)


def test_gateway_inconsistency_retains_both_sides_of_its_compound_basis() -> None:
    mx = EvidenceRecord("MX", "10 mx.example.net", "Proofpoint", "proofpoint")
    dmarc = EvidenceRecord("DMARC", "v=DMARC1; p=none", SVC_DMARC, "dmarc")
    info = _info(
        dmarc_policy="none",
        email_gateway="Proofpoint",
        services=(SVC_DMARC,),
        slugs=("dmarc", "proofpoint"),
        evidence=(mx, dmarc),
    )

    gap = _gap(info, "guidance.consistency.gateway-without-dmarc-reject.v1")

    assert gap.observation_state == "observed_configuration_inconsistency"
    assert gap.observation_scope == ("dns:mx", "dns:dmarc")
    assert {item.source_type for item in gap.evidence} == {"MX", "DMARC"}
    assert {item.field for item in gap.metadata_dependencies} == {
        "gateway_mx_observed",
        "email_gateway",
        "effective_dmarc_policy",
    }
    _assert_exact_lineage(info)


def test_weak_scalar_state_without_matching_role_bearing_evidence_is_withheld() -> None:
    mx = EvidenceRecord("MX", "10 mx.example.net", "Proofpoint", "proofpoint")
    wrong_role_dmarc = EvidenceRecord("CNAME", "mail.example.net", SVC_DMARC, "dmarc")
    wrong_mode_mta_sts = EvidenceRecord("MTA_STS_POLICY", "mode: enforce", SVC_MTA_STS, "mta-sts")
    info = _info(
        dmarc_policy="none",
        mta_sts_mode="testing",
        email_gateway="Proofpoint",
        services=(SVC_DMARC, SVC_MTA_STS),
        slugs=("dmarc", "mta-sts", "proofpoint"),
        evidence=(mx, wrong_role_dmarc, wrong_mode_mta_sts),
    )

    rule_ids = {gap.generator_rule_id for gap in find_gaps_from_info(info).gaps}

    assert "guidance.email.dmarc.monitoring.v1" not in rule_ids
    assert "guidance.email.mta-sts.testing.v1" not in rule_ids
    assert "guidance.consistency.gateway-without-dmarc-reject.v1" not in rule_ids


@pytest.mark.parametrize(
    ("info", "expected_review_rule"),
    [
        (
            _info(
                dmarc_policy="none",
                services=(SVC_DMARC,),
                slugs=("dmarc",),
                evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=reject", SVC_DMARC, "dmarc"),),
            ),
            "guidance.email.dmarc.ambiguous-observation.v1",
        ),
        (
            _info(
                dmarc_policy="reject",
                dmarc_pct=0,
                services=(SVC_DMARC,),
                slugs=("dmarc",),
                evidence=(EvidenceRecord("DMARC", "v=DMARC1; p=reject", SVC_DMARC, "dmarc"),),
            ),
            None,
        ),
    ],
)
def test_specific_dmarc_guidance_is_withheld_when_scalars_do_not_match_raw_evidence(
    info: TenantInfo,
    expected_review_rule: str | None,
) -> None:
    rule_ids = {gap.generator_rule_id for gap in find_gaps_from_info(info).gaps}

    assert not rule_ids.intersection(
        {
            "guidance.email.dmarc.monitoring.v1",
            "guidance.email.dmarc.not-effectively-enforcing.v1",
            "guidance.email.dmarc.quarantine.v1",
        }
    )
    if expected_review_rule is None:
        assert not any(rule_id.startswith("guidance.email.dmarc.") for rule_id in rule_ids)
    else:
        assert expected_review_rule in rule_ids
    assert "guidance.consistency.gateway-without-dmarc-reject.v1" not in rule_ids


def test_invalid_dmarc_material_emits_evidence_backed_review_prompt() -> None:
    invalid = EvidenceRecord("DMARC", "v=DMARC1; p=bogus", SVC_DMARC, "dmarc-invalid")
    info = _info(services=(SVC_DMARC,), slugs=("dmarc-invalid",), evidence=(invalid,))

    gap = _gap(info, "guidance.email.dmarc.invalid-observation.v1")

    assert gap.observation_state == "observed_weak_configuration"
    assert tuple(item.raw_value for item in gap.evidence) == (invalid.raw_value,)
    assert {item.field: item.observed_value for item in gap.metadata_dependencies} == {
        "dmarc_construction_state": "invalid"
    }


def test_mta_sts_dns_absence_does_not_claim_an_unattempted_http_scope() -> None:
    gap = _gap(_info(), "guidance.email.mta-sts.missing.v1")

    assert gap.observation_scope == ("dns:mta_sts",)
    assert {item.field: item.observed_value for item in gap.metadata_dependencies} == {"mta_sts_txt_observed": False}


def test_mta_sts_declaration_without_valid_http_policy_has_both_scopes() -> None:
    txt = EvidenceRecord("MTA_STS", "v=STSv1; id=lineage3", SVC_MTA_STS, "mta-sts")
    info = _info(services=(SVC_MTA_STS,), slugs=("mta-sts",), evidence=(txt,))

    gap = _gap(info, "guidance.email.mta-sts.policy-not-observed.v1")

    assert gap.observation_state == "bounded_non_observation"
    assert gap.observation_scope == ("dns:mta_sts", "http:mta_sts_policy")
    assert tuple(item.raw_value for item in gap.evidence) == (txt.raw_value,)


def test_mta_sts_scope_availability_is_independent() -> None:
    assert hardening_scopes_available(("dns:mta_sts",), ("http:mta_sts_policy",))
    assert hardening_scopes_available(("http:mta_sts_policy",), ("dns:mta_sts",))


def test_http_degradation_does_not_mask_completed_mta_sts_dns_absence() -> None:
    info = _info(degraded_sources=("http:mta_sts_policy",))

    gap = _gap(info, "guidance.email.mta-sts.missing.v1")

    assert gap.observation_scope == ("dns:mta_sts",)


def test_http_degradation_with_mta_sts_txt_withholds_policy_guidance() -> None:
    txt = EvidenceRecord("MTA_STS", "v=STSv1; id=lineage4", SVC_MTA_STS, "mta-sts")
    info = _info(
        services=(SVC_MTA_STS,),
        slugs=("mta-sts",),
        evidence=(txt,),
        degraded_sources=("http:mta_sts_policy",),
    )

    rule_ids = {gap.generator_rule_id for gap in find_gaps_from_info(info).gaps}

    assert "guidance.email.mta-sts.missing.v1" not in rule_ids
    assert "guidance.email.mta-sts.policy-not-observed.v1" not in rule_ids


def test_gateway_label_must_match_the_retained_mx_role() -> None:
    info = _info(
        dmarc_policy="none",
        email_gateway="Mimecast",
        services=(SVC_DMARC,),
        slugs=("dmarc", "proofpoint"),
        evidence=(
            EvidenceRecord("MX", "10 mx.example.net", "Proofpoint", "proofpoint"),
            EvidenceRecord("DMARC", "v=DMARC1; p=none", SVC_DMARC, "dmarc"),
        ),
    )

    rule_ids = {gap.generator_rule_id for gap in find_gaps_from_info(info).gaps}

    assert "guidance.consistency.gateway-without-dmarc-reject.v1" not in rule_ids


def test_multi_gateway_label_retains_every_contributing_mx_record() -> None:
    proofpoint = EvidenceRecord("MX", "10 mx1.example.net", "Proofpoint", "proofpoint")
    mimecast = EvidenceRecord("MX", "20 mx2.example.net", "Mimecast", "mimecast")
    dmarc = EvidenceRecord("DMARC", "v=DMARC1; p=none", SVC_DMARC, "dmarc")
    info = _info(
        dmarc_policy="none",
        email_gateway="Mimecast + Proofpoint",
        services=(SVC_DMARC,),
        slugs=("dmarc", "mimecast", "proofpoint"),
        evidence=(proofpoint, mimecast, dmarc),
    )

    gap = _gap(info, "guidance.consistency.gateway-without-dmarc-reject.v1")

    assert {item.raw_value for item in gap.evidence if item.source_type == "MX"} == {
        proofpoint.raw_value,
        mimecast.raw_value,
    }


def test_public_gap_shape_exposes_replayable_basis_without_removing_compatibility_flag() -> None:
    report = find_gaps_from_info(_info())

    data = format_gaps_dict(report)
    gap = data["gaps"][0]

    assert {
        "generator_rule_id",
        "observation_state",
        "observation_scope",
        "metadata_dependencies",
        "absence_confirmable",
        "evidence",
    } <= set(gap)
    assert gap["generator_rule_id"]
    assert gap["observation_scope"]
    assert gap["metadata_dependencies"]


def test_panel_distinguishes_bounded_and_hideable_non_observation() -> None:
    output = io.StringIO()

    Console(file=output, width=100, force_terminal=False).print(render_gaps_panel(find_gaps_from_info(_info())))

    rendered = output.getvalue()
    assert "bounded non-observation" in rendered
    assert "unresolved; bounded selectors only" in rendered
    assert "not an overall security assessment" in rendered


@pytest.mark.parametrize(
    ("marker", "rule_id"),
    [
        ("dns:dmarc", "guidance.email.dmarc.missing.v1"),
        ("dns:dkim", "guidance.email.dkim.common-selectors-not-observed.v1"),
        ("dns:mta_sts", "guidance.email.mta-sts.missing.v1"),
        ("dns:tls_rpt", "guidance.email.tls-rpt.missing.v1"),
        ("dns:caa", "guidance.infrastructure.caa.missing.v1"),
    ],
)
def test_unavailable_scope_cannot_emit_a_non_observation(marker: str, rule_id: str) -> None:
    report = find_gaps_from_info(_info(degraded_sources=(marker,)))

    assert rule_id not in {gap.generator_rule_id for gap in report.gaps}
