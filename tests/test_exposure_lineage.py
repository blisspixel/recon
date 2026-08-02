"""Exact generation-time lineage for the model-bound exposure index."""

from __future__ import annotations

from dataclasses import replace

import pytest

from recon_tool.constants import (
    SVC_BIMI,
    SVC_DKIM,
    SVC_DMARC,
    SVC_MTA_STS,
    SVC_SPF_STRICT,
)
from recon_tool.exposure import assess_exposure_from_info, compare_postures_from_infos
from recon_tool.exposure_models import (
    EvidenceReference,
    ExposureAssessment,
    ExposureIndex,
    ExposureIndexComponent,
    ExposureMetadataDependency,
    PostureComparison,
)
from recon_tool.formatter.exposure import format_exposure_dict, render_exposure_panel
from recon_tool.formatter.panel import format_comparison_dict
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo


def _fully_observed_info() -> TenantInfo:
    evidence = (
        EvidenceRecord("DMARC", "v=DMARC1; p=reject", SVC_DMARC, "dmarc"),
        EvidenceRecord("DKIM", "v=DKIM1; p=opaque", SVC_DKIM, "dkim"),
        EvidenceRecord("SPF", "v=spf1 -all", SVC_SPF_STRICT, "spf-strict"),
        EvidenceRecord("MTA_STS", "v=STSv1; id=20260801", SVC_MTA_STS, "mta-sts"),
        EvidenceRecord("MTA_STS_POLICY", "mode: enforce", SVC_MTA_STS, "mta-sts-enforce"),
        EvidenceRecord("BIMI", "v=BIMI1; l=https://assets.invalid/logo.svg", SVC_BIMI, "bimi"),
        EvidenceRecord("TXT", "v=TLSRPTv1; rua=mailto:reports@example.invalid", "TLS-RPT", "tls-rpt"),
        EvidenceRecord("CAA", '0 issue "letsencrypt.org"', "CAA record", "caa"),
        EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365"),
        EvidenceRecord("MX", "10 mx1-us1.ppe-hosted.com", "Proofpoint", "proofpoint"),
    )
    return TenantInfo(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        display_name="Synthetic Alpha",
        default_domain="alpha.onmicrosoft.com",
        queried_domain="alpha.invalid",
        confidence=ConfidenceLevel.HIGH,
        sources=("dns_records", "user_realm"),
        services=(SVC_DMARC, SVC_DKIM, SVC_SPF_STRICT, SVC_MTA_STS, SVC_BIMI, "TLS-RPT", "Proofpoint"),
        slugs=(
            "dmarc",
            "dkim",
            "spf-strict",
            "mta-sts",
            "mta-sts-enforce",
            "bimi",
            "tls-rpt",
            "caa",
            "microsoft365",
            "proofpoint",
        ),
        auth_type="Federated",
        dmarc_policy="reject",
        mta_sts_mode="enforce",
        email_gateway="Proofpoint",
        evidence=evidence,
    )


class TestExposureIndexLineage:
    def test_every_weighted_component_has_one_exact_generation_time_basis(self) -> None:
        assessment = assess_exposure_from_info(_fully_observed_info())
        components = {component.component_id: component for component in assessment.index_components}

        assert set(components) == {
            "index.email.dmarc.v1",
            "index.email.dkim.v1",
            "index.email.spf-strict.v1",
            "index.email.mta-sts.v1",
            "index.email.bimi.v1",
            "index.email.tls-rpt.v1",
            "index.infrastructure.caa.v1",
            "index.identity.federation.v1",
            "index.email.gateway.v1",
        }
        assert assessment.posture_score == sum(component.awarded_points for component in components.values())
        assert assessment.unconfirmable_absent_points == sum(
            component.unconfirmable_points for component in components.values()
        )
        assert assessment.posture_score == 90
        assert assessment.unconfirmable_absent_points == 0
        assert all(component.state == "observed_value" for component in components.values())
        assert all(component.evidence for component in components.values())
        assert all(component.metadata_dependencies for component in components.values())
        assert all(component.observation_scope for component in components.values())

    def test_scalar_without_matching_record_receives_no_index_credit(self) -> None:
        info = replace(
            _fully_observed_info(),
            evidence=tuple(record for record in _fully_observed_info().evidence if record.source_type != "HTTP"),
        )

        assessment = assess_exposure_from_info(info)
        identity = next(item for item in assessment.index_components if item.control == "Federated identity")

        assert identity.state == "unresolved"
        assert identity.awarded_points == 0
        assert identity.unconfirmable_points == 10
        assert identity.evidence == ()
        assert assessment.posture_score == 80

    def test_spf_detection_without_matching_record_remains_unresolved(self) -> None:
        info = _fully_observed_info()
        assessment = assess_exposure_from_info(
            replace(
                info,
                evidence=tuple(record for record in info.evidence if record.source_type != "SPF"),
            )
        )
        spf = next(item for item in assessment.index_components if item.component_id == "index.email.spf-strict.v1")

        assert spf.state == "unresolved"
        assert spf.awarded_points == 0
        assert spf.unconfirmable_points == 10

    @pytest.mark.parametrize(
        ("component_id", "source_types", "metadata_changes"),
        [
            ("index.email.dmarc.v1", frozenset({"DMARC"}), {"dmarc_policy": None}),
            (
                "index.email.mta-sts.v1",
                frozenset({"MTA_STS", "MTA_STS_POLICY"}),
                {"mta_sts_mode": None},
            ),
            ("index.infrastructure.caa.v1", frozenset({"CAA"}), {}),
        ],
    )
    def test_declared_control_without_matching_record_remains_unresolved(
        self,
        component_id: str,
        source_types: frozenset[str],
        metadata_changes: dict[str, object],
    ) -> None:
        info = _fully_observed_info()
        evidence = tuple(record for record in info.evidence if record.source_type not in source_types)

        assessment = assess_exposure_from_info(replace(info, evidence=evidence, **metadata_changes))
        component = next(item for item in assessment.index_components if item.component_id == component_id)

        assert component.state == "unresolved"
        assert component.awarded_points == 0
        assert component.unconfirmable_points == component.maximum_points
        assert component.evidence == ()

    def test_caa_issuer_detection_without_matching_record_remains_unresolved(self) -> None:
        info = _fully_observed_info()
        evidence = tuple(record for record in info.evidence if record.source_type != "CAA")
        services = (*info.services, "CAA: Let's Encrypt")
        slugs = tuple("letsencrypt" if slug == "caa" else slug for slug in info.slugs)

        assessment = assess_exposure_from_info(replace(info, evidence=evidence, services=services, slugs=slugs))
        caa = next(item for item in assessment.index_components if item.component_id == "index.infrastructure.caa.v1")

        assert caa.state == "unresolved"
        assert caa.unconfirmable_points == 5
        assert caa.evidence == ()

    def test_conflicting_dmarc_scalar_and_record_fail_closed(self) -> None:
        info = replace(_fully_observed_info(), dmarc_policy="quarantine")

        assessment = assess_exposure_from_info(info)
        dmarc = next(item for item in assessment.index_components if item.control == "DMARC")

        assert dmarc.state == "unresolved"
        assert dmarc.awarded_points == 0
        assert dmarc.unconfirmable_points == 20
        assert assessment.posture_score == 70

    def test_degraded_channel_is_unavailable_and_cannot_retain_credit(self) -> None:
        assessment = assess_exposure_from_info(replace(_fully_observed_info(), degraded_sources=("dns:dmarc",)))
        dmarc = next(item for item in assessment.index_components if item.control == "DMARC")

        assert dmarc.state == "unavailable"
        assert dmarc.awarded_points == 0
        assert dmarc.unconfirmable_points == 20
        assert dmarc.evidence == ()
        assert "DMARC" in assessment.unavailable_controls

    def test_identity_degradation_is_listed_from_the_component_ledger(self) -> None:
        assessment = assess_exposure_from_info(
            replace(_fully_observed_info(), degraded_sources=("identity:user_realm",))
        )
        identity = next(item for item in assessment.index_components if item.control == "Federated identity")

        assert identity.state == "unavailable"
        assert assessment.unavailable_controls == ("Federated identity",)

    def test_bounded_dkim_and_gateway_non_observation_remain_unresolved(self) -> None:
        info = TenantInfo(
            tenant_id=None,
            display_name="Synthetic Quiet",
            default_domain="quiet.invalid",
            queried_domain="quiet.invalid",
            confidence=ConfidenceLevel.LOW,
        )

        assessment = assess_exposure_from_info(info)
        components = {item.control: item for item in assessment.index_components}

        assert components["DKIM"].state == "unresolved"
        assert components["Email gateway"].state == "unresolved"
        assert components["Federated identity"].state == "unresolved"
        assert assessment.posture_score == 0
        assert assessment.unconfirmable_absent_points == 30

    def test_duplicate_evidence_does_not_inflate_component_points(self) -> None:
        info = _fully_observed_info()
        assessment = assess_exposure_from_info(replace(info, evidence=info.evidence + info.evidence))

        assert assessment.posture_score == 90
        assert len(next(item for item in assessment.index_components if item.control == "DMARC").evidence) == 1

    def test_provider_specific_dkim_evidence_retains_generic_control_credit(self) -> None:
        info = _fully_observed_info()
        evidence = tuple(
            EvidenceRecord("DKIM", record.raw_value, "SendGrid DKIM", "sendgrid")
            if record.source_type == "DKIM"
            else record
            for record in info.evidence
        )

        assessment = assess_exposure_from_info(replace(info, evidence=evidence))
        dkim = next(item for item in assessment.index_components if item.control == "DKIM")

        assert dkim.state == "observed_value"
        assert dkim.awarded_points == 15
        assert dkim.evidence[0].rule_name == "SendGrid DKIM"

    def test_structured_output_exposes_the_exact_component_ledger(self) -> None:
        payload = format_exposure_dict(assess_exposure_from_info(_fully_observed_info()))
        observability = payload["observability"]

        assert observability["score_floor"] == payload["posture_score"]
        assert observability["score_ceiling"] == payload["posture_score"]
        assert observability["model_maximum_points"] == 90
        assert len(observability["components"]) == 9
        assert all(component["generator_rule_id"].startswith("index.") for component in observability["components"])
        assert all(component["metadata_dependencies"] for component in observability["components"])
        assert all(component["observation_scope"] for component in observability["components"])
        assert observability["score_is_lower_bound"] is False
        assert "fully resolved within the current component model" in observability["note"]

    def test_hypothetical_assertion_is_not_erased_by_a_degraded_live_channel(self) -> None:
        assessment = assess_exposure_from_info(
            replace(_fully_observed_info(), degraded_sources=("dns:dmarc",)),
            hypothetical_components=frozenset({"index.email.dmarc.v1"}),
        )
        dmarc = next(item for item in assessment.index_components if item.control == "DMARC")

        assert dmarc.state == "hypothetical_value"
        assert dmarc.awarded_points == 20
        assert "DMARC" not in assessment.unavailable_controls

    def test_comparison_carries_both_exact_index_ledgers(self) -> None:
        info_a = _fully_observed_info()
        info_b = replace(
            _fully_observed_info(),
            queried_domain="beta.invalid",
            default_domain="beta.onmicrosoft.com",
            evidence=tuple(record for record in _fully_observed_info().evidence if record.source_type != "DKIM"),
            services=tuple(service for service in _fully_observed_info().services if service != SVC_DKIM),
            slugs=tuple(slug for slug in _fully_observed_info().slugs if slug != "dkim"),
        )

        payload = format_comparison_dict(compare_postures_from_infos(info_a, info_b))
        metrics = {metric["metric_name"]: metric for metric in payload["metrics"]}

        assert payload["domain_a_observability"]["score_floor"] == 90
        assert payload["domain_b_observability"]["score_floor"] == 75
        assert metrics["public_evidence_index"]["domain_a_value"] == "90/100"
        assert metrics["public_evidence_index"]["domain_b_value"] == "75-90/100"

    def test_legacy_positional_assessment_remains_renderable(self) -> None:
        current = assess_exposure_from_info(_fully_observed_info())
        legacy = ExposureAssessment(
            current.domain,
            current.email_posture,
            current.identity_posture,
            current.infrastructure_footprint,
            current.consistency_observations,
            current.hardening_status,
            current.posture_score,
            current.posture_score_label,
            current.disclaimer,
            current.evidence,
            current.unconfirmable_absent_points,
            current.unavailable_controls,
        )

        assert legacy.index_components == ()
        assert format_exposure_dict(legacy)["observability"]["score_ceiling"] == 90
        assert render_exposure_panel(legacy).title == "Exposure Assessment"

    def test_legacy_positional_comparison_remains_serializable(self) -> None:
        current = compare_postures_from_infos(_fully_observed_info(), _fully_observed_info())
        legacy = PostureComparison(
            current.domain_a,
            current.domain_b,
            current.metrics,
            current.differences,
            current.relative_assessment,
            current.disclaimer,
        )

        payload = format_comparison_dict(legacy)

        assert legacy.domain_a_index_components == ()
        assert "domain_a_observability" not in payload
        assert "domain_b_observability" not in payload


class TestExposureIndexModelValidation:
    @staticmethod
    def _component(**overrides: object) -> ExposureIndexComponent:
        values: dict[str, object] = {
            "component_id": "index.email.test.v1",
            "control": "Test control",
            "state": "observed_value",
            "awarded_points": 5,
            "maximum_points": 5,
            "generator_rule_id": "index.email.test.v1",
            "metadata_dependencies": (
                ExposureMetadataDependency("dkim_observed_at_common_selectors", "eq", True, True),
            ),
            "observation_scope": ("dns:test",),
            "evidence": (EvidenceReference("TXT", "test=true", "Test", "test"),),
        }
        values.update(overrides)
        return ExposureIndexComponent(**values)  # type: ignore[arg-type]

    def test_positive_points_require_retained_evidence(self) -> None:
        with pytest.raises(ValueError, match="positive exposure-index credit requires retained evidence"):
            self._component(evidence=())

    def test_unavailable_component_cannot_award_points(self) -> None:
        with pytest.raises(ValueError, match="unavailable exposure-index component cannot award points"):
            self._component(state="unavailable")

    def test_observed_value_requires_retained_evidence_even_without_credit(self) -> None:
        with pytest.raises(ValueError, match="observed_value exposure-index component requires retained evidence"):
            self._component(awarded_points=0, evidence=())

    def test_index_rejects_duplicate_component_ids(self) -> None:
        component = self._component()
        with pytest.raises(ValueError, match="distinct component IDs"):
            ExposureIndex((component, component))

    def test_index_rejects_a_changed_component_weight(self) -> None:
        assessment = assess_exposure_from_info(_fully_observed_info())
        components = list(assessment.index_components)
        components[0] = replace(components[0], maximum_points=19, awarded_points=19)

        with pytest.raises(ValueError, match="component specification differs"):
            ExposureIndex(tuple(components))

    def test_unknown_hypothetical_component_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="unsupported hypothetical exposure component"):
            assess_exposure_from_info(
                _fully_observed_info(),
                hypothetical_components=frozenset({"index.unknown.v1"}),
            )
