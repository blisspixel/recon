"""Positive Bayesian scenarios must fail before arithmetic if roles disappear."""

from __future__ import annotations

from dataclasses import replace

import pytest

from recon_tool.bayesian import infer_from_tenant_info, load_network
from recon_tool.models import EvidenceRecord, TenantInfo
from tests.bayesian_scenarios import ObservationScenario, assert_scenario_preconditions, shipped_scenarios


@pytest.mark.parametrize("scenario", shipped_scenarios(), ids=lambda scenario: scenario.name)
def test_named_scenarios_fire_their_current_role_contract(scenario: ObservationScenario) -> None:
    assert_scenario_preconditions(load_network(), scenario)


@pytest.mark.parametrize("scenario", shipped_scenarios()[:2], ids=lambda scenario: scenario.name)
def test_removing_identity_observations_fails_the_scenario_precondition(scenario: ObservationScenario) -> None:
    without_identity = replace(
        scenario.info,
        tenant_id=None,
        auth_type=None,
        google_auth_type=None,
        evidence=tuple(record for record in scenario.info.evidence if record.source_type != "HTTP"),
    )
    with pytest.raises(AssertionError, match="must fire"):
        assert_scenario_preconditions(load_network(), replace(scenario, info=without_identity))


@pytest.mark.parametrize("slug", ["microsoft365", "entra-id", "exchange-online", "google-workspace", "gmail", "okta"])
def test_generic_inventory_and_verification_txt_remain_nonbinding(slug: str) -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic",
        default_domain="example.com",
        queried_domain="example.com",
        slugs=(slug,),
        evidence=(EvidenceRecord("TXT", "synthetic-verification=opaque", "Synthetic inventory", slug),),
    )
    result = infer_from_tenant_info(info, network=load_network(), priors_override={})
    for posterior in result.posteriors:
        assert posterior.evidence_used == ()
        if posterior.name in {"m365_tenant", "google_workspace_tenant", "okta_idp"}:
            assert posterior.sparse
            assert posterior.n_eff == 4.0


def test_scenario_checks_never_load_operator_local_prior_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_override() -> dict[str, float]:
        pytest.fail("Assurance scenarios must use explicit default priors")

    monkeypatch.setattr("recon_tool.bayesian.load_priors_override", forbidden_override)
    for scenario in shipped_scenarios():
        assert_scenario_preconditions(load_network(), scenario)
