"""Shared shipped-model scenario contracts, independent of numeric assertions.

These fixtures exercise the real TenantInfo-to-role adapter. Their explicit
binding, effective-unit and sparse-state preconditions keep sensitivity and
pipeline tests from passing after a positive scenario silently becomes inert.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace

from recon_tool.bayesian import BayesianNetwork, InferenceResult, infer, infer_from_tenant_info
from recon_tool.bayesian_observations import signals_from_tenant_info
from recon_tool.models import EvidenceRecord, TenantInfo


@dataclass(frozen=True)
class ObservationScenario:
    """Synthetic observations and the direct bindings they must activate."""

    name: str
    info: TenantInfo
    bindings: tuple[tuple[str, tuple[str, ...], int], ...]

    @property
    def inputs(self) -> tuple[list[str], list[str]]:
        return list(self.info.slugs), sorted(signals_from_tenant_info(self.info))


def assert_fired_signals(result: InferenceResult, signals: Iterable[str]) -> None:
    """Require the named current observation contract before comparing numbers."""
    fired = {binding for posterior in result.posteriors for binding in posterior.evidence_used}
    expected = {f"signal:{signal}" for signal in signals}
    assert expected <= fired, f"Required bound observations did not fire: {sorted(expected - fired)}"


def _empty_info() -> TenantInfo:
    return TenantInfo(
        tenant_id=None, display_name="Synthetic", default_domain="example.com", queried_domain="example.com"
    )


def shipped_scenarios() -> tuple[ObservationScenario, ...]:
    """Return M365, GWS and empty cases with explicit role provenance."""
    controls = (
        EvidenceRecord("DKIM", "selector._domainkey.example.com", "Synthetic DKIM", "dkim"),
        EvidenceRecord("SPF", "v=spf1 -all", "Synthetic SPF", "spf-strict"),
    )
    policy = (
        "email_security_policy_enforcing",
        ("signal:dmarc_reject", "signal:mta_sts_enforce", "signal:spf_strict"),
        3,
    )
    base = replace(_empty_info(), dmarc_policy="reject", mta_sts_mode="enforce")
    m365 = replace(
        base,
        tenant_id="00000000-0000-4000-8000-000000000001",
        auth_type="Federated",
        evidence=(*controls, EvidenceRecord("HTTP", "Synthetic tenant response", "Synthetic identity", "microsoft365")),
    )
    gws = replace(
        base,
        google_auth_type="Managed",
        evidence=(
            *controls,
            EvidenceRecord("HTTP", "Synthetic routing response", "Synthetic identity", "google-workspace"),
        ),
    )
    return (
        ObservationScenario(
            "dense_m365_stack",
            m365,
            (
                ("m365_tenant", ("signal:m365_tenant_observed",), 1),
                ("federated_identity", ("signal:federated_sso_hub",), 1),
                policy,
            ),
        ),
        ObservationScenario(
            "dense_gws_stack",
            gws,
            (("google_workspace_tenant", ("signal:google_workspace_tenant_observed",), 1), policy),
        ),
        ObservationScenario("empty_observation", _empty_info(), ()),
    )


def assert_scenario_preconditions(network: BayesianNetwork, scenario: ObservationScenario) -> InferenceResult:
    """Reject a vacuous scenario before any numerical property is evaluated."""
    result = infer_from_tenant_info(scenario.info, network=network, priors_override={})
    by_name = {posterior.name: posterior for posterior in result.posteriors}
    baseline = {posterior.name: posterior for posterior in infer(network, (), (), priors_override={}).posteriors}
    expected_nodes = {name for name, _, _ in scenario.bindings}
    for name, bindings, units in scenario.bindings:
        posterior = by_name[name]
        assert set(posterior.evidence_used) == set(bindings), f"{scenario.name}: {name} must fire {bindings}"
        mass = network.calibration.min_n_eff + units * network.calibration.evidence_n_eff_contrib
        assert posterior.n_eff == round(mass, 2), f"{scenario.name}: {name} must retain {units} effective units"
        assert posterior.n_eff > network.calibration.min_n_eff
        assert not posterior.sparse
        assert posterior.posterior > baseline[name].posterior, f"{scenario.name}: {name} must move above baseline"
    for node in network.nodes:
        if node.name not in expected_nodes:
            assert by_name[node.name].evidence_used == (), f"{scenario.name}: unexpected direct binding on {node.name}"
        if not scenario.bindings and node.missingness == "hideable":
            assert by_name[node.name].sparse
    return result
