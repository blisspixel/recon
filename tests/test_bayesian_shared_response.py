"""Bounded shared-origin characterization, not an independence estimator."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from recon_tool.bayesian import InferenceResult, NodePosterior, infer_from_tenant_info, load_network
from recon_tool.bayesian_observations import signals_from_tenant_info
from recon_tool.models import CandidateValue, EvidenceRecord, MergeConflicts, TenantInfo

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "src/recon_tool/data/bayesian_network.yaml"
RECEIPT = ROOT / "validation/shared-response-characterization-2026-10-23.json"
IDENTITY_NODES = ("m365_tenant", "google_workspace_tenant", "federated_identity", "okta_idp")
GOOGLE_UNITS = ("google_workspace_tenant_observed", "federated_sso_hub", "okta_idp_observed")
GOOGLE = EvidenceRecord("HTTP", "Synthetic Google routing response", "Synthetic Google identity", "google-workspace")
MAIL = EvidenceRecord("MX", "10 aspmx.l.google.com.", "Synthetic Google mail route", "google-workspace")
M365 = EvidenceRecord("HTTP", "Synthetic Microsoft response", "Synthetic Microsoft identity", "microsoft365")


def _empty() -> TenantInfo:
    return TenantInfo(
        tenant_id=None, display_name="Synthetic", default_domain="example.com", queried_domain="example.com"
    )


def _response() -> TenantInfo:
    return replace(_empty(), google_auth_type="Federated", google_idp_name="Okta", evidence=(GOOGLE,))


def _withdraw_google(info: TenantInfo) -> TenantInfo:
    """Withdraw this fixture's declared origin, not every HTTP or Google role.

    Field ownership and record identity are declared here, not inferred from a
    production response string. Remove duplicate copies of that same record.
    Keep unrelated records, contradictions and source-availability metadata.
    """
    return replace(
        info,
        google_auth_type=None,
        google_idp_name=None,
        evidence=tuple(record for record in info.evidence if record != GOOGLE),
    )


def _run(info: TenantInfo, masks: tuple[str, ...] = ()) -> InferenceResult:
    return infer_from_tenant_info(info, network=load_network(), priors_override={}, masked_units=masks)


def _nodes(result: InferenceResult) -> dict[str, NodePosterior]:
    return {node.name: node for node in result.posteriors if node.name in IDENTITY_NODES}


def _model_digest(path: Path) -> str:
    """Hash UTF-8 source text with universal-newline normalization."""
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def characterization() -> dict[str, object]:
    """Recompute fixed-input diagnostics, including local explanations."""
    response = _response()
    with_mail = replace(response, evidence=(GOOGLE, MAIL))
    cases = {
        "empty": (_empty(), ()),
        "one_response": (response, ()),
        "duplicate_ingestion": (replace(response, evidence=(GOOGLE, GOOGLE)), ()),
        "distinct_mx_added": (with_mail, ()),
        "withdraw_response": (_withdraw_google(response), ()),
        "withdraw_response_keep_mx": (_withdraw_google(with_mail), ()),
        "mask_all_derived_units": (response, GOOGLE_UNITS),
        **{f"mask_{unit}": (response, (unit,)) for unit in GOOGLE_UNITS},
    }
    diagnostics = {}
    for name, (info, masks) in cases.items():
        result = _run(info, masks)
        diagnostics[name] = {
            "adapter_signals": sorted(signals_from_tenant_info(info)),
            "masked_units": list(masks),
            "fired_binding_count": result.evidence_count,
            "identity_nodes": {name: asdict(node) for name, node in _nodes(result).items()},
        }
    return {"model_sha256": _model_digest(MODEL), "cases": diagnostics}


def test_declared_response_fires_three_local_bindings_from_one_origin() -> None:
    response = _response()
    assert signals_from_tenant_info(response) == set(GOOGLE_UNITS)
    result = _run(response)
    assert result.evidence_count == 3
    for name, unit in zip(IDENTITY_NODES[1:], GOOGLE_UNITS, strict=True):
        node = _nodes(result)[name]
        assert node.evidence_used == (f"signal:{unit}",)
        assert node.n_eff == 5.0
        assert not node.sparse
    # The root without local evidence moves through an observed descendant.
    m365 = _nodes(result)["m365_tenant"]
    assert not m365.evidence_used
    assert m365.sparse
    assert m365.posterior > _nodes(_run(_empty()))["m365_tenant"].posterior


@pytest.mark.parametrize("records", [(GOOGLE, GOOGLE), (GOOGLE, MAIL), (MAIL, GOOGLE, GOOGLE)])
def test_boolean_role_contract_does_not_count_duplicate_or_corroborating_records(
    records: tuple[EvidenceRecord, ...],
) -> None:
    assert _run(replace(_response(), evidence=records)) == _run(_response())


@pytest.mark.parametrize("unit", GOOGLE_UNITS)
def test_one_unit_counterfactual_is_not_complete_response_withdrawal(unit: str) -> None:
    response = _response()
    baseline = _nodes(_run(_withdraw_google(response)))
    masked = _nodes(_run(response, (unit,)))
    assert sum(len(node.evidence_used) for node in masked.values()) == 2
    # At least one other consequence still directly supports a connected node.
    assert any(node.posterior != baseline[name].posterior for name, node in masked.items())
    original = _nodes(_run(response))
    for name, node in original.items():
        counterfactual = next((item for item in node.unit_counterfactuals if item.unit == unit), None)
        if counterfactual is not None:
            assert counterfactual.posterior_without == masked[name].posterior
    assert _run(response, GOOGLE_UNITS) == _run(_withdraw_google(response))


def test_response_withdrawal_preserves_distinct_mx_and_unrelated_http_support() -> None:
    response = replace(
        _response(),
        tenant_id="00000000-0000-4000-8000-000000000001",
        auth_type="Managed",
        evidence=(GOOGLE, GOOGLE, MAIL, M365),
    )
    withdrawn = _withdraw_google(response)
    assert withdrawn.evidence == (MAIL, M365)
    assert withdrawn.tenant_id == response.tenant_id
    assert withdrawn.auth_type == "Managed"
    nodes = _nodes(_run(withdrawn))
    for name in IDENTITY_NODES[:2]:
        assert nodes[name].evidence_used
        assert nodes[name].n_eff == 5.0
    for name in IDENTITY_NODES[2:]:
        assert not nodes[name].evidence_used
        assert nodes[name].sparse
    # A global role mask also suppresses legitimate MX support. It therefore
    # cannot stand in for removing only the identity response's consequences.
    masked = _nodes(_run(response, GOOGLE_UNITS))
    assert nodes["google_workspace_tenant"].posterior > masked["google_workspace_tenant"].posterior


def test_withdrawal_keeps_conflicts_and_unavailable_metadata_without_inventing_absence() -> None:
    conflicts = MergeConflicts(
        google_auth_type=(
            CandidateValue("Federated", "synthetic-response", "high"),
            CandidateValue("Managed", "synthetic-other", "high"),
        )
    )
    info = replace(_response(), merge_conflicts=conflicts, degraded_sources=("dns:mx",))
    result = _run(info)
    assert result.conflict_count == 1
    for node in _nodes(result).values():
        assert node.conflict_provenance[0].field == "google_auth_type"
        assert node.n_eff == 4.0
        assert node.sparse
    withdrawn = _withdraw_google(info)
    assert withdrawn.merge_conflicts is conflicts
    assert withdrawn.degraded_sources == ("dns:mx",)
    for node in _nodes(_run(withdrawn)).values():
        assert not node.evidence_used
        assert not node.absence_informative
        assert node.sparse
    assert _withdraw_google(_empty()) == _empty()


def test_dated_receipt_reproduces_committed_model_diagnostics() -> None:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    assert receipt["characterization"] == json.loads(json.dumps(characterization()))


def test_model_digest_normalizes_checkout_line_endings_and_still_detects_content_changes(tmp_path: Path) -> None:
    path = tmp_path / "model.yaml"
    canonical = MODEL.read_text(encoding="utf-8").encode("utf-8")
    expected = _model_digest(MODEL)
    path.write_bytes(canonical)
    assert _model_digest(path) == expected
    path.write_bytes(canonical.replace(b"\n", b"\r\n"))
    assert _model_digest(path) == expected
    path.write_bytes(canonical + b"\n# changed model source\n")
    assert _model_digest(path) != expected
