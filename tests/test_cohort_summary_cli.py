"""Integration test for `recon batch --summary` via the emit path.

Builds a small cohort of TenantInfo, runs the same _batch_emit_summary the batch
command calls, and checks the JSON document and the panel. No network.
"""

from __future__ import annotations

import contextlib
import io
import json

from rich.console import Console

from recon_tool.bayesian import load_network
from recon_tool.cli import _batch_emit_summary
from recon_tool.models import ConfidenceLevel, PosteriorObservation, TenantInfo

_NODES = {node.name: node for node in load_network().nodes}
_OBSERVATION_SIGNAL = {
    "m365_tenant": "m365_tenant_observed",
    "google_workspace_tenant": "google_workspace_tenant_observed",
}


def _po(name: str, p: float, lo: float, hi: float, *, fired: bool = True, sparse: bool = False) -> PosteriorObservation:
    return PosteriorObservation(
        name=name,
        description=_NODES[name].description,
        posterior=p,
        interval_low=lo,
        interval_high=hi,
        evidence_used=((f"signal:{_OBSERVATION_SIGNAL[name]}",) if fired else ()),
        n_eff=5.0,
        sparse=sparse,
    )


def _info(
    domain: str,
    services: tuple[str, ...],
    slugs: tuple[str, ...],
    dmarc: str,
    posteriors: tuple[PosteriorObservation, ...],
) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.HIGH,
        services=services,
        slugs=slugs,
        dmarc_policy=dmarc,
        posterior_observations=posteriors,
    )


def _cohort() -> dict[str, TenantInfo]:
    return {
        "contoso.com": _info(
            "contoso.com",
            ("Microsoft 365",),
            ("microsoft365",),
            "reject",
            (_po("m365_tenant", 0.93, 0.85, 0.97),),
        ),
        "northwind.com": _info(
            "northwind.com",
            ("Microsoft 365",),
            ("microsoft365",),
            "quarantine",
            (_po("m365_tenant", 0.9, 0.82, 0.96),),
        ),
        "fabrikam.com": _info(
            "fabrikam.com",
            ("Google Workspace",),
            ("google-workspace",),
            "none",
            (_po("google_workspace_tenant", 0.88, 0.8, 0.95),),
        ),
    }


def test_summary_json_document() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(_cohort(), attempted=5, console=Console(), as_json=True)
    doc = json.loads(buf.getvalue())
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.1"
    assert doc["n"] == 3
    assert doc["observability"]["attempted"] == 5
    assert doc["observability"]["resolution_rate"] == 0.6
    assert doc["mix"]["provider"]["categorized_n"] == 3
    assert len(doc["mix"]["provider"]["shares"]) == 2
    assert doc["prevalence"]["dmarc_enforcing"]["observed_rate"] == 0.6667
    # Hideable model outputs report support coverage, not prevalence or a
    # two-sided observation fraction.
    m365 = doc["prevalence"]["m365_tenant"]
    assert m365["metric_kind"] == "model_support_coverage"
    assert m365["model_evidence_n"] == 2
    assert m365["support_coverage"] == 0.6667
    assert m365["observed_rate"] is None


def test_summary_panel_renders() -> None:
    console = Console(file=io.StringIO(), width=82, force_terminal=False)
    _batch_emit_summary(_cohort(), attempted=3, console=console, as_json=False)
    out = console.file.getvalue()
    assert "Cohort summary" in out
    assert "DMARC enforcing" in out


def test_summary_rejects_include_ecosystem() -> None:
    import pytest
    import typer

    from recon_tool.cli import _batch_validate_flags

    with pytest.raises(typer.Exit):
        _batch_validate_flags(
            json_output=True,
            markdown=False,
            csv_output=False,
            ndjson=False,
            include_ecosystem=True,
            summary=True,
        )


def test_summary_empty_batch_no_crash() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary({}, attempted=4, console=Console(), as_json=True)
    doc = json.loads(buf.getvalue())
    assert doc["n"] == 0
    assert doc["observability"]["attempted"] == 4
