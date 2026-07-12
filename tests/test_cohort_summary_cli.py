"""Integration test for `recon batch --summary` via the emit path.

Builds a small cohort of TenantInfo, runs the same _batch_emit_summary the batch
command calls, and checks the JSON document and the panel. No network.
"""

from __future__ import annotations

import contextlib
import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from rich.console import Console

from recon_tool.bayesian import load_network
from recon_tool.claim_contract import (
    DMARC_EFFECTIVE_POLICY_FIELD,
    DMARC_REJECT_CLAIM_STATE_FIELD,
    dmarc_apex_reject_dossier,
)
from recon_tool.cli import _batch_emit_summary
from recon_tool.formatter import format_tenant_dict
from recon_tool.models import (
    CandidateValue,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    PosteriorObservation,
    TenantInfo,
)

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
    **options: Any,
) -> TenantInfo:
    posteriors = options.pop("posteriors", ())
    raw_dmarc = options.pop("raw_dmarc", None)
    dmarc_pct = options.pop("dmarc_pct", None)
    dmarc_testing = options.pop("dmarc_testing", False)
    if options:
        raise ValueError(f"unsupported fixture options: {sorted(options)}")
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.HIGH,
        services=services,
        slugs=slugs,
        dmarc_policy=dmarc,
        dmarc_pct=dmarc_pct,
        dmarc_testing=dmarc_testing,
        evidence=(EvidenceRecord("DMARC", raw_dmarc or f"v=DMARC1; p={dmarc}", "DMARC", "dmarc"),),
        resolved_at=datetime.now(UTC).isoformat(),
        posterior_observations=posteriors,
    )


def _cohort() -> dict[str, TenantInfo]:
    return {
        "contoso.com": _info(
            "contoso.com",
            ("Microsoft 365",),
            ("microsoft365",),
            "reject",
            posteriors=(_po("m365_tenant", 0.93, 0.85, 0.97),),
        ),
        "northwind.com": _info(
            "northwind.com",
            ("Microsoft 365",),
            ("microsoft365",),
            "quarantine",
            posteriors=(_po("m365_tenant", 0.9, 0.82, 0.96),),
        ),
        "fabrikam.com": _info(
            "fabrikam.com",
            ("Google Workspace",),
            ("google-workspace",),
            "none",
            posteriors=(_po("google_workspace_tenant", 0.88, 0.8, 0.95),),
        ),
    }


def test_summary_json_document() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(
            _cohort(),
            attempted=5,
            console=Console(),
            as_json=True,
            schema_version="2.2",
        )
    doc = json.loads(buf.getvalue())
    assert doc["record_type"] == "cohort_summary"
    assert doc["schema_version"] == "2.2"
    assert doc["n"] == 3
    assert doc["observability"]["attempted"] == 5
    assert doc["observability"]["resolution_rate"] == 0.6
    assert doc["mix"]["provider"]["categorized_n"] == 3
    assert len(doc["mix"]["provider"]["shares"]) == 2
    assert doc["prevalence"]["dmarc_enforcing"]["observed_rate"] == 0.6667
    assert doc["prevalence"]["dmarc_reject"]["metric_kind"] == "contract_scoped_observed_rate"
    # Hideable model outputs report support coverage, not prevalence or a
    # two-sided observation fraction.
    m365 = doc["prevalence"]["m365_tenant"]
    assert m365["metric_kind"] == "model_support_coverage"
    assert m365["model_evidence_n"] == 2
    assert m365["support_coverage"] == 0.6667
    assert m365["observed_rate"] is None


def test_summary_panel_renders() -> None:
    console = Console(file=io.StringIO(), width=82, force_terminal=False)
    _batch_emit_summary(
        _cohort(),
        attempted=3,
        console=console,
        as_json=False,
        schema_version="2.2",
    )
    out = console.file.getvalue()
    assert "Cohort summary" in out
    assert "DMARC enforcing" in out


def test_batch_summary_excludes_unresolved_dmarc_units_from_denominator() -> None:
    fresh = _info("fresh.example", (), (), "reject")
    unresolved = {
        "scalar-only.example": replace(
            fresh,
            queried_domain="scalar-only.example",
            default_domain="scalar-only.example",
            evidence=(),
        ),
        "stale.example": replace(
            fresh,
            queried_domain="stale.example",
            default_domain="stale.example",
            resolved_at=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
        ),
        "unavailable.example": replace(
            fresh,
            queried_domain="unavailable.example",
            default_domain="unavailable.example",
            degraded_sources=("dns:dmarc",),
        ),
        "conflicted.example": replace(
            fresh,
            queried_domain="conflicted.example",
            default_domain="conflicted.example",
            merge_conflicts=MergeConflicts(
                dmarc_policy=(
                    CandidateValue("reject", "dns-a", "high"),
                    CandidateValue("none", "dns-b", "high"),
                )
            ),
        ),
    }
    cohort = {"fresh.example": fresh, **unresolved}

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(
            cohort,
            attempted=len(cohort),
            console=Console(),
            as_json=True,
            schema_version="2.2",
        )
    metric = json.loads(buf.getvalue())["prevalence"]["dmarc_reject"]

    assert metric["observable_n"] == 1
    assert metric["observability_fraction"] == 0.2
    assert metric["metric_kind"] == "contract_scoped_observed_rate"


def test_batch_summary_freezes_one_evaluation_time_and_keeps_annotation_private() -> None:
    cohort = _cohort()
    with patch(
        "recon_tool.claim_contract.dmarc_apex_reject_dossier",
        wraps=dmarc_apex_reject_dossier,
    ) as evaluate:
        _batch_emit_summary(
            cohort,
            attempted=3,
            console=Console(file=io.StringIO()),
            as_json=False,
            schema_version="2.2",
        )

    assert evaluate.call_count == len(cohort)
    assert len({call.kwargs["as_of"] for call in evaluate.call_args_list}) == 1
    assert all(
        DMARC_REJECT_CLAIM_STATE_FIELD not in format_tenant_dict(info)
        and DMARC_EFFECTIVE_POLICY_FIELD not in format_tenant_dict(info)
        for info in cohort.values()
    )


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


def test_summary_schema_validation() -> None:
    import pytest
    import typer

    from recon_tool.cli import _batch_validate_flags

    common = {
        "json_output": True,
        "markdown": False,
        "csv_output": False,
        "ndjson": False,
        "include_ecosystem": False,
    }
    with pytest.raises(typer.Exit):
        _batch_validate_flags(**common, summary=True, summary_schema="3.0")
    with pytest.raises(typer.Exit):
        _batch_validate_flags(**common, summary=False, summary_schema="2.2")


def test_summary_empty_batch_no_crash() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(
            {},
            attempted=4,
            console=Console(),
            as_json=True,
            schema_version="2.2",
        )
    doc = json.loads(buf.getvalue())
    assert doc["n"] == 0
    assert doc["observability"]["attempted"] == 4
    assert doc["prevalence"]["dmarc_reject"]["metric_kind"] == "contract_scoped_observed_rate"


def test_summary_defaults_to_released_v21_contract() -> None:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(_cohort(), attempted=3, console=Console(), as_json=True)

    doc = json.loads(buf.getvalue())
    assert doc["schema_version"] == "2.1"
    assert doc["prevalence"]["dmarc_reject"]["metric_kind"] == "authoritative_observed_rate"


def test_v22_enforcement_is_bound_to_raw_dmarc_modifiers() -> None:
    info = _info(
        "testing.example",
        (),
        (),
        "quarantine",
        raw_dmarc="v=DMARC1; p=quarantine; t=y",
        dmarc_testing=False,
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _batch_emit_summary(
            {"testing.example": info},
            attempted=1,
            console=Console(),
            as_json=True,
            schema_version="2.2",
        )

    prevalence = json.loads(buf.getvalue())["prevalence"]
    assert prevalence["dmarc_reject"]["observed_rate"] == 0.0
    assert prevalence["dmarc_enforcing"]["observed_rate"] == 0.0
