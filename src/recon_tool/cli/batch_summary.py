"""Aggregate-only summary construction and rendering for batch commands."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import typer

from recon_tool import claim_contract
from recon_tool.cohort_summary import build_summary_document, render_cohort_summary
from recon_tool.formatter import format_tenant_dict


def build_batch_summary_document(
    batch_infos: dict[str, Any],
    attempted: int,
    *,
    schema_version: str = "2.1",
) -> dict[str, Any]:
    """Build one aggregate-only cohort summary over the resolved batch.

    The operation is stateless: it stores no baseline, names no domain, and
    freezes one evaluation time for every record in the supplied cohort.
    """
    as_of = datetime.now(UTC)
    records = []
    for info in batch_infos.values():
        record = format_tenant_dict(info)
        if schema_version == "2.2":
            claim_state = claim_contract.dmarc_apex_reject_dossier(info, as_of=as_of).state.value
            atemporal_state, effective_policy = claim_contract.dmarc_explicit_policy_projection_from_mapping(record)
            state_is_raw_bound = claim_state == atemporal_state.value and claim_state in {
                claim_contract.ClaimState.SUPPORTED.value,
                claim_contract.ClaimState.DISCONFIRMED.value,
            }
            record[claim_contract.DMARC_REJECT_CLAIM_STATE_FIELD] = claim_state
            record[claim_contract.DMARC_EFFECTIVE_POLICY_FIELD] = effective_policy if state_is_raw_bound else None
        records.append(record)
    return build_summary_document(
        records,
        attempted=attempted,
        schema_version=schema_version,
        dmarc_contract_scoped=schema_version == "2.2",
    )


def emit_batch_summary(
    batch_infos: dict[str, Any],
    attempted: int,
    console: Any,
    *,
    as_json: bool,
    schema_version: str = "2.1",
) -> None:
    """Build and emit one aggregate-only cohort summary."""
    document = build_batch_summary_document(
        batch_infos,
        attempted,
        schema_version=schema_version,
    )
    if as_json:
        typer.echo(json.dumps(document, indent=2))
    else:
        console.print(render_cohort_summary(document))
