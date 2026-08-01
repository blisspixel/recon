"""Pure state transitions for model-bound hardening simulations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from recon_tool.exposure_models import (
    BIMI_COMPONENT_ID,
    CAA_COMPONENT_ID,
    DKIM_COMPONENT_ID,
    DMARC_COMPONENT_ID,
    DMARC_QUARANTINE_POINTS,
    MTA_STS_COMPONENT_ID,
    SPF_COMPONENT_ID,
    TLS_RPT_COMPONENT_ID,
    ExposureIndexComponent,
    exposure_component_spec,
)
from recon_tool.models import EvidenceRecord, TenantInfo
from recon_tool.validator import strip_control_chars


@dataclass
class SimulationState:
    """Mutable copy of fields that supported hardening fixes can change."""

    services: set[str]
    slugs: set[str]
    dmarc: str | None
    dmarc_pct: int | None
    dmarc_testing: bool
    dmarc_changed: bool
    mta_sts: str | None
    evidence: list[EvidenceRecord]
    hypothetical_components: set[str]
    observed_components: set[str]
    satisfied_components: set[str]
    component_points: dict[str, int]


def _mark_hypothetical_component(
    state: SimulationState,
    component_id: str,
    awarded_points: int | None = None,
    *,
    fully_satisfied: bool,
) -> None:
    """Record a scenario value so repeated fixes become exact no-ops."""
    maximum_points = exposure_component_spec(component_id)[1]
    points = maximum_points if fully_satisfied else awarded_points
    if points is None:
        raise ValueError("a partial hypothetical component requires explicit points")
    state.hypothetical_components.add(component_id)
    state.observed_components.add(component_id)
    state.component_points[component_id] = points
    if fully_satisfied:
        state.satisfied_components.add(component_id)
    else:
        state.satisfied_components.discard(component_id)


def _record_hypothetical_control(
    state: SimulationState,
    *,
    source_type: str,
    rule_name: str,
    slug: str,
    raw_value: str = "hypothetical simulation only",
) -> None:
    """Add typed simulation evidence without representing a live observation."""
    marker = EvidenceRecord(
        source_type=source_type,
        raw_value=raw_value,
        rule_name=rule_name,
        slug=slug,
    )
    if marker not in state.evidence:
        state.evidence.append(marker)


def _replace_simulated_evidence(
    state: SimulationState,
    source_types: frozenset[str],
) -> None:
    """Remove superseded evidence for a control changed by the simulation."""
    state.evidence[:] = [record for record in state.evidence if record.source_type.upper() not in source_types]


def _set_simulated_dmarc(
    state: SimulationState,
    policy: Literal["quarantine", "reject"],
) -> None:
    """Set one internally consistent hypothetical DMARC policy and proof row."""
    state.dmarc = policy
    state.dmarc_pct = None
    state.dmarc_testing = False
    state.dmarc_changed = True
    state.services.add("DMARC")
    state.slugs.discard("dmarc-invalid")
    state.slugs.add("dmarc")
    points = None if policy == "reject" else DMARC_QUARANTINE_POINTS
    _mark_hypothetical_component(
        state,
        DMARC_COMPONENT_ID,
        awarded_points=points,
        fully_satisfied=policy == "reject",
    )
    _replace_simulated_evidence(state, frozenset({"DMARC"}))
    _record_hypothetical_control(
        state,
        source_type="DMARC",
        rule_name="DMARC",
        slug="dmarc",
        raw_value=f"v=DMARC1; p={policy}",
    )


def _apply_dmarc_fix(fix: str, state: SimulationState) -> str | None:
    """Apply a DMARC fix, returning its description or null for a no-op."""
    if "reject" in fix:
        if DMARC_COMPONENT_ID in state.satisfied_components:
            return None
        _set_simulated_dmarc(state, "reject")
        return "DMARC policy set to reject"
    if "quarantine" in fix:
        if state.dmarc == "reject" or (
            DMARC_COMPONENT_ID in state.observed_components
            and state.component_points.get(DMARC_COMPONENT_ID, 0) >= DMARC_QUARANTINE_POINTS
        ):
            return None
        _set_simulated_dmarc(state, "quarantine")
        return "DMARC policy set to quarantine"
    if state.dmarc is None or state.dmarc == "none":
        _set_simulated_dmarc(state, "reject")
        return "DMARC policy set to reject"
    return None


def _apply_mta_sts_fix(fix: str, state: SimulationState) -> str | None:
    """Apply an MTA-STS fix, returning its description or null for a no-op."""
    if MTA_STS_COMPONENT_ID in state.satisfied_components:
        return None
    if "enforce" not in fix and state.mta_sts is not None:
        return None
    state.mta_sts = "enforce"
    state.services.add("MTA-STS")
    state.slugs.update({"mta-sts", "mta-sts-enforce"})
    _mark_hypothetical_component(state, MTA_STS_COMPONENT_ID, fully_satisfied=True)
    _replace_simulated_evidence(state, frozenset({"MTA_STS", "MTA_STS_POLICY"}))
    _record_hypothetical_control(
        state,
        source_type="MTA_STS",
        rule_name="MTA-STS",
        slug="mta-sts",
        raw_value="v=STSv1; id=simulation1",
    )
    _record_hypothetical_control(
        state,
        source_type="MTA_STS_POLICY",
        rule_name="MTA-STS",
        slug="mta-sts-enforce",
        raw_value="mode: enforce",
    )
    return "MTA-STS set to enforce"


def _apply_one_fix(fix: str, state: SimulationState) -> str | None:
    """Apply one lowercased supported fix using deterministic precedence."""
    if "dmarc" in fix:
        return _apply_dmarc_fix(fix, state)
    if "dkim" in fix:
        if DKIM_COMPONENT_ID in state.satisfied_components:
            return None
        state.services.add("DKIM")
        state.slugs.add("dkim")
        _mark_hypothetical_component(state, DKIM_COMPONENT_ID, fully_satisfied=True)
        _replace_simulated_evidence(state, frozenset({"DKIM"}))
        _record_hypothetical_control(state, source_type="DKIM", rule_name="DKIM", slug="dkim")
        return "DKIM configured"
    if "mta-sts" in fix:
        return _apply_mta_sts_fix(fix, state)
    if "bimi" in fix:
        if BIMI_COMPONENT_ID in state.satisfied_components:
            return None
        state.services.add("BIMI")
        state.slugs.add("bimi")
        _mark_hypothetical_component(state, BIMI_COMPONENT_ID, fully_satisfied=True)
        _replace_simulated_evidence(state, frozenset({"BIMI"}))
        _record_hypothetical_control(state, source_type="BIMI", rule_name="BIMI", slug="bimi")
        return "BIMI configured"
    if "spf" in fix and ("strict" in fix or "hardfail" in fix or "-all" in fix):
        if SPF_COMPONENT_ID in state.satisfied_components:
            return None
        state.services.add("SPF: strict (-all)")
        _mark_hypothetical_component(state, SPF_COMPONENT_ID, fully_satisfied=True)
        _replace_simulated_evidence(state, frozenset({"SPF"}))
        _record_hypothetical_control(
            state,
            source_type="SPF",
            rule_name="SPF: strict (-all)",
            slug="spf-strict",
        )
        return "SPF set to strict (-all)"
    if "tls-rpt" in fix or "tlsrpt" in fix:
        if TLS_RPT_COMPONENT_ID in state.satisfied_components:
            return None
        state.services.add("TLS-RPT")
        state.slugs.add("tls-rpt")
        _mark_hypothetical_component(state, TLS_RPT_COMPONENT_ID, fully_satisfied=True)
        state.evidence[:] = [record for record in state.evidence if record.slug != "tls-rpt"]
        _record_hypothetical_control(
            state,
            source_type="TXT",
            rule_name="TLS-RPT",
            slug="tls-rpt",
            raw_value="v=TLSRPTv1; rua=mailto:reports@example.invalid",
        )
        return "TLS-RPT configured"
    if "caa" in fix:
        if CAA_COMPONENT_ID in state.satisfied_components:
            return None
        state.slugs.add("letsencrypt")
        state.slugs.add("caa")
        _mark_hypothetical_component(state, CAA_COMPONENT_ID, fully_satisfied=True)
        _replace_simulated_evidence(state, frozenset({"CAA"}))
        _record_hypothetical_control(
            state,
            source_type="CAA",
            rule_name="CAA: Let's Encrypt",
            slug="letsencrypt",
        )
        return "CAA records configured"
    return f"Unrecognized fix: {strip_control_chars(fix)[:80]}"


def simulate_fixes(
    fixes_lower: list[str],
    info: TenantInfo,
    current_components: tuple[ExposureIndexComponent, ...] = (),
) -> tuple[list[str], SimulationState]:
    """Apply supported fixes to a fresh mutable state seeded from ``info``."""
    state = SimulationState(
        services=set(info.services),
        slugs=set(info.slugs),
        dmarc=info.dmarc_policy,
        dmarc_pct=info.dmarc_pct,
        dmarc_testing=info.dmarc_testing,
        dmarc_changed=False,
        mta_sts=info.mta_sts_mode,
        evidence=list(info.evidence),
        hypothetical_components=set(),
        observed_components={
            component.component_id for component in current_components if component.state == "observed_value"
        },
        satisfied_components={
            component.component_id
            for component in current_components
            if component.state == "observed_value" and component.awarded_points == component.maximum_points
        },
        component_points={component.component_id: component.awarded_points for component in current_components},
    )
    applied: list[str] = []
    for fix in fixes_lower:
        message = _apply_one_fix(fix, state)
        if message is not None:
            applied.append(message)
    return applied, state


__all__ = ["SimulationState", "simulate_fixes"]
