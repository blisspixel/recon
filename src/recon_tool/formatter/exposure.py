"""Exposure / gaps / assessment rendering.

Extracted from formatter.py to keep that module under the file-size ratchet
(scripts/check_file_size.py). The public names are re-exported from
recon_tool.formatter, so the stable import path is unchanged. This module has no
dependency back on formatter (it renders ExposureAssessment / GapReport from
recon_tool.exposure), so the split introduces no import cycle.
"""

from __future__ import annotations

import json
from typing import Any

from rich.panel import Panel
from rich.text import Text

from recon_tool.exposure import ExposureAssessment, GapReport
from recon_tool.exposure_models import ExposureIndex


def _evidence_list(refs: tuple[Any, ...]) -> list[dict[str, str]]:
    """Serialize exposure evidence references without changing their order."""
    return [
        {
            "source_type": reference.source_type,
            "raw_value": reference.raw_value,
            "rule_name": reference.rule_name,
            "slug": reference.slug,
        }
        for reference in refs
    ]


def format_index_observability(
    index: ExposureIndex,
    unavailable_controls: tuple[str, ...],
) -> dict[str, Any]:
    """Serialize one validated index envelope and its exact component ledger."""
    if unavailable_controls != index.unavailable_controls:
        raise ValueError("exposure unavailable controls differ from the component ledger")
    unconfirmable = index.unconfirmable_absent_points
    hypothetical = any(component.state == "hypothetical_value" for component in index.components)
    basis_note = (
        "score_floor is scenario arithmetic over retained live evidence and explicitly labeled hypothetical "
        "component values."
        if hypothetical
        else "score_floor is the exact-evidence total from the component ledger."
    )
    resolution_note = (
        f" Up to {unconfirmable} more modeled point(s) remain unresolved because collection was unavailable, "
        "the public scope cannot establish the modeled value, or retained inputs are insufficient or "
        "inconsistent."
        if unconfirmable
        else " The public-evidence index is fully resolved within the current component model."
    )
    note = (
        basis_note
        + resolution_note
        + " Generic vendor indicators receive no active-control credit. This is not an overall security grade "
        "or certification."
    )
    return {
        "score_floor": index.score_floor,
        "score_is_lower_bound": unconfirmable > 0,
        "unconfirmable_absent_points": unconfirmable,
        "score_ceiling": index.score_ceiling,
        "model_maximum_points": index.model_maximum_points,
        "unavailable_controls": list(unavailable_controls),
        "components": [
            {
                "component_id": component.component_id,
                "control": component.control,
                "state": component.state,
                "awarded_points": component.awarded_points,
                "maximum_points": component.maximum_points,
                "unconfirmable_points": component.unconfirmable_points,
                "generator_rule_id": component.generator_rule_id,
                "metadata_dependencies": [
                    {
                        "field": item.field,
                        "operator": item.operator,
                        "expected_value": item.expected_value,
                        "observed_value": item.observed_value,
                    }
                    for item in component.metadata_dependencies
                ],
                "observation_scope": list(component.observation_scope),
                "evidence": _evidence_list(component.evidence),
            }
            for component in index.components
        ],
        "note": note,
    }


def format_observability_dict(assessment: ExposureAssessment) -> dict[str, Any]:
    """Serialize the validated index envelope from an exposure assessment."""
    if not assessment.index_components:
        unconfirmable = assessment.unconfirmable_absent_points
        return {
            "score_is_lower_bound": unconfirmable > 0,
            "unconfirmable_absent_points": unconfirmable,
            "score_ceiling": min(100, assessment.posture_score + unconfirmable),
            "unavailable_controls": list(assessment.unavailable_controls),
            "note": (
                "posture_score counts only observed-present controls; up to "
                f"{unconfirmable} more point(s) come from unresolved or unavailable control state. "
                "This compatibility-constructed assessment has no component ledger."
            ),
        }
    return format_index_observability(
        ExposureIndex(assessment.index_components),
        assessment.unavailable_controls,
    )


def format_exposure_dict(assessment: ExposureAssessment) -> dict[str, Any]:
    """Format ExposureAssessment as a dict for JSON output."""
    ep = assessment.email_posture
    ip = assessment.identity_posture
    infra = assessment.infrastructure_footprint

    d: dict[str, Any] = {
        "domain": assessment.domain,
        "posture_score": assessment.posture_score,
        "posture_score_label": assessment.posture_score_label,
        "observability": format_observability_dict(assessment),
        "email_posture": {
            "dmarc_policy": ep.dmarc_policy,
            "dkim_configured": ep.dkim_configured,
            "spf_strict": ep.spf_strict,
            "mta_sts_mode": ep.mta_sts_mode,
            "email_gateway": ep.email_gateway,
            "bimi_configured": ep.bimi_configured,
            "email_security_score": ep.email_security_score,
            "evidence": _evidence_list(ep.evidence),
        },
        "identity_posture": {
            "auth_type": ip.auth_type,
            "identity_provider": ip.identity_provider,
            "google_auth_type": ip.google_auth_type,
            "google_idp_name": ip.google_idp_name,
            "evidence": _evidence_list(ip.evidence),
        },
        "infrastructure_footprint": {
            "cloud_providers": list(infra.cloud_providers),
            "dns_provider": infra.dns_provider,
            "cdn_waf": list(infra.cdn_waf),
            "certificate_authorities": list(infra.certificate_authorities),
            "evidence": _evidence_list(infra.evidence),
        },
        "consistency_observations": [
            {
                "observation": obs.observation,
                "category": obs.category,
                "evidence": _evidence_list(obs.evidence),
            }
            for obs in assessment.consistency_observations
        ],
        "hardening_status": {
            "controls": [
                {
                    "name": ctrl.name,
                    "present": ctrl.present,
                    "detail": ctrl.detail,
                    "evidence": _evidence_list(ctrl.evidence),
                }
                for ctrl in assessment.hardening_status.controls
            ],
        },
        "disclaimer": assessment.disclaimer,
        "evidence": _evidence_list(assessment.evidence),
    }
    return d


def format_exposure_json(assessment: ExposureAssessment) -> str:
    """Format ExposureAssessment as a JSON string."""
    return json.dumps(format_exposure_dict(assessment), indent=2)


def _append_hardening_status(text: Text, assessment: ExposureAssessment) -> None:
    """Append collection-aware hardening rows to an exposure panel."""
    text.append("\n  Hardening Controls\n", style="bold")
    for control in assessment.hardening_status.controls:
        unavailable = control.detail == "source unavailable"
        mark = "?" if unavailable else "+" if control.present else "-"
        style = "yellow" if unavailable else "green" if control.present else "red"
        text.append("    ")
        text.append(mark, style=style)
        text.append(f" {control.name}: {control.detail}\n")


def _append_email_posture(text: Text, assessment: ExposureAssessment) -> None:
    """Append email controls with unavailable channels stated explicitly."""
    email = assessment.email_posture
    details = {control.name: control.detail for control in assessment.hardening_status.controls}
    unavailable = set(assessment.unavailable_controls)
    dkim = details.get("DKIM", "observed" if email.dkim_configured else "not observed at common names")
    spf = "source unavailable" if "SPF" in unavailable else "strict (-all)" if email.spf_strict else "not strict"
    text.append("\n  Email Security\n", style="bold")
    text.append(f"    DMARC:     {email.dmarc_policy or details.get('DMARC', 'not configured')}\n")
    text.append(f"    DKIM:      {dkim}\n")
    text.append(f"    SPF:       {spf}\n")
    text.append(f"    MTA-STS:   {email.mta_sts_mode or details.get('MTA-STS', 'not configured')}\n")
    text.append(f"    BIMI:      {details.get('BIMI', 'configured' if email.bimi_configured else 'not configured')}\n")
    if email.email_gateway:
        text.append(f"    Gateway:   {email.email_gateway}\n")
    elif "Email gateway" in unavailable:
        text.append("    Gateway:   source unavailable\n")


def _append_index_summary(
    text: Text,
    assessment: ExposureAssessment,
    index: ExposureIndex | None,
) -> None:
    """Append the compatible score line and exact ledger detail when present."""
    text.append("  Public-evidence index: ", style="dim")
    score = index.score_floor if index is not None else assessment.posture_score
    score_style = "#a3d9a5" if score >= 60 else "#7ec8e3" if score >= 30 else "#e07a5f"
    text.append(f"{score}/100", style=score_style)
    text.append(f" ({assessment.posture_score_label})\n", style="dim")
    if index is None:
        if assessment.unconfirmable_absent_points:
            ceiling = min(100, score + assessment.unconfirmable_absent_points)
            text.append(
                f"    (lower bound; up to {ceiling}/100 if unresolved controls are present)\n",
                style="dim",
            )
        return

    text.append(f"    Evidence-bound range: {score}-{index.score_ceiling}/100\n", style="dim")
    text.append(f"    Current model allocation: {index.model_maximum_points}/100 points\n", style="dim")
    credited = [
        f"{component.control} +{component.awarded_points}"
        for component in assessment.index_components
        if component.awarded_points
    ]
    text.append(
        f"    Index basis: {', '.join(credited) if credited else 'no credited public controls'}\n",
        style="dim",
    )
    unresolved = [
        component.control
        for component in assessment.index_components
        if component.state in {"unavailable", "unresolved"}
    ]
    if unresolved:
        text.append(f"    Unresolved capacity: {', '.join(unresolved)}\n", style="dim")


def render_exposure_panel(assessment: ExposureAssessment) -> Panel:
    """Render ExposureAssessment as a Rich panel with categorized sections."""
    text = Text()
    index = ExposureIndex(assessment.index_components) if assessment.index_components else None

    text.append("  Domain: ", style="dim")
    text.append(f"{assessment.domain}\n")
    _append_index_summary(text, assessment, index)

    _append_email_posture(text, assessment)

    # Identity posture
    ip = assessment.identity_posture
    text.append("\n  Identity\n", style="bold")
    text.append(f"    Auth Type: {ip.auth_type or 'unknown'}\n")
    if ip.identity_provider:
        text.append(f"    IdP:       {ip.identity_provider}\n")
    if ip.google_auth_type:
        label = ip.google_auth_type
        if ip.google_idp_name:
            label += f" ({ip.google_idp_name})"
        text.append(f"    GWS Auth:  {label}\n")

    # Infrastructure
    infra = assessment.infrastructure_footprint
    text.append("\n  Infrastructure\n", style="bold")
    if infra.cloud_providers:
        text.append(f"    Cloud:     {', '.join(infra.cloud_providers)}\n")
    if infra.dns_provider:
        text.append(f"    DNS:       {infra.dns_provider}\n")
    if infra.cdn_waf:
        text.append(f"    CDN/WAF:   {', '.join(infra.cdn_waf)}\n")
    if infra.certificate_authorities:
        text.append(f"    CAA issuers: {', '.join(infra.certificate_authorities)}\n")

    # Consistency observations
    if assessment.consistency_observations:
        text.append("\n  Consistency\n", style="bold")
        for obs in assessment.consistency_observations:
            text.append(f"    - {obs.observation}\n", style="#e6c07b")

    _append_hardening_status(text, assessment)

    return Panel(
        text,
        title="Exposure Assessment",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Gap report rendering ────────────────────────────────────────────────

_SEVERITY_COLORS: dict[str, str] = {
    "high": "#e07a5f",
    "medium": "#e6c07b",
    "low": "#7ec8e3",
}

_SEVERITY_INDICATORS: dict[str, str] = {
    "high": "●",
    "medium": "◐",
    "low": "○",
}

_GAP_STATE_LABELS: dict[str, str] = {
    "observed_weak_configuration": "observed weak configuration",
    "bounded_non_observation": "bounded non-observation",
    "unresolved_hideable_state": "unresolved; bounded selectors only",
    "observed_configuration_inconsistency": "observed configuration inconsistency",
}


def format_gaps_dict(report: GapReport) -> dict[str, Any]:
    """Format GapReport as a dict for JSON output."""
    if any(gap.observation_state is None for gap in report.gaps):
        raise ValueError("cannot format a hardening gap without complete generation-time lineage")
    return {
        "domain": report.domain,
        "gaps": [
            {
                "category": gap.category,
                "severity": gap.severity,
                "observation": gap.observation,
                "recommendation": gap.recommendation,
                "generator_rule_id": gap.generator_rule_id,
                "observation_state": gap.observation_state,
                "observation_scope": list(gap.observation_scope),
                "metadata_dependencies": [
                    {
                        "field": item.field,
                        "operator": item.operator,
                        "expected_value": item.expected_value,
                        "observed_value": item.observed_value,
                    }
                    for item in gap.metadata_dependencies
                ],
                # False = this gap rests on not observing a hideable control, so
                # it may be a false positive (the control could be present but
                # unobservable). True = a confirmed public-records fact.
                "absence_confirmable": gap.absence_confirmable,
                "evidence": [
                    {
                        "source_type": r.source_type,
                        "raw_value": r.raw_value,
                        "rule_name": r.rule_name,
                        "slug": r.slug,
                    }
                    for r in gap.evidence
                ],
            }
            for gap in report.gaps
        ],
        "disclaimer": report.disclaimer,
        "unavailable_controls": list(report.unavailable_controls),
        "degraded_sources": list(report.degraded_sources),
    }


def format_gaps_json(report: GapReport) -> str:
    """Format GapReport as a JSON string."""
    return json.dumps(format_gaps_dict(report), indent=2)


def render_gaps_panel(report: GapReport) -> Panel:
    """Render GapReport as a Rich panel with gaps grouped by category."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{report.domain}\n")

    if report.unavailable_controls:
        text.append("\n  Collection unavailable for: ", style="yellow")
        text.append(", ".join(report.unavailable_controls), style="yellow")
        text.append(". No absence conclusion is drawn for those controls.\n", style="dim")

    if not report.gaps:
        message = (
            "No additional observed hardening gaps detected."
            if report.unavailable_controls
            else "No hardening gaps detected."
        )
        text.append(f"\n  {message}", style="dim italic")
    else:
        # Group by category
        groups: dict[str, list[Any]] = {}
        for gap in report.gaps:
            groups.setdefault(gap.category, []).append(gap)

        for category, gaps in groups.items():
            text.append(f"\n  {category.replace('_', ' ').title()}\n", style="bold")
            for gap in gaps:
                indicator = _SEVERITY_INDICATORS.get(gap.severity, "○")
                color = _SEVERITY_COLORS.get(gap.severity, "dim")
                state_label = _GAP_STATE_LABELS.get(gap.observation_state or "", "lineage unavailable")
                text.append(f"    {indicator} ", style=color)
                text.append(f"[{gap.severity}] [{state_label}] ", style=color)
                text.append(f"{gap.observation}\n")
                text.append(f"      → {gap.recommendation}\n", style="dim")

    text.append(f"\n  {report.disclaimer}", style="dim italic")

    return Panel(
        text,
        title="Hardening Gaps",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )
