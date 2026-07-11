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


def format_exposure_dict(assessment: ExposureAssessment) -> dict[str, Any]:
    """Format ExposureAssessment as a dict for JSON output."""

    def _evidence_list(refs: tuple[Any, ...]) -> list[dict[str, str]]:
        return [
            {
                "source_type": r.source_type,
                "raw_value": r.raw_value,
                "rule_name": r.rule_name,
                "slug": r.slug,
            }
            for r in refs
        ]

    ep = assessment.email_posture
    ip = assessment.identity_posture
    infra = assessment.infrastructure_footprint

    unconfirmable = assessment.unconfirmable_absent_points
    d: dict[str, Any] = {
        "domain": assessment.domain,
        "posture_score": assessment.posture_score,
        "posture_score_label": assessment.posture_score_label,
        # The score counts only observed-present controls, so it is a lower
        # bound. This envelope tells a consuming agent how much that floor could
        # understate the true posture: a low score may mean "hardened but quiet",
        # not "weak". A declarative record counts toward the ceiling only when
        # its collection channel was unavailable.
        "observability": {
            "score_is_lower_bound": unconfirmable > 0,
            "unconfirmable_absent_points": unconfirmable,
            "score_ceiling": min(100, assessment.posture_score + unconfirmable),
            "unavailable_controls": list(assessment.unavailable_controls),
            "note": (
                "posture_score counts only observed-present controls; up to "
                f"{unconfirmable} more point(s) come from controls whose absence "
                "the passive channel cannot confirm (DKIM at non-standard "
                "selectors, an email gateway behind non-MX routing, or a "
                "temporarily unavailable declarative channel). Generic vendor "
                "indicators receive no active-control credit. "
                "A low score may reflect limited observability, not weak posture."
            ),
        },
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


def render_exposure_panel(assessment: ExposureAssessment) -> Panel:
    """Render ExposureAssessment as a Rich panel with categorized sections."""
    text = Text()

    text.append("  Domain: ", style="dim")
    text.append(f"{assessment.domain}\n")
    text.append("  Posture Score: ", style="dim")
    score = assessment.posture_score
    score_style = "#a3d9a5" if score >= 60 else "#7ec8e3" if score >= 30 else "#e07a5f"
    text.append(f"{score}/100", style=score_style)
    text.append(f" ({assessment.posture_score_label})\n", style="dim")
    if assessment.unconfirmable_absent_points > 0:
        ceiling = min(100, score + assessment.unconfirmable_absent_points)
        text.append(
            f"    (lower bound; up to {ceiling}/100 if unobservable controls are present)\n",
            style="dim",
        )

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


def format_gaps_dict(report: GapReport) -> dict[str, Any]:
    """Format GapReport as a dict for JSON output."""
    return {
        "domain": report.domain,
        "gaps": [
            {
                "category": gap.category,
                "severity": gap.severity,
                "observation": gap.observation,
                "recommendation": gap.recommendation,
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
                text.append(f"    {indicator} ", style=color)
                text.append(f"[{gap.severity}] ", style=color)
                text.append(f"{gap.observation}\n")
                text.append(f"      → {gap.recommendation}\n", style="dim")

    return Panel(
        text,
        title="Hardening Gaps",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )
