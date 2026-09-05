"""Aggregate index emphasis stays neutral across magnitude and collection state."""

from __future__ import annotations

from dataclasses import replace

import pytest
from rich.console import Console
from rich.text import Text

from recon_tool.exposure import assess_exposure_from_info
from recon_tool.formatter.exposure import format_exposure_dict, render_exposure_panel
from recon_tool.models import TenantInfo


def _assert_neutral_index(text: Text, score: int) -> None:
    label = f"{score}/100"
    offset = text.plain.index(label)
    console = Console()
    for position in range(offset, offset + len(label)):
        style = text.get_style_at_offset(console, position)
        assert style.color is None
        assert style.bgcolor is None
        assert style.bold is True


@pytest.mark.parametrize("score", [0, 29, 30, 59, 60, 90, 100])
def test_compatible_index_magnitudes_share_neutral_emphasis(
    fully_populated_tenant_info: TenantInfo, score: int
) -> None:
    assessment = replace(
        assess_exposure_from_info(fully_populated_tenant_info),
        index_components=(),
        posture_score=score,
    )
    before = format_exposure_dict(assessment)
    panel = render_exposure_panel(assessment)
    assert isinstance(panel.renderable, Text)

    _assert_neutral_index(panel.renderable, score)
    assert format_exposure_dict(assessment) == before
    assert before["posture_score"] == score


@pytest.mark.parametrize("degraded_sources", [(), ("dns:dmarc",), ("source:dns_records",)])
def test_ledger_index_stays_neutral_without_removing_control_status_styles(
    fully_populated_tenant_info: TenantInfo, degraded_sources: tuple[str, ...]
) -> None:
    assessment = assess_exposure_from_info(replace(fully_populated_tenant_info, degraded_sources=degraded_sources))
    before = format_exposure_dict(assessment)
    panel = render_exposure_panel(assessment)
    assert isinstance(panel.renderable, Text)
    text = panel.renderable

    _assert_neutral_index(text, assessment.posture_score)
    assert "Evidence-bound range:" in text.plain
    assert "Current model allocation: 90/100 points" in text.plain
    assert format_exposure_dict(assessment) == before
    for control in assessment.hardening_status.controls:
        unavailable = control.detail == "source unavailable"
        marker = "?" if unavailable else "+" if control.present else "-"
        expected = "yellow" if unavailable else "green" if control.present else "red"
        offset = text.plain.index(f"{marker} {control.name}: {control.detail}")
        assert text.get_style_at_offset(Console(), offset).color == Console().get_style(expected).color
