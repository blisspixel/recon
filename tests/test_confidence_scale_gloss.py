"""The panel says why its two dot scales can disagree.

`Confidence` counts corroborating sources; `Model support` is threshold-relative
against a hand-set band. Both were already documented as different questions,
and two consecutive black-box passes still read `Low (1 source)` above a filled
model display as a contradiction. A reader meets the panel before the docs, so
the gloss belongs on the row, and only where the gap is wide enough to jar.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.briefing import SCALE_GAP_NOTE, scales_disagree
from recon_tool.models import ConfidenceLevel, PosteriorObservation, TenantInfo
from tests.test_role_split_panel import split_info


def _claim(low: float) -> PosteriorObservation:
    """A claim the panel will actually render.

    The description and the evidence unit have to match the shipped network, or
    the collection view drops the row as a stale cached contract and the panel
    renders no `Model support` row at all.
    """
    from recon_tool.bayesian import load_network

    node = next(node for node in load_network().nodes if node.name == "google_workspace_tenant")
    return PosteriorObservation(
        name=node.name,
        description=node.description,
        posterior=0.88,
        interval_low=low,
        interval_high=0.99,
        evidence_used=("signal:google_workspace_tenant_observed",),
        n_eff=1.0,
        sparse=False,
    )


def _panel_text(info: TenantInfo) -> str:
    console = Console(file=io.StringIO(), width=78, no_color=True, legacy_windows=False)
    console.print(render_tenant_panel(info))
    return console.file.getvalue()


@pytest.mark.parametrize(
    ("level", "fill", "expected"),
    [
        (ConfidenceLevel.LOW, 3, True),
        (ConfidenceLevel.HIGH, 1, True),
        (ConfidenceLevel.MEDIUM, 3, False),
        (ConfidenceLevel.HIGH, 3, False),
        (ConfidenceLevel.LOW, 1, False),
    ],
)
def test_only_a_two_step_gap_earns_the_gloss(level: ConfidenceLevel, fill: int, expected: bool) -> None:
    assert scales_disagree(level, fill) is expected


def test_low_confidence_beside_a_full_model_display_explains_itself() -> None:
    from dataclasses import replace

    info = replace(
        split_info(),
        confidence=ConfidenceLevel.LOW,
        sources=("dns",),
        posterior_observations=(_claim(0.82),),
    )

    assert SCALE_GAP_NOTE in _panel_text(info)


def test_an_agreeing_record_stays_quiet() -> None:
    from dataclasses import replace

    info = replace(split_info(), posterior_observations=(_claim(0.82),))

    assert SCALE_GAP_NOTE not in _panel_text(info)
