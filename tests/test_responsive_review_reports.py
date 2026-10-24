"""Whole identifiers, stable hanging indents and real boxed widths."""

from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from rich.cells import cell_len
from rich.console import Console
from rich.panel import Panel
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.exposure import assess_exposure_from_info, find_gaps_from_info
from recon_tool.formatter.delta import render_delta_panel
from recon_tool.formatter.exposure import render_exposure_panel, render_gaps_panel
from recon_tool.formatter.serialize import format_tenant_json
from recon_tool.formatter.terminal import get_console
from recon_tool.models import DeltaReport, TenantInfo

_WIDTHS = (40, 79, 80, 99, 100, 120)


def _info() -> TenantInfo:
    return TenantInfo(tenant_id=None, display_name="", default_domain="example.com", queried_domain="example.com")


def _render(panel: Panel, width: int) -> str:
    stream = io.StringIO()
    Console(file=stream, width=width, no_color=True, legacy_windows=False).print(panel, crop=False)
    return stream.getvalue()


def _delta() -> DeltaReport:
    return DeltaReport(
        domain="example.com",
        added_services=(
            "Synthetic mail configuration observation with a deliberately long description that wraps to a second line",
        ),
        removed_services=(),
        added_slugs=(),
        removed_slugs=(),
        added_signals=(),
        removed_signals=(),
    )


@pytest.mark.parametrize("width", _WIDTHS)
@pytest.mark.parametrize("surface", ["gaps", "exposure", "delta"])
def test_review_boxes_use_the_console_width_capped_at_100(width: int, surface: str) -> None:
    panel = {
        "gaps": render_gaps_panel(find_gaps_from_info(_info())),
        "exposure": render_exposure_panel(assess_exposure_from_info(_info())),
        "delta": render_delta_panel(_delta()),
    }[surface]
    output = _render(panel, width)
    lines = output.splitlines()
    assert "\x1b" not in output
    if width >= 80:
        assert max(map(cell_len, lines)) == min(width, 100)
    assert all(cell_len(line) <= min(width, 100) for line in lines)
    boxed = [line for line in lines if line.startswith("\N{BOX DRAWINGS LIGHT VERTICAL}")]
    assert bool(boxed) is (width >= 80)
    assert all(cell_len(line) == min(width, 100) for line in boxed)
    # Rendering one instance again must not retain its previous console width.
    assert max(map(cell_len, _render(panel, 100).splitlines())) == 100


@pytest.mark.parametrize("width", _WIDTHS)
def test_gap_and_recommendation_continuations_hang_after_the_marker(width: int) -> None:
    report = find_gaps_from_info(_info())
    dkim = next(gap for gap in report.gaps if "dkim" in gap.generator_rule_id)
    output = _render(render_gaps_panel(replace(report, gaps=(dkim,))), width)
    lines = output.splitlines()
    marker = next(index for index, line in enumerate(lines) if "[medium]" in line)
    arrow = next(index for index, line in enumerate(lines) if "Consider verifying" in line)
    marker_column = lines[marker].index("[medium]")
    arrow_column = lines[arrow].index("Consider")
    for line in lines[marker + 1 : arrow]:
        text = line.removeprefix("\N{BOX DRAWINGS LIGHT VERTICAL}").rstrip("\N{BOX DRAWINGS LIGHT VERTICAL} ")
        assert len(text) - len(text.lstrip()) >= marker_column - (1 if width >= 80 else 0)
    for line in lines[arrow + 1 :]:
        text = line.removeprefix("\N{BOX DRAWINGS LIGHT VERTICAL}").rstrip("\N{BOX DRAWINGS LIGHT VERTICAL} ")
        if not text.strip():
            break
        assert len(text) - len(text.lstrip()) >= arrow_column - (1 if width >= 80 else 0)


@pytest.mark.parametrize("width", _WIDTHS)
def test_delta_continuations_stay_under_the_value_marker(width: int) -> None:
    lines = _render(render_delta_panel(_delta()), width).splitlines()
    start = next(index for index, line in enumerate(lines) if "+ Service:" in line)
    column = lines[start].index("Service:")
    for line in lines[start + 1 :]:
        text = line.removeprefix("\N{BOX DRAWINGS LIGHT VERTICAL}").rstrip("\N{BOX DRAWINGS LIGHT VERTICAL} ")
        if not text.strip():
            break
        assert len(text) - len(text.lstrip()) >= column - (1 if width >= 80 else 0)


@pytest.mark.parametrize("width", _WIDTHS)
def test_an_identifier_wider_than_the_box_stays_whole_without_a_border(width: int) -> None:
    identifier = (
        "https://long-reserved-synthetic-identifier.example.com/a/long/path/that/must/remain/copyable/without/a/break"
    )
    report = replace(_delta(), added_services=(identifier,))
    output = _render(render_delta_panel(report), width)
    assert identifier in output
    assert "\N{BOX DRAWINGS LIGHT VERTICAL}" not in output


@pytest.mark.parametrize("width", _WIDTHS)
@pytest.mark.parametrize("mode", ["--gaps", "--exposure", "--compare", "delta"])
def test_cli_no_color_and_ascii_reports_wrap_once(
    width: int, mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("TERM", "xterm-256color")
    info = _info()
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(format_tenant_json(info))
    args = ["delta", "example.com"] if mode == "delta" else ["example.com", mode]
    if mode == "--compare":
        args.append(str(snapshot))
    args.extend(["--ascii", "--no-color"])
    with (
        patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(info, []))),
        patch("recon_tool.cache.cache_get", return_value=info),
        patch("recon_tool.cache.cache_put"),
    ):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert result.output.isascii()
    assert "\x1b" not in result.output
    # Legacy Windows consoles can reserve the last COLUMNS cell. The box
    # follows the actual console width, which is the operator's usable space.
    actual_width = get_console().width
    assert all(cell_len(line) <= min(actual_width, 100) for line in result.output.splitlines())
    if actual_width >= 80:
        assert max(map(cell_len, result.output.splitlines())) == min(actual_width, 100)
