"""Narrow terminal wrapping preserves the established briefing and text styles."""

from __future__ import annotations

import io
from dataclasses import replace

import pytest
from rich.console import Console, Group, RenderableType
from rich.text import Text

from recon_tool.formatter import render_tenant_panel
from recon_tool.formatter.layout import wrap_indented_text
from scripts.generate_terminal_demo import demo_tenant_info


def _render(renderable: RenderableType, width: int) -> str:
    stream = io.StringIO()
    Console(file=stream, width=width, no_color=True, legacy_windows=False).print(renderable)
    return stream.getvalue()


def _content(output: str) -> str:
    return "".join(character for character in output if not character.isspace() and character != "─")


@pytest.mark.parametrize("width", [40, 60, 80])
@pytest.mark.parametrize("detailed", [False, True])
def test_narrow_panel_preserves_content_and_indents_continuations(width: int, detailed: bool) -> None:
    info = replace(demo_tenant_info(), degraded_sources=("dns:dmarc", "crt.sh", "certspotter"), ct_provider_used=None)
    panel = render_tenant_panel(info, explain=detailed)
    wide = _render(panel, 120)
    output = _render(panel, width)
    lines = output.splitlines()
    rules = [line for line in lines if line and not line.strip("─")]

    assert rules == ["─" * min(width, 78)]
    assert all(Text(line).cell_len <= width for line in lines)
    assert _content(output) == _content(wide)
    # The same renderable may be displayed again at a different width.
    assert _render(panel, 120) == wide
    assert "AllCTprovidersunavailable" in _content(output)
    if width == 40:
        provider_continuation = next(line for line in lines if line.strip().startswith("Proofpoint gateway"))
        assert provider_continuation.startswith(" " * 15)
        service_continuation = next(line for line in lines if line.strip().startswith("GitHub"))
        assert service_continuation.startswith(" " * 19)
    # Section headings remain distinct from indented body rows.
    assert "Services" in lines
    assert "Insights" in lines


@pytest.mark.parametrize("width", [78, 80, 120])
def test_normal_width_output_is_identical_to_existing_group_layout(width: int) -> None:
    panel = render_tenant_panel(demo_tenant_info())
    assert _render(panel, width) == _render(Group(*panel.renderables), width)


@pytest.mark.parametrize("width", [1, 8, 40, 60])
def test_wrapping_preserves_wide_unicode_unbroken_values_and_styles(width: int) -> None:
    text = Text("  ")
    text.append("Provider     ", style="dim")
    value = "Synthetic" + "界" * 25 + "-" + "x" * 45
    text.append(value, style="yellow")
    console = Console()

    wrapped = wrap_indented_text(text, console, width)

    assert _content(wrapped.plain) == _content(text.plain)
    # At a one-cell width a two-cell character cannot fit, but is not discarded.
    if width > 1:
        assert all(line.cell_len <= width for line in wrapped.split("\n"))
    for index, character in enumerate(wrapped.plain):
        if character in {"界", "x"}:
            assert wrapped.get_style_at_offset(console, index).color == console.get_style("yellow").color
