"""User-facing hints stay visible and usable outside a source checkout."""

from __future__ import annotations

import io
from unittest.mock import AsyncMock, patch

import pytest
from rich.console import Console
from rich.markdown import Markdown
from rich.text import Text
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.merger import merge_results
from recon_tool.models import SourceResult
from recon_tool.server.lookup import lookup_tenant

_GUIDE = "https://github.com/pueo-labs/recon/blob/main/docs/weak-areas.md"


@pytest.mark.parametrize("width", [40, 80, 100, 120])
@pytest.mark.parametrize("color_flag", ["--color", "--no-color"])
def test_ascii_help_example_survives_rich_markup(width: int, color_flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", str(width))
    result = CliRunner().invoke(app, [color_flag, "--help"])
    assert result.exit_code == 0
    visible = Text.from_ansi(result.output).plain
    assert "#/- for dots" in " ".join(visible.replace("\N{BOX DRAWINGS LIGHT VERTICAL}", "").split())


@pytest.mark.parametrize("structured", [False, True])
def test_sparse_guidance_is_a_complete_url_in_cli_and_json(structured: bool) -> None:
    info = merge_results([SourceResult(source_name="dns_records")], "example.com")
    assert any(_GUIDE in insight for insight in info.insights)
    assert any(_GUIDE in insight for insight in format_tenant_dict(info)["insights"])
    args = ["example.com", "--no-cache", "--no-color"]
    if structured:
        args.append("--json")
    with patch("recon_tool.resolver.resolve_tenant", new=AsyncMock(return_value=(info, []))):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert _GUIDE in result.output


@pytest.mark.asyncio
@pytest.mark.parametrize("output_format", ["text", "json", "markdown"])
async def test_mcp_guidance_uses_the_same_installed_user_url(output_format: str) -> None:
    info = merge_results([SourceResult(source_name="dns_records")], "example.com")
    with patch("recon_tool.server.lookup.cache_get", return_value=(info, [])):
        result = await lookup_tenant("example.com", format=output_format)
    if output_format == "markdown":
        stream = io.StringIO()
        Console(file=stream, width=200, no_color=True).print(Markdown(result))
        result = stream.getvalue()
    assert _GUIDE in result
