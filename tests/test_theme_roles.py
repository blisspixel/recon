"""Color roles, color precedence and the ASCII glyph fallback (issue #226).

The role table in ``formatter/theme.py`` is the only place a renderer color is
named. These tests pin that table, the override order
``--color/--no-color > NO_COLOR > TERM=dumb > FORCE_COLOR > TTY``, and the ASCII
fallback that ``--ascii``, ``TERM=dumb`` or a terminal that cannot encode the
glyphs selects.
"""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.cli.routing import hoist_trailing_color_flags
from recon_tool.formatter import get_console, get_err_console, render_error, render_tenant_panel, theme
from recon_tool.formatter import terminal as term
from recon_tool.formatter.panel import render_source_status_panel
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

runner = CliRunner()
_SRC = Path(__file__).resolve().parent.parent / "src" / "recon_tool"
_SGR = "\x1b["
_NAMED_16 = {"red", "green", "yellow", "blue", "magenta", "cyan", "white", "black"}


# ── Role table ──────────────────────────────────────────────────────────────


def test_role_table_matches_the_design_language() -> None:
    assert dict(theme.ROLES) == {
        "accent": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "info": "blue",
        "muted": "dim",
    }
    assert dict(theme.CONFIDENCE_ROLE) == {
        ConfidenceLevel.HIGH: "green",
        ConfidenceLevel.MEDIUM: "blue",
        ConfidenceLevel.LOW: "yellow",
    }
    assert dict(theme.GAP_SEVERITY_ROLE) == {"high": "red", "medium": "yellow", "low": "blue"}
    assert dict(theme.FILL_ROLE) == {3: "green", 2: "blue", 1: "yellow"}


def test_roles_use_named_ansi_without_black_or_magenta() -> None:
    for style in theme.ROLES.values():
        if style == "dim":
            continue
        assert style in _NAMED_16
        assert style not in {"black", "magenta"}


_HEX = re.compile(r"#[0-9a-fA-F]{6}")
# Rich markup or a style string that names an ANSI color directly.
_BARE_COLOR = re.compile(
    r"\[/?(?:bold |dim |italic )*(?:red|green|yellow|blue|cyan|magenta|black|white)\]"
    r"|[\"'](?:bold |dim )*(?:red|green|yellow|blue|cyan|magenta|black|white)(?: bold)?[\"']"
)


def _renderer_sources() -> list[Path]:
    paths = sorted((_SRC / "formatter").glob("*.py")) + sorted((_SRC / "cli").glob("*.py"))
    return [*paths, _SRC / "updater.py"]


def test_no_hex_color_in_renderers() -> None:
    offenders = [
        f"{path.name}:{number}"
        for path in _renderer_sources()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if _HEX.search(line)
    ]
    assert offenders == []


def test_renderers_name_colors_only_through_the_role_table() -> None:
    offenders = [
        f"{path.name}:{number}: {line.strip()}"
        for path in _renderer_sources()
        if path.name != "theme.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if _BARE_COLOR.search(line)
    ]
    assert offenders == []


# ── Color precedence ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("flag", "environ", "tty", "enabled", "source"),
    [
        (False, {"FORCE_COLOR": "1"}, True, False, "--no-color"),
        (True, {"NO_COLOR": "1", "TERM": "dumb"}, False, True, "--color"),
        (None, {"NO_COLOR": "1", "FORCE_COLOR": "1"}, True, False, "NO_COLOR"),
        (None, {"NO_COLOR": "", "FORCE_COLOR": "1"}, False, True, "FORCE_COLOR"),
        (None, {"TERM": "dumb", "FORCE_COLOR": "1"}, True, False, "TERM=dumb"),
        (None, {"TERM": "DUMB"}, True, False, "TERM=dumb"),
        (None, {"FORCE_COLOR": "0"}, False, False, "tty"),
        (None, {"FORCE_COLOR": "0"}, True, True, "tty"),
        (None, {"FORCE_COLOR": ""}, False, False, "tty"),
        (None, {"FORCE_COLOR": "3"}, False, True, "FORCE_COLOR"),
        (None, {}, True, True, "tty"),
        (None, {}, False, False, "tty"),
    ],
)
def test_color_precedence(flag: bool | None, environ: dict[str, str], tty: bool, enabled: bool, source: str) -> None:
    decision = term.resolve_color(flag, environ, tty)
    assert (decision.enabled, decision.source) == (enabled, source)


@pytest.fixture
def printed_lookup(monkeypatch: pytest.MonkeyPatch, fully_populated_tenant_info: TenantInfo) -> None:
    """Replace the network lookup with one that prints a panel and an error."""

    async def fake_lookup(domain: str, _options: Any) -> None:
        get_console().print(render_tenant_panel(fully_populated_tenant_info))
        render_error(f"synthetic diagnostic for {domain}")

    monkeypatch.setattr("recon_tool.cli._lookup", fake_lookup)


def _invoke(args: list[str]) -> Any:
    try:
        return runner.invoke(app, args)
    finally:
        term.set_color_override(None)


def test_force_color_emits_sgr_as_a_control(monkeypatch: pytest.MonkeyPatch, printed_lookup: None) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = _invoke(["example.com"])
    assert result.exit_code == 0, result.output
    assert _SGR in result.stdout
    assert _SGR in result.stderr


@pytest.mark.parametrize("args", [["--no-color", "example.com"], ["example.com", "--no-color"]])
def test_no_color_flag_beats_force_color_on_both_streams(
    monkeypatch: pytest.MonkeyPatch, printed_lookup: None, args: list[str]
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    assert _SGR not in result.stdout
    assert _SGR not in result.stderr


def test_force_color_zero_does_not_force(monkeypatch: pytest.MonkeyPatch, printed_lookup: None) -> None:
    monkeypatch.setenv("FORCE_COLOR", "0")
    result = _invoke(["example.com"])
    assert result.exit_code == 0, result.output
    assert _SGR not in result.stdout
    assert _SGR not in result.stderr


@pytest.mark.parametrize(("name", "value"), [("NO_COLOR", "1"), ("TERM", "dumb")])
def test_no_color_and_dumb_terminal_beat_force_color(
    monkeypatch: pytest.MonkeyPatch, printed_lookup: None, name: str, value: str
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv(name, value)
    result = _invoke(["example.com"])
    assert result.exit_code == 0, result.output
    assert _SGR not in result.stdout
    assert _SGR not in result.stderr


def test_color_flag_beats_no_color_env(monkeypatch: pytest.MonkeyPatch, printed_lookup: None) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    result = _invoke(["example.com", "--color"])
    assert result.exit_code == 0, result.output
    assert _SGR in result.stdout


def test_explicit_color_still_colors_a_dumb_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")
    try:
        term.set_color_override(True)
        assert term._make_console(stderr=False).color_system is not None
    finally:
        term.set_color_override(None)


def test_disabled_color_keeps_terminal_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disabling color must not also pretend a TTY is a pipe (width, spinners)."""
    monkeypatch.setenv("TTY_COMPATIBLE", "1")
    try:
        term.set_color_override(False)
        console = term._make_console(stderr=True)
        assert console.is_terminal is True
        assert console.color_system is None
    finally:
        term.set_color_override(None)


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_tty_compatible_overrides_isatty() -> None:
    assert term._stream_is_tty(_Tty(), {}) is True
    assert term._stream_is_tty(_Tty(), {"TTY_COMPATIBLE": "0"}) is False
    assert term._stream_is_tty(io.StringIO(), {"TTY_COMPATIBLE": "1"}) is True
    assert term._stream_is_tty(io.StringIO(), {"TTY_COMPATIBLE": "maybe"}) is False


def test_stream_without_isatty_or_closed_is_not_a_tty() -> None:
    class _Closed:
        def isatty(self) -> bool:
            raise ValueError("I/O operation on closed file")

    assert term._stream_is_tty(object(), {}) is False
    assert term._stream_is_tty(_Closed(), {}) is False


# ── ASCII fallback ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("flag", "environ", "encoding", "tty", "expected"),
    [
        (True, {}, "utf-8", True, True),
        (False, {"TERM": "dumb"}, "utf-8", True, True),
        (False, {}, "latin-1", True, True),
        (False, {}, "ascii", True, True),
        (False, {}, "latin-1", False, False),  # a pipe is re-encoded as UTF-8
        (False, {}, "not-a-codec", True, True),
        (False, {}, "utf-8", True, False),
        (False, {}, None, True, False),
    ],
)
def test_ascii_resolution(flag: bool, environ: dict[str, str], encoding: str | None, tty: bool, expected: bool) -> None:
    assert term.resolve_ascii(flag, environ, encoding, tty) is expected


def test_glyph_forms() -> None:
    theme.set_ascii_active(False)
    assert theme.confidence_marker(ConfidenceLevel.MEDIUM) == "●●○"
    assert theme.fill_marker(1) == "●○○"
    assert theme.rule(3) == "───"
    assert theme.spinner_kwargs() == {}
    theme.set_ascii_active(True)
    assert theme.confidence_marker(ConfidenceLevel.HIGH) == "[###]"
    assert theme.confidence_marker(ConfidenceLevel.MEDIUM) == "[##-]"
    assert theme.confidence_marker(ConfidenceLevel.LOW) == "[#--]"
    assert theme.dots(5) == "[###]"
    assert (theme.glyph("ok"), theme.glyph("neutral"), theme.glyph("fail")) == ("ok", "-", "x")
    assert [theme.glyph(f"salience_{level}") for level in ("high", "medium", "low")] == ["H", "M", "L"]
    assert theme.rule(3) == "---"
    assert theme.spinner_kwargs() == {"spinner": "line"}


def test_to_ascii_transliterates_and_never_leaks_unicode() -> None:
    assert theme.to_ascii("plain") == "plain"
    assert theme.to_ascii("a \u2014 b → c … \u2713 \u2717 •") == "a - b -> c ... ok x *"
    assert theme.to_ascii("Café ─│╭") == "Cafe -|+"
    folded = theme.to_ascii("⠋ spinner 中")
    assert folded.isascii()
    assert folded == "? spinner ?"


def test_ascii_stream_filters_and_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buffer)
    stream = term._AsciiStream(stderr=False)
    assert stream.encoding == "ascii"
    stream.write("●○ \u2014 ok")
    stream.flush()
    assert buffer.getvalue() == "*o - ok"
    assert stream.isatty() is False
    with pytest.raises(io.UnsupportedOperation):
        stream.fileno()


def test_prepare_output_follows_a_terminal_that_cannot_encode(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Latin1Tty(io.StringIO):
        encoding = "latin-1"

        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdout", _Latin1Tty())
    sentinel = Console(file=io.StringIO())
    term.set_console(sentinel)
    assert term.prepare_output() is True
    assert theme.ascii_active() is True
    assert term._console is None  # rebuilt for the new glyph set
    term.set_console(sentinel)
    assert term.prepare_output() is True
    assert term._console is sentinel  # unchanged state keeps an injected console


def _assert_pure_ascii(text: str) -> None:
    offenders = sorted({char for char in text if not char.isascii()})
    assert offenders == []


@pytest.mark.parametrize("args", [["--ascii", "example.com"], ["example.com", "--ascii"]])
def test_ascii_flag_output_is_pure_ascii(printed_lookup: None, args: list[str]) -> None:
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    _assert_pure_ascii(result.stdout)
    _assert_pure_ascii(result.stderr)
    assert "[###] High" in result.stdout
    assert "-" * 40 in result.stdout


def test_dumb_terminal_output_is_pure_ascii(monkeypatch: pytest.MonkeyPatch, printed_lookup: None) -> None:
    monkeypatch.setenv("TERM", "dumb")
    result = _invoke(["example.com"])
    assert result.exit_code == 0, result.output
    _assert_pure_ascii(result.stdout)
    _assert_pure_ascii(result.stderr)


def test_ascii_does_not_carry_into_the_next_invocation(printed_lookup: None) -> None:
    first = _invoke(["example.com", "--ascii"])
    second = _invoke(["example.com"])
    assert "[###]" in first.stdout
    assert "●●●" in second.stdout


def test_ascii_source_status_marks() -> None:
    results = [
        SourceResult(source_name="alpha_source", tenant_id="t-1"),
        SourceResult(source_name="beta_source", error="no match"),
        SourceResult(source_name="gamma_source", error="timed out"),
    ]
    theme.set_ascii_active(True)
    console = Console(file=io.StringIO(), width=100, no_color=True, record=True)
    panel = render_source_status_panel(results)
    assert panel is not None
    console.print(panel)
    plain = console.export_text()
    assert "ok alpha_source" in plain
    assert "x gamma_source" in plain


def test_hoisting_includes_ascii() -> None:
    assert hoist_trailing_color_flags(["example.com", "--ascii", "--json"]) == ["--ascii", "example.com", "--json"]


def test_err_console_shares_the_ascii_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.StringIO()
    monkeypatch.setattr(sys, "stderr", buffer)
    theme.set_ascii_active(True)
    get_err_console().print("x → y")
    assert buffer.getvalue() == "x -> y\n"
