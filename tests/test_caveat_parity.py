"""Caveat parity across every lookup surface (issue #229).

Two qualifiers travel with a lookup result: a provider-reported display name
is unverified, and a reserved special-use queried name returns public residue,
not an organization. The panel, ``--plain`` (default and ``--full``), ``--md``,
``--json`` and both MCP formats must each carry the same two, so a qualifier
cannot survive on one surface and drop off another. Unavailable values print
``n/a``, and output string literals carry no em or en dash.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.formatter import (
    format_tenant_json,
    format_tenant_markdown,
    format_tenant_plain,
    render_sources_detail,
    render_tenant_panel,
)
from recon_tool.formatter.caveats import (
    DISPLAY_NAME_QUALIFIER,
    RESERVED_NAME_STATEMENT,
    qualified_display_name,
)
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo
from recon_tool.server.lookup import _format_lookup_tenant, _lookup_tenant_text
from recon_tool.validator import is_special_use_name

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "src" / "recon_tool"
_BRAND = "Synthetic Residue Brand"


def _info(queried_domain: str, display_name: str = _BRAND) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=display_name,
        default_domain=queried_domain,
        queried_domain=queried_domain,
        confidence=ConfidenceLevel.HIGH,
        sources=("user_realm",),
    )


# example.com is RFC 2606 reserved. example.co.uk is an ordinary registrable
# name under the public suffix co.uk; the fixture makes no network request.
RESERVED = _info("example.com")
NORMAL = _info("example.co.uk")


def _panel(info: TenantInfo) -> str:
    console = Console(no_color=True, record=True, width=120)
    console.print(render_tenant_panel(info))
    return console.export_text()


def _human_surfaces(info: TenantInfo) -> dict[str, str]:
    return {
        "panel": _panel(info),
        "plain": format_tenant_plain(info),
        "plain_full": format_tenant_plain(info, full=True),
        "markdown": format_tenant_markdown(info),
        "mcp_text": _lookup_tenant_text(info),
        "mcp_markdown": _format_lookup_tenant(info, [], "markdown", False),
    }


def _json_surfaces(info: TenantInfo) -> dict[str, dict[str, object]]:
    return {
        "json": json.loads(format_tenant_json(info)),
        "mcp_json": json.loads(_format_lookup_tenant(info, [], "json", False)),
    }


@pytest.mark.parametrize(("info", "reserved"), [(RESERVED, True), (NORMAL, False)], ids=["reserved", "normal"])
def test_every_surface_carries_the_same_two_qualifiers(info: TenantInfo, reserved: bool) -> None:
    for surface, text in _human_surfaces(info).items():
        assert _BRAND in text, surface
        assert DISPLAY_NAME_QUALIFIER in text, surface
        assert (RESERVED_NAME_STATEMENT in text) is reserved, surface
    for surface, payload in _json_surfaces(info).items():
        assert payload["display_name"] == _BRAND, surface
        assert payload["display_name_verified"] is False, surface
        if reserved:
            assert payload["reserved_name"] is True, surface
        else:
            assert "reserved_name" not in payload, surface


def test_panel_title_carries_the_qualifier_and_the_reserved_line_under_it() -> None:
    lines = [line.strip() for line in _panel(RESERVED).splitlines() if line.strip()]
    assert lines[:3] == [f"{_BRAND} (unverified)", "example.com", RESERVED_NAME_STATEMENT]


def test_plain_names_the_qualifier_and_note_in_linear_order() -> None:
    lines = format_tenant_plain(RESERVED).splitlines()
    assert lines[:3] == [
        "queried_domain: example.com",
        f"display_name: {_BRAND} (unverified)",
        f"reserved_name_note: {RESERVED_NAME_STATEMENT}",
    ]


def test_plain_bounds_a_long_display_name_before_the_qualifier() -> None:
    info = _info("example.co.uk", display_name="A" * 300)
    line = next(line for line in format_tenant_plain(info).splitlines() if line.startswith("display_name:"))
    assert line.endswith(" [truncated; see --json] (unverified)")


def test_domain_fallback_display_name_carries_no_qualifier() -> None:
    """The queried-domain fallback is not provider-reported, so nothing marks it."""
    info = _info("example.co.uk", display_name="example.co.uk")
    assert qualified_display_name(info) == "example.co.uk"
    for surface, text in _human_surfaces(info).items():
        assert DISPLAY_NAME_QUALIFIER not in text, surface
    assert json.loads(format_tenant_json(info))["display_name_verified"] is False


@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "www.example.net",
        "example.org",
        "alpha.example",
        "alpha.test",
        "alpha.invalid",
        "alpha.localhost",
        "printer.local",
        "alpha.onion",
        "alpha.alt",
        "router.home.arpa",
        "ipv4only.arpa",
        "resolver.arpa",
    ],
)
def test_special_use_names_are_reserved(name: str) -> None:
    assert is_special_use_name(name)


@pytest.mark.parametrize("name", ["example.co.uk", "myexample.com", "example.com.au", "invalid.co.uk", "alt.co.uk"])
def test_lookalikes_are_not_reserved(name: str) -> None:
    assert not is_special_use_name(name)


def test_missing_tenant_id_and_region_render_n_a() -> None:
    console = Console(no_color=True, record=True, width=120)
    console.print(render_sources_detail([SourceResult(source_name="dns_records")]))
    text = console.export_text()
    row = next(line for line in text.splitlines() if "dns_records" in line)
    assert row.count("n/a") == 3
    assert "\N{EM DASH}" not in text


def test_command_typo_suggests_the_command() -> None:
    result = CliRunner().invoke(app, ["lookpu", "example.com"])
    assert result.exit_code == 2
    assert 'Unknown command "lookpu". Did you mean "lookup"?' in " ".join(result.output.replace("│", " ").split())


# Literals that legitimately hold a dash character: the glyph tables that map
# the functional source mark and its ASCII fallbacks, and the matchers that
# still recognize insight text written by earlier releases.
_DASH_LITERAL_ALLOWLIST = frozenset(
    {
        ("formatter/theme.py", "\N{EN DASH}"),
        ("formatter/theme.py", "\N{EM DASH}"),
        ("formatter/terminal.py", "\u25cf\u25cb\u25d0\u2713\u2717\u2013\u2500\u2022\u2192"),
        ("formatter/briefing.py", "Sparse public signal \N{EM DASH}"),
        ("formatter/briefing.py", "Next step \N{EM DASH}"),
    }
)


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _dash_literals() -> Iterator[tuple[str, int, str]]:
    for package in ("formatter", "cli", "server"):
        for path in sorted((_PACKAGE / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = _docstring_ids(tree)
            relative = path.relative_to(_PACKAGE).as_posix()
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in docstrings
                    and ("\N{EM DASH}" in node.value or "\N{EN DASH}" in node.value)
                ):
                    yield relative, node.lineno, node.value


def test_output_string_literals_carry_no_em_or_en_dash() -> None:
    offenders = [
        f"{relative}:{lineno}: {value!r}"
        for relative, lineno, value in _dash_literals()
        if (relative, value) not in _DASH_LITERAL_ALLOWLIST
    ]
    assert offenders == []


def test_dash_allowlist_has_no_stale_entries() -> None:
    found = {(relative, value) for relative, _lineno, value in _dash_literals()}
    assert found >= _DASH_LITERAL_ALLOWLIST
