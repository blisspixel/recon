# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none
"""Narrow terminals: lay the panel out once at the real width, never break identifiers.

Acceptance for the width rule in ``formatter/layout.py`` and
``docs/design-language.md``. Every render goes through the CLI composition
(``_lookup_emit_panel``) on a fixed-width console printed with ``crop=False``,
the way the CLI prints panels, so an identifier wider than the console runs
past the edge instead of being cut. Fixtures use reserved example names only.
"""

from __future__ import annotations

import io
import os
from dataclasses import replace
from itertools import pairwise
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from recon_tool.bayesian import load_network
from recon_tool.cli.lookup import _lookup_compute_observations, _lookup_emit_panel
from recon_tool.cli.shared import render_status_row
from recon_tool.collection_view import collection_observable_info
from recon_tool.formatter import render_explanations_panel, render_tenant_panel
from recon_tool.formatter.briefing import briefing_insights, cap_insights
from recon_tool.formatter.key_facts_block import render_key_facts
from recon_tool.formatter.layout import (
    BORDERED_PANEL_WIDTH,
    FittedPanel,
    is_identifier,
    label_column,
    pack_service_items,
    panel_width_scope,
    wrap_plain_text,
)
from recon_tool.models import PosteriorObservation, SourceResult, TenantInfo
from scripts.generate_terminal_demo import demo_tenant_info

_GOLDEN_DIR = Path(__file__).parent / "golden_renders"
_TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
_LONG_HOST = "example-industries-international-holdings.onmicrosoft.example.com"
_LONG_URL = "https://crt.sh/?q=example-industries-international-holdings.example.com"
_WIDTHS = (40, 60, 80, 120)
_VIEWS = ("default", "full", "explain")
_KEY_FACT_LABELS = (
    "Provider",
    "Mail",
    "Identity",
    "Tenant",
    "Region",
    "Tenant domain",
    "Auth",
    "Cloud",
    "Multi-cloud",
    "Confidence",
    "Model support",
)


def _info() -> TenantInfo:
    return replace(
        demo_tenant_info(),
        tenant_id=_TENANT_ID,
        default_domain=_LONG_HOST,
        degraded_sources=("dns:dmarc", "crt.sh", "certspotter"),
        ct_provider_used=None,
    )


def _results(info: TenantInfo) -> list[SourceResult]:
    return [
        SourceResult(source_name="oidc_discovery", tenant_id=info.tenant_id, region="NA"),
        SourceResult(source_name="dns_records", detected_services=("Microsoft 365",), dmarc_policy="reject"),
        SourceResult(source_name="google_identity", error="not a Google Workspace domain"),
        SourceResult(source_name="crt.sh", error=f"HTTP 503 from {_LONG_URL}"),
    ]


def _console(width: int) -> tuple[Console, io.StringIO]:
    stream = io.StringIO()
    return Console(file=stream, width=width, no_color=True, legacy_windows=False), stream


def _render_view(view: str, width: int, info: TenantInfo | None = None) -> str:
    """Render ``recon example.com`` (default, --full or --explain) as the CLI does."""
    info = info or _info()
    full = view == "full"
    explain = view == "explain"
    console, stream = _console(width)
    _lookup_emit_panel(
        console,
        info,
        _results(info),
        _lookup_compute_observations(info, None, full or explain),
        show_services=full,
        show_domains=full,
        verbose=full,
        show_explain=explain,
        show_sources=False,
        show_posture=full,
        confidence_mode="hedged",
    )
    return stream.getvalue()


def _fits_or_single_identifier(line: str, width: int) -> bool:
    """A line fits, or only one identifier, alone after its label, runs past the edge."""
    if cell_len(line) <= width:
        return True
    head, _, last = line.rstrip().rpartition(" ")
    return is_identifier(last) and cell_len(head) < width and not any(is_identifier(word) for word in head.split())


@pytest.mark.parametrize("view", _VIEWS)
@pytest.mark.parametrize("width", _WIDTHS)
def test_no_line_exceeds_width_except_a_single_identifier(view: str, width: int) -> None:
    lines = _render_view(view, width).splitlines()

    overlong = [line for line in lines if not _fits_or_single_identifier(line, width)]
    assert overlong == []


@pytest.mark.parametrize("view", _VIEWS)
@pytest.mark.parametrize("width", _WIDTHS)
def test_identifiers_appear_unbroken_on_one_line(view: str, width: int) -> None:
    lines = _render_view(view, width).splitlines()

    assert any(_TENANT_ID in line for line in lines)
    assert any(_LONG_HOST in line for line in lines)
    if view == "explain" and width < BORDERED_PANEL_WIDTH:
        # Flat below the box width, so the URL is neither folded nor cropped.
        assert any(_LONG_URL in line for line in lines)


def _greedy_violations(lines: list[str], width: int) -> list[str]:
    """Continuation rows whose first word would have fit on the row above.

    That is the signature of wrapping twice: text laid out at one width and
    re-wrapped at another leaves a short row followed by a word that fits.
    A row ending in a comma closes a list item, so the next item may start a
    new row by design.
    """
    violations: list[str] = []
    for above, below in pairwise(lines):
        indent = len(below) - len(below.lstrip(" "))
        if not above.strip() or not below.strip() or indent <= 2 or above.rstrip().endswith(","):
            continue
        if "--explain" in below or "--full" in below:  # the evidence-role note is its own row
            continue
        first_word = below.split()[0]
        if cell_len(above.rstrip()) + 1 + cell_len(first_word) <= width:
            violations.append(f"{above!r} / {below!r}")
    return violations


@pytest.mark.parametrize("width", [40, 60])
@pytest.mark.parametrize("detailed", [False, True])
def test_key_facts_and_services_wrap_once(width: int, detailed: bool) -> None:
    lines = _render_view("explain" if detailed else "default", width).splitlines()
    end = lines.index("High-signal related domains")

    assert _greedy_violations(lines[:end], width) == []


@pytest.mark.parametrize("width", [40, 60, 120])
def test_insight_prose_wraps_once_at_the_real_width(width: int) -> None:
    info = collection_observable_info(_info())
    output = _render_view("default", width)
    score_line, ordered = briefing_insights(info, "hedged")
    insights, _overflow = cap_insights(ordered, False)
    prose = [*([score_line] if score_line else []), *insights]
    assert prose

    for sentence in prose:
        expected = "\n".join(f"  {line}" for line in wrap_plain_text(sentence, min(width, 78) - 2))
        assert expected in output


def _value_columns(output: str) -> set[int]:
    """Return the value column of every labelled key-facts row."""
    lines = output.splitlines()
    rule = next(index for index, line in enumerate(lines) if line and not line.strip("─"))
    columns: set[int] = set()
    for line in lines[rule + 1 :]:
        if not line.strip():
            break
        if line.startswith("  ") and not line.startswith("   "):
            label = max((label for label in _KEY_FACT_LABELS if line[2:].startswith(label + " ")), key=len)
            rest = line[2 + len(label) :]
            columns.add(2 + len(label) + len(rest) - len(rest.lstrip(" ")))
    return columns


def _model_support_info() -> TenantInfo:
    node = next(node for node in load_network().nodes if node.name == "m365_tenant")
    posterior = PosteriorObservation(
        name=node.name,
        description=node.description,
        posterior=0.95,
        interval_low=0.88,
        interval_high=0.99,
        evidence_used=("signal:m365_tenant_observed",),
        n_eff=6.0,
        sparse=False,
    )
    return replace(_info(), posterior_observations=(posterior,))


@pytest.mark.parametrize("width", _WIDTHS)
@pytest.mark.parametrize("model_support", [False, True])
def test_every_key_fact_value_starts_in_one_column(width: int, model_support: bool) -> None:
    info = _model_support_info() if model_support else _info()
    output = _render_view("default", width, info)

    assert "Tenant domain" in output
    assert ("Model support" in output) is model_support
    # "Tenant domain" and "Model support" are 13 columns, so the shared column
    # is 2 + 14; no row keeps the older 15 that misaligned them.
    assert _value_columns(output) == {16}


def test_label_column_rule() -> None:
    assert label_column(["Provider", "Auth", "Confidence"]) == 13  # floor: the wide layout
    assert label_column(["Provider", "Tenant domain"]) == 14
    assert label_column(["Provider", "A very long label here"]) == 16  # cap


def test_label_past_the_cap_puts_its_value_on_the_next_line() -> None:
    from recon_tool.formatter.key_facts_block import _append_field

    facts = Text()
    with panel_width_scope(60):
        _append_field(facts, "Synthetic long label", "value one", 16)
        _append_field(facts, "Auth", "Federated", 16)
    lines = facts.plain.splitlines()

    assert lines[0] == "  Synthetic long label"
    assert lines[1] == " " * 18 + "value one"
    assert lines[2].index("Federated") == 18


@pytest.mark.parametrize("width", [40, 60])
@pytest.mark.parametrize("view", ["default", "explain"])
def test_narrow_golden_renders(width: int, view: str) -> None:
    """Pin the narrow layout so a regression to double wrapping shows as a diff."""
    console, stream = _console(width)
    # No degraded sources: the collection note's wording belongs to other
    # surfaces' tests, and this golden pins layout only.
    info = replace(_info(), degraded_sources=())
    console.print(render_tenant_panel(info, explain=view == "explain"), crop=False)
    actual = stream.getvalue()
    path = _GOLDEN_DIR / f"panel_narrow_{view}_w{width}.txt"
    if os.environ.get("RECON_REGEN_GOLDEN"):
        path.write_text(actual, encoding="utf-8")
        return
    assert actual == path.read_text(encoding="utf-8")


def test_wide_render_is_built_once_at_the_panel_width() -> None:
    panel = render_tenant_panel(_info())
    console, stream = _console(120)
    console.print(panel, crop=False)
    wide = stream.getvalue()

    assert all(_fits_or_single_identifier(line, 78) for line in wide.splitlines())
    assert panel.rebuild is not None
    narrow = "".join(block.plain for block in panel.rebuild(40) if isinstance(block, Text))
    assert _TENANT_ID in narrow


@pytest.mark.parametrize("width", [80, 120])
def test_bordered_panel_keeps_its_box_when_it_fits(width: int) -> None:
    body = Text("  [Signal] Synthetic observation\n    Lineage: Exact\n")
    fitted = FittedPanel(body, title="Explanations", width=BORDERED_PANEL_WIDTH, padding=(1, 2), border_style="dim")
    plain = Panel(body, title="Explanations", width=BORDERED_PANEL_WIDTH, padding=(1, 2), border_style="dim")
    fitted_console, fitted_stream = _console(width)
    plain_console, plain_stream = _console(width)
    fitted_console.print(fitted)
    plain_console.print(plain)

    assert fitted_stream.getvalue() == plain_stream.getvalue()


def test_bordered_panel_turns_flat_below_its_box_width() -> None:
    from recon_tool.models import ExplanationRecord

    record = ExplanationRecord(
        item_type="signal",
        item_name="Synthetic observation",
        matched_evidence=(),
        fired_rules=(f"rule citing {_LONG_URL}",),
        confidence_derivation="",
        weakening_conditions=(),
        curated_explanation="",
    )
    console, stream = _console(40)
    console.print(render_explanations_panel([record]), crop=False)
    lines = stream.getvalue().splitlines()

    assert "Explanations" in lines
    assert not any(line.lstrip().startswith(("╭", "+", "│", "|")) for line in lines)
    assert any(line.strip() == _LONG_URL for line in lines)
    assert all(_fits_or_single_identifier(line, 40) for line in lines)


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (_TENANT_ID, True),
        (_LONG_HOST, True),
        (f"{_LONG_HOST},", True),
        (_LONG_URL, True),
        ("ops@example.com", True),
        ("C:\\Users\\example\\fingerprints.yaml", True),
        ("Proofpoint", False),
        ("x" * 60, False),
        ("(Jira/Confluence)", True),
        ("", False),
    ],
)
def test_identifier_tokens(token: str, expected: bool) -> None:
    assert is_identifier(token) is expected


def test_pack_service_items_keeps_items_together_and_wraps_long_items_once() -> None:
    items = ["Microsoft 365", "Proofpoint", "Atlassian (Jira/Confluence)", "Zoom"]

    assert pack_service_items(items, 21) == [
        "Microsoft 365,",
        "Proofpoint, Atlassian",
        "(Jira/Confluence),",
        "Zoom",
    ]
    assert pack_service_items(["Datadog", "Snowflake"], 40) == ["Datadog, Snowflake"]


def _status_lines(width: int, name: str, detail: str) -> list[str]:
    console, stream = _console(width)
    render_status_row(console, "fail", name, detail)
    return stream.getvalue().splitlines()


@pytest.mark.parametrize("width", [60, 80, 100])
def test_doctor_continuation_lines_start_at_the_detail_column(width: int) -> None:
    detail = (
        "could not resolve TXT records for example.com through the configured resolver; "
        "check the network path to C:\\Users\\example\\AppData\\Local\\recon\\resolver.conf and retry"
    )
    lines = _status_lines(width, "DNS resolver", detail)
    detail_column = lines[0].index("could")

    assert len(lines) > 1
    for line in lines[1:]:
        assert len(line) - len(line.lstrip(" ")) == detail_column
    assert all(_fits_or_single_identifier(line, width) for line in lines)
    assert "C:\\Users\\example\\AppData\\Local\\recon\\resolver.conf" in "\n".join(lines)


def test_doctor_detail_moves_below_a_long_name() -> None:
    lines = _status_lines(40, "Resources enumerated", "missing canonical: recon://surface-inventory")

    assert lines[0].strip() == "fail  Resources enumerated:"
    assert all(line.startswith(" " * 8) and not line.startswith(" " * 9) for line in lines[1:])


def test_render_key_facts_wide_layout_is_unchanged() -> None:
    """At the panel width the key facts keep the established 13-column labels."""
    info = replace(_info(), default_domain=_info().queried_domain)
    with panel_width_scope(78):
        plain = render_key_facts(info, detailed=False).plain

    assert "  Provider     Microsoft 365" in plain
    assert "  Confidence   " in plain
