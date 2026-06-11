"""Services panel: the category label never collides with its value.

Regression for the "Data & AnalyticsMongoDB Atlas" bug: the Services
sub-category column was a fixed 15 chars, one short of the longest label
("Data & Analytics", 16), so ``str.ljust(15)`` left no trailing space
and the value rendered flush against the label. The width is now
``max(floor, longest-present-label + 1)``, so every label keeps at least
one space before its value, and short-label panels keep their column
width (and value space) unchanged.
"""

from __future__ import annotations

import re

from rich.console import Console

from recon_tool.formatter import _CATEGORY_WIDTH, _SERVICE_CATEGORIES_ORDER, render_tenant_panel
from recon_tool.models import ConfidenceLevel, TenantInfo


def _panel_text(info: TenantInfo) -> str:
    console = Console(no_color=True, record=True, width=120)
    console.print(render_tenant_panel(info))
    return console.export_text()


def _info(services: tuple[str, ...], slugs: tuple[str, ...]) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Contoso Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records",),
        services=services,
        slugs=slugs,
        domain_count=1,
    )


def test_long_category_label_keeps_a_gap_before_its_value() -> None:
    # looker-studio classifies as "Data & Analytics" (the 16-char label).
    text = _panel_text(_info(("Looker Studio",), ("looker-studio",)))
    line = next((ln for ln in text.splitlines() if "Data & Analytics" in ln), None)
    assert line is not None, "expected a Data & Analytics services row"
    # The label must be followed by whitespace, then the value: never
    # "Data & AnalyticsLooker".
    assert re.search(r"Data & Analytics\s+\S", line), f"label collided with value: {line!r}"
    assert "Looker Studio" in line


def test_short_label_panel_keeps_the_floor_width() -> None:
    # A panel whose longest present label is "Collaboration" (13) keeps the
    # established 15-col column: the value column is not narrowed by the
    # mere existence of a longer category elsewhere in the catalog.
    text = _panel_text(_info(("Microsoft 365", "Slack"), ("microsoft365", "slack")))
    email = next(ln for ln in text.splitlines() if ln.strip().startswith("Email"))
    # Two-space indent + "Email" + padding to the floor width, then value.
    assert email.startswith("  Email" + " " * (_CATEGORY_WIDTH - len("Email")))


def test_category_width_floor_is_below_the_longest_label() -> None:
    # The bug was a floor wider than nothing but narrower than the longest
    # label, so the per-render widening is load-bearing. Document that the
    # longest label genuinely exceeds the floor (otherwise this whole
    # mechanism would be dead code and the test a tautology).
    longest = max(len(c) for c in _SERVICE_CATEGORIES_ORDER)
    assert longest >= _CATEGORY_WIDTH, "if the floor already fits every label, the widening logic is untested"
