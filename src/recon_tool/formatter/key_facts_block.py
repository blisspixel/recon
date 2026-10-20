"""The key-facts block of the flat lookup panel: Provider, Tenant, Auth, Confidence.

Every value in the block starts in one column. The label column is the longest
label present plus one, with the established 13 columns as a floor and 16 as
a cap (``layout.label_column``). Values wrap once at the width the panel is
being laid out at (``layout.panel_width``), and identifiers never break: a
UUID or hostname that does not fit runs past the edge on its own line.
"""

from __future__ import annotations

from rich.cells import cell_len
from rich.text import Text

from recon_tool.formatter.briefing import SCALE_GAP_NOTE, scales_disagree
from recon_tool.formatter.classify import compact_provider_line, provider_line
from recon_tool.formatter.key_facts import key_facts_auth_line, key_facts_multicloud_line
from recon_tool.formatter.layout import label_column, panel_width, wrap_plain_text
from recon_tool.formatter.roles import (
    DOT_FILL_COLOR,
    model_support_claims,
    posterior_support_phrase,
    role_split_vendors,
)
from recon_tool.formatter.theme import CONFIDENCE_ROLE, confidence_marker, fill_marker
from recon_tool.models import TenantInfo

__all__ = ["render_key_facts"]

_CONFIDENCE_LABEL = "Confidence"
_MODEL_SUPPORT_LABEL = "Model support"


def _append_label(facts: Text, label: str, label_width: int) -> bool:
    """Write ``  Label`` padded to the column; return True when the value fits beside it.

    A label too long for the column takes the row alone, and its value starts
    on the next line at the value indent, so every value shares one column.
    """
    facts.append("  ")
    if cell_len(label) < label_width:
        facts.append(label + " " * (label_width - cell_len(label)), style="dim")
        return True
    facts.append(label, style="dim")
    facts.append("\n")
    facts.append(" " * (2 + label_width))
    return False


def _append_field(facts: Text, label: str, value: str, label_width: int, value_style: str = "") -> None:
    """Emit one ``  Label    value`` row, wrapping the value once under the value column."""
    indent_width = 2 + label_width
    for index, line in enumerate(wrap_plain_text(value, max(1, panel_width() - indent_width))):
        if index == 0:
            _append_label(facts, label, label_width)
        else:
            facts.append(" " * indent_width)
        facts.append(line, style=value_style)
        facts.append("\n")


def _append_marked_lines(
    facts: Text,
    label: str,
    label_width: int,
    marker: tuple[str, str, str],
    lines: list[str],
) -> None:
    """Emit a row whose value opens with a colored marker; continuations indent past it.

    ``marker`` holds the marker text, the marker style and the style of the words.
    """
    marker_text, marker_style, line_style = marker
    value_indent = 2 + label_width + cell_len(marker_text) + 1
    for index, line in enumerate(lines):
        if index == 0:
            _append_label(facts, label, label_width)
            facts.append(marker_text, style=marker_style)
            facts.append(" ")
        else:
            facts.append(" " * value_indent)
        facts.append(line, style=line_style)
        facts.append("\n")


def _append_confidence_field(facts: Text, info: TenantInfo, label_width: int) -> None:
    """Render the Confidence row and, when fusion claimed a node, the Model support row.

    Confidence is always the deterministic source/corroboration tier. The
    separate ``Model support`` row shows the weakest claimed node's
    threshold-relative display, so the hand-set uncertainty band is never
    presented as calibrated confidence. When the two dot scales sit two steps
    apart, the row says why they can.
    """
    source_count = len(info.sources)
    source_noun = "source" if source_count == 1 else "sources"
    marker = confidence_marker(info.confidence)
    tail = f"{info.confidence.value.capitalize()} ({source_count} {source_noun})"
    value_width = max(1, panel_width() - (2 + label_width + cell_len(marker) + 1))
    # The marker carries the role color; the level word stays readable in the
    # default foreground on light and dark themes alike.
    _append_marked_lines(
        facts,
        _CONFIDENCE_LABEL,
        label_width,
        (marker, CONFIDENCE_ROLE[info.confidence], ""),
        wrap_plain_text(tail, value_width),
    )
    claimed = [o for o in info.posterior_observations if o.evidence_used]
    if not claimed:
        return
    named, fill = model_support_claims(claimed)
    fill_dots = fill_marker(fill)
    phrase = posterior_support_phrase(named, fill)
    if scales_disagree(info.confidence, fill):
        # Two rows, two dot scales, two steps apart: say so here rather than in
        # a doc the reader meets after the panel.
        phrase = f"{phrase}. {SCALE_GAP_NOTE}"
    value_width = max(1, panel_width() - (2 + label_width + cell_len(fill_dots) + 1))
    _append_marked_lines(
        facts,
        _MODEL_SUPPORT_LABEL,
        label_width,
        (fill_dots, DOT_FILL_COLOR[fill], "dim"),
        wrap_plain_text(phrase, value_width),
    )


def _key_fact_rows(info: TenantInfo, detailed: bool) -> list[tuple[str, str]]:
    """Return the ordered ``(label, value)`` rows above the Confidence row."""
    rows: list[tuple[str, str]] = []
    # ADR-0015: when a vendor observed at an identity endpoint is not the one
    # the mail summary names, print both with their roles instead of letting a
    # single unroled "Provider" row read as the answer.
    split = role_split_vendors(info)
    if split is not None:
        mail, identity = split
        rows.append(("Mail", mail if detailed else compact_provider_line(mail)))
        rows.append(("Identity", identity))
    else:
        provider = provider_line(info)
        rows.append(("Provider", provider if detailed else compact_provider_line(provider)))

    if info.tenant_id:
        tenant_line = info.tenant_id
        if info.region:
            tenant_line += f" • {info.region}"
        rows.append(("Tenant", tenant_line))
    elif info.region:
        rows.append(("Region", info.region))

    if info.default_domain != info.queried_domain:
        rows.append(("Tenant domain", info.default_domain))

    auth_line = key_facts_auth_line(info)
    if auth_line is not None:
        rows.append(("Auth", auth_line))

    # Sovereignty, only when cloud_instance indicates non-commercial.
    if info.cloud_instance and "microsoftonline.com" not in info.cloud_instance.lower():
        sov_label = info.cloud_instance
        if info.tenant_region_sub_scope:
            sov_label += f" ({info.tenant_region_sub_scope})"
        rows.append(("Cloud", sov_label))

    multicloud_line = key_facts_multicloud_line(info)
    if multicloud_line is not None:
        rows.append(("Multi-cloud", multicloud_line))
    return rows


def render_key_facts(info: TenantInfo, detailed: bool) -> Text:
    """Build the key-facts block: Provider, Tenant/Region, Auth, Cloud, Multi-cloud, Confidence.

    ``detailed`` is the --explain / --verbose / --full view. The default view
    compacts the Provider row's record-role qualifiers per ADR-0012; the
    detailed view keeps them. The golden renders in
    ``tests/test_golden_renders.py`` pin the wide output.
    """
    rows = _key_fact_rows(info, detailed)
    labels = [label for label, _value in rows]
    labels.append(_CONFIDENCE_LABEL)
    if any(o.evidence_used for o in info.posterior_observations):
        labels.append(_MODEL_SUPPORT_LABEL)
    label_width = label_column(labels)
    facts = Text()
    for label, value in rows:
        _append_field(facts, label, value, label_width)
    _append_confidence_field(facts, info, label_width)
    return facts
