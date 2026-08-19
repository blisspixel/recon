"""Rich terminal output formatting for domain intelligence.

Console management: All output goes through get_console(). The CLI module
should use get_console() instead of creating its own Console instance, so
that set_console() in tests captures everything.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from recon_tool.confidence import is_confidence_contributor
from recon_tool.formatter.briefing import (
    SCALE_GAP_NOTE,
    briefing_insights,
    cap_insights,
    high_signal_related,
    scales_disagree,
)
from recon_tool.formatter.classify import (
    CATEGORY_BY_SLUG,
    CLOUD_SLUG_QUALIFIERS,
    CLOUD_VENDOR_BY_SLUG,
    CLOUD_VENDOR_ROLLUP_EXCLUSIONS,
    EMAIL_SERVICE_PREFIXES,
    FILTERED_SERVICE_PREFIXES,
    FILTERED_SERVICE_SUFFIXES,
    M365_KEYWORDS,
    SERVICE_CATEGORIES_ORDER,
    SLUG_DISPLAY_OVERRIDES,
    canonical_cloud_vendor,
    categorize_service,
    categorize_services,
    category_for_slug,
    compact_categorized_services,
    compact_provider_line,
    count_cloud_vendors,
    detect_provider,
    is_gws_service,
    is_m365_service,
    provider_line,
    slug_to_relationship_metadata,
)
from recon_tool.formatter.comparison import format_comparison_dict, format_comparison_json
from recon_tool.formatter.delta import (  # re-exported: stable import path after the split
    format_delta_dict,
    format_delta_json,
    render_delta_panel,
)
from recon_tool.formatter.email_summary import normalize_email_services
from recon_tool.formatter.explanations import format_explanations_list, render_explanations_panel
from recon_tool.formatter.exposure import (  # re-exported: stable import path after the split
    format_exposure_dict,
    format_exposure_json,
    format_gaps_dict,
    format_gaps_json,
    render_exposure_panel,
    render_gaps_panel,
)
from recon_tool.formatter.key_facts import key_facts_auth_line, key_facts_multicloud_line
from recon_tool.formatter.layout import compact_subdomain_summary_lines, subdomain_surface_summary_items
from recon_tool.formatter.markdown import (
    format_explanations_markdown,
    format_tenant_markdown,
    markdown_escape,
)
from recon_tool.formatter.panel_status import confidence_is_high, render_low_confidence_guidance
from recon_tool.formatter.roles import (
    DOT_FILL_COLOR,
    DOT_FILL_GLYPH,
    model_support_claims,
    posterior_support_phrase,
    role_split_vendors,
)
from recon_tool.formatter.serialize import (
    CSV_COLUMNS,
    format_batch_csv,
    format_tenant_csv_row,
    format_tenant_dict,
    format_tenant_json,
    format_tenant_plain,
    plain_lines,
)
from recon_tool.models import (
    CandidateValue,
    ChainReport,
    ConfidenceLevel,
    MergeConflicts,
    Observation,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.validator import strip_control_chars

# The service-classification layer lives in ``recon_tool.formatter.classify``
# and ``recon_tool.formatter.classify_tables``. Those modules use public names
# because pyright-strict forbids cross-module access to underscore names.
# Re-export them under historical ``_NAME`` aliases for compatibility.
_CATEGORY_BY_SLUG = CATEGORY_BY_SLUG
_CLOUD_SLUG_QUALIFIERS = CLOUD_SLUG_QUALIFIERS
_CLOUD_VENDOR_BY_SLUG = CLOUD_VENDOR_BY_SLUG
_CLOUD_VENDOR_ROLLUP_EXCLUSIONS = CLOUD_VENDOR_ROLLUP_EXCLUSIONS
_EMAIL_SERVICE_PREFIXES = EMAIL_SERVICE_PREFIXES
_FILTERED_SERVICE_PREFIXES = FILTERED_SERVICE_PREFIXES
_FILTERED_SERVICE_SUFFIXES = FILTERED_SERVICE_SUFFIXES
_M365_KEYWORDS = M365_KEYWORDS
_SERVICE_CATEGORIES_ORDER = SERVICE_CATEGORIES_ORDER
_SLUG_DISPLAY_OVERRIDES = SLUG_DISPLAY_OVERRIDES
_categorize_service = categorize_service
_categorize_services = categorize_services
_is_gws_service = is_gws_service
_is_m365_service = is_m365_service
_slug_to_relationship_metadata = slug_to_relationship_metadata
_markdown_escape = markdown_escape
_plain_lines = plain_lines

logger = logging.getLogger(__name__)

__all__ = [
    "CSV_COLUMNS",
    "canonical_cloud_vendor",
    "category_for_slug",
    "count_cloud_vendors",
    "detect_provider",
    "format_batch_csv",
    "format_chain_dict",
    "format_chain_json",
    "format_comparison_dict",
    "format_comparison_json",
    "format_delta_dict",
    "format_delta_json",
    "format_explanations_list",
    "format_explanations_markdown",
    "format_exposure_dict",
    "format_exposure_json",
    "format_gaps_dict",
    "format_gaps_json",
    "format_posture_observations",
    "format_tenant_csv_row",
    "format_tenant_dict",
    "format_tenant_json",
    "format_tenant_markdown",
    "format_tenant_plain",
    "get_console",
    "render_chain_panel",
    "render_conflict_annotation",
    "render_delta_panel",
    "render_error",
    "render_explanations_panel",
    "render_exposure_panel",
    "render_gaps_panel",
    "render_posture_panel",
    "render_source_status_panel",
    "render_sources_detail",
    "render_tenant_panel",
    "render_verbose_sources",
    "render_warning",
    "set_console",
]

# Default console — can be overridden via get_console/set_console for testing.
# Why a global instead of dependency injection? Because Rich's Console is used
# by dozens of call sites (render_*, cli status spinners, etc.) and threading
# a console parameter through every function would be noisy. The global is
# effectively a singleton with a test seam via set_console().
_console: Console | None = None
# Separate console bound to stderr for diagnostics (errors, warnings, progress
# spinners). Keeping these off stdout means a consumer piping `recon ... --json`
# gets only the data stream, never an error line or a spinner mixed into it —
# the core clig.dev / 12-factor-CLI rule. Test seam via set_err_console().
_err_console: Console | None = None
# Explicit color override from --color/--no-color: True forces color (even when
# piped), False disables it (overriding NO_COLOR's auto behavior), None = auto
# (Rich's TTY/NO_COLOR detection). Applied to both consoles at creation.
_color_override: bool | None = None


def _make_console(*, stderr: bool) -> Console:
    """Construct a Console honoring the --color/--no-color override."""
    if _color_override is False:
        return Console(stderr=stderr, no_color=True)
    if _color_override is True:
        return Console(stderr=stderr, force_terminal=True)
    return Console(stderr=stderr)


def set_color_override(value: bool | None) -> None:
    """Force (True) / disable (False) / auto (None) color, rebuilding consoles."""
    global _color_override, _console, _err_console  # noqa: PLW0603
    _color_override = value
    _console = None
    _err_console = None


def get_console() -> Console:
    """Return the active console instance, creating a default if needed.

    On Windows, the default stdout encoding is often cp1252 which cannot
    represent the Unicode characters used in panel rendering (confidence
    dots, arrows, em-dashes, box-drawing). Reconfigure stdout to UTF-8
    with replacement-on-error so the tool never crashes on unencodable
    glyphs — worst case the user sees "?" in place of a decorator
    character instead of a traceback.
    """
    global _console  # noqa: PLW0603
    if _console is None:
        import sys
        from typing import cast

        try:
            stdout_any: Any = cast(Any, sys.stdout)
            if hasattr(stdout_any, "reconfigure"):
                stdout_any.reconfigure(encoding="utf-8", errors="replace")
            stderr_any: Any = cast(Any, sys.stderr)
            if hasattr(stderr_any, "reconfigure"):
                stderr_any.reconfigure(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.debug("stdout UTF-8 reconfigure failed: %s", exc)
        _console = _make_console(stderr=False)
    return _console


def get_err_console() -> Console:
    """Return the active stderr console, creating a default if needed.

    Diagnostics — errors, warnings, and progress spinners — go here so they
    never contaminate the stdout data stream that a pipe or agent consumes.
    stderr is already reconfigured to UTF-8 in get_console().
    """
    global _err_console  # noqa: PLW0603
    if _err_console is None:
        get_console()  # ensure stdout/stderr UTF-8 reconfigure has run
        _err_console = _make_console(stderr=True)
    return _err_console


def set_console(console: Console) -> None:
    """Replace the active console (for testing)."""
    global _console  # noqa: PLW0603
    _console = console


def set_err_console(console: Console) -> None:
    """Replace the active stderr console (for testing)."""
    global _err_console  # noqa: PLW0603
    _err_console = console


CONFIDENCE_COLORS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "#a3d9a5",  # soft sage green
    ConfidenceLevel.MEDIUM: "#7ec8e3",  # muted sky blue
    ConfidenceLevel.LOW: "#e07a5f",  # warm terracotta
}

CONFIDENCE_DOTS: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "●●●",
    ConfidenceLevel.MEDIUM: "●●○",
    ConfidenceLevel.LOW: "●○○",
}

# Services filtered from the compact (default) view because they appear
# in insights instead. Uses exact prefix matching to avoid false positives
# (e.g. a service named "Advanced DNS Security" won't be hidden).
_SKIP_COMPACT_PREFIXES = (
    "dmarc",
    "domain verified",
    "spf:",
    "spf complexity",
    "dns:",
    "cdn:",
    "hosting:",
    "waf:",
    "domain connect",
)

# Exact substrings that must appear as standalone tokens in the service name.
_SKIP_COMPACT_EXACT = frozenset({"(SPF)", "(site verified)"})

# ── Panel constants ─────────────────────────────────────────────

_PANEL_WIDTH = 78  # One char narrower than an 80-col terminal to avoid
# wrap-to-next-line artefacts when the last cell is
# filled. The layout has no border, so the
# effective content width equals the panel width.
_LABEL_WIDTH = 13  # columns for Provider/Tenant/Auth/Confidence labels


# Minimum columns for the Services sub-category labels. The effective
# width per render is max(this floor, longest label present + 1), so a
# panel that only shows short labels keeps the established 15-col column
# (and its value width), while a panel that shows a long label widens
# just enough to keep one space before the value. A fixed 15 silently
# collided "Data & Analytics" (16 cols) onto its value
# ("Data & AnalyticsMongoDB Atlas"); the +1 guarantees the gap.
_CATEGORY_WIDTH = 15


def _wrap_service_list(
    services: list[str],
    label_width: int = 14,
    panel_width: int = 80,
    panel_pad: int = 2,
) -> str:
    """Join services with comma-separation, wrapping lines to align under the label.

    The available content width inside a Rich Panel is:
        panel_width - 2 (border chars) - 2 * panel_pad (left + right padding)

    The first line starts after the label (e.g. "  Services:   "), so it has
    fewer chars available than continuation lines.  Continuation lines are
    indented with spaces so text aligns with the first service name.
    """
    content_width = panel_width - 2 - 2 * panel_pad
    # First line: "  " prefix + label already consumed by caller
    first_line_max = content_width - 2 - label_width
    # Continuation lines: indented by label_width (no "  " prefix needed)
    cont_line_max = content_width - label_width
    continuation_indent = " " * label_width

    joined = ", ".join(services)
    # If it fits on one line, just return it
    if len(joined) <= first_line_max:
        return joined

    # Word-wrap at comma boundaries.
    # Account for trailing comma (1 char) on non-final lines when checking fit.
    lines: list[str] = []
    current_line = ""
    for svc in services:
        candidate = svc if not current_line else f"{current_line}, {svc}"
        limit = first_line_max if not lines else cont_line_max
        # Reserve 1 char for the trailing comma on non-final lines
        if current_line and len(candidate) + 1 > limit:
            lines.append(current_line + ",")
            current_line = svc
        else:
            current_line = candidate
    if current_line:
        lines.append(current_line)

    return ("\n" + continuation_indent).join(lines)


def _wrap_text(text: str, max_width: int) -> list[str]:
    """Word-wrap a plain text string to fit within max_width characters."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) > max_width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [text]


def _append_field(facts: Text, label: str, value: str, value_style: str = "") -> None:
    """Emit one "  Label    value" row into ``facts``, wrapping the value at the
    panel width with a continuation indent matching the label column."""
    label_width = max(_LABEL_WIDTH, len(label) + 1)
    indent_width = 2 + label_width  # "  " + label column
    max_width = _PANEL_WIDTH - indent_width
    for i, line in enumerate(_wrap_text(value, max_width)):
        if i == 0:
            facts.append("  ")
            facts.append(label.ljust(label_width), style="dim")
        else:
            facts.append(" " * indent_width)
        facts.append(line, style=value_style)
        facts.append("\n")


def _append_confidence_field(facts: Text, info: TenantInfo) -> None:
    """Render the Confidence row.

    Confidence is always the deterministic source/corroboration tier. When
    fusion ran and at least one positive claim fired, a separate ``Model
    support`` row shows the weakest claimed node's threshold-relative display.
    Keeping the two rows separate prevents the hand-set uncertainty band from
    being presented as calibrated confidence, and when the two dot scales sit
    two steps apart the row says why they can.
    """
    facts.append("  ")
    facts.append("Confidence".ljust(_LABEL_WIDTH), style="dim")
    source_count = len(info.sources)
    source_noun = "source" if source_count == 1 else "sources"
    tail = f" {info.confidence.value.capitalize()} ({source_count} {source_noun})"
    dots = CONFIDENCE_DOTS[info.confidence]
    style = "green" if confidence_is_high(info.confidence) else ""
    facts.append(dots + tail, style=style)
    facts.append("\n")
    claimed = [o for o in info.posterior_observations if o.evidence_used]
    if not claimed:
        return
    named, fill = model_support_claims(claimed)
    # Wrap like every other row. This row appended without wrapping, which was
    # invisible while the phrase named one claim and spilled past the panel
    # edge once it could name two (ADR-0015). The dots sit in the value column,
    # so continuation lines indent past them, not just past the label.
    label = "Model support"
    label_width = max(_LABEL_WIDTH, len(label) + 1)
    glyph = DOT_FILL_GLYPH[fill]
    value_indent = 2 + label_width + len(glyph) + 1
    phrase = posterior_support_phrase(named, fill)
    if scales_disagree(info.confidence, fill):
        # Two rows, two dot scales, two steps apart: "Low (1 source)" above a
        # filled model display reads as self-contradiction until you know they
        # answer different questions. Say so here rather than in a doc the
        # reader meets after the panel.
        phrase = f"{phrase}. {SCALE_GAP_NOTE}"
    for index, line in enumerate(_wrap_text(phrase, _PANEL_WIDTH - value_indent)):
        if index == 0:
            facts.append("  ")
            facts.append(label.ljust(label_width), style="dim")
            facts.append(glyph, style=DOT_FILL_COLOR[fill])
            facts.append(" ")
        else:
            facts.append(" " * value_indent)
        facts.append(line, style="dim")
        facts.append("\n")


def _render_key_facts(info: TenantInfo, detailed: bool) -> Text:
    """Build the key-facts block: Provider, Tenant/Region, Auth, Cloud
    (sovereignty), Multi-cloud rollup, Confidence.

    Extracted from ``render_tenant_panel`` so the panel orchestrator stays
    a thin sequence of section calls. The golden renders in
    ``tests/test_golden_renders.py`` pin the exact output.

    ``detailed`` is the --explain / --verbose / --full view. The default view
    compacts the Provider row's record-role qualifiers per ADR-0012; the
    detailed view keeps them.
    """
    facts = Text()
    # ADR-0015: when a vendor observed at an identity endpoint is not the one
    # the mail summary names, print both with their roles instead of letting a
    # single unroled "Provider" row read as the answer. Only a real split
    # branches here; every other panel keeps the historical row byte for byte.
    split = role_split_vendors(info)
    if split is not None:
        mail, identity = split
        _append_field(facts, "Mail", mail if detailed else compact_provider_line(mail))
        _append_field(facts, "Identity", identity)
    else:
        provider = provider_line(info)
        _append_field(facts, "Provider", provider if detailed else compact_provider_line(provider))

    if info.tenant_id:
        tenant_line = info.tenant_id
        if info.region:
            tenant_line += f" • {info.region}"
        _append_field(facts, "Tenant", tenant_line)
    elif info.region:
        _append_field(facts, "Region", info.region)

    if info.default_domain != info.queried_domain:
        _append_field(facts, "Tenant domain", info.default_domain)

    auth_line = key_facts_auth_line(info)
    if auth_line is not None:
        _append_field(facts, "Auth", auth_line)

    # Sovereignty — only when cloud_instance indicates non-commercial.
    if info.cloud_instance and "microsoftonline.com" not in info.cloud_instance.lower():
        sov_label = info.cloud_instance
        if info.tenant_region_sub_scope:
            sov_label += f" ({info.tenant_region_sub_scope})"
        _append_field(facts, "Cloud", sov_label)

    multicloud_line = key_facts_multicloud_line(info)
    if multicloud_line is not None:
        _append_field(facts, "Multi-cloud", multicloud_line)

    # Deterministic confidence and, when fusion ran, a separate model display.
    _append_confidence_field(facts, info)

    return facts


def render_tenant_panel(
    info: TenantInfo,
    show_services: bool = False,
    show_domains: bool = False,
    verbose: bool = False,
    explain: bool = False,
    confidence_mode: str = "hedged",
):  # -> rich renderable
    """Render TenantInfo as a plain-text hero layout.

    Replaces the old bordered Panel with a flat, professional layout
    that foregrounds Services, keeps Related domains compact, and
    uses color sparingly and intelligently.

    Layout (default mode)
        Company name (bold, full width)
        apex.domain.com (dim)
        ──────────────────────────────── (dim horizontal rule)

        Provider     <detect_provider output>
        Tenant       <tenant_id> • <region>          (only if present)
        Auth         <auth_type> + <GWS auth>        (only if present)
        Confidence   ●●○ Medium (N sources)          (green only on High)

        Services                                     (bold cyan header)
          Email          svc, svc, svc
          Identity       svc, svc
          …

        High-signal related domains                  (bold cyan header)
          login.x, sso.x, api.x ... (N total, use --full to see all)

        Note: …                                     (yellow only when degraded)

    --verbose, --explain, --domains add sections after the core layout. The
    function name and ``show_services`` remain for compatibility; Services are
    part of the default panel.
    """
    from rich.console import Group

    from recon_tool.collection_view import collection_observable_info

    info = collection_observable_info(info)

    # Core layout blocks are accumulated into a list and wrapped in a
    # Rich Group at the end. Each block is a Text instance so we can
    # style per-segment without fighting markup.
    blocks: list[Any] = []

    def _spacer() -> None:
        """Insert a blank line between sections to separate them visually."""
        blocks.append(Text(""))

    # ── Hero header ────────────────────────────────────────────────
    # When display_name falls back to the queried namespace, render it once as
    # bold instead of showing the same string twice.
    header = Text()
    header.append(info.display_name, style="bold")
    if info.queried_domain != info.display_name:
        header.append("\n")
        header.append(info.queried_domain, style="dim")
    blocks.append(header)
    rule = Text("─" * _PANEL_WIDTH, style="dim")
    blocks.append(rule)

    # ── Key facts block ────────────────────────────────────────────
    # --explain, --verbose, and --full are the "how do we know" views and keep
    # every evidence-role qualifier. The default view is the "what do they run"
    # view and compacts them (ADR-0012). --domains is not a detail view: it
    # widens the domain listing without asking for evidence.
    detailed = verbose or explain
    blocks.append(_render_key_facts(info, detailed))

    # ── Services section ──────────────────────────────────────────
    svc_block, ceiling_categorized_count = _render_services(info, show_domains, detailed)
    if svc_block is not None:
        _spacer()
        blocks.append(svc_block)

    # ── Passive-DNS ceiling phrasing ─────────────────────
    ceiling = _render_passive_dns_ceiling(info, show_domains, ceiling_categorized_count)
    if ceiling is not None:
        _spacer()
        blocks.append(ceiling)

    # ── Related domains & external-footprint listings ─────────────
    # Each helper self-gates on default-vs-full mode and returns None when its
    # section does not apply, so the panel just appends whatever is present in
    # the original section order.
    for footprint_section in (
        _render_related_compact(info, show_domains),
        _render_unclassified_surface(info, show_domains),
        _render_full_tenant_domains(info, show_domains),
        _render_full_related(info, show_domains),
        _render_external_surface(info, show_domains),
    ):
        if footprint_section is not None:
            _spacer()
            blocks.append(footprint_section)

    # ── Insights, certs, degraded note, and verbose / explain detail ─
    # Each helper self-gates and returns None when its section does not apply.
    for detail_section in (
        _render_insights(info, verbose, confidence_mode),
        _render_certs(info, verbose),
        _render_degraded_note(info),
        render_low_confidence_guidance(info, verbose, explain),
        _render_verbose_detail(info, verbose),
        _render_explain_conflicts(info, explain, verbose),
    ):
        if detail_section is not None:
            _spacer()
            blocks.append(detail_section)

    return Group(*blocks)


def _append_subdomain_summary(svc_block: Text, info: TenantInfo, show_domains: bool, max_width: int) -> bool:
    """Default-mode-only line summarising the providers the CNAME-chain
    classifier attributed to subdomains, with per-provider counts so the
    multi-cloud distribution is visible at a glance (e.g. ``AWS CloudFront (5),
    Fastly (3)``).

    Kept separate from the apex Services categories because apex DNS evidence
    and subdomain CNAME-chain evidence answer different questions and conflating
    them double-counts; --full shows the full per-subdomain table instead, so
    the summary is suppressed there. Deliberately no apex-evidence filter: the
    line answers "how many subdomains sit on which provider", distinct from the
    Cloud line's "what does the apex resolve to". Counts the primary attribution
    per subdomain (the fronting infra tier is the same subdomain, not an extra),
    falling back to the infra tier only when there is no primary.

    Returns whether a summary row was appended, so the caller can keep the
    Services section alive on a panel whose apex rows were all compacted away.
    """
    if not (info.surface_attributions and not show_domains):
        return False
    surface_summary = subdomain_surface_summary_items(info.surface_attributions)
    if not surface_summary:
        return False
    budget = _PANEL_WIDTH - (2 + max_width)
    lines = compact_subdomain_summary_lines(surface_summary, budget)
    svc_block.append("  ")
    svc_block.append("Subdomain".ljust(max_width), style="dim")
    for index, line in enumerate(lines):
        if index:
            svc_block.append(" " * (2 + max_width))
        svc_block.append(line)
        svc_block.append("\n")
    return True


def _evidence_role_note(compacted_count: int, dropped_count: int) -> str | None:
    """Name what the default view left out, or ``None`` when it left out nothing.

    A panel whose every label was already role-free must not carry a note about
    roles, so this returns ``None`` rather than a generic footer. Dropped
    matches are counted and point at --full: an operator can infer a compacted
    label from the label, but cannot infer a hidden row from a row that is not
    there.
    """
    if compacted_count and dropped_count:
        return f"Evidence roles + {dropped_count} unattributed: --full"
    if dropped_count:
        noun = "match" if dropped_count == 1 else "matches"
        return f"{dropped_count} unattributed {noun}: --full"
    if compacted_count:
        return "Evidence roles: --explain"
    return None


def _render_services(info: TenantInfo, show_domains: bool, detailed: bool) -> tuple[Text | None, int]:
    """Render the categorized Services section and return it with the count of
    service categories (used by the passive-DNS ceiling trigger).

    Returns ``(None, 0)`` when there are no services. ``detailed`` is the
    --explain / --verbose / --full view, which keeps every evidence-role
    qualifier; the default view compacts them per ADR-0012 and points at the
    detailed surfaces. Compaction can empty the section outright when every
    match was unattributed, so the emptiness check runs after it, not just on
    ``info.services``. Output held byte-identical by
    ``tests/test_golden_renders.py`` (``panel_dense_default`` /
    ``panel_surface_default``).

    The returned count is deliberately the count *before* compaction. It feeds
    the passive-DNS ceiling, which asks how much signal the collection found,
    not how many rows this view chose to draw; compacting a label must not move
    a domain across the sparseness boundary.
    """
    if not info.services:
        return None, 0
    categorized = _categorize_services(info)
    if "Email" in categorized:
        normalize_email_services(categorized, info)
    collected_category_count = len(categorized)
    compacted_count = 0
    dropped_count = 0
    if not detailed:
        categorized, compacted_count, dropped_count = compact_categorized_services(categorized)
    # Widen the label column only when a label present in this render needs
    # it, so short-label panels keep their value width and a long label
    # (e.g. "Data & Analytics") still gets one space before its value.
    max_width = max(_CATEGORY_WIDTH, max((len(c) for c in categorized), default=0) + 1)
    body = Text()
    for cat, svcs in categorized.items():
        body.append("  ")
        body.append(cat.ljust(max_width), style="dim")
        wrapped = _wrap_service_list(
            svcs,
            label_width=2 + max_width,
            panel_width=_PANEL_WIDTH,
            panel_pad=0,
        )
        body.append(wrapped)
        body.append("\n")
    # The subdomain summary is CNAME-chain attribution, not an apex catalog
    # label, so it survives apex compaction and keeps the section alive on its
    # own. Without this the section would vanish whole when every apex match
    # was unattributed, taking an unrelated finding with it.
    has_subdomain_summary = _append_subdomain_summary(body, info, show_domains, max_width)
    has_rows = bool(categorized) or has_subdomain_summary
    note = _evidence_role_note(compacted_count, dropped_count)
    if not has_rows and note is None:
        return None, collected_category_count
    if note is not None:
        # Align under the value column when rows precede it; fall back to the
        # section indent when the note is the whole section, which is what a
        # --domains render looks like once every apex match was unattributed.
        body.append(" " * (2 + max_width) if has_rows else "  ")
        body.append(note, style="dim italic")
        body.append("\n")
    svc_block = Text()
    svc_block.append("Services", style="bold")
    svc_block.append("\n")
    svc_block.append(body)
    return svc_block, collected_category_count


def _render_passive_dns_ceiling(info: TenantInfo, show_domains: bool, categorized_count: int) -> Text | None:
    """One-line teaching note about what passive DNS cannot see, shown on a
    default panel that looks sparser than the org probably is.

    Operators (and AI agents) reading a sparse panel otherwise risk the
    "absence of finding = service not present" misread. The trigger is
    conservative: default panel only (--full signals scale on its own),
    services present (a fully-failed run is handled by ``render_warning``),
    ``domain_count >= 3`` (a non-trivial org), and fewer than five categorized
    families AND fewer than five subdomain attributions. Both halves of the
    sparseness check matter: four categories with thirty attributions is not
    sparse; four with zero is. Returns ``None`` when the trigger does not fire.
    """
    _SPARSE_CATEGORY_FLOOR = 5
    _SPARSE_SURFACE_FLOOR = 5
    _MIN_DOMAINS_FOR_CEILING = 3
    if not (
        info.services
        and not show_domains
        and info.domain_count >= _MIN_DOMAINS_FOR_CEILING
        and categorized_count < _SPARSE_CATEGORY_FLOOR
        and len(info.surface_attributions) < _SPARSE_SURFACE_FLOOR
    ):
        return None
    ceiling = Text()
    ceiling.append("Passive-DNS ceiling", style="bold")
    ceiling.append("\n")
    message = (
        "Passive DNS surfaces what publishes externally. Server-side API consumption, internal workloads, and "
        "SaaS without DNS verification do not appear in public DNS records."
    )
    _append_wrapped_lines(ceiling, message, _PANEL_WIDTH - 2, "dim")
    ceiling.rstrip()
    return ceiling


def _render_related_compact(info: TenantInfo, show_domains: bool) -> Text | None:
    """Compact high-signal related-domains list (default panel only).

    Returns ``None`` unless there are related domains and at least one survives
    the high-signal filter. Extracted from ``render_tenant_panel``; output held
    byte-identical by ``tests/test_golden_renders.py`` (``panel_dense_default``).
    """
    if not (info.related_domains and not show_domains):
        return None
    picked, total = high_signal_related(tuple(info.related_domains))
    if not picked:
        return None
    rel = Text()
    rel.append("High-signal related domains", style="bold")
    rel.append("\n")
    rel.append("  ")
    # Render as a wrapped comma-list within the panel width.
    joined = ", ".join(picked)
    max_width = _PANEL_WIDTH - 2
    for j, line in enumerate(_wrap_text(joined, max_width)):
        if j > 0:
            rel.append("\n  ")
        rel.append(line, style="dim")
    if total > len(picked):
        remaining = total - len(picked)
        rel.append(
            f"\n  ({total} total, {remaining} more, use --full to see all)",
            style="dim italic",
        )
    return rel


def _render_unclassified_surface(info: TenantInfo, show_domains: bool) -> Text | None:
    """Unclassified-CNAME-termini note (default panel only).

    The chain walker reached CNAME termini the catalog could not classify.
    Surfacing the count plus up to two representative subdomain -> terminus
    examples corrects the default panel's implicit "they only use the services
    we listed" to "they use AT LEAST those, plus N unclassified surfaces" —
    humility over completeness, since absence of evidence otherwise reads as
    evidence of absence. Returns ``None`` when there are no unclassified chains
    or in --domains / --full mode. Output held byte-identical by
    ``tests/test_golden_renders.py`` (``panel_surface_default``).
    """
    if not (info.unclassified_cname_chains and not show_domains):
        return None
    unc = Text()
    n = len(info.unclassified_cname_chains)
    noun = "terminus" if n == 1 else "termini"
    unc.append("Unclassified surface", style="bold")
    unc.append("\n  ")
    unc.append(
        f"{n} CNAME chain {noun} reached, no fingerprint match. ",
        style="dim",
    )
    unc.append(
        "We walked them but cannot name them — open a fingerprint PR or run\n  ",
        style="dim",
    )
    unc.append(
        f"`recon discover {info.queried_domain}` to triage candidates.",
        style="dim italic",
    )
    # Up to 2 representative pairs so the operator can sanity-check what's
    # getting missed; --full / `recon discover` is the path to the full list.
    examples = list(info.unclassified_cname_chains[:2])
    if examples:
        unc.append("\n  ", style="dim")
        unc.append("examples: ", style="dim")
        sample_strs: list[str] = []
        for uc in examples:
            terminus = uc.chain[-1] if uc.chain else "(no terminus)"
            sample_strs.append(f"{strip_control_chars(uc.subdomain)} → {strip_control_chars(terminus)}")
        unc.append(", ".join(sample_strs), style="dim italic")
    return unc


def _render_full_tenant_domains(info: TenantInfo, show_domains: bool) -> Text | None:
    """Full tenant-domains listing (--domains / --full only)."""
    if not (show_domains and info.tenant_domains):
        return None
    dom = Text()
    dom.append(f"Domains ({info.domain_count})", style="bold")
    dom.append("\n")
    for d in info.tenant_domains:
        dom.append(f"  {d}\n", style="dim")
    return dom


def _render_full_related(info: TenantInfo, show_domains: bool) -> Text | None:
    """Classified related-host list (--domains / --full only).

    The default briefing keeps the high-signal comma list. The complete
    record groups every related host by first-label class so a reader can
    route on auth. / shop. / workday. without a dump.
    """
    if not (show_domains and info.related_domains):
        return None
    from recon_tool.formatter.connection_map import related_host_classes

    classes = related_host_classes(tuple(info.related_domains), info.surface_attributions)
    rel = Text()
    rel.append("Related host classes", style="bold")
    rel.append("\n")
    for item in classes:
        prefix = str(item["prefix"])
        slugs = item["primary_slugs"]
        heading = prefix if not slugs else f"{prefix} ({', '.join(str(s) for s in slugs)})"
        rel.append(f"  {heading}\n", style="dim")
        for host in item["hosts"]:
            rel.append(f"    {host}\n", style="dim")
    rel.rstrip()
    return rel


_SURFACE_COLLAPSE_THRESHOLD = 5


def _surface_partition(
    attributions: tuple[Any, ...],
) -> tuple[list[Any], list[tuple[str, list[Any]]]]:
    """Split surface attributions into individually-listed rows and collapsed
    per-service groups.

    Services with ``>= _SURFACE_COLLAPSE_THRESHOLD`` attributions (typically an
    apex's primary CDN, e.g. Fastly fronting 54 of a domain's subdomains)
    collapse to a single group so the section stays scannable; the rest are
    shown one per line, which preserves the "what is this URL serving" answer
    for low-frequency findings. Individuals are sorted by subdomain; collapsed
    groups by descending size (largest first, most important to know about).
    """
    from collections import defaultdict as _dd

    groups: dict[str, list[Any]] = _dd(list)
    for sa in attributions:
        groups[sa.primary_name].append(sa)

    individuals: list[Any] = []
    collapsed: list[tuple[str, list[Any]]] = []
    for service_name, sas in groups.items():
        if len(sas) >= _SURFACE_COLLAPSE_THRESHOLD:
            collapsed.append((service_name, sorted(sas, key=lambda s: s.subdomain)))
        else:
            individuals.extend(sas)

    individuals.sort(key=lambda s: s.subdomain)
    collapsed.sort(key=lambda t: -len(t[1]))
    return individuals, collapsed


def _append_individual_rows(surf: Text, individuals: list[Any]) -> None:
    """Append one row per individually-listed attribution: subdomain (left,
    truncated to a derived column width) then the service label, with the
    fronting infrastructure tier appended when the chain matched both an
    application and an infrastructure service (e.g. Auth0 fronted by Cloudflare).
    """
    if not individuals:
        return
    # Column width derived from the longest individual subdomain. Min 24 so
    # short panels don't crowd; max _PANEL_WIDTH - 30 so long ones don't push
    # the service column off-screen.
    ind_max = max(len(s.subdomain) for s in individuals)
    col_width = max(24, min(ind_max, _PANEL_WIDTH - 30))
    for sa in individuals:
        sub = strip_control_chars(sa.subdomain)
        if len(sub) > col_width:
            sub = sub[: col_width - 2] + ".."
        services_label = strip_control_chars(sa.primary_name)
        if sa.infra_name:
            services_label = f"{strip_control_chars(sa.primary_name)}, {strip_control_chars(sa.infra_name)}"
        surf.append("  ")
        surf.append(f"{sub:<{col_width}}", style="dim")
        surf.append("  ")
        surf.append(services_label)
        surf.append("\n")


def _append_collapsed_rows(
    surf: Text, collapsed: list[tuple[str, list[Any]]], had_individuals: bool, apex: str
) -> None:
    """Append the collapsed per-service groups after any individual rows: one
    bold header per service, then the wrapped list of subdomains with the apex
    suffix stripped to a bare label (``app`` instead of ``app.alpha.invalid``) so
    more fit per wrapped line.
    """
    if not collapsed:
        return
    if had_individuals:
        surf.append("\n")
    for service_name, sas in collapsed:
        surf.append("  ")
        surf.append(f"{service_name} ({len(sas)})", style="bold")
        surf.append("\n")
        short_names: list[str] = []
        for s in sas:
            sub = s.subdomain
            if sub.endswith("." + apex):
                sub = sub[: -(len(apex) + 1)]
            elif sub == apex:
                sub = "(apex)"
            short_names.append(sub)
        joined = ", ".join(short_names)
        for line in _wrap_text(joined, _PANEL_WIDTH - 4):
            surf.append("    ")
            surf.append(line, style="dim")
            surf.append("\n")


def _render_external_surface(info: TenantInfo, show_domains: bool) -> Text | None:
    """Per-subdomain external-surface section (only with --domains / --full).

    Two-column layout (subdomain, primary service name) sorted alphabetically
    by subdomain. No arrows or decorative characters — the gutter does the
    separating. Default panel hides this; --full / --domains shows it because
    only operators investigating the external footprint care about the map.

    Returns ``None`` when the section does not apply. Extracted from
    ``render_tenant_panel`` (C901 decomposition); output held byte-identical by
    ``tests/test_golden_renders.py`` (``panel_surface_full``).
    """
    if not (show_domains and info.surface_attributions):
        return None
    surf = Text()
    surf.append(f"External surface ({len(info.surface_attributions)})", style="bold")
    surf.append("\n")

    individuals, collapsed = _surface_partition(info.surface_attributions)
    _append_individual_rows(surf, individuals)
    _append_collapsed_rows(surf, collapsed, bool(individuals), info.queried_domain)

    # Discovery-loop hint: when there are unclassified CNAME chains the surface
    # classifier resolved but couldn't attribute, invite the user into the
    # catalog-growth loop. Only here (--full / --domains), where the user is
    # already engaged with the surface map.
    if info.unclassified_cname_chains:
        n = len(info.unclassified_cname_chains)
        noun = "subdomain" if n == 1 else "subdomains"
        surf.append("\n  ")
        surf.append(
            f"{n} unclassified {noun}: `recon discover {info.queried_domain}` to surface fingerprint candidates",
            style="dim italic",
        )
        surf.append("\n")

    return surf


def _append_wrapped_lines(text: Text, content: str, max_width: int, style: str) -> None:
    """Append ``content`` wrapped to ``max_width``, each line indented two
    spaces, with a trailing newline. Shared by the panel's score and insight
    lines so both wrap identically.
    """
    for j, line in enumerate(_wrap_text(content, max_width)):
        text.append("  " if j == 0 else "\n  ")
        text.append(line, style=style)
    text.append("\n")


def _render_insights(info: TenantInfo, verbose: bool, confidence_mode: str) -> Text | None:
    """Curated Insights section.

    Selection, hedging, and ordering come from ``briefing`` so the linear
    ``--plain`` view makes the same cut; this function is the Rich rendering of
    that decision, with the email-security score in bold above the rest.
    Returns ``None`` when there is nothing to show. Output held byte-identical
    by ``tests/test_golden_renders.py`` (``panel_dense_default`` and the strict
    / sparse variants).
    """
    if not info.insights:
        return None
    score_line, ordered_insights = briefing_insights(info, confidence_mode)
    if score_line is None and not ordered_insights:
        return None
    ins = Text()
    ins.append("Insights", style="bold")
    ins.append("\n")
    max_width = _PANEL_WIDTH - 2

    if score_line is not None:
        _append_wrapped_lines(ins, score_line, max_width, "bold")

    display_insights, overflow_count = cap_insights(ordered_insights, verbose)

    for insight in display_insights:
        _append_wrapped_lines(ins, insight, max_width, "dim")

    if overflow_count > 0:
        ins.append("  ")
        ins.append(f"{overflow_count} more, use --full to see all", style="dim italic")
        ins.append("\n")

    return ins


def _render_certs(info: TenantInfo, verbose: bool) -> Text | None:
    """Certificate summary line (--verbose / --full only)."""
    if not (verbose and info.cert_summary is not None):
        return None
    cs = info.cert_summary
    issuer_list = ", ".join(cs.top_issuers) if cs.top_issuers else "unknown"
    certs = Text()
    certs.append("Certs", style="bold")
    certs.append("\n  ")
    certs.append(
        f"{cs.cert_count} total, {cs.issuance_velocity} in last 90d, {cs.issuer_diversity} issuers ({issuer_list})",
        style="dim",
    )
    return certs


def _degraded_note_parts(info: TenantInfo) -> tuple[list[str], bool]:
    """Decide which degraded-source note lines to show and whether the framing
    is a warning.

    Warning tone (yellow) applies when a non-CT source is unavailable or every
    CT provider failed. Info tone (dim) covers a routine CT fallback that
    recovered. Routine crt.sh -> certspotter fallbacks are suppressed as noise
    (provenance stays in --json); a cache fallback that actually changed the
    answer (returned at least one subdomain) is surfaced.
    """
    non_ct_degraded = [s for s in info.degraded_sources if s not in ("crt.sh", "certspotter")]
    ct_in_degraded = [s for s in info.degraded_sources if s in ("crt.sh", "certspotter")]
    ct_fallback_succeeded = bool(ct_in_degraded) and info.ct_provider_used is not None
    ct_fallback_failed = bool(ct_in_degraded) and info.ct_provider_used is None
    ct_from_cache = info.ct_cache_age_days is not None
    ct_fallback_informative = ct_fallback_succeeded and info.ct_subdomain_count > 0
    is_warning = bool(non_ct_degraded) or ct_fallback_failed

    note_parts: list[str] = []
    if non_ct_degraded:
        note_parts.append(f"Some sources unavailable ({', '.join(non_ct_degraded)})")
    if ct_fallback_failed:
        note_parts.append(f"All CT providers unavailable ({', '.join(ct_in_degraded)})")
    elif ct_from_cache and ct_fallback_informative:
        age = info.ct_cache_age_days
        age_str = "today" if age == 0 else f"{age} day{'s' if age != 1 else ''} old"
        note_parts.append(f"CT: from local cache, {age_str} ({info.ct_subdomain_count} subdomains)")
    return note_parts, is_warning


def _render_degraded_note(info: TenantInfo) -> Text | None:
    """Degraded-sources note. Returns ``None`` when there is nothing worth
    noting. Output held byte-identical by ``tests/test_golden_renders.py``
    (``panel_hardened_default`` exercises the warning path).
    """
    if not info.degraded_sources:
        return None
    note_parts, is_warning = _degraded_note_parts(info)
    if not note_parts:
        return None
    style = "yellow" if is_warning else "dim"
    note = Text()
    note.append("Note", style=style)
    note.append("\n  ")
    note_text = " — ".join(note_parts) + "."
    for j, line in enumerate(_wrap_text(note_text, _PANEL_WIDTH - 2)):
        if j > 0:
            note.append("\n  ")
        note.append(line, style=style)
    return note


def _render_verbose_detail(info: TenantInfo, verbose: bool) -> Text | None:
    """Evidence-detail section (--verbose / --full only): dual confidence,
    detection scores, and the evidence chain.
    """
    if not verbose:
        return None
    v = Text()
    v.append("Evidence Detail", style="bold")
    v.append("\n")
    v.append(
        f"  Evidence confidence:  {info.evidence_confidence.value.capitalize()}\n",
        style="dim",
    )
    v.append(
        f"  Inference confidence: {info.inference_confidence.value.capitalize()}\n",
        style="dim",
    )
    # Model-relative Bayesian posteriors with 80% uncertainty bands, for
    # operators who want the math visible by default. The label names the
    # band so the comma range is not read as a frequentist confidence
    # interval. Claimed nodes only (the verdict's nodes), strongest first.
    claimed_posteriors = [o for o in info.posterior_observations if o.evidence_used]
    if claimed_posteriors:
        v.append("  Model posteriors (80% uncertainty band):\n", style="dim")
        for o in sorted(claimed_posteriors, key=lambda x: -x.posterior):
            v.append(
                f"    {o.name}: {o.posterior:.2f} [{o.interval_low:.2f}, {o.interval_high:.2f}]\n",
                style="dim",
            )
    if info.detection_scores:
        v.append("  Detection scores:\n", style="dim")
        for slug, score in info.detection_scores:
            v.append(f"    {slug}: {score}\n", style="dim")
    if info.evidence:
        v.append("  Evidence chain:\n", style="dim")
        for ev in info.evidence:
            v.append(f"    [{ev.source_type}] {ev.rule_name} -> {ev.slug}\n", style="dim")
    return v


def _render_explain_conflicts(info: TenantInfo, explain: bool, verbose: bool) -> Text | None:
    """Conflict annotations (--explain only) for the fields that carry merge
    conflicts.
    """
    if not (explain and info.merge_conflicts and info.merge_conflicts.has_conflicts):
        return None
    conf_block = Text()
    conf_block.append("Conflicts", style="bold")
    conf_block.append("\n")
    for field_name in ("display_name", "auth_type", "region", "tenant_id", "dmarc_policy"):
        ann = render_conflict_annotation(field_name, info.merge_conflicts, verbose=verbose)
        if ann:
            conf_block.append(f"  {field_name}: {ann}\n", style="dim")
    return conf_block


def render_verbose_sources(results: list[SourceResult], *, console: Console | None = None) -> None:
    """Print per-source status lines to console."""
    c = console or get_console()
    for result in results:
        success = is_confidence_contributor(result)
        soft_miss = not success and _is_soft_miss(result.error)
        marker = "[green]match[/green]" if success else ("[dim]no match[/dim]" if soft_miss else "[red]error[/red]")
        detail = _source_success_description(result) if success else result.error or "no match"
        safe_detail = escape(strip_control_chars(detail))
        c.print(f"  {marker} {result.source_name}: {safe_detail}")


def _source_success_description(result: SourceResult) -> str:
    """Build a brief description for a successful source result."""
    parts: list[str] = []
    if result.tenant_id:
        parts.append("tenant ID found")
    if result.region:
        parts.append("region confirmed")
    if result.m365_detected and not result.tenant_id:
        parts.append("M365 association detected")
    if result.display_name:
        parts.append("display name found")
    if result.auth_type:
        parts.append(f"auth: {result.auth_type}")
    if result.tenant_domains:
        parts.append(f"{len(result.tenant_domains)} domains")
    if result.dmarc_policy:
        parts.append(f"DMARC: {result.dmarc_policy}")
    return ", ".join(parts) if parts else "data returned"


def render_sources_detail(results: list[SourceResult]) -> Table:
    """Return a rich Table with detailed per-source data."""
    table = Table(title="Source Details")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("Tenant ID")
    table.add_column("Region")
    table.add_column("Details")

    for result in results:
        status = (
            Text("\u2713 success", style="green")
            if is_confidence_contributor(result)
            else Text("\u2717 failed", style="red")
        )
        tenant_id = result.tenant_id or "—"
        # region and error can carry attacker-influenced text (a federation
        # region value, or a domain / exception interpolated into an error
        # string); strip control bytes for parity with the primary panel.
        region = strip_control_chars(result.region) if result.region else "—"
        details = (
            strip_control_chars(result.error) if result.error else ("M365 detected" if result.m365_detected else "—")
        )
        table.add_row(result.source_name, status, tenant_id, region, details)

    return table


def render_warning(domain: str, error: ReconLookupError | None = None) -> None:
    """Print a yellow warning for not-found domains.

    When ``error`` is provided and carries per-source failure reasons, the
    concrete reasons are rendered as a dim second line so the user can tell
    whether the domain is genuinely empty or whether a transient failure
    hid real data. Without ``error`` (or when no source_errors are
    populated), the original one-liner is used.
    """
    console = get_err_console()
    safe_domain = escape(strip_control_chars(domain))
    console.print(f"[yellow]No information found for {safe_domain}[/yellow]")
    if error is not None and getattr(error, "source_errors", ()):
        for name, reason in error.source_errors:
            line = escape(strip_control_chars(f"{name}: {reason}"))
            console.print(f"  [dim]{line}[/dim]")


def render_error(message: str) -> None:
    """Print a red error message to stderr. The message is escaped and
    control-stripped so untrusted content (for example a batch-file domain
    echoed back in the error) cannot inject rich markup or terminal escapes
    into the console. Goes to stderr so it never pollutes a piped stdout
    data stream."""
    safe = escape(strip_control_chars(message))
    get_err_console().print(f"[red]{safe}[/red]")


# ── Posture observation rendering ────────────────────────────────────────

_SALIENCE_INDICATORS: dict[str, str] = {
    "high": "●",
    "medium": "◐",
    "low": "○",
}


def format_posture_observations(observations: tuple[Observation, ...]) -> list[dict[str, Any]]:
    """Format observations as a list of dicts for JSON output."""
    return [
        {
            "category": obs.category,
            "salience": obs.salience,
            "statement": obs.statement,
            "related_slugs": list(obs.related_slugs),
        }
        for obs in observations
    ]


def render_posture_panel(observations: tuple[Observation, ...]) -> Panel | None:
    """Render posture observations as a Rich panel grouped by category."""
    if not observations:
        return None

    # Group by category, preserving order of first appearance
    groups: dict[str, list[Observation]] = {}
    for obs in observations:
        groups.setdefault(obs.category, []).append(obs)

    text = Text()
    first_group = True
    for category, obs_list in groups.items():
        if not first_group:
            text.append("\n\n")
        first_group = False

        text.append(f"  {category.replace('_', ' ').title()}\n", style="bold")
        for obs in obs_list:
            indicator = _SALIENCE_INDICATORS.get(obs.salience, "○")
            text.append(f"  {indicator} ", style="dim")
            text.append(obs.statement)
            text.append("\n")

    return Panel(
        text,
        title="Posture Analysis",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Chain rendering ──────────────────────────────────────────────────────


def format_chain_dict(report: ChainReport) -> dict[str, Any]:
    """Format ChainReport as a dict for JSON output."""
    return {
        "total_domains": len(report.results),
        "max_depth_reached": report.max_depth_reached,
        "truncated": report.truncated,
        "domains": [
            {
                **format_tenant_dict(r.info),
                "chain_depth": r.chain_depth,
            }
            for r in report.results
        ],
    }


def format_chain_json(report: ChainReport) -> str:
    """Format ChainReport as a JSON string."""
    return json.dumps(format_chain_dict(report), indent=2)


def render_chain_panel(report: ChainReport) -> Panel:
    """Render chain report as a Rich panel with domain tree."""
    text = Text()

    text.append("  Total Domains: ", style="dim")
    text.append(f"{len(report.results)}\n")
    text.append("  Max Depth:     ", style="dim")
    text.append(f"{report.max_depth_reached}\n")
    if report.truncated:
        text.append("  Status:        ", style="dim")
        text.append("Truncated (cap reached)", style="yellow")
        text.append("\n")

    # Domain tree grouped by depth
    if report.results:
        text.append("\n")
        current_depth = -1
        for r in report.results:
            if r.chain_depth != current_depth:
                current_depth = r.chain_depth
                text.append(f"  Depth {current_depth}:\n", style="bold")
            indent = "    " + "  " * r.chain_depth
            # One compact summary row per resolved domain: this tree is the
            # densest repetition of the provider line in the tool, so it takes
            # the default view's compaction (ADR-0012) unconditionally.
            provider = compact_provider_line(provider_line(r.info))
            text.append(f"{indent}{r.domain}", style="cyan")
            text.append(f" — {r.info.display_name}", style="dim")
            if not provider.startswith("Unknown"):
                text.append(f" ({provider})", style="dim")
            text.append("\n")

    return Panel(
        text,
        title="Chain Resolution",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


# ── Explanation rendering ────────────────────────────────────────────────


# Substrings that mark a SourceResult error as a "soft miss" — the source
# ran cleanly and determined the target isn't theirs — rather than a
# transport/transient failure. Rendering these with `✗` in red misreads
# a legitimate "not a customer" answer as if the tool had broken.
_SOFT_MISS_MARKERS: tuple[str, ...] = (
    "No Google Workspace",
    "No federated IdP redirect",
    "Not a Google Workspace",
    "No M365 tenant",
    "Not a registered M365",
    "HTTP 400 from OIDC discovery",
    "No information could be resolved",
    "no data returned",
)


def _is_soft_miss(error: str | None) -> bool:
    if not error:
        return True  # empty error but is_success False = soft miss
    return any(marker in error for marker in _SOFT_MISS_MARKERS)


def render_source_status_panel(results: list[SourceResult]) -> Panel | None:
    """Render a compact per-source status panel for ``--explain`` output.

    Three states:

    - ``✓`` (green) — source ran and produced a match.
    - ``–`` (dim) — source ran cleanly but the target isn't their
      customer ("not a Workspace domain", "HTTP 400 from OIDC" = not
      an M365 tenant, "no federated IdP redirect", etc.). Previously
      rendered as ``✗`` which misread a legitimate "not a match"
      answer as if the tool had broken.
    - ``✗`` (red) — transport/HTTP failure, timeout, or other genuine
      problem with the source.

    Duplicate rows from enrichment passes (multiple ``dns_records``
    entries from subdomain lookups) are collapsed into one summary
    line per source to keep the panel focused on the primary lookup.
    """
    if not results:
        return None

    # Collapse duplicate source_name rows from enrichment — only keep
    # the first (primary) result per source. Enrichment subdomain
    # lookups appear as additional SourceResults with source_name
    # "dns_records" and their success/failure status is an internal
    # detail, not a primary-source observation.
    seen: set[str] = set()
    primary: list[SourceResult] = []
    for r in results:
        if r.source_name in seen:
            continue
        seen.add(r.source_name)
        primary.append(r)

    text = Text()
    for i, result in enumerate(primary):
        if i > 0:
            text.append("\n")
        if is_confidence_contributor(result):
            description = _source_success_description(result)
            text.append("  ✓ ", style="#a3d9a5")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {description}", style="dim")
        elif _is_soft_miss(result.error):
            text.append("  – ", style="dim")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {result.error or 'no match'}", style="dim")
        else:
            text.append("  ✗ ", style="#e07a5f")
            text.append(f"{result.source_name}", style="bold")
            text.append(f" — {result.error}", style="dim")
    return Panel(
        text,
        title="Source Status",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def render_conflict_annotation(
    field_name: str,
    conflicts: MergeConflicts,
    verbose: bool = False,
) -> str:
    """Render a dim conflict indicator for a Rich panel field.

    Returns a string like "  [2 sources disagree]" when the field has conflicts.
    When verbose=True, also lists all candidate values.
    Returns empty string when no conflict exists for the field.
    """
    candidates: tuple[CandidateValue, ...] = getattr(conflicts, field_name, ())
    if not candidates:
        return ""

    unique_values = {c.value for c in candidates}
    if len(unique_values) < 2:
        return ""

    annotation = f"  [{len(candidates)} sources disagree]"

    if verbose:
        parts: list[str] = []
        for c in candidates:
            parts.append(f"{strip_control_chars(str(c.value))} ({c.source})")
        annotation += f"  ({', '.join(parts)})"

    return annotation
