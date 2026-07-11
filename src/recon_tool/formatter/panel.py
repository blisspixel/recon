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
from recon_tool.exposure import (
    PostureComparison,
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
    count_cloud_vendors,
    detect_provider,
    is_gws_service,
    is_m365_service,
    provider_line,
    slug_to_relationship_metadata,
)
from recon_tool.formatter.delta import (  # re-exported: stable import path after the split
    format_delta_dict,
    format_delta_json,
    render_delta_panel,
)
from recon_tool.formatter.exposure import (  # re-exported: stable import path after the split
    format_exposure_dict,
    format_exposure_json,
    format_gaps_dict,
    format_gaps_json,
    render_exposure_panel,
    render_gaps_panel,
)
from recon_tool.formatter.layout import compact_subdomain_summary_lines, subdomain_surface_summary_items
from recon_tool.formatter.markdown import (
    format_explanations_markdown,
    format_tenant_markdown,
    markdown_escape,
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
from recon_tool.merger_tables import GATEWAY_SLUGS
from recon_tool.models import (
    CandidateValue,
    ChainReport,
    ConfidenceLevel,
    ExplanationRecord,
    MergeConflicts,
    Observation,
    PosteriorObservation,
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

# Model-relative display support for the weakest claimed node. This stays
# distinct from deterministic confidence because the hand-set uncertainty band
# is not calibrated and its width is not generally evidence-monotone.
_POSTERIOR_DECISION_THRESHOLD = 0.5

_DOT_FILL_GLYPH: dict[int, str] = {3: "●●●", 2: "●●○", 1: "●○○"}

_DOT_FILL_COLOR: dict[int, str] = {
    3: CONFIDENCE_COLORS[ConfidenceLevel.HIGH],
    2: CONFIDENCE_COLORS[ConfidenceLevel.MEDIUM],
    1: CONFIDENCE_COLORS[ConfidenceLevel.LOW],
}


def _posterior_dot_fill(obs: PosteriorObservation, threshold: float = _POSTERIOR_DECISION_THRESHOLD) -> int:
    """Solid-dot count (1 to 3) for a positive claim's model display.

    - 3: the whole interval is above the threshold.
    - 2: the point estimate is on the yes-side but the interval dips below the
      threshold, so the display straddles the threshold.
    - 1: the point estimate is on the no-side of the model threshold.

    Pure and monotone in ``interval_low`` then ``posterior``; pinned by a
    property test so the renderer cannot drift or recalibrate through the UI.
    """
    if obs.interval_low >= threshold:
        return 3
    if obs.posterior >= threshold:
        return 2
    return 1


# Human-readable name for each node's claim, for the disagreement clause. Kept
# short so the dimmed line stays on one row in the panel.
_NODE_CLAIM_NAMES: dict[str, str] = {
    "m365_tenant": "the M365 tenant",
    "google_workspace_tenant": "the Workspace tenant",
    "federated_identity": "federated identity",
    "okta_idp": "the Okta IdP",
    "email_gateway_present": "the email gateway",
    "email_security_modern_provider": "modern email security",
    "email_security_policy_enforcing": "the email policy",
    "cdn_fronting": "the CDN",
    "aws_hosting": "AWS hosting",
}


def _posterior_support_phrase(obs: PosteriorObservation, fill: int) -> str:
    """Describe a claimed node's model display without confidence language."""
    claim = _NODE_CLAIM_NAMES.get(obs.name, f"the {obs.name} call")
    if fill >= 3:
        return f"display above threshold for {claim}"
    if fill == 2:
        return f"threshold-straddling display for {claim}"
    return f"model mean below threshold for {claim}"


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

_SPARSE_INSIGHT_PREFIXES = (
    "Sparse public signal —",
    "Next step — see docs/weak-areas.md",
)


def _is_sparse_insight(line: str) -> bool:
    """Return True when an insight line is part of sparse-result diagnosis."""
    return line.startswith(_SPARSE_INSIGHT_PREFIXES)


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


def _append_unique(summary: list[str], value: str | None) -> None:
    """Append ``value`` to ``summary`` when it is truthy and not already present."""
    if value and value not in summary:
        summary.append(value)


def _email_summary_providers(info: TenantInfo, service_set: set[str], summary: list[str]) -> None:
    """Order observed delivery paths before hedged downstream indicators."""

    ordered_services = sorted(service_set)

    def _add_list(value: str | None, *, hedge: bool = False) -> None:
        for raw_part in (value or "").split(" + "):
            part = raw_part.strip()
            if not part:
                continue
            label = next((item for item in ordered_services if item == part or item.startswith(f"{part} (")), part)
            if hedge and label == part and part not in service_set:
                label = f"{part} (possible downstream indicator)"
            _append_unique(summary, label)

    if info.primary_email_provider:
        _add_list(info.primary_email_provider)
        _add_list(info.email_gateway)
    else:
        _add_list(info.email_gateway)
        _add_list(info.likely_primary_email_provider, hedge=True)
    if not summary:
        for provider in ("Microsoft 365", "Google Workspace", "Zoho Mail", "ProtonMail", "AWS SES"):
            if provider in service_set:
                _append_unique(summary, provider)


def _email_summary_controls(
    info: TenantInfo, service_set: set[str], email_services: list[str], summary: list[str]
) -> None:
    """Append the main email hardening controls (DMARC, DKIM, SPF, MTA-STS,
    BIMI) to ``summary``."""
    if info.dmarc_policy:
        _append_unique(summary, f"DMARC {info.dmarc_policy}")
    elif "DMARC" in service_set:
        _append_unique(summary, "DMARC")

    if any(s.startswith("DKIM") for s in email_services):
        _append_unique(summary, "DKIM")

    if any(s.startswith("SPF: strict") for s in email_services):
        _append_unique(summary, "SPF strict")
    elif any(s.startswith("SPF: softfail") for s in email_services):
        _append_unique(summary, "SPF softfail")

    if info.mta_sts_mode and info.mta_sts_mode != "none":
        _append_unique(summary, f"MTA-STS {info.mta_sts_mode}")
    elif "MTA-STS" in service_set:
        _append_unique(summary, "MTA-STS")

    if "BIMI" in service_set:
        _append_unique(summary, "BIMI")


def _compact_email_summary(info: TenantInfo, email_services: list[str]) -> list[str]:
    """Build the evidence-scoped Email core retained by every panel mode."""
    service_set = set(email_services)
    summary: list[str] = []
    _email_summary_providers(info, service_set, summary)
    _email_summary_controls(info, service_set, email_services, summary)
    return summary


# High-signal subdomain prefixes for compact related-domain display.
# Tuned to match the UI goal: the related line should fit in 1-2
# lines and show the names a security analyst cares about first.
_HIGH_SIGNAL_RELATED_PREFIXES: tuple[str, ...] = (
    "login.",
    "sso.",
    "auth.",
    "idp.",
    "api.",
    "admin.",
    "portal.",
    "dashboard.",
    "support.",
    "status.",
    "app.",
    "cdn.",
)


def _pick_high_signal_related(
    related: tuple[str, ...],
    limit: int = 8,
) -> tuple[list[str], int]:
    """Pick the top ``limit`` high-signal related domains.

    High-signal = matches one of the ``_HIGH_SIGNAL_RELATED_PREFIXES``.
    Falls back to the first ``limit`` non-wildcard entries when too
    few high-signal names are present. Returns a tuple of
    ``(picked, total_count)`` so callers can emit the "N total" footer.

    ``*.onmicrosoft.com`` entries are filtered out.
    These are Microsoft 365 tenant artefacts — they appear in the
    related list because the user realm / autodiscover path surfaces
    them, but they carry no "related brand" signal. A CISO reading
    "high-signal related domains" doesn't want to see the tenant's
    own internal domain listed as if it were a separate discovery.
    """

    def _is_high_signal_candidate(d: str) -> bool:
        # Filter out tenant artefacts and wildcards
        if "*" in d:
            return False
        # .onmicrosoft.com and .onmicrosoft.us are M365 tenant
        # artefacts, not brand-related domains worth surfacing.
        return not d.endswith((".onmicrosoft.com", ".onmicrosoft.us"))

    non_wild = [d for d in related if _is_high_signal_candidate(d)]
    total = len(non_wild)
    high: list[str] = []
    for d in non_wild:
        first_label = d.split(".", 1)[0] + "."
        if any(d.startswith(pfx) or first_label == pfx for pfx in _HIGH_SIGNAL_RELATED_PREFIXES):
            high.append(d)
        if len(high) >= limit:
            break
    if len(high) < limit:
        for d in non_wild:
            if d in high:
                continue
            high.append(d)
            if len(high) >= limit:
                break
    return high, total


def _confidence_is_high(level: ConfidenceLevel) -> bool:
    """True only for HIGH — used by the disciplined color palette so
    Medium / Low never trigger alarmist coloring."""
    return level == ConfidenceLevel.HIGH


def _append_field(facts: Text, label: str, value: str, value_style: str = "") -> None:
    """Emit one "  Label    value" row into ``facts``, wrapping the value at the
    panel width with a continuation indent matching the label column."""
    indent_width = 2 + _LABEL_WIDTH  # "  " + label column
    max_width = _PANEL_WIDTH - indent_width
    for i, line in enumerate(_wrap_text(value, max_width)):
        if i == 0:
            facts.append("  ")
            facts.append(label.ljust(_LABEL_WIDTH), style="dim")
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
    being presented as calibrated confidence.
    """
    facts.append("  ")
    facts.append("Confidence".ljust(_LABEL_WIDTH), style="dim")
    tail = f" {info.confidence.value.capitalize()} ({len(info.sources)} sources)"
    dots = CONFIDENCE_DOTS[info.confidence]
    style = "green" if _confidence_is_high(info.confidence) else ""
    facts.append(dots + tail, style=style)
    facts.append("\n")

    claimed = [o for o in info.posterior_observations if o.evidence_used]
    if not claimed:
        return
    weakest = min(claimed, key=lambda o: (_posterior_dot_fill(o), o.posterior))
    fill = _posterior_dot_fill(weakest)
    facts.append("  ")
    facts.append("Model support".ljust(_LABEL_WIDTH), style="dim")
    facts.append(" ")
    facts.append(_DOT_FILL_GLYPH[fill], style=_DOT_FILL_COLOR[fill])
    facts.append(f" {_posterior_support_phrase(weakest, fill)}", style="dim")
    facts.append("\n")


def _with_idp(base: str, google_idp_name: str | None) -> str:
    """Append " via <IdP>" to a Google Workspace auth label when an IdP name is
    known."""
    return f"{base} via {google_idp_name}" if google_idp_name else base


def _key_facts_auth_line(info: TenantInfo) -> str | None:
    """Combine the M365 and Google Workspace auth labels into one line.

    "Managed (Entra ID + Google Workspace)" reads cleaner than
    "Managed + Managed (GWS)" when both providers share an auth type.
    GetUserRealm returns NameSpaceType=Unknown for domains that are not real
    M365 tenants, so "Unknown" is treated as no auth info here. Returns ``None``
    when no usable auth info is present.
    """
    effective_auth: str | None = info.auth_type
    if effective_auth and effective_auth.strip().lower() == "unknown":
        effective_auth = None

    auth_parts: list[str] = []
    if effective_auth and info.google_auth_type:
        if effective_auth == info.google_auth_type:
            # Only claim "Entra ID" when the microsoft365 slug is actually
            # detected; a dormant tenant_id from OIDC discovery on a
            # Google-primary domain otherwise yields a confident-wrong claim.
            ms_label = "Entra ID" if "microsoft365" in info.slugs else "Microsoft"
            providers = [ms_label, _with_idp("Google Workspace", info.google_idp_name)]
            auth_parts.append(f"{effective_auth} ({' + '.join(providers)})")
        else:
            auth_parts.append(effective_auth)
            auth_parts.append(f"{_with_idp(info.google_auth_type, info.google_idp_name)} (Google Workspace)")
    elif effective_auth:
        auth_parts.append(effective_auth)
    elif info.google_auth_type:
        auth_parts.append(f"{_with_idp(info.google_auth_type, info.google_idp_name)} (Google Workspace)")
    if not auth_parts:
        return None
    return " + ".join(auth_parts)


def _key_facts_multicloud_line(info: TenantInfo) -> str | None:
    """At-a-glance multi-cloud indicator.

    The apex slugs and the CNAME-chain subdomain attributions both contribute;
    ``count_cloud_vendors`` collapses sibling slugs so the count reflects
    distinct vendors. Returns ``None`` unless the footprint touches >= 2.
    """
    surface_slug_stream: list[str] = []
    for sa in info.surface_attributions:
        if sa.primary_slug:
            surface_slug_stream.append(sa.primary_slug)
        if sa.infra_slug:
            surface_slug_stream.append(sa.infra_slug)
    vendor_counts = count_cloud_vendors(info.slugs, surface_slug_stream, apex_evidence=info.evidence)
    if len(vendor_counts) < 2:
        return None
    ranked_vendors = sorted(vendor_counts.items(), key=lambda p: (-p[1], p[0]))
    vendor_names = [v for v, _ in ranked_vendors]
    return f"{len(vendor_names)} providers observed ({', '.join(vendor_names)})"


def _render_key_facts(info: TenantInfo) -> Text:
    """Build the key-facts block: Provider, Tenant/Region, Auth, Cloud
    (sovereignty), Multi-cloud rollup, Confidence.

    Extracted from ``render_tenant_panel`` so the panel orchestrator stays
    a thin sequence of section calls. Behavior is unchanged; the golden
    renders in ``tests/test_golden_renders.py`` pin the exact output.
    """
    facts = Text()
    _append_field(facts, "Provider", provider_line(info))

    if info.tenant_id:
        tenant_line = info.tenant_id
        if info.region:
            tenant_line += f" • {info.region}"
        _append_field(facts, "Tenant", tenant_line)
    elif info.region:
        _append_field(facts, "Region", info.region)

    auth_line = _key_facts_auth_line(info)
    if auth_line is not None:
        _append_field(facts, "Auth", auth_line)

    # Sovereignty — only when cloud_instance indicates non-commercial.
    if info.cloud_instance and "microsoftonline.com" not in info.cloud_instance.lower():
        sov_label = info.cloud_instance
        if info.tenant_region_sub_scope:
            sov_label += f" ({info.tenant_region_sub_scope})"
        _append_field(facts, "Cloud", sov_label)

    multicloud_line = _key_facts_multicloud_line(info)
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
          login.x, sso.x, api.x … (N total — use --full to see all)

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
    # When display_name falls back to the raw
    # domain (no company name extractable), render it once as bold
    # instead of showing the same string twice.
    header = Text()
    header.append(info.display_name, style="bold")
    if info.default_domain and info.default_domain != info.display_name:
        header.append("\n")
        header.append(info.default_domain, style="dim")
    blocks.append(header)
    rule = Text("─" * _PANEL_WIDTH, style="dim")
    blocks.append(rule)

    # ── Key facts block ────────────────────────────────────────────
    blocks.append(_render_key_facts(info))

    # ── Services section ──────────────────────────────────────────
    svc_block, ceiling_categorized_count = _render_services(info, show_domains)
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
        _render_verbose_detail(info, verbose),
        _render_explain_conflicts(info, explain, verbose),
    ):
        if detail_section is not None:
            _spacer()
            blocks.append(detail_section)

    return Group(*blocks)


def _normalize_email_services(categorized: dict[str, list[str]], info: TenantInfo) -> None:
    """Lead with compact Email facts, then append remaining indicators."""
    from recon_tool.collection_view import collection_observable_evidence

    original_email = list(categorized["Email"])
    _email_noise = {
        "DKIM",
        "DKIM (Exchange Online)",
        "DMARC",
        "MTA-STS",
        "BIMI",
        "TLS-RPT",
        "Exchange Autodiscover",
        "Microsoft 365",
        "Google Workspace",
        "Exchange-style endpoint indicator",
        "Custom or unclassified MX",
        "Null MX (domain does not accept email)",
    }
    gateway_names = {
        record.rule_name
        for record in collection_observable_evidence(info)
        if record.source_type.upper() == "MX" and record.slug in GATEWAY_SLUGS
    }
    _all_noise = _email_noise | gateway_names
    remaining = [s for s in categorized["Email"] if s not in _all_noise and not s.startswith("SPF")]
    email_summary = _compact_email_summary(info, original_email)
    for service in remaining:
        _append_unique(email_summary, service)
    if email_summary:
        categorized["Email"] = email_summary
    else:
        del categorized["Email"]


def _append_subdomain_summary(svc_block: Text, info: TenantInfo, show_domains: bool, max_width: int) -> None:
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
    """
    if not (info.surface_attributions and not show_domains):
        return
    surface_summary = subdomain_surface_summary_items(info.surface_attributions)
    if not surface_summary:
        return
    budget = _PANEL_WIDTH - (2 + max_width)
    lines = compact_subdomain_summary_lines(surface_summary, budget)
    svc_block.append("  ")
    svc_block.append("Subdomain".ljust(max_width), style="dim")
    for index, line in enumerate(lines):
        if index:
            svc_block.append(" " * (2 + max_width))
        svc_block.append(line)
        svc_block.append("\n")


def _render_services(info: TenantInfo, show_domains: bool) -> tuple[Text | None, int]:
    """Render the categorized Services section and return it with the count of
    service categories (used by the passive-DNS ceiling trigger).

    Returns ``(None, 0)`` when there are no services. Output held byte-identical
    by ``tests/test_golden_renders.py`` (``panel_dense_default`` /
    ``panel_surface_default``).
    """
    if not info.services:
        return None, 0
    svc_block = Text()
    svc_block.append("Services", style="bold")
    svc_block.append("\n")
    categorized = _categorize_services(info)
    if "Email" in categorized:
        _normalize_email_services(categorized, info)
    # Widen the label column only when a label present in this render needs
    # it, so short-label panels keep their value width and a long label
    # (e.g. "Data & Analytics") still gets one space before its value.
    max_width = max(_CATEGORY_WIDTH, max((len(c) for c in categorized), default=0) + 1)
    for cat, svcs in categorized.items():
        svc_block.append("  ")
        svc_block.append(cat.ljust(max_width), style="dim")
        wrapped = _wrap_service_list(
            svcs,
            label_width=2 + max_width,
            panel_width=_PANEL_WIDTH,
            panel_pad=0,
        )
        svc_block.append(wrapped)
        svc_block.append("\n")
    _append_subdomain_summary(svc_block, info, show_domains, max_width)
    return svc_block, len(categorized)


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
    picked, total = _pick_high_signal_related(tuple(info.related_domains))
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
            f"\n  ({total} total — {remaining} more, use --full to see all)",
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
    """Full related-domains list (--domains / --full only)."""
    if not (show_domains and info.related_domains):
        return None
    rel = Text()
    rel.append("Related domains", style="bold")
    rel.append("\n")
    rel.append("  ")
    joined = ", ".join(info.related_domains)
    for j, line in enumerate(_wrap_text(joined, _PANEL_WIDTH - 2)):
        if j > 0:
            rel.append("\n  ")
        rel.append(line, style="dim")
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
    suffix stripped to a bare label (``app`` instead of ``app.contoso.com``) so
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
            f"{n} unclassified {noun} — `recon discover {info.queried_domain}` to surface fingerprint candidates",
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
    """Curated Insights section: the email-security score is promoted to a bold
    first line, sparse-context insights are ordered ahead of the rest, and the
    list is capped at five in default mode (--full / --verbose shows all).

    Strict confidence mode drops hedging qualifiers on dense evidence only; the
    "never overclaim on thin evidence" invariant keeps sparse output untouched.
    Returns ``None`` when there is nothing to show. Output held byte-identical
    by ``tests/test_golden_renders.py`` (``panel_dense_default`` and the strict
    / sparse variants).
    """
    if not info.insights:
        return None
    curated: list[str] = _curate_insights(info.insights)
    from recon_tool.strict_mode import apply_strict_mode, should_apply_strict

    if should_apply_strict(info, confidence_mode):
        curated = list(apply_strict_mode(tuple(curated)))
    if not curated:
        return None
    ins = Text()
    ins.append("Insights", style="bold")
    ins.append("\n")
    max_width = _PANEL_WIDTH - 2

    # Promote the email security score to the first (bold) position; order the
    # remaining insights sparse-context first.
    score_line: str | None = None
    sparse_insights: list[str] = []
    other_insights: list[str] = []
    for c in curated:
        if c.startswith("Email security ") and score_line is None:
            score_line = c
        elif _is_sparse_insight(c):
            sparse_insights.append(c)
        else:
            other_insights.append(c)

    if score_line is not None:
        _append_wrapped_lines(ins, score_line, max_width, "bold")

    ordered_insights = sparse_insights + other_insights

    # Cap at 5 in default mode; --full / --verbose shows all.
    display_insights = ordered_insights
    overflow_count = 0
    if not verbose and len(ordered_insights) > 5:
        display_insights = ordered_insights[:5]
        overflow_count = len(ordered_insights) - 5

    for insight in display_insights:
        _append_wrapped_lines(ins, insight, max_width, "dim")

    if overflow_count > 0:
        ins.append("  ")
        ins.append(f"{overflow_count} more — use --full to see all", style="dim italic")
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


def _curate_insights(insights: tuple[str, ...]) -> list[str]:
    """Filter and deduplicate insights for the default panel.

    Two kinds of cleanup:

    1. **Drop laundry-list dumps.** Prefixes like ``"Security stack:"``,
       ``"Security-vendor indicators observed:"``, ``"Infrastructure:"``,
       ``"PKI:"``, and ``"Google Workspace module indicators observed:"``
       all duplicate information that
       the Services block already shows in a categorized, deduped
       form. Low-signal organizational-size hints
       (``"mid-size organization"``, ``"domains in tenant"``) read as
       padding and add nothing.

    2. **Collapse overlapping signal families.** Real runs often
       trigger three or four signals about the same underlying pattern
       because `signals.yaml` has multiple rules covering it from
       different angles. On a dual-provider run (M365 tenant + Google
       Workspace via DKIM) the Insights block used to show:

           Dual provider: Google + Microsoft coexistence
           Dual Email Provider: microsoft365, google-workspace
           Dual Email Delivery Path: microsoft365, google-workspace
           Secondary Email Provider Observed: google-workspace

       Four different wordings of the same fact. The curator collapses
       these into a single canonical line, keeping the highest-
       signal wording and dropping the rest.

    The collapse rules are intentionally narrow: only overlapping
    signals that describe the same underlying pattern. Real distinct
    signals ("Edge Layering" vs "Zero Trust Pattern Observed") never collapse
    into each other.
    """
    drop_prefixes = (
        "Security stack:",
        "Security-vendor indicators observed:",
        "Network-security vendor indicator",
        "Device-management vendor indicator",
        "Infrastructure:",
        "PKI:",
        "Google Workspace modules:",  # module list also belongs in Services
        "Google Workspace module indicators observed:",
    )
    # Drop insights that restate what the Services
    # block or header already shows. These follow a "Label: slug1, slug2"
    # pattern where the slugs are visible in the categorized Services
    # section. They add zero interpretation — just a differently-worded
    # service list. Keep insights that synthesize (scores, topology,
    # tier inference, migration patterns, security observations).
    restatement_prefixes = (
        # These all follow the "Label: slug1, slug2" pattern where the
        # slugs are already visible in the categorized Services section.
        # They add zero interpretation — just a differently-worded list.
        "Multi-Cloud:",
        "Dev & Engineering Heavy:",
        "Heavy Outbound Stack:",
        "Modern Collaboration:",
        "Google Cloud Investment:",
        "Google-Native Identity:",
        "Dual provider:",
        "Provider indicators co-observed:",
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Google MTA-STS Enforcing:",
        "AI Platform Diversity:",
        "AI Adoption:",  # bare form; "Without Governance" variant kept (security context)
        "Enterprise Security Stack:",
        "Digital Transformation:",
        "Email gateway:",  # already in Provider line
        "MX gateway observed:",
        "Email Gateway Topology:",
        "Email delivery path:",
        "Secondary Email Provider Observed:",
    )
    curated: list[str] = []
    for line in insights:
        if any(line.startswith(pfx) for pfx in drop_prefixes):
            continue
        if any(line.startswith(pfx) for pfx in restatement_prefixes):
            continue
        lower = line.lower()
        if "mid-size organization" in lower or "domains in tenant" in lower:
            continue
        curated.append(line)

    # ── Collapse overlapping signal families ──────────────────────────

    # Dual-provider family: four overlapping signals all describing
    # "both Microsoft 365 and Google Workspace detected". We keep the
    # most informative wording ("Dual provider: Google + Microsoft
    # coexistence") and drop the rest.
    dual_family_prefixes = (
        "Dual Email Provider:",
        "Dual Email Delivery Path:",
        "Secondary Email Provider Observed:",
    )
    has_canonical_dual = any(
        line.startswith("Dual provider:") or "Google + Microsoft coexistence" in line for line in curated
    )
    if has_canonical_dual:
        curated = [line for line in curated if not any(line.startswith(pfx) for pfx in dual_family_prefixes)]
    else:
        # No canonical line — keep at most one of the family as a
        # promoted representative. "Dual Email Delivery Path" is the
        # most information-dense wording of the three, so prefer it.
        family_lines = [line for line in curated if any(line.startswith(pfx) for pfx in dual_family_prefixes)]
        if len(family_lines) >= 2:
            # Preference order for promotion
            pref_order = (
                "Dual Email Delivery Path:",
                "Dual Email Provider:",
                "Secondary Email Provider Observed:",
            )
            chosen: str | None = None
            for pfx in pref_order:
                for line in family_lines:
                    if line.startswith(pfx):
                        chosen = line
                        break
                if chosen:
                    break
            curated = [line for line in curated if line not in family_lines or line == chosen]

    # "Dual Email Provider" signal family overlap with the older
    # "Dual provider: Google + Microsoft coexistence" insight line:
    # when BOTH the canonical insight and the newer "Dual Email
    # Provider" signal fire, keep only the canonical (human-readable)
    # one. Already handled above via has_canonical_dual; this comment
    # just documents the precedence for future maintainers.

    # ── Email security aux-note dedup ──────────────────────────────
    # The score line ("Email security: <inventory>") already
    # names what's present/absent. The auxiliary "DMARC: none", "No
    # DMARC record at apex", "No DKIM at common selectors" insights
    # restate the same observation in prose. Keep the score line on
    # the default panel; the aux notes stay in the raw `insights`
    # JSON field for consumers that want them.
    has_score_line = any(line.startswith("Email security:") for line in curated)
    if has_score_line:
        curated = [
            line
            for line in curated
            if not line.startswith("No DMARC record")
            and not line.startswith("No valid DMARC policy record")
            and not line.startswith("No DKIM at common selectors")
            and not line.startswith("No DKIM selectors observed")
            and not line.startswith("DKIM not observed")
            and not line.startswith("DMARC: none")
        ]

    # ── Google Workspace identity echo dedup ───────────────────────
    # The insight "Google Workspace: Managed identity (Google-native)"
    # restates the Auth line AND the Identity row in the Services
    # block. On domains with minimal signal this is the third time
    # the same fact appears in the panel. Drop it — the Auth line
    # already says "Managed (Google Workspace)" and the Services
    # block carries the slug detection.
    return [
        line
        for line in curated
        if line != "Google Workspace: Managed identity (Google-native)"
        and not line.startswith("Google Workspace: Managed identity")
    ]

    # Note on the "Cloud-managed identity indicators" insight: the
    # dedup for dual-provider targets happens upstream in
    # insights._auth_insights, which refuses to emit the line when
    # google_auth_type is set (the Auth line's compound format
    # "Managed (Entra ID + Google Workspace)" already carries the
    # same fact). On pure M365 targets the insight DOES fire and
    # the Auth line just says "Managed", so both surfaces carry
    # distinct information — no dedup needed here.


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
            provider = provider_line(r.info)
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


# ── Comparison rendering ────────────────────────────────────────────────


def format_comparison_dict(comparison: PostureComparison) -> dict[str, Any]:
    """Format PostureComparison as a dict for JSON output."""
    return {
        "domain_a": comparison.domain_a,
        "domain_b": comparison.domain_b,
        "metrics": [
            {
                "metric_name": m.metric_name,
                "domain_a_value": m.domain_a_value,
                "domain_b_value": m.domain_b_value,
            }
            for m in comparison.metrics
        ],
        "differences": [
            {
                "description": d.description,
                "domain_a_has": d.domain_a_has,
                "domain_b_has": d.domain_b_has,
            }
            for d in comparison.differences
        ],
        "relative_assessment": [
            {
                "dimension": ra.dimension,
                "summary": ra.summary,
            }
            for ra in comparison.relative_assessment
        ],
        "disclaimer": comparison.disclaimer,
    }


def format_comparison_json(comparison: PostureComparison) -> str:
    """Format PostureComparison as a JSON string."""
    return json.dumps(format_comparison_dict(comparison), indent=2)


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


def render_explanations_panel(explanations: list[ExplanationRecord]) -> Panel:
    """Render explanation records as a Rich panel for CLI --explain output."""
    text = Text()

    for i, rec in enumerate(explanations):
        if i > 0:
            text.append("\n\n")

        # Header: item type + name
        type_label = rec.item_type.capitalize()
        text.append(f"  [{type_label}] ", style="bold")
        text.append(f"{rec.item_name}\n")

        # Curated explanation (from YAML explain field)
        if rec.curated_explanation:
            text.append(f"    {rec.curated_explanation}\n", style="dim italic")

        # Fired rules
        if rec.fired_rules:
            text.append("    Rules: ", style="dim")
            text.append(", ".join(rec.fired_rules))
            text.append("\n")

        # Confidence derivation
        if rec.confidence_derivation:
            text.append("    Confidence: ", style="dim")
            text.append(f"{rec.confidence_derivation}\n")

        # Evidence summary
        if rec.matched_evidence:
            text.append(f"    Evidence: {len(rec.matched_evidence)} record(s)\n", style="dim")

        # Weakening conditions
        if rec.weakening_conditions:
            text.append("    Weakening:\n", style="dim")
            for cond in rec.weakening_conditions:
                text.append(f"      • {cond}\n", style="dim")

    return Panel(
        text,
        title="Explanations",
        width=80,
        padding=(1, 2),
        border_style="dim",
    )


def format_explanations_list(explanations: list[ExplanationRecord]) -> list[dict[str, Any]]:
    """Serialize explanation records for JSON output."""
    from recon_tool.explanation import serialize_explanation

    return [serialize_explanation(rec) for rec in explanations]


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
