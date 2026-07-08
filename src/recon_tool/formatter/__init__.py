# pyright: reportPrivateUsage=false
"""Public formatter facade.

Implementation lives in focused formatter submodules. This package preserves
the historical `recon_tool.formatter` import surface.
"""

from __future__ import annotations

import sys
import types
from typing import Any

from recon_tool.formatter import panel as _panel
from recon_tool.formatter.panel import (
    _CATEGORY_BY_SLUG,
    _CATEGORY_WIDTH,
    _CLOUD_SLUG_QUALIFIERS,
    _CLOUD_VENDOR_BY_SLUG,
    _CLOUD_VENDOR_ROLLUP_EXCLUSIONS,
    _EMAIL_SERVICE_PREFIXES,
    _FILTERED_SERVICE_PREFIXES,
    _FILTERED_SERVICE_SUFFIXES,
    _M365_KEYWORDS,
    _POSTERIOR_DECISION_THRESHOLD,
    _SERVICE_CATEGORIES_ORDER,
    _SLUG_DISPLAY_OVERRIDES,
    CONFIDENCE_COLORS,
    CSV_COLUMNS,
    _categorize_service,
    _categorize_services,
    _is_gws_service,
    _is_m365_service,
    _make_console,
    _markdown_escape,
    _plain_lines,
    _posterior_dot_fill,
    _slug_to_relationship_metadata,
    canonical_cloud_vendor,
    category_for_slug,
    count_cloud_vendors,
    detect_provider,
    format_batch_csv,
    format_chain_dict,
    format_chain_json,
    format_comparison_dict,
    format_comparison_json,
    format_delta_dict,
    format_delta_json,
    format_explanations_list,
    format_explanations_markdown,
    format_exposure_dict,
    format_exposure_json,
    format_gaps_dict,
    format_gaps_json,
    format_posture_observations,
    format_tenant_csv_row,
    format_tenant_dict,
    format_tenant_json,
    format_tenant_markdown,
    format_tenant_plain,
    get_console,
    get_err_console,
    render_chain_panel,
    render_conflict_annotation,
    render_delta_panel,
    render_error,
    render_explanations_panel,
    render_exposure_panel,
    render_gaps_panel,
    render_posture_panel,
    render_source_status_panel,
    render_sources_detail,
    render_tenant_panel,
    render_verbose_sources,
    render_warning,
    set_color_override,
    set_console,
    set_err_console,
)

panel = _panel
_PROXIED_STATE = frozenset({"_console", "_err_console", "_color_override"})

__all__ = [
    "CONFIDENCE_COLORS",
    "CSV_COLUMNS",
    "_CATEGORY_BY_SLUG",
    "_CATEGORY_WIDTH",
    "_CLOUD_SLUG_QUALIFIERS",
    "_CLOUD_VENDOR_BY_SLUG",
    "_CLOUD_VENDOR_ROLLUP_EXCLUSIONS",
    "_EMAIL_SERVICE_PREFIXES",
    "_FILTERED_SERVICE_PREFIXES",
    "_FILTERED_SERVICE_SUFFIXES",
    "_M365_KEYWORDS",
    "_POSTERIOR_DECISION_THRESHOLD",
    "_SERVICE_CATEGORIES_ORDER",
    "_SLUG_DISPLAY_OVERRIDES",
    "_categorize_service",
    "_categorize_services",
    "_is_gws_service",
    "_is_m365_service",
    "_make_console",
    "_markdown_escape",
    "_plain_lines",
    "_posterior_dot_fill",
    "_slug_to_relationship_metadata",
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
    "get_err_console",
    "panel",
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
    "set_color_override",
    "set_console",
    "set_err_console",
]


def __getattr__(name: str) -> Any:
    """Return historical formatter attributes from the panel module."""
    return getattr(_panel, name)


class _FormatterFacade(types.ModuleType):
    """Proxy historical mutable console state to `formatter.panel`."""

    def __getattribute__(self, name: str) -> Any:
        if name in _PROXIED_STATE:
            return getattr(_panel, name)
        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _PROXIED_STATE:
            setattr(_panel, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _FormatterFacade
