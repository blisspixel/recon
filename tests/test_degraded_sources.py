"""Unit tests for degraded_sources on SourceResult, TenantInfo, merger, and formatter.

Covers: defaults, crtsh_degraded property, merger deduplication,
formatter output, JSON partial key.

Requirements: 5.1, 5.3, 6.1, 6.2, 6.3, 7.1–7.5, 11.2, 11.3
"""

from __future__ import annotations

import dataclasses
from io import StringIO

import pytest
from rich.console import Console

from recon_tool.formatter import (
    format_tenant_dict,
    format_tenant_markdown,
    render_tenant_panel,
    set_console,
)
from recon_tool.merger import merge_results
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo


def _make_tenant_info(**overrides) -> TenantInfo:
    """Build a minimal TenantInfo with sensible defaults."""
    defaults = dict(
        tenant_id="test-id",
        display_name="Test Corp",
        default_domain="test.com",
        queried_domain="test.com",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records",),
        services=("DMARC",),
    )
    defaults.update(overrides)
    return TenantInfo(**defaults)


# ── SourceResult defaults and properties ────────────────────────────────


class TestSourceResultDegradedSources:
    def test_default_is_empty_tuple(self):
        sr = SourceResult(source_name="dns_records")
        assert sr.degraded_sources == ()

    def test_crtsh_degraded_true_when_crtsh_in_sources(self):
        sr = SourceResult(source_name="dns_records", degraded_sources=("crt.sh",))
        assert sr.crtsh_degraded is True

    def test_crtsh_degraded_false_when_crtsh_not_in_sources(self):
        sr = SourceResult(source_name="dns_records", degraded_sources=("certspotter",))
        assert sr.crtsh_degraded is False

    def test_crtsh_degraded_false_when_empty(self):
        sr = SourceResult(source_name="dns_records")
        assert sr.crtsh_degraded is False

    def test_multiple_degraded_sources(self):
        sr = SourceResult(source_name="dns_records", degraded_sources=("crt.sh", "certspotter"))
        assert sr.crtsh_degraded is True
        assert "certspotter" in sr.degraded_sources

    def test_frozen_dataclass(self):
        sr = SourceResult(source_name="dns_records", degraded_sources=("crt.sh",))
        assert dataclasses.is_dataclass(sr)
        with pytest.raises(AttributeError):
            sr.degraded_sources = ()  # type: ignore[misc]


# ── TenantInfo defaults and properties ──────────────────────────────────


class TestTenantInfoDegradedSources:
    def test_default_is_empty_tuple(self):
        ti = _make_tenant_info()
        assert ti.degraded_sources == ()

    def test_crtsh_degraded_true_when_crtsh_in_sources(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh",))
        assert ti.crtsh_degraded is True

    def test_crtsh_degraded_false_when_crtsh_not_in_sources(self):
        ti = _make_tenant_info(degraded_sources=("certspotter",))
        assert ti.crtsh_degraded is False

    def test_crtsh_degraded_false_when_empty(self):
        ti = _make_tenant_info()
        assert ti.crtsh_degraded is False

    def test_frozen_dataclass(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh",))
        assert dataclasses.is_dataclass(ti)
        with pytest.raises(AttributeError):
            ti.degraded_sources = ()  # type: ignore[misc]


# ── Merger deduplication ────────────────────────────────────────────────


class TestMergerDegradedSources:
    def test_collects_from_multiple_results(self):
        results = [
            SourceResult(source_name="src1", tenant_id="id1", degraded_sources=("crt.sh",)),
            SourceResult(source_name="src2", m365_detected=True, degraded_sources=("certspotter",)),
        ]
        merged = merge_results(results, queried_domain="example.com")
        assert set(merged.degraded_sources) == {"crt.sh", "certspotter"}

    def test_deduplicates(self):
        results = [
            SourceResult(source_name="src1", tenant_id="id1", degraded_sources=("crt.sh",)),
            SourceResult(source_name="src2", m365_detected=True, degraded_sources=("crt.sh",)),
        ]
        merged = merge_results(results, queried_domain="example.com")
        assert merged.degraded_sources.count("crt.sh") == 1

    def test_empty_when_no_degradation(self):
        results = [
            SourceResult(source_name="src1", tenant_id="id1"),
        ]
        merged = merge_results(results, queried_domain="example.com")
        assert merged.degraded_sources == ()


# ── Formatter output ────────────────────────────────────────────────────


class TestFormatterDegradedOutput:
    def test_panel_shows_degraded_note_when_nonempty(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh", "certspotter"))
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        set_console(console)
        panel = render_tenant_panel(ti)
        console.print(panel)
        output = buf.getvalue()
        assert "crt.sh" in output
        assert "certspotter" in output

    def test_panel_no_degraded_note_when_empty(self):
        ti = _make_tenant_info(degraded_sources=())
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        set_console(console)
        panel = render_tenant_panel(ti)
        console.print(panel)
        output = buf.getvalue()
        assert "Some sources were unavailable" not in output

    def test_json_includes_degraded_sources(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh",))
        d = format_tenant_dict(ti)
        assert d["degraded_sources"] == ["crt.sh"]

    def test_json_partial_true_when_degraded(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh",))
        d = format_tenant_dict(ti)
        assert d["partial"] is True

    def test_json_partial_false_when_not_degraded(self):
        ti = _make_tenant_info(degraded_sources=())
        d = format_tenant_dict(ti)
        assert d["partial"] is False

    def test_markdown_includes_degraded_note(self):
        ti = _make_tenant_info(degraded_sources=("crt.sh", "certspotter"))
        md = format_tenant_markdown(ti)
        assert "crt.sh" in md
        assert "certspotter" in md

    def test_markdown_no_degraded_note_when_empty(self):
        ti = _make_tenant_info(degraded_sources=())
        md = format_tenant_markdown(ti)
        assert "unavailable" not in md.lower()
