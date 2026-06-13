"""Property-based tests for M365 tenant lookup formatter.

Tests Properties 9, 10, 19, 20, 21 from the design document.
"""

from __future__ import annotations

import dataclasses
import io
import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from rich.console import Console

from recon_tool.formatter import (
    CONFIDENCE_COLORS,
    _markdown_escape,
    format_tenant_json,
    format_tenant_markdown,
    get_console,
    get_err_console,
    render_tenant_panel,
    render_verbose_sources,
    render_warning,
    set_console,
    set_err_console,
)
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo

# --- Strategies ---

non_empty_str = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    min_size=1,
    max_size=30,
)

uuid_str = st.uuids().map(str)

confidence_st = st.sampled_from(list(ConfidenceLevel))

optional_str = st.one_of(st.none(), non_empty_str)

source_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    min_size=1,
    max_size=20,
)

tenant_info_st = st.builds(
    TenantInfo,
    tenant_id=uuid_str,
    display_name=non_empty_str,
    default_domain=non_empty_str,
    queried_domain=non_empty_str,
    confidence=confidence_st,
    region=optional_str,
    sources=st.lists(source_name_st, min_size=0, max_size=5).map(tuple),
)


source_result_st = st.builds(
    SourceResult,
    source_name=source_name_st,
    tenant_id=st.one_of(st.none(), uuid_str),
    display_name=optional_str,
    default_domain=optional_str,
    region=optional_str,
    m365_detected=st.booleans(),
    error=st.one_of(st.none(), non_empty_str),
)


def _render_panel_to_str(panel) -> str:
    """Render a rich Panel to a plain string."""
    c = Console(
        file=io.StringIO(),
        force_terminal=True,
        width=200,
        no_color=True,
        highlight=False,
    )
    c.print(panel)
    return c.file.getvalue()


class TestRichPanelOutputContainsAllFields:
    """Property 9: Rich panel output contains all fields including confidence.

    For any TenantInfo instance, render_tenant_panel(info) should produce a Panel
    whose renderable text contains info.display_name, info.tenant_id,
    info.default_domain, and the confidence level label.

    **Validates: Requirements 3.1, 3.2, 3.6**
    """

    @given(info=tenant_info_st)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_panel_contains_all_fields(self, info: TenantInfo):
        panel = render_tenant_panel(info)
        output = _render_panel_to_str(panel)

        assert info.display_name in output, f"display_name {info.display_name!r} not in panel output"
        assert info.default_domain in output, f"default_domain {info.default_domain!r} not in panel output"
        # Confidence label should appear (e.g. "High", "Medium", "Low")
        assert info.confidence.value.capitalize() in output, (
            f"confidence label {info.confidence.value.capitalize()!r} not in panel output"
        )


class TestPlainOutput:
    """`--plain` linear output: greppable, screen-reader-friendly, no markup."""

    @staticmethod
    def _info() -> TenantInfo:
        return TenantInfo(
            tenant_id="aaaa-bbbb",
            display_name="Contoso",
            default_domain="contoso.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.HIGH,
            services=("Microsoft 365", "DMARC"),
            slugs=("microsoft365", "dmarc"),
            dmarc_policy="reject",
        )

    def test_is_linear_keyvalue_with_no_ansi_or_boxdrawing(self) -> None:
        from recon_tool.formatter import format_tenant_plain

        out = format_tenant_plain(self._info())
        assert "\x1b" not in out  # no ANSI color
        # no box-drawing characters
        assert "─" not in out
        assert "│" not in out
        assert "╭" not in out
        assert "tenant_id: aaaa-bbbb" in out
        assert "dmarc_policy: reject" in out
        # Lists render as indented "- item" lines.
        assert "  - microsoft365" in out

    def test_falsy_scalars_are_preserved_not_dropped(self) -> None:
        # A 0 / False field is real data and must survive --plain (the explicit
        # empty-sentinel check, not a naive `if not value`).
        from recon_tool.formatter import _plain_lines

        lines = _plain_lines({"score": 0, "flag": False, "ratio": 0.0, "blank": "", "none": None}, "m", 0)
        text = "\n".join(lines)
        assert "score: 0" in text
        assert "flag: False" in text
        assert "ratio: 0.0" in text
        assert "blank" not in text  # empty string dropped
        assert "none" not in text  # None dropped

    def test_no_dangling_header_for_all_empty_container(self) -> None:
        from recon_tool.formatter import _plain_lines

        # A dict whose every child is empty emits nothing (no bare "key:").
        assert _plain_lines({"a": "", "b": None, "c": []}, "parent", 0) == []

    def test_strips_control_chars_from_untrusted_values(self) -> None:
        from recon_tool.formatter import format_tenant_plain

        info = TenantInfo(
            tenant_id=None,
            display_name="Evil\x1b[2J\x07Corp",
            default_domain="x.onmicrosoft.com",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.LOW,
        )
        out = format_tenant_plain(info)
        assert "\x1b" not in out  # ESC control byte stripped
        assert "\x07" not in out  # BEL control byte stripped
        assert "Evil" in out  # printable text preserved
        assert "Corp" in out


class TestStdoutStderrDiscipline:
    """Diagnostics go to stderr, not stdout.

    A consumer piping `recon ... --json` must get only the data stream on
    stdout; errors and warnings belong on stderr (clig.dev / 12-factor CLI).
    """

    def test_render_error_goes_to_stderr_not_stdout(self, capsys) -> None:
        from recon_tool.formatter import render_error

        render_error("boom-message-xyz")
        captured = capsys.readouterr()
        assert "boom-message-xyz" in captured.err
        assert "boom-message-xyz" not in captured.out

    def test_render_warning_goes_to_stderr_not_stdout(self, capsys) -> None:
        render_warning("contoso.example")
        captured = capsys.readouterr()
        assert "contoso.example" in captured.err
        assert "contoso.example" not in captured.out


class TestNotFoundWarningContainsDomain:
    """Property 10: Not-found warning contains queried domain.

    For any domain string d, render_warning(d) should produce output that contains d.

    **Validates: Requirements 3.3**
    """

    @given(domain=non_empty_str)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_warning_contains_domain(self, domain: str):
        buf = io.StringIO()
        test_console = Console(
            file=buf,
            force_terminal=True,
            width=200,
            no_color=True,
            highlight=False,
        )
        original = get_err_console()
        set_err_console(test_console)
        try:
            render_warning(domain)
            output = buf.getvalue()
            assert domain in output, f"domain {domain!r} not found in warning output"
        finally:
            set_err_console(original)


class TestJsonOutputRoundTrip:
    """Property 19: JSON output round-trip.

    For any TenantInfo instance, json.loads(format_tenant_json(info)) should produce
    a dict where dict["tenant_id"] == info.tenant_id, dict["display_name"] ==
    info.display_name, dict["default_domain"] == info.default_domain, and
    dict["confidence"] == info.confidence.value.

    **Validates: Requirements 11.4**
    """

    @given(info=tenant_info_st)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_json_round_trip(self, info: TenantInfo):
        json_str = format_tenant_json(info)
        data = json.loads(json_str)

        assert data["tenant_id"] == info.tenant_id
        assert data["display_name"] == info.display_name
        assert data["default_domain"] == info.default_domain
        assert data["confidence"] == info.confidence.value


class TestConfidenceColorMappingCompleteness:
    """Property 20: Confidence color mapping completeness.

    For any ConfidenceLevel value, CONFIDENCE_COLORS should contain a mapping for
    that value, and the mapped color should be one of "green", "yellow", or "red".

    **Validates: Requirements 3.6**
    """

    @given(level=confidence_st)
    @settings(max_examples=100)
    def test_all_confidence_levels_have_valid_color(self, level: ConfidenceLevel):
        assert level in CONFIDENCE_COLORS, f"{level} not in CONFIDENCE_COLORS"
        assert CONFIDENCE_COLORS[level] in {"#a3d9a5", "#7ec8e3", "#e07a5f"}, (
            f"Color for {level} is {CONFIDENCE_COLORS[level]!r}, expected a valid palette color"
        )


class TestVerboseOutputListsAllSources:
    """Property 21: Verbose output lists all attempted sources.

    For any list of SourceResult objects (both successful and failed),
    render_verbose_sources(results) should produce output containing the
    source_name of every result.

    **Validates: Requirements 11.5**
    """

    @given(results=st.lists(source_result_st, min_size=1, max_size=10))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_verbose_output_contains_all_source_names(self, results: list[SourceResult]):
        buf = io.StringIO()
        test_console = Console(
            file=buf,
            force_terminal=True,
            width=200,
            no_color=True,
            highlight=False,
        )
        original = get_console()
        set_console(test_console)
        try:
            render_verbose_sources(results)
            output = buf.getvalue()

            for result in results:
                assert result.source_name in output, f"source_name {result.source_name!r} not found in verbose output"
        finally:
            set_console(original)


class TestMarkdownEscaping:
    """The markdown report escapes attacker-derived free text (certificate
    issuer names, display_name) so it cannot inject links, code spans,
    tables, or HTML into the rendered document."""

    def test_markdown_escape_breaks_link_injection(self):
        out = _markdown_escape("Bad](http://evil)`code`*x*|y<b>")
        assert "](http://evil)" not in out
        for ch in "`*[]()|<>":
            assert ch not in out or ("\\" + ch) in out

    def test_display_name_escaped_in_markdown(self, fully_populated_tenant_info):
        info = dataclasses.replace(fully_populated_tenant_info, display_name="Evil [x](http://e)")
        assert "[x](http://e)" not in format_tenant_markdown(info)

    def test_auth_type_and_region_escaped_in_markdown(self, fully_populated_tenant_info):
        # auth_type (GetUserRealm NameSpaceType) and region are
        # attacker-influenced free text; they must be markdown-escaped too,
        # not just display_name / issuers.
        info = dataclasses.replace(
            fully_populated_tenant_info,
            auth_type="Managed](http://evil)",
            region="EU`code`",
        )
        md = format_tenant_markdown(info)
        assert "](http://evil)" not in md
        assert "`code`" not in md
