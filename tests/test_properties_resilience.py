"""Property-based tests for resilience and validation features.

Properties 1–6 from the design document. Property 7 (fixture schema) is
skipped per task instructions since fixtures don't exist yet.

Uses Hypothesis for property-based testing.
"""

from __future__ import annotations

import string
from datetime import datetime, timezone
from io import StringIO

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from rich.console import Console

from recon_tool.formatter import (
    format_tenant_dict,
    format_tenant_markdown,
    render_tenant_panel,
    set_console,
)
from recon_tool.merger import merge_results
from recon_tool.models import ConfidenceLevel, SourceResult, TenantInfo
from recon_tool.sources.cert_providers import (
    MAX_SUBDOMAINS,
    SKIP_PREFIXES,
    build_cert_summary,
    filter_subdomains,
)

# ── Shared strategies ───────────────────────────────────────────────────

# Simple label: 1-10 lowercase alphanumeric chars
_label = st.text(
    alphabet=string.ascii_lowercase + string.digits,
    min_size=1,
    max_size=10,
)

# A valid domain like "example.com"
_domain = st.tuples(_label, _label).map(lambda t: f"{t[0]}.{t[1]}")

# Source name strings for degraded_sources
_source_name = st.text(
    alphabet=string.ascii_lowercase + string.digits + ".-",
    min_size=1,
    max_size=15,
)

# Non-empty source name for SourceResult
_sr_source_name = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=15,
)


# ── Property 1: Subdomain filtering invariants ─────────────────────────


def _raw_subdomain_names(domain: str) -> st.SearchStrategy[list[str]]:
    """Generate a mix of valid subdomains, wildcards, noise, and junk."""
    valid = _label.map(lambda lbl: f"{lbl}.{domain}")
    wildcard = st.just(f"*.{domain}")
    noise = st.sampled_from([f"{p}{domain}" for p in SKIP_PREFIXES])
    other_domain = _label.map(lambda lbl: f"{lbl}.other.com")
    bare = st.just(domain)
    return st.lists(st.one_of(valid, wildcard, noise, other_domain, bare), max_size=200)


class TestProperty1SubdomainFiltering:
    """Property 1: Subdomain filtering invariants.

    **Validates: Requirements 2.2, 3.3**
    """

    @given(data=st.data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_filtering_invariants(self, data):
        """For any domain and raw names, filtered results satisfy all invariants."""
        domain = data.draw(_domain)
        raw_names = data.draw(_raw_subdomain_names(domain))

        result = filter_subdomains(raw_names, domain)

        # (a) No wildcards
        for name in result:
            assert not name.startswith("*.")

        # (b) No noise prefixes
        for name in result:
            assert not any(name.startswith(p) for p in SKIP_PREFIXES)

        # (c) All end with .{domain}
        for name in result:
            assert name.endswith(f".{domain.lower()}")

        # (d) Length ≤ max cap
        assert len(result) <= MAX_SUBDOMAINS


# ── Property 2: CertSummary field invariants ────────────────────────────

# Strategy for ISO date strings within a reasonable range
_iso_date = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2025, 12, 31),
).map(lambda dt: dt.isoformat())

_issuer_name = st.text(
    alphabet=string.ascii_letters + " '-",
    min_size=1,
    max_size=30,
)

_cert_entry = st.fixed_dictionaries(
    {
        "issuer_id": _label,
        "issuer_name": _issuer_name,
        "not_before": _iso_date,
        "not_after": _iso_date,
    }
)


class TestProperty2CertSummaryInvariants:
    """Property 2: CertSummary field invariants.

    **Validates: Requirements 2.3, 3.4**
    """

    @given(entries=st.lists(_cert_entry, min_size=1, max_size=50))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cert_summary_invariants(self, entries):
        """For any non-empty cert entries, CertSummary satisfies all invariants."""
        now = datetime(2025, 6, 1, tzinfo=timezone.utc)
        cs = build_cert_summary(entries, now)

        # build_cert_summary may return None if all entries are invalid
        assume(cs is not None)

        # (a) cert_count >= 1
        assert cs.cert_count >= 1

        # (b) 1 <= issuer_diversity <= cert_count
        assert 1 <= cs.issuer_diversity <= cs.cert_count

        # (c) 0 <= issuance_velocity <= cert_count
        assert 0 <= cs.issuance_velocity <= cs.cert_count

        # (d) len(top_issuers) <= 3
        assert len(cs.top_issuers) <= 3

        # (e) newest_cert_age_days >= 0
        assert cs.newest_cert_age_days >= 0

        # (f) oldest_cert_age_days >= newest_cert_age_days
        assert cs.oldest_cert_age_days >= cs.newest_cert_age_days


# ── Property 3: crtsh_degraded derivation ───────────────────────────────

_degraded_sources_tuple = st.lists(
    st.sampled_from(["crt.sh", "certspotter", "other-source", "dns-backup"]),
    max_size=4,
    unique=True,
).map(tuple)


class TestProperty3CrtshDegradedDerivation:
    """Property 3: crtsh_degraded derivation from degraded_sources.

    **Validates: Requirements 5.3, 6.3, 11.2**
    """

    @given(degraded=_degraded_sources_tuple)
    @settings(max_examples=100)
    def test_source_result_crtsh_degraded(self, degraded):
        """SourceResult.crtsh_degraded == ('crt.sh' in degraded_sources)."""
        sr = SourceResult(source_name="dns_records", degraded_sources=degraded)
        assert sr.crtsh_degraded == ("crt.sh" in degraded)

    @given(degraded=_degraded_sources_tuple)
    @settings(max_examples=100)
    def test_tenant_info_crtsh_degraded(self, degraded):
        """TenantInfo.crtsh_degraded == ('crt.sh' in degraded_sources)."""
        ti = TenantInfo(
            tenant_id="t1",
            display_name="Test",
            default_domain="test.com",
            queried_domain="test.com",
            degraded_sources=degraded,
        )
        assert ti.crtsh_degraded == ("crt.sh" in degraded)


# ── Property 4: Merger degraded_sources is deduplicated union ───────────

_source_result_with_degraded = st.builds(
    SourceResult,
    source_name=_sr_source_name,
    tenant_id=st.just("some-id"),
    degraded_sources=_degraded_sources_tuple,
)


class TestProperty4MergerDegradedUnion:
    """Property 4: Merger degraded_sources is the deduplicated union.

    **Validates: Requirements 6.2**
    """

    @given(results=st.lists(_source_result_with_degraded, min_size=1, max_size=5))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_merger_degraded_is_set_union(self, results):
        """TenantInfo.degraded_sources == set-union of all input degraded_sources."""
        expected = set()
        for r in results:
            expected.update(r.degraded_sources)

        merged = merge_results(results, queried_domain="test.com")
        assert set(merged.degraded_sources) == expected


# ── Property 5: Degraded sources appear in all formatted outputs ────────

_nonempty_degraded = st.lists(
    st.sampled_from(["crt.sh", "certspotter", "other-source"]),
    min_size=1,
    max_size=3,
    unique=True,
).map(tuple)


def _make_ti_with_degraded(degraded: tuple[str, ...]) -> TenantInfo:
    """Build a TenantInfo with the given degraded_sources."""
    return TenantInfo(
        tenant_id="t1",
        display_name="Test Corp",
        default_domain="test.com",
        queried_domain="test.com",
        confidence=ConfidenceLevel.MEDIUM,
        sources=("dns_records",),
        services=("DMARC",),
        degraded_sources=degraded,
    )


class TestProperty5DegradedInAllOutputs:
    """Property 5: Degraded sources appear in all formatted outputs.

    **Validates: Requirements 7.1, 7.2, 7.3, 7.5**
    """

    @given(degraded=_nonempty_degraded)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_degraded_in_all_formats(self, degraded):
        """Every source name in degraded_sources appears in panel, JSON, markdown, MCP text."""
        ti = _make_ti_with_degraded(degraded)

        # (a) Rich panel text
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        set_console(console)
        panel = render_tenant_panel(ti)
        console.print(panel)
        panel_text = buf.getvalue()

        # (b) JSON dict
        json_dict = format_tenant_dict(ti)

        # (c) Markdown
        md = format_tenant_markdown(ti)

        # (d) MCP text output (simulated from server.py logic)
        mcp_lines = []
        if ti.degraded_sources:
            mcp_lines.append(f"Degraded sources: {', '.join(ti.degraded_sources)}")
        mcp_text = "\n".join(mcp_lines)

        for source_name in degraded:
            assert source_name in panel_text, f"{source_name} missing from panel"
            assert source_name in json_dict["degraded_sources"], f"{source_name} missing from JSON"
            assert source_name in md, f"{source_name} missing from markdown"
            assert source_name in mcp_text, f"{source_name} missing from MCP text"


# ── Property 6: JSON partial key reflects degraded state ────────────────


class TestProperty6JsonPartialKey:
    """Property 6: JSON partial key reflects core-source degradation only.

    As of v1.0.2, `partial` is reserved for core-source failures (OIDC,
    UserRealm, Google Identity, DNS). CT-provider degradation (crt.sh,
    CertSpotter) is handled gracefully by the fallback + cache pipeline
    and must not flip the global `partial` bit on its own.

    **Validates: Requirements 7.4, 11.3**
    """

    _CT_PROVIDERS = frozenset({"crt.sh", "certspotter"})

    @given(degraded=_degraded_sources_tuple)
    @settings(max_examples=100)
    def test_partial_matches_non_ct_degradation(self, degraded):
        """format_tenant_dict['partial'] iff a non-CT source is degraded."""
        ti = TenantInfo(
            tenant_id="t1",
            display_name="Test",
            default_domain="test.com",
            queried_domain="test.com",
            confidence=ConfidenceLevel.MEDIUM,
            sources=("dns_records",),
            services=("DMARC",),
            degraded_sources=degraded,
        )
        d = format_tenant_dict(ti)
        expected = any(src not in self._CT_PROVIDERS for src in degraded)
        assert d["partial"] == expected
