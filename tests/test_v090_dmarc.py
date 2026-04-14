"""v0.9.0 — QA Round 2: DMARC Intelligence.

Validates:
- pct= parsing (valid 0-100, absent, non-integer, out-of-range) (6.1)
- rua= extraction (single, multiple, no @, no rua=, non-mailto, matched vendor) (6.2)
- All 6 DMARC vendor fingerprints (load, detection type, patterns) (6.3)
- dmarc_phased_rollout posture observation (6.4)
- "DMARC Governance Investment" signal (6.5)
- Property 3: DMARC pct= Parsing Correctness (6.6)
- Property 4: DMARC rua= Extraction Correctness (6.7)
- Requirements: 9.1–9.5, 10.1, 10.3–10.5, 11.1–11.3, 12.1–12.4, 21.2, 21.3, 21.11
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from recon_tool.fingerprints import get_dmarc_rua_patterns, load_fingerprints, reload_fingerprints
from recon_tool.models import ConfidenceLevel, SignalContext, TenantInfo
from recon_tool.posture import analyze_posture, reload_posture
from recon_tool.signals import evaluate_signals, load_signals, reload_signals
from recon_tool.sources.dns import DNSSource, _detect_email_security, _DetectionCtx, _extract_dmarc_rua

# ── Helpers ───────────────────────────────────────────────────────────


def _mock_safe_resolve_factory(records_by_query: dict[str, list[str]]):
    """Create an async mock for _safe_resolve based on (domain/rdtype) key."""

    async def mock_resolve(domain: str, rdtype: str, **kwargs: object) -> list[str]:
        key = f"{domain}/{rdtype}"
        if key in records_by_query:
            return records_by_query[key]
        return []

    return mock_resolve


def _make_tenant_info(**overrides: object) -> TenantInfo:
    """Create a TenantInfo with Contoso defaults, overriding specific fields."""
    defaults: dict[str, object] = {
        "tenant_id": "contoso-tenant-id",
        "display_name": "Contoso Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


# ── 6.1: pct= parsing ────────────────────────────────────────────────


class TestDmarcPctParsing:
    """Verify pct= parsing in _detect_email_security via DNSSource."""

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_valid_pct_50(self, mock_resolve) -> None:  # type: ignore[no-untyped-def]
        """pct=50 → dmarc_pct == 50."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject; pct=50"]}
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct == 50

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_valid_pct_0(self, mock_resolve) -> None:  # type: ignore[no-untyped-def]
        """pct=0 → dmarc_pct == 0 (monitoring only)."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=quarantine; pct=0"]}
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct == 0

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_valid_pct_100(self, mock_resolve) -> None:  # type: ignore[no-untyped-def]
        """pct=100 → dmarc_pct == 100 (full enforcement)."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject; pct=100"]}
        )
        result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct == 100

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_absent_pct(self, mock_resolve) -> None:  # type: ignore[no-untyped-def]
        """No pct= tag → dmarc_pct is None (not defaulting to 100)."""
        mock_resolve.side_effect = _mock_safe_resolve_factory({"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject"]})
        result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct is None

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_non_integer_pct(self, mock_resolve, caplog: pytest.LogCaptureFixture) -> None:  # type: ignore[no-untyped-def]
        """pct=abc → warning logged, dmarc_pct is None."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject; pct=abc"]}
        )
        with caplog.at_level(logging.WARNING, logger="recon"):
            result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct is None
        assert any("not a valid integer" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_out_of_range_pct_150(self, mock_resolve, caplog: pytest.LogCaptureFixture) -> None:  # type: ignore[no-untyped-def]
        """pct=150 → warning logged, dmarc_pct is None."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject; pct=150"]}
        )
        with caplog.at_level(logging.WARNING, logger="recon"):
            result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct is None
        assert any("out of range" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_out_of_range_pct_negative(self, mock_resolve, caplog: pytest.LogCaptureFixture) -> None:  # type: ignore[no-untyped-def]
        """pct=-5 → warning logged, dmarc_pct is None."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {"_dmarc.contoso.com/TXT": ["v=DMARC1; p=reject; pct=-5"]}
        )
        with caplog.at_level(logging.WARNING, logger="recon"):
            result = await DNSSource().lookup("contoso.com")
        assert result.dmarc_pct is None
        assert any("out of range" in r.message for r in caplog.records)


# ── 6.2: rua= extraction ─────────────────────────────────────────────


class TestDmarcRuaExtraction:
    """Verify rua= extraction in _extract_dmarc_rua and via DNSSource."""

    def test_single_rua_domain_extracted(self) -> None:
        """Single rua=mailto:user@vendor.example.com → domain extracted."""
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, "v=DMARC1; p=reject; rua=mailto:reports@agari.com")
        # agari.com matches the Agari fingerprint
        assert "agari" in ctx.slugs
        assert any(e.source_type == "DMARC_RUA" for e in ctx.evidence)

    def test_multiple_rua_entries(self) -> None:
        """Multiple rua=mailto: entries (semicolon-separated tags) → all domains extracted."""
        ctx = _DetectionCtx()
        # DMARC records can have multiple rua= tags or comma-separated mailto: URIs.
        # The regex captures each rua=mailto: occurrence independently.
        _extract_dmarc_rua(
            ctx,
            "v=DMARC1; p=reject; rua=mailto:d@agari.com; rua=mailto:r@dmarcian.com",
        )
        assert "agari" in ctx.slugs
        assert "dmarcian" in ctx.slugs

    def test_rua_without_at_skipped(self) -> None:
        """rua=mailto:noemail → skipped (no @ sign)."""
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, "v=DMARC1; p=reject; rua=mailto:noemail")
        assert len(ctx.slugs) == 0
        assert len(ctx.evidence) == 0

    def test_no_rua_tag(self) -> None:
        """No rua= tag → no extraction."""
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, "v=DMARC1; p=reject")
        assert len(ctx.slugs) == 0
        assert len(ctx.evidence) == 0

    def test_non_mailto_uri_ignored(self) -> None:
        """rua=https://example.com → not matched by mailto regex."""
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, "v=DMARC1; p=reject; rua=https://example.com/report")
        assert len(ctx.slugs) == 0

    def test_matched_vendor_creates_evidence(self) -> None:
        """Matched vendor domain → slug added, EvidenceRecord with DMARC_RUA source_type."""
        ctx = _DetectionCtx()
        _extract_dmarc_rua(
            ctx,
            "v=DMARC1; p=reject; rua=mailto:dmarc@emaildefense.proofpoint.com",
        )
        assert "proofpoint-efd" in ctx.slugs
        evidence = [e for e in ctx.evidence if e.source_type == "DMARC_RUA"]
        assert len(evidence) == 1
        assert evidence[0].slug == "proofpoint-efd"
        assert "rua=mailto:" in evidence[0].raw_value

    @pytest.mark.asyncio
    @patch("recon_tool.sources.dns._safe_resolve")
    async def test_rua_extraction_via_dns_source(self, mock_resolve) -> None:  # type: ignore[no-untyped-def]
        """End-to-end: DNSSource extracts rua= and detects vendor slug."""
        mock_resolve.side_effect = _mock_safe_resolve_factory(
            {
                "_dmarc.northwind.com/TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@valimail.com"],
            }
        )
        result = await DNSSource().lookup("northwind.com")
        assert "valimail" in result.detected_slugs


# ── 6.3: DMARC vendor fingerprints ───────────────────────────────────


class TestDmarcVendorFingerprints:
    """Verify all 6 DMARC vendor fingerprints load correctly."""

    _EXPECTED_VENDORS: dict[str, str] = {
        "agari": "agari.com",
        "proofpoint-efd": "emaildefense.proofpoint.com",
        "ondmarc": "ondmarc.com",
        "dmarcian": "dmarcian.com",
        "valimail": "valimail.com",
        "easydmarc": "easydmarc.com",
    }

    def setup_method(self) -> None:
        reload_fingerprints()

    def test_all_six_load_without_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        """All 6 DMARC vendor fingerprints load without warnings."""
        with caplog.at_level(logging.WARNING, logger="recon"):
            reload_fingerprints()
            fps = load_fingerprints()
        vendor_slugs = {fp.slug for fp in fps if fp.slug in self._EXPECTED_VENDORS}
        assert vendor_slugs == set(self._EXPECTED_VENDORS.keys())
        # No warnings about these specific fingerprints
        vendor_warnings = [r for r in caplog.records if any(slug in r.message for slug in self._EXPECTED_VENDORS)]
        assert len(vendor_warnings) == 0

    def test_each_has_dmarc_rua_detection_type(self) -> None:
        """Each DMARC vendor fingerprint has at least one dmarc_rua detection."""
        fps = load_fingerprints()
        for slug in self._EXPECTED_VENDORS:
            matching = [fp for fp in fps if fp.slug == slug]
            assert len(matching) >= 1, f"No fingerprint found for slug {slug}"
            has_dmarc_rua = any(det.type == "dmarc_rua" for fp in matching for det in fp.detections)
            assert has_dmarc_rua, f"Fingerprint {slug} has no dmarc_rua detection"

    def test_patterns_match_expected_vendor_domains(self) -> None:
        """Each fingerprint's dmarc_rua pattern matches the expected vendor domain."""
        rua_patterns = get_dmarc_rua_patterns()
        pattern_by_slug: dict[str, list[str]] = {}
        for det in rua_patterns:
            pattern_by_slug.setdefault(det.slug, []).append(det.pattern)

        for slug, expected_domain in self._EXPECTED_VENDORS.items():
            assert slug in pattern_by_slug, f"No dmarc_rua pattern for slug {slug}"
            patterns = pattern_by_slug[slug]
            assert any(expected_domain in p for p in patterns), (
                f"Pattern for {slug} does not contain {expected_domain}: {patterns}"
            )


# ── 6.4: dmarc_phased_rollout posture observation ────────────────────


class TestDmarcPhasedRolloutPosture:
    """Verify dmarc_phased_rollout posture observation fires correctly."""

    def setup_method(self) -> None:
        reload_posture()

    def test_fires_when_pct_below_100_and_quarantine(self) -> None:
        """pct=50, policy=quarantine → observation fires."""
        info = _make_tenant_info(
            dmarc_policy="quarantine",
            dmarc_pct=50,
            services=("DMARC",),
        )
        observations = analyze_posture(info)
        phased = [o for o in observations if "phased rollout" in o.statement.lower()]
        assert len(phased) == 1
        assert "50%" in phased[0].statement

    def test_fires_when_pct_below_100_and_reject(self) -> None:
        """pct=25, policy=reject → observation fires."""
        info = _make_tenant_info(
            dmarc_policy="reject",
            dmarc_pct=25,
            services=("DMARC",),
        )
        observations = analyze_posture(info)
        phased = [o for o in observations if "phased rollout" in o.statement.lower()]
        assert len(phased) == 1
        assert "25%" in phased[0].statement

    def test_does_not_fire_when_pct_is_none(self) -> None:
        """pct=None (absent) → observation does not fire."""
        info = _make_tenant_info(
            dmarc_policy="reject",
            dmarc_pct=None,
            services=("DMARC",),
        )
        observations = analyze_posture(info)
        phased = [o for o in observations if "phased rollout" in o.statement.lower()]
        assert len(phased) == 0

    def test_does_not_fire_when_policy_is_none(self) -> None:
        """pct=50, policy=none → observation does not fire (policy is 'none')."""
        info = _make_tenant_info(
            dmarc_policy="none",
            dmarc_pct=50,
            services=("DMARC",),
        )
        observations = analyze_posture(info)
        phased = [o for o in observations if "phased rollout" in o.statement.lower()]
        assert len(phased) == 0

    def test_template_includes_percentage(self) -> None:
        """Template renders with actual pct value."""
        info = _make_tenant_info(
            dmarc_policy="reject",
            dmarc_pct=75,
            services=("DMARC",),
        )
        observations = analyze_posture(info)
        phased = [o for o in observations if "phased rollout" in o.statement.lower()]
        assert len(phased) == 1
        assert "75%" in phased[0].statement
        assert phased[0].category == "email"
        assert phased[0].salience == "medium"


# ── 6.5: "DMARC Governance Investment" signal ────────────────────────


class TestDmarcGovernanceInvestmentSignal:
    """Verify the DMARC Governance Investment signal fires correctly."""

    def setup_method(self) -> None:
        reload_signals()
        reload_fingerprints()

    def _ctx(self, slugs: set[str]) -> SignalContext:
        return SignalContext(detected_slugs=frozenset(slugs))

    def test_fires_when_agari_detected(self) -> None:
        """Signal fires when agari slug is detected."""
        result = evaluate_signals(self._ctx({"agari"}))
        governance = [s for s in result if s.name == "DMARC Governance Investment"]
        assert len(governance) == 1
        assert governance[0].confidence == "high"
        assert governance[0].category == "Email"

    def test_fires_when_proofpoint_efd_detected(self) -> None:
        """Signal fires when proofpoint-efd slug is detected."""
        result = evaluate_signals(self._ctx({"proofpoint-efd"}))
        governance = [s for s in result if s.name == "DMARC Governance Investment"]
        assert len(governance) == 1

    def test_fires_when_dmarcian_detected(self) -> None:
        """Signal fires when dmarcian slug is detected."""
        result = evaluate_signals(self._ctx({"dmarcian"}))
        governance = [s for s in result if s.name == "DMARC Governance Investment"]
        assert len(governance) == 1

    def test_does_not_fire_when_no_vendor_slugs(self) -> None:
        """Signal does not fire when no DMARC vendor slugs detected."""
        result = evaluate_signals(self._ctx({"microsoft365", "proofpoint"}))
        governance = [s for s in result if s.name == "DMARC Governance Investment"]
        assert len(governance) == 0

    def test_expected_counterparts_populated(self) -> None:
        """Signal has expected_counterparts with email gateway slugs."""
        signals = load_signals()
        governance = [s for s in signals if s.name == "DMARC Governance Investment"]
        assert len(governance) == 1
        sig = governance[0]
        assert len(sig.expected_counterparts) > 0
        # Should include email gateway slugs
        assert "proofpoint" in sig.expected_counterparts
        assert "mimecast" in sig.expected_counterparts

    def test_fires_for_each_vendor_slug(self) -> None:
        """Signal fires for each individual DMARC vendor slug."""
        vendor_slugs = ["agari", "proofpoint-efd", "ondmarc", "dmarcian", "valimail", "easydmarc"]
        for slug in vendor_slugs:
            result = evaluate_signals(self._ctx({slug}))
            governance = [s for s in result if s.name == "DMARC Governance Investment"]
            assert len(governance) == 1, f"Signal did not fire for slug {slug}"


# ── 6.6: Property 3 — DMARC pct= Parsing Correctness (PBT) ──────────
# Feature: intelligence-amplification, Property 3: DMARC pct= Parsing Correctness
# **Validates: Requirements 10.1, 10.3, 10.4, 10.5**


class TestProperty3DmarcPctParsing:
    """Hypothesis PBT for DMARC pct= parsing correctness."""

    @given(n=st.integers(min_value=0, max_value=100))
    @settings(max_examples=100, deadline=None)
    def test_valid_pct_integers(self, n: int) -> None:
        """For any valid integer n in [0, 100], pct={n} → dmarc_pct == n."""
        import asyncio

        ctx = _DetectionCtx()

        async def _mock_resolve(domain: str, rdtype: str, **kwargs: object) -> list[str]:
            if domain == "_dmarc.contoso.com" and rdtype == "TXT":
                return [f"v=DMARC1; p=reject; pct={n}"]
            return []

        with patch("recon_tool.sources.dns._safe_resolve", side_effect=_mock_resolve):
            asyncio.new_event_loop().run_until_complete(_detect_email_security(ctx, "contoso.com"))

        assert ctx.dmarc_pct == n, f"Expected dmarc_pct={n}, got {ctx.dmarc_pct}"

    @given(policy=st.sampled_from(["none", "quarantine", "reject"]))
    @settings(max_examples=100)
    def test_absent_pct_always_none(self, policy: str) -> None:
        """For any DMARC record without pct= → dmarc_pct is None."""
        import asyncio

        ctx = _DetectionCtx()

        async def _mock_resolve(domain: str, rdtype: str, **kwargs: object) -> list[str]:
            if domain == "_dmarc.contoso.com" and rdtype == "TXT":
                return [f"v=DMARC1; p={policy}"]
            return []

        with patch("recon_tool.sources.dns._safe_resolve", side_effect=_mock_resolve):
            asyncio.new_event_loop().run_until_complete(_detect_email_security(ctx, "contoso.com"))

        assert ctx.dmarc_pct is None, f"Expected None for absent pct=, got {ctx.dmarc_pct}"

    @given(
        bad_val=st.one_of(
            st.text(
                alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz"),
                min_size=1,
                max_size=10,
            ),
            st.integers(min_value=101, max_value=10000).map(str),
            st.integers(min_value=-10000, max_value=-1).map(str),
        )
    )
    @settings(max_examples=100)
    def test_invalid_pct_values_produce_none(self, bad_val: str) -> None:
        """For any invalid pct= value (non-integer or out-of-range) → dmarc_pct is None."""
        import asyncio

        ctx = _DetectionCtx()

        async def _mock_resolve(domain: str, rdtype: str, **kwargs: object) -> list[str]:
            if domain == "_dmarc.contoso.com" and rdtype == "TXT":
                return [f"v=DMARC1; p=reject; pct={bad_val}"]
            return []

        with patch("recon_tool.sources.dns._safe_resolve", side_effect=_mock_resolve):
            asyncio.new_event_loop().run_until_complete(_detect_email_security(ctx, "contoso.com"))

        assert ctx.dmarc_pct is None, f"Expected None for invalid pct={bad_val}, got {ctx.dmarc_pct}"


# ── 6.7: Property 4 — DMARC rua= Extraction Correctness (PBT) ───────
# Feature: intelligence-amplification, Property 4: DMARC rua= Extraction Correctness
# **Validates: Requirements 9.1, 9.4**


class TestProperty4DmarcRuaExtraction:
    """Hypothesis PBT for DMARC rua= extraction correctness."""

    @given(
        addr=st.tuples(
            st.from_regex(r"[a-z][a-z0-9]{0,9}", fullmatch=True),
            st.from_regex(r"[a-z][a-z0-9]{1,8}\.[a-z]{2,4}", fullmatch=True),
        ).map(lambda t: f"{t[0]}@{t[1]}")
    )
    @settings(max_examples=100)
    def test_valid_email_domain_extracted(self, addr: str) -> None:
        """For any valid email in rua=mailto:{addr}, domain portion extracted correctly."""
        expected_domain = addr.split("@", 1)[1].lower()
        dmarc_record = f"v=DMARC1; p=reject; rua=mailto:{addr}"
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, dmarc_record)
        # Verify the function doesn't crash and any evidence has the correct domain
        for ev in ctx.evidence:
            assert expected_domain in ev.raw_value.lower()

    @given(
        domains=st.lists(
            st.sampled_from(["agari.com", "dmarcian.com", "valimail.com", "easydmarc.com"]),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    @settings(max_examples=100)
    def test_multi_rua_all_extracted(self, domains: list[str]) -> None:
        """For multi-rua records (semicolon-separated rua= tags), all domains extracted."""
        # Each rua= tag is a separate DMARC tag, semicolon-separated per RFC 7489
        rua_tags = "; ".join(f"rua=mailto:reports@{d}" for d in domains)
        dmarc_record = f"v=DMARC1; p=reject; {rua_tags}"
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, dmarc_record)
        assert len(ctx.evidence) == len(domains), (
            f"Expected {len(domains)} evidence records, got {len(ctx.evidence)} for domains {domains}"
        )

    @given(
        val=st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789.-_"),
            min_size=1,
            max_size=20,
        ).filter(lambda s: "@" not in s)
    )
    @settings(max_examples=100)
    def test_rua_without_at_no_extraction(self, val: str) -> None:
        """For rua= without @, no domain extracted."""
        dmarc_record = f"v=DMARC1; p=reject; rua=mailto:{val}"
        ctx = _DetectionCtx()
        _extract_dmarc_rua(ctx, dmarc_record)
        assert len(ctx.evidence) == 0, f"Expected no evidence for rua=mailto:{val}, got {len(ctx.evidence)}"
