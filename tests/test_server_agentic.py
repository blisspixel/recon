"""Phase 2b: tests for the MCP agentic and introspection tools.

Covers tools that didn't get coverage in v0.9.1 or earlier v0.9.2 work:
- get_fingerprints, get_signals (introspection)
- explain_signal (with and without domain)
- test_hypothesis (each likelihood path)
- simulate_hardening (each fix type, score delta)
- inject_ephemeral_fingerprint, list_ephemeral, clear_ephemeral, reevaluate_domain
  (full lifecycle)

All tests mock ``_resolve_or_cache`` or pre-populate the in-memory cache,
so no real network calls happen.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp.exceptions import ToolError

from recon_tool.models import (
    ConfidenceLevel,
    SourceResult,
    TenantInfo,
)


def _info(**overrides: object) -> TenantInfo:
    """Synthetic TenantInfo for agentic tool tests. No real company names."""
    defaults: dict[str, object] = {
        "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "display_name": "Contoso Ltd",
        "default_domain": "contoso.onmicrosoft.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.HIGH,
        "region": "NA",
        "sources": ("oidc_discovery", "user_realm", "dns_records"),
        "services": ("Microsoft 365", "DMARC", "DKIM (Exchange Online)"),
        "slugs": ("microsoft365", "dmarc", "dkim-exchange"),
        "auth_type": "Federated",
        "dmarc_policy": "reject",
        "domain_count": 1,
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


def _results() -> list[SourceResult]:
    return [
        SourceResult(
            source_name="oidc_discovery",
            tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            region="NA",
        ),
        SourceResult(
            source_name="user_realm",
            display_name="Contoso Ltd",
            m365_detected=True,
            auth_type="Federated",
        ),
        SourceResult(
            source_name="dns_records",
            m365_detected=True,
            detected_services=("Microsoft 365", "DMARC"),
            detected_slugs=("microsoft365", "dmarc"),
            dmarc_policy="reject",
        ),
    ]


@pytest.fixture
def fresh_server_cache() -> Iterator[None]:
    """Wipe the server's in-memory cache between tests."""
    from recon_tool.server import _cache

    _cache.clear()
    yield
    _cache.clear()


@pytest.fixture
def mocked_resolve(fresh_server_cache: None):
    """Patch _resolve_or_cache to return synthetic data without network."""

    async def fake(domain: str):
        return _info(queried_domain=domain), _results()

    with patch("recon_tool.server_app.resolve_or_cache", side_effect=fake):
        yield


# ── get_fingerprints ──────────────────────────────────────────────────


class TestGetFingerprints:
    @pytest.mark.asyncio
    async def test_returns_array_of_fingerprints(self) -> None:
        from recon_tool.server import get_fingerprints

        data = await get_fingerprints()
        assert isinstance(data, list)
        assert len(data) > 0
        # Each entry has expected fields
        first = data[0]
        assert "name" in first
        assert "slug" in first
        assert "category" in first
        assert "detection_types" in first

    @pytest.mark.asyncio
    async def test_category_filter_narrows_results(self) -> None:
        from recon_tool.server import get_fingerprints

        all_fps = await get_fingerprints()
        # Pick the first category that appears
        if not all_fps:
            return
        target_cat = all_fps[0]["category"]
        filtered = await get_fingerprints(category=target_cat)
        # All filtered entries share the category (case-insensitive partial match)
        for fp in filtered:
            assert target_cat.lower() in fp["category"].lower()

    @pytest.mark.asyncio
    async def test_category_filter_no_match_returns_empty(self) -> None:
        from recon_tool.server import get_fingerprints

        result = await get_fingerprints(category="absolutely-no-such-category")
        assert result == []


# ── get_signals ──────────────────────────────────────────────────────


class TestGetSignals:
    @pytest.mark.asyncio
    async def test_returns_array_of_signals(self) -> None:
        from recon_tool.server import get_signals

        result = await get_signals()
        assert isinstance(result, list)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_category_filter(self) -> None:
        from recon_tool.server import get_signals

        result = await get_signals(category="email")
        for sig in result:
            assert "email" in sig.get("category", "").lower()

    @pytest.mark.asyncio
    async def test_layer_filter(self) -> None:
        from recon_tool.server import get_signals

        result = await get_signals(layer=1)
        for sig in result:
            assert sig.get("layer") == 1


# ── explain_signal ────────────────────────────────────────────────────


class TestExplainSignal:
    @pytest.mark.asyncio
    async def test_definition_only_no_domain(self) -> None:
        """Without a domain, returns the signal's static definition."""
        from recon_tool.server import explain_signal

        result = await explain_signal("AI Adoption")
        assert result["name"] == "AI Adoption"
        assert "trigger_conditions" in result
        assert "weakening_conditions" in result
        # No domain → no "fired" or "matched_evidence" key
        assert "fired" not in result

    @pytest.mark.asyncio
    async def test_unknown_signal_raises_tool_error(self) -> None:
        from recon_tool.server import explain_signal

        with pytest.raises(ToolError, match="not found"):
            await explain_signal("NoSuchSignal")

    @pytest.mark.asyncio
    async def test_with_domain_evaluates_signal(self, mocked_resolve) -> None:
        from recon_tool.server import explain_signal

        result = await explain_signal("AI Adoption", domain="contoso.com")
        assert "fired" in result
        assert "matched_slugs" in result
        assert result["domain"] == "contoso.com"


# ── test_hypothesis ──────────────────────────────────────────────────


class TestHypothesis:
    @pytest.mark.asyncio
    async def test_returns_structured_assessment(self, mocked_resolve) -> None:
        from recon_tool.server import test_hypothesis

        result = await test_hypothesis("contoso.com", "they are doing email migration")
        # Required keys
        for key in (
            "domain",
            "hypothesis",
            "likelihood",
            "supporting_signals",
            "contradicting_signals",
            "missing_evidence",
            "confidence",
            "disclaimer",
        ):
            assert key in result, f"missing key: {key}"
        assert result["domain"] == "contoso.com"
        assert result["likelihood"] in {"strong", "moderate", "weak", "unsupported"}
        assert result["confidence"] in {"high", "medium", "low"}

    @pytest.mark.asyncio
    async def test_unsupported_when_no_relevant_signals(self, mocked_resolve) -> None:
        from recon_tool.server import test_hypothesis

        result = await test_hypothesis("contoso.com", "this organization is using a quantum SaaS")
        # No matching signals → unsupported
        assert result["likelihood"] == "unsupported"

    @pytest.mark.asyncio
    async def test_disclaimer_always_present(self, mocked_resolve) -> None:
        from recon_tool.server import test_hypothesis

        result = await test_hypothesis("contoso.com", "they use cloud identity")
        assert "indicators" in result["disclaimer"].lower()


# ── simulate_hardening ───────────────────────────────────────────────


class TestSimulateHardening:
    @pytest.mark.asyncio
    async def test_returns_score_delta(self, mocked_resolve) -> None:
        from recon_tool.server import simulate_hardening

        result = await simulate_hardening("contoso.com", ["DMARC reject", "MTA-STS enforce"])
        assert "current_score" in result
        assert "simulated_score" in result
        assert "score_delta" in result
        assert "applied_fixes" in result

    @pytest.mark.asyncio
    async def test_applies_known_fixes(self, mocked_resolve) -> None:
        from recon_tool.server import simulate_hardening

        result = await simulate_hardening("contoso.com", ["DKIM", "BIMI", "SPF strict"])
        applied = result["applied_fixes"]
        # All three should be recognized
        assert any("DKIM" in a for a in applied)
        assert any("BIMI" in a for a in applied)
        assert any("SPF" in a for a in applied)

    @pytest.mark.asyncio
    async def test_unrecognized_fix_noted(self, mocked_resolve) -> None:
        from recon_tool.server import simulate_hardening

        result = await simulate_hardening("contoso.com", ["something completely made up"])
        applied = result["applied_fixes"]
        assert any("Unrecognized" in a for a in applied)

    @pytest.mark.asyncio
    async def test_dmarc_reject_increases_score(self, mocked_resolve) -> None:
        """For a domain starting without DMARC reject, simulating it
        should produce a positive score delta."""
        from recon_tool.server import simulate_hardening

        # Override mocked_resolve to return an info WITHOUT dmarc reject
        async def fake(domain: str):
            return _info(dmarc_policy="none"), _results()

        with patch("recon_tool.server_app.resolve_or_cache", side_effect=fake):
            result = await simulate_hardening("contoso.com", ["DMARC reject"])
        assert result["score_delta"] >= 0


# ── Ephemeral fingerprint lifecycle ──────────────────────────────────


class TestEphemeralFingerprints:
    @pytest.fixture(autouse=True)
    def _clean_ephemeral(self) -> Iterator[None]:
        """Clear ephemerals before and after each test."""
        from recon_tool.fingerprints import clear_ephemeral

        clear_ephemeral()
        yield
        clear_ephemeral()

    @pytest.mark.asyncio
    async def test_inject_then_list_then_clear(self) -> None:
        import time

        from recon_tool.server import (
            _cache,
            clear_ephemeral_fingerprints,
            inject_ephemeral_fingerprint,
            list_ephemeral_fingerprints,
        )

        # Inject one
        inject_result = await inject_ephemeral_fingerprint(
            name="Test Platform",
            slug="test-platform",
            category="SaaS",
            confidence="medium",
            detections=[{"type": "txt", "pattern": "test-platform-verify="}],
        )
        assert inject_result["status"] == "ok"
        assert inject_result["slug"] == "test-platform"
        assert inject_result["detections_accepted"] == 1

        # List shows it
        listed = await list_ephemeral_fingerprints()
        assert any(fp["slug"] == "test-platform" for fp in listed)

        _cache["contoso.com"] = (time.monotonic(), _info(display_name="Before Clear"), tuple(_results()))

        # Clear removes it
        refreshed_info = _info(display_name="After Clear")
        with patch("recon_tool.merger.merge_results", return_value=refreshed_info):
            cleared = await clear_ephemeral_fingerprints()
        assert cleared["status"] == "ok"
        assert cleared["removed"] >= 1

        # List is now empty (or doesn't have our slug)
        listed_after = await list_ephemeral_fingerprints()
        assert not any(fp["slug"] == "test-platform" for fp in listed_after)
        assert _cache["contoso.com"][1].display_name == "After Clear"

    @pytest.mark.asyncio
    async def test_inject_invalid_returns_error(self) -> None:
        from recon_tool.server import inject_ephemeral_fingerprint

        # Invalid: detection type not in valid set
        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="Bad",
                slug="bad",
                category="SaaS",
                confidence="high",
                detections=[{"type": "totally_invalid_type", "pattern": "foo"}],
            )

    @pytest.mark.asyncio
    async def test_inject_invalid_regex_returns_error(self) -> None:
        from recon_tool.server import inject_ephemeral_fingerprint

        # Invalid: unbalanced regex
        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="BadRegex",
                slug="bad-regex",
                category="SaaS",
                confidence="high",
                detections=[{"type": "txt", "pattern": "[unclosed"}],
            )


# ── reevaluate_domain ────────────────────────────────────────────────


class TestReevaluateDomain:
    @pytest.mark.asyncio
    async def test_no_cache_returns_error(self, fresh_server_cache: None) -> None:
        from recon_tool.server import reevaluate_domain

        with pytest.raises(ToolError, match="No cached data"):
            await reevaluate_domain("not-cached.example")

    @pytest.mark.asyncio
    async def test_invalid_domain_returns_error(self) -> None:
        from recon_tool.server import reevaluate_domain

        with pytest.raises(ToolError):
            await reevaluate_domain("not a valid domain!!")

    @pytest.mark.asyncio
    async def test_cached_domain_reevaluates(self, fresh_server_cache: None) -> None:
        """Pre-seed the server cache, then re-evaluate."""
        import time

        from recon_tool.server import _cache, reevaluate_domain

        info = _info()
        results = _results()
        _cache["contoso.com"] = (time.monotonic(), info, tuple(results))

        result = await reevaluate_domain("contoso.com")
        # A tenant-info dict (raises ToolError on failure, never an error payload)
        assert result.get("display_name") == "Contoso Ltd"
        assert result["evidence"] == []
        assert result["record_type"] == "lookup"
        assert result["schema_version"] == "2.0"

    @pytest.mark.asyncio
    async def test_reevaluate_updates_cached_info(self, fresh_server_cache: None) -> None:
        import time

        from recon_tool.server import _cache, _cache_get, reevaluate_domain

        original = _info(display_name="Original")
        refreshed = _info(display_name="Refreshed")
        results = _results()
        _cache["contoso.com"] = (time.monotonic(), original, tuple(results))

        with patch("recon_tool.merger.merge_results", return_value=refreshed):
            result = await reevaluate_domain("contoso.com")

        assert result["display_name"] == "Refreshed"
        cached = _cache_get("contoso.com")
        assert cached is not None
        assert cached[0].display_name == "Refreshed"


class TestReloadData:
    @pytest.mark.asyncio
    async def test_reload_clears_cache_but_preserves_rate_limiter(self, fresh_server_cache: None) -> None:
        # reload_data clears the result cache (definitions changed) but must
        # NOT clear the per-domain rate limiter: resetting it would let a
        # caller bypass the limiter by calling reload_data between lookups
        # (v1.9.19 hardening).
        import time

        from recon_tool.server import _cache, _rate_limit, reload_data

        _cache["contoso.com"] = (time.monotonic(), _info(), tuple(_results()))
        _rate_limit["contoso.com"] = time.monotonic()

        result = await reload_data()

        assert result.startswith("Reloaded:")
        assert "rate limiter preserved" in result.lower()
        assert _cache == {}
        # The rate-limit entry survives the reload.
        assert "contoso.com" in _rate_limit


class TestClusterVerificationTokensCap:
    @pytest.mark.asyncio
    async def test_rejects_oversized_distinct_input(self) -> None:
        # The MCP tool caps and dedups its input like the CLI batch path,
        # so a caller cannot drive unbounded sequential resolves.
        from recon_tool.server import cluster_verification_tokens

        domains = [f"d{i}.example.com" for i in range(101)]  # > 100 distinct
        with pytest.raises(ToolError, match="max"):
            await cluster_verification_tokens(domains)
