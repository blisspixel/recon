"""Ephemeral fingerprint injection tests (in-memory, session-scoped).

Validates:
- inject_ephemeral(), get_ephemeral(), clear_ephemeral() core logic (18.1)
- inject_ephemeral_fingerprint MCP tool (18.2)
- list_ephemeral_fingerprints MCP tool (18.3)
- clear_ephemeral_fingerprints MCP tool (18.4)
- reevaluate_domain MCP tool (18.5)
- Ephemeral fingerprint integration with pipeline (18.6)
- Property 5: Ephemeral Fingerprint Injection/Clear Round-Trip (18.7)
- Requirements: 13.1–13.6, 14.1–14.6, 15.1–15.5, 16.1–16.5, 21.5, 21.7
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recon_tool.fingerprints import (
    DetectionRule,
    EphemeralCapacityError,
    Fingerprint,
    clear_ephemeral,
    get_ephemeral,
    get_m365_names,
    get_m365_slugs,
    inject_ephemeral,
    load_fingerprints,
    reload_fingerprints,
)
from recon_tool.regex_safety import _compile_regex_cached, compile_regex

pytest.importorskip("mcp")

from mcp.server.fastmcp.exceptions import ToolError

# ── Helpers ───────────────────────────────────────────────────────────


def _make_fingerprint(
    name: str = "Contoso Platform",
    slug: str = "contoso-platform",
    category: str = "SaaS",
    confidence: str = "high",
    det_type: str = "txt",
    pattern: str = "^contoso-verification=",
    m365: bool = False,
) -> Fingerprint:
    """Create a minimal valid Fingerprint for testing."""
    return Fingerprint(
        name=name,
        slug=slug,
        category=category,
        confidence=confidence,
        m365=m365,
        detections=(DetectionRule(type=det_type, pattern=pattern),),
    )


@pytest.fixture(autouse=True)
def _cleanup_ephemeral():  # pyright: ignore[reportUnusedFunction]
    """Ensure ephemeral fingerprints are cleared before and after each test."""
    clear_ephemeral()
    reload_fingerprints()
    yield
    clear_ephemeral()
    reload_fingerprints()


# ── 18.1: inject_ephemeral(), get_ephemeral(), clear_ephemeral() ──────


class TestEphemeralCoreFunctions:
    """Verify inject_ephemeral(), get_ephemeral(), clear_ephemeral() in fingerprints.py."""

    def test_inject_then_get_contains_fingerprint(self) -> None:
        """inject → get returns collection containing injected fingerprint."""
        fp = _make_fingerprint()
        inject_ephemeral(fp)
        result = get_ephemeral()
        assert fp in result

    def test_catalog_generation_changes_invalidate_compiled_regexes(self) -> None:
        assert compile_regex("^warm-cache$") is not None
        assert _compile_regex_cached.cache_info().currsize > 0

        fp = _make_fingerprint(slug="cache-invalidation")
        inject_ephemeral(fp)
        assert _compile_regex_cached.cache_info().currsize == 0

        assert compile_regex(fp.detections[0].pattern) is not None
        clear_ephemeral()
        assert _compile_regex_cached.cache_info().currsize == 0

        assert compile_regex("^warm-cache-again$") is not None
        reload_fingerprints()
        assert _compile_regex_cached.cache_info().currsize == 0

    def test_inject_then_load_includes_ephemeral(self) -> None:
        """inject → load_fingerprints() includes ephemeral fingerprint."""
        fp = _make_fingerprint(slug="northwind-test")
        inject_ephemeral(fp)
        all_fps = load_fingerprints()
        slugs = {f.slug for f in all_fps}
        assert "northwind-test" in slugs

    def test_clear_then_get_returns_empty(self) -> None:
        """clear → get returns empty collection."""
        fp = _make_fingerprint()
        inject_ephemeral(fp)
        clear_ephemeral()
        assert get_ephemeral() == ()

    def test_clear_then_load_excludes_ephemeral(self) -> None:
        """clear → load_fingerprints() excludes ephemeral fingerprint."""
        fp = _make_fingerprint(slug="fabrikam-temp")
        inject_ephemeral(fp)
        clear_ephemeral()
        all_fps = load_fingerprints()
        slugs = {f.slug for f in all_fps}
        assert "fabrikam-temp" not in slugs

    def test_clear_returns_correct_count(self) -> None:
        """clear returns correct count of removed fingerprints."""
        inject_ephemeral(_make_fingerprint(slug="contoso-a"))
        inject_ephemeral(_make_fingerprint(slug="contoso-b"))
        inject_ephemeral(_make_fingerprint(slug="contoso-c"))
        count = clear_ephemeral()
        assert count == 3

    def test_clear_empty_returns_zero(self) -> None:
        """clear on empty collection returns 0."""
        count = clear_ephemeral()
        assert count == 0

    def test_cache_invalidation_on_inject(self) -> None:
        """_get_detections and load_fingerprints caches cleared on inject."""
        # Load fingerprints to populate cache
        before = load_fingerprints()
        fp = _make_fingerprint(slug="contoso-cache-test")
        inject_ephemeral(fp)
        after = load_fingerprints()
        # After inject, the new fingerprint should appear (cache was cleared)
        assert len(after) == len(before) + 1

    def test_cache_invalidation_on_clear(self) -> None:
        """_get_detections and load_fingerprints caches cleared on clear."""
        fp = _make_fingerprint(slug="contoso-cache-clear")
        inject_ephemeral(fp)
        with_ephemeral = load_fingerprints()
        clear_ephemeral()
        without_ephemeral = load_fingerprints()
        assert len(without_ephemeral) == len(with_ephemeral) - 1

    def test_m365_views_invalidate_on_inject_and_clear(self) -> None:
        before_names = get_m365_names()
        before_slugs = get_m365_slugs()
        fp = _make_fingerprint(name="Contoso M365", slug="contoso-m365", m365=True)

        inject_ephemeral(fp)
        assert "Contoso M365" in get_m365_names()
        assert "contoso-m365" in get_m365_slugs()

        clear_ephemeral()
        assert get_m365_names() == before_names
        assert get_m365_slugs() == before_slugs

    def test_multiple_inject_all_present(self) -> None:
        """Multiple injections → all fingerprints present in get_ephemeral()."""
        fp1 = _make_fingerprint(slug="northwind-a")
        fp2 = _make_fingerprint(slug="northwind-b")
        inject_ephemeral(fp1)
        inject_ephemeral(fp2)
        result = get_ephemeral()
        assert fp1 in result
        assert fp2 in result
        assert len(result) == 2

    @pytest.mark.parametrize(
        "reserved_slug",
        ["okta", "proofpoint", "cloudflare", "aws-cloudfront", "google-federated", "null-mx"],
    )
    def test_inject_rejects_builtin_slug_collision(self, reserved_slug: str) -> None:
        """Ephemeral rules cannot impersonate a built-in semantic slug."""
        with pytest.raises(ValueError, match="already exists"):
            inject_ephemeral(_make_fingerprint(slug=reserved_slug))
        assert get_ephemeral() == ()

    def test_inject_rejects_existing_ephemeral_slug_collision(self) -> None:
        inject_ephemeral(_make_fingerprint(slug="contoso-unique"))

        with pytest.raises(ValueError, match="already exists"):
            inject_ephemeral(_make_fingerprint(slug="contoso-unique", pattern="^other="))

        assert len(get_ephemeral()) == 1

    @pytest.mark.parametrize(
        "reserved_name",
        [
            "SPF: strict (-all)",
            "Google Workspace CSE",
            "CAA: Acme",
            "CDN: Acme",
            "CSE Key Manager: Acme",
            "Google Workspace: Drive",
        ],
    )
    def test_inject_rejects_reserved_semantic_name_or_prefix(self, reserved_name: str) -> None:
        with pytest.raises(ValueError, match="reserved semantics"):
            inject_ephemeral(
                _make_fingerprint(
                    name=reserved_name,
                    slug="contoso-semantic-name",
                )
            )

        assert get_ephemeral() == ()

    def test_inject_rejects_too_many_detections_per_fingerprint(self) -> None:
        """Oversized single ephemeral fingerprint is rejected before storage."""
        detections = tuple(DetectionRule(type="txt", pattern=f"^quota-{idx}=") for idx in range(21))
        fp = Fingerprint(
            name="Contoso Quota",
            slug="contoso-quota",
            category="SaaS",
            confidence="high",
            m365=False,
            detections=detections,
        )

        with pytest.raises(EphemeralCapacityError, match="detection cap"):
            inject_ephemeral(fp)

        assert get_ephemeral() == ()

    def test_inject_rejects_total_detection_quota(self) -> None:
        """Total ephemeral detections are capped so lookup work stays bounded."""
        for fp_idx in range(25):
            detections = tuple(
                DetectionRule(type="txt", pattern=f"^quota-{fp_idx}-{det_idx}=") for det_idx in range(20)
            )
            inject_ephemeral(
                Fingerprint(
                    name=f"Contoso Quota {fp_idx}",
                    slug=f"contoso-quota-{fp_idx}",
                    category="SaaS",
                    confidence="high",
                    m365=False,
                    detections=detections,
                )
            )

        assert len(get_ephemeral()) == 25
        with pytest.raises(EphemeralCapacityError, match="Ephemeral detection cap"):
            inject_ephemeral(_make_fingerprint(slug="contoso-overflow", pattern="^contoso-overflow="))
        assert len(get_ephemeral()) == 25


# ── 18.2: inject_ephemeral_fingerprint MCP tool ──────────────────────


class TestInjectEphemeralFingerprintMCP:
    """Verify inject_ephemeral_fingerprint MCP tool."""

    @pytest.mark.asyncio
    async def test_valid_input_returns_confirmation(self) -> None:
        """Valid input → confirmation JSON with name, slug, detections_accepted."""
        from recon_tool.server import inject_ephemeral_fingerprint

        result = await inject_ephemeral_fingerprint(
            name="Contoso Analytics",
            slug="contoso-analytics",
            category="SaaS",
            confidence="high",
            detections=[{"type": "txt", "pattern": "^contoso-analytics="}],
        )
        data = result
        assert data["status"] == "ok"
        assert data["name"] == "Contoso Analytics"
        assert data["slug"] == "contoso-analytics"
        assert data["detections_accepted"] == 1

    @pytest.mark.asyncio
    async def test_invalid_detection_type_returns_error(self) -> None:
        """Invalid detection type → error JSON."""
        from recon_tool.server import inject_ephemeral_fingerprint

        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="Fabrikam Widget",
                slug="fabrikam-widget",
                category="SaaS",
                confidence="high",
                detections=[{"type": "invalid_type", "pattern": "fabrikam"}],
            )

    @pytest.mark.asyncio
    async def test_redos_unsafe_pattern_returns_error(self) -> None:
        """ReDoS-unsafe pattern → error JSON."""
        from recon_tool.server import inject_ephemeral_fingerprint

        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="Northwind Unsafe",
                slug="northwind-unsafe",
                category="SaaS",
                confidence="high",
                detections=[{"type": "txt", "pattern": "(a+)+"}],
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("detection_type", ["txt", "cname", "subdomain_txt"])
    async def test_multiple_unbounded_quantifiers_return_error(self, detection_type: str) -> None:
        """Session-injected regexes allow at most one unbounded repetition."""
        from recon_tool.server import inject_ephemeral_fingerprint

        pattern = "_proof:^a*a*a*a*a*b$" if detection_type == "subdomain_txt" else "^a*a*a*a*a*b$"
        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="Northwind Polynomial",
                slug=f"northwind-polynomial-{detection_type}",
                category="SaaS",
                confidence="high",
                detections=[{"type": detection_type, "pattern": pattern}],
            )

    @pytest.mark.asyncio
    async def test_empty_detections_returns_error(self) -> None:
        """Empty detections list → error JSON."""
        from recon_tool.server import inject_ephemeral_fingerprint

        with pytest.raises(ToolError):
            await inject_ephemeral_fingerprint(
                name="Contoso Empty",
                slug="contoso-empty",
                category="SaaS",
                confidence="high",
                detections=[],
            )

    @pytest.mark.asyncio
    async def test_invalid_confidence_defaults_to_medium(self) -> None:
        """Invalid confidence level → defaults to medium (validation still passes)."""
        from recon_tool.server import inject_ephemeral_fingerprint

        result = await inject_ephemeral_fingerprint(
            name="Fabrikam Conf",
            slug="fabrikam-conf",
            category="SaaS",
            confidence="ultra-high",
            detections=[{"type": "txt", "pattern": "^fabrikam-conf="}],
        )
        data = result
        # _validate_fingerprint defaults invalid confidence to "medium" and still succeeds
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_multiple_detections_accepted(self) -> None:
        """Multiple valid detections → all accepted."""
        from recon_tool.server import inject_ephemeral_fingerprint

        result = await inject_ephemeral_fingerprint(
            name="Contoso Multi",
            slug="contoso-multi",
            category="SaaS",
            confidence="high",
            detections=[
                {"type": "txt", "pattern": "^contoso-multi="},
                {"type": "spf", "pattern": "include:contoso.example.com"},
            ],
        )
        data = result
        assert data["status"] == "ok"
        assert data["detections_accepted"] == 2

    @pytest.mark.asyncio
    async def test_oversized_detection_list_returns_error(self) -> None:
        """MCP injection rejects oversized detection arrays before validation."""
        from recon_tool.server import inject_ephemeral_fingerprint

        with pytest.raises(ToolError, match="detection cap"):
            await inject_ephemeral_fingerprint(
                name="Contoso Oversized",
                slug="contoso-oversized",
                category="SaaS",
                confidence="high",
                detections=[{"type": "invalid_type", "pattern": f"^contoso-{idx}="} for idx in range(21)],
            )
        assert get_ephemeral() == ()


# ── 18.3: list_ephemeral_fingerprints MCP tool ───────────────────────


class TestListEphemeralFingerprintsMCP:
    """Verify list_ephemeral_fingerprints MCP tool."""

    @pytest.mark.asyncio
    async def test_empty_list_returns_empty_array(self) -> None:
        """Empty list → empty JSON array."""
        from recon_tool.server import list_ephemeral_fingerprints

        result = await list_ephemeral_fingerprints()
        data = result
        assert data == []

    @pytest.mark.asyncio
    async def test_populated_list_returns_summaries(self) -> None:
        """Populated list → JSON array with correct summaries."""
        from recon_tool.server import list_ephemeral_fingerprints

        fp = _make_fingerprint(
            name="Northwind CRM",
            slug="northwind-crm",
            category="CRM",
            confidence="medium",
        )
        inject_ephemeral(fp)

        result = await list_ephemeral_fingerprints()
        data = result
        assert len(data) == 1
        assert data[0]["name"] == "Northwind CRM"
        assert data[0]["slug"] == "northwind-crm"
        assert data[0]["category"] == "CRM"
        assert data[0]["confidence"] == "medium"
        assert data[0]["detection_count"] == 1


# ── 18.4: clear_ephemeral_fingerprints MCP tool ─────────────────────


class TestClearEphemeralFingerprintsMCP:
    """Verify clear_ephemeral_fingerprints MCP tool."""

    @pytest.mark.asyncio
    async def test_clear_when_empty(self) -> None:
        """Clear when empty → {"status": "ok", "removed": 0}."""
        from recon_tool.server import clear_ephemeral_fingerprints

        result = await clear_ephemeral_fingerprints()
        data = result
        assert data["status"] == "ok"
        assert data["removed"] == 0

    @pytest.mark.asyncio
    async def test_clear_when_populated(self) -> None:
        """Clear when populated → correct count."""
        from recon_tool.server import clear_ephemeral_fingerprints

        inject_ephemeral(_make_fingerprint(slug="contoso-x"))
        inject_ephemeral(_make_fingerprint(slug="contoso-y"))

        result = await clear_ephemeral_fingerprints()
        data = result
        assert data["status"] == "ok"
        assert data["removed"] == 2

        # Verify actually cleared
        assert get_ephemeral() == ()


# ── 18.5: reevaluate_domain MCP tool ─────────────────────────────────


class TestReevaluateDomainMCP:
    """Verify reevaluate_domain MCP tool."""

    def test_annotation_marks_shared_cache_mutation_stateful(self) -> None:
        from recon_tool.server import mcp

        tool = mcp._tool_manager.get_tool("reevaluate_domain")
        assert tool is not None
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is False

    def setup_method(self) -> None:
        from recon_tool.server import _cache_clear  # pyright: ignore[reportPrivateUsage]

        _cache_clear()

    def teardown_method(self) -> None:
        from recon_tool.server import _cache_clear  # pyright: ignore[reportPrivateUsage]

        _cache_clear()

    @pytest.mark.asyncio
    async def test_uncached_domain_returns_error(self) -> None:
        """Uncached domain → error JSON 'No cached data...'."""
        from recon_tool.server import reevaluate_domain

        raw = "https://www.contoso.com/private/path?token=secret"
        with pytest.raises(ToolError) as exc_info:
            await reevaluate_domain(raw)

        message = str(exc_info.value)
        assert "No cached data for contoso.com" in message
        assert raw not in message
        assert "/private/path" not in message

    @pytest.mark.asyncio
    async def test_internal_error_and_log_use_only_normalized_domain(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from recon_tool.merger import merge_results
        from recon_tool.models import SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        source = SourceResult(source_name="DNS", display_name="Contoso Ltd")
        info = merge_results([source], "contoso.com")
        _cache_set("contoso.com", info, [source])

        def fail(_results: object, domain: str) -> None:
            assert domain == "contoso.com"
            raise RuntimeError("boom")

        monkeypatch.setattr("recon_tool.merger.merge_results", fail)
        raw = "https://www.contoso.com/private/path?token=secret"

        with caplog.at_level("ERROR", logger="recon"), pytest.raises(ToolError) as exc_info:
            await reevaluate_domain(raw)

        message = str(exc_info.value)
        assert "Error re-evaluating contoso.com" in message
        assert raw not in message
        assert "/private/path" not in message
        assert "merge failed for contoso.com" in caplog.text
        assert raw not in caplog.text
        assert "/private/path" not in caplog.text

    @pytest.mark.asyncio
    async def test_cached_domain_returns_updated_info(self) -> None:
        """Cached domain → updated TenantInfo JSON returned."""
        from recon_tool.models import EvidenceRecord, SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        # Build a minimal cached entry
        source = SourceResult(
            source_name="DNS",
            display_name="Contoso Ltd",
            default_domain="contoso.example.com",
            detected_services=("DMARC",),
            detected_slugs=("microsoft365",),
            evidence=(
                EvidenceRecord(
                    source_type="MX",
                    raw_value="contoso-example-com.mail.protection.outlook.com",
                    rule_name="Microsoft 365",
                    slug="microsoft365",
                ),
            ),
        )
        from recon_tool.merger import merge_results

        # Use an apex domain: reevaluate_domain validates input, which reduces a
        # sub-host to its registrable apex, so the cache key must be the apex too.
        info = merge_results([source], "contoso.com")
        _cache_set("contoso.com", info, [source])

        result = await reevaluate_domain("contoso.com")
        data = result
        # Should return valid tenant info JSON
        assert "display_name" in data
        assert data["queried_domain"] == "contoso.com"

    @pytest.mark.asyncio
    async def test_zero_network_calls(self) -> None:
        """reevaluate_domain makes zero network calls — uses cached data only."""
        from unittest.mock import AsyncMock, patch

        from recon_tool.models import SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        source = SourceResult(
            source_name="DNS",
            display_name="Fabrikam Inc",
            default_domain="fabrikam.example.com",
            detected_services=("DMARC",),
            detected_slugs=(),
            evidence=(),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "fabrikam.com")
        _cache_set("fabrikam.com", info, [source])

        # Patch resolve_tenant to verify it's never called
        with patch("recon_tool.server_app.resolve_tenant", new_callable=AsyncMock) as mock_resolve:
            result = await reevaluate_domain("fabrikam.com")
            mock_resolve.assert_not_called()

        data = result
        assert "error" not in data

    @pytest.mark.asyncio
    async def test_ephemeral_detections_in_reevaluated_results(self) -> None:
        """Ephemeral fingerprint detections appear in re-evaluated results."""
        from recon_tool.models import SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        # Cache a domain with a TXT record that matches our ephemeral fingerprint
        source = SourceResult(
            source_name="DNS",
            display_name="Northwind Traders",
            default_domain="northwind.example.com",
            detected_services=("DMARC",),
            detected_slugs=(),
            evidence=(),
            raw_dns_records=(("TXT", "northwind-verification=abc123"),),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "northwind.com")
        _cache_set("northwind.com", info, [source])

        fp = _make_fingerprint(slug="northwind-ephemeral", pattern="^northwind-verification=")
        inject_ephemeral(fp)

        result = await reevaluate_domain("northwind.com")
        assert "northwind-ephemeral" in result["slugs"]
        assert "Contoso Platform" in result["services"]
        assert {(record["source_type"], record["raw_value"], record["slug"]) for record in result["evidence"]} >= {
            ("TXT", "northwind-verification=abc123", "northwind-ephemeral")
        }

    @pytest.mark.asyncio
    async def test_reevaluation_skips_records_from_degraded_channel(self) -> None:
        """A retained value cannot become evidence when its channel was unavailable."""
        from recon_tool.models import SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        source = SourceResult(
            source_name="dns_records",
            display_name="Northwind Traders",
            default_domain="northwind.com",
            degraded_sources=("dns:apex_txt",),
            raw_dns_records=(("TXT", "northwind-verification=abc123"),),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "northwind.com")
        _cache_set("northwind.com", info, [source])
        inject_ephemeral(_make_fingerprint(slug="northwind-ephemeral", pattern="^northwind-verification="))

        result = await reevaluate_domain("northwind.com")

        assert "northwind-ephemeral" not in result["slugs"]
        assert all(record["slug"] != "northwind-ephemeral" for record in result["evidence"])

    @pytest.mark.asyncio
    async def test_reevaluation_does_not_duplicate_existing_match(self) -> None:
        """Replay is idempotent when collection already used the current fingerprint."""
        from recon_tool.models import EvidenceRecord, SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        fingerprint = _make_fingerprint(slug="northwind-ephemeral", pattern="^northwind-verification=")
        inject_ephemeral(fingerprint)
        occurrence = EvidenceRecord(
            source_type="TXT",
            raw_value="northwind-verification=abc123",
            rule_name=fingerprint.name,
            slug=fingerprint.slug,
        )
        source = SourceResult(
            source_name="dns_records",
            display_name="Northwind Traders",
            default_domain="northwind.com",
            detected_services=(fingerprint.name,),
            detected_slugs=(fingerprint.slug,),
            evidence=(occurrence,),
            raw_dns_records=(("TXT", occurrence.raw_value), ("TXT", occurrence.raw_value)),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "northwind.com")
        _cache_set("northwind.com", info, [source])

        first = await reevaluate_domain("northwind.com")
        second = await reevaluate_domain("northwind.com")

        for result in (first, second):
            matches = [record for record in result["evidence"] if record["slug"] == fingerprint.slug]
            assert len(matches) == 1

    @pytest.mark.asyncio
    async def test_reevaluation_rejects_uncached_owner_qualified_rule_type(self) -> None:
        """Re-evaluation reports rule types that the raw cache cannot represent."""
        from recon_tool.models import SourceResult
        from recon_tool.server import _cache_set, reevaluate_domain  # pyright: ignore[reportPrivateUsage]

        source = SourceResult(
            source_name="dns_records",
            display_name="Northwind Traders",
            default_domain="northwind.com",
            raw_dns_records=(("TXT", "northwind-verification=abc123"),),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "northwind.com")
        _cache_set("northwind.com", info, [source])
        inject_ephemeral(
            _make_fingerprint(
                slug="northwind-surface",
                det_type="cname_target",
                pattern=r"\.northwind\.example$",
            )
        )

        with pytest.raises(ToolError, match="cannot replay owner-qualified cname_target"):
            await reevaluate_domain("northwind.com")

    @pytest.mark.asyncio
    async def test_clear_removes_ephemeral_projection_collected_before_cache(self) -> None:
        """Clearing removes a session fingerprint that participated in lookup."""
        from recon_tool.models import EvidenceRecord, SourceResult
        from recon_tool.server import (  # pyright: ignore[reportPrivateUsage]
            _cache_get,
            _cache_set,
            clear_ephemeral_fingerprints,
        )

        fingerprint = _make_fingerprint(slug="northwind-ephemeral", pattern="^northwind-verification=")
        inject_ephemeral(fingerprint)
        occurrence = EvidenceRecord(
            source_type="TXT",
            raw_value="northwind-verification=abc123",
            rule_name=fingerprint.name,
            slug=fingerprint.slug,
        )
        source = SourceResult(
            source_name="dns_records",
            display_name="Northwind Traders",
            default_domain="northwind.com",
            detected_services=(fingerprint.name,),
            detected_slugs=(fingerprint.slug,),
            evidence=(occurrence,),
            raw_dns_records=(("TXT", occurrence.raw_value),),
        )
        from recon_tool.merger import merge_results

        info = merge_results([source], "northwind.com")
        _cache_set("northwind.com", info, [source])

        cleared = await clear_ephemeral_fingerprints()
        cached = _cache_get("northwind.com")

        assert cleared["removed"] == 1
        assert cached is not None
        cached_info, cached_results = cached
        assert fingerprint.slug not in cached_info.slugs
        assert fingerprint.name not in cached_info.services
        assert all(record.slug != fingerprint.slug for record in cached_info.evidence)
        assert cached_results[0].raw_dns_records == source.raw_dns_records


# ── 18.6: Ephemeral fingerprint integration with pipeline ────────────


class TestEphemeralPipelineIntegration:
    """Verify ephemeral detections extend matching without forging semantic claims."""

    def test_ephemeral_detections_in_detection_scoring(self) -> None:
        """Ephemeral detections participate in detection scoring via load_fingerprints."""
        from recon_tool.fingerprints import get_txt_patterns

        # Before injection, our custom pattern shouldn't exist
        patterns_before = get_txt_patterns()
        slugs_before = {p.slug for p in patterns_before}
        assert "contoso-scoring" not in slugs_before

        # Inject ephemeral fingerprint
        fp = _make_fingerprint(slug="contoso-scoring", pattern="^contoso-scoring=")
        inject_ephemeral(fp)

        # After injection, the pattern should be available
        patterns_after = get_txt_patterns()
        slugs_after = {p.slug for p in patterns_after}
        assert "contoso-scoring" in slugs_after

    def test_unique_txt_fingerprint_is_role_qualified_in_service_output(self) -> None:
        from recon_tool.formatter.classify import categorize_services
        from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo

        fingerprint = _make_fingerprint(
            name="Acme Platform",
            slug="acme-platform-observation",
            pattern="^acme-platform=",
        )
        inject_ephemeral(fingerprint)
        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain="example.com",
            queried_domain="example.com",
            confidence=ConfidenceLevel.MEDIUM,
            services=(fingerprint.name,),
            slugs=(fingerprint.slug,),
            evidence=(
                EvidenceRecord(
                    "TXT",
                    "acme-platform=token",
                    fingerprint.name,
                    fingerprint.slug,
                ),
            ),
        )

        labels = [label for category in categorize_services(info).values() for label in category]

        assert labels == ["Acme Platform (public TXT account indicator)"]

    def test_unique_ephemeral_slug_does_not_impersonate_signal_candidate(self) -> None:
        """A custom match cannot silently acquire a reserved signal meaning."""
        from recon_tool.models import SignalContext
        from recon_tool.signals import evaluate_signals

        fp = _make_fingerprint(
            name="Contoso AI",
            slug="contoso-ai-observation",
            pattern="^contoso-openai=",
        )
        inject_ephemeral(fp)

        ctx = SignalContext(detected_slugs=frozenset({fp.slug}))
        signals = evaluate_signals(ctx)
        assert all(signal.name != "AI Adoption" for signal in signals)

    def test_unique_ephemeral_slug_does_not_generate_signal_explanation(self) -> None:
        """Explanation output remains limited to actual declarative rule matches."""
        from recon_tool.explanation import explain_signals
        from recon_tool.models import SignalContext
        from recon_tool.signals import evaluate_signals, load_signals

        fp = _make_fingerprint(
            name="Contoso AI",
            slug="contoso-ai-observation",
            pattern="^contoso-openai=",
        )
        inject_ephemeral(fp)

        ctx = SignalContext(detected_slugs=frozenset({fp.slug}))
        signal_matches = evaluate_signals(ctx)
        all_signal_defs = load_signals()

        records = explain_signals(
            signal_matches=signal_matches,
            signals=all_signal_defs,
            context_detected_slugs=ctx.detected_slugs,
            context_metadata={},
            evidence=(),
            detection_scores=(),
        )
        assert all("AI Adoption" not in record.fired_rules for record in records)


# ── 18.7: Property 5 — Ephemeral Fingerprint Injection/Clear Round-Trip (PBT) ──
# Feature: intelligence-amplification, Property 5: Ephemeral Fingerprint Injection/Clear Round-Trip
# **Validates: Requirements 16.1, 16.2, 16.3, 16.5**

# Strategy: generate random valid Fingerprint instances
_VALID_DET_TYPES = ["txt", "spf", "mx", "ns", "cname", "caa", "srv", "dmarc_rua"]
_VALID_CONFIDENCES = ["high", "medium", "low"]
_SAFE_PATTERNS = [
    "^contoso-verify=",
    "include:contoso\\.example\\.com",
    "contoso\\.mail\\.protection\\.outlook\\.com",
    "ns1\\.contoso\\.example\\.com",
    "autodiscover\\.contoso\\.example\\.com",
    "contoso\\.example\\.com",
    "fabrikam\\.example\\.com",
    "northwind\\.example\\.com",
    "^northwind-site-verification=",
    "^fabrikam-domain-verify=",
]


@st.composite
def valid_fingerprint(draw: st.DrawFn) -> Fingerprint:
    """Generate a random valid Fingerprint instance."""
    suffix = draw(st.from_regex(r"[a-z0-9]{2,12}", fullmatch=True))
    slug = f"hypothesis-ephemeral-{suffix}"
    name = f"Hypothesis Ephemeral {suffix}"
    category = draw(st.sampled_from(["SaaS", "Security", "Email", "AI", "DevOps", "CRM"]))
    confidence = draw(st.sampled_from(_VALID_CONFIDENCES))

    # Generate 1-3 detection rules with safe patterns
    n_dets = draw(st.integers(min_value=1, max_value=3))
    dets: list[DetectionRule] = []
    for _ in range(n_dets):
        det_type = draw(st.sampled_from(_VALID_DET_TYPES))
        pattern = draw(st.sampled_from(_SAFE_PATTERNS))
        dets.append(DetectionRule(type=det_type, pattern=pattern))

    return Fingerprint(
        name=name,
        slug=slug,
        category=category,
        confidence=confidence,
        m365=False,
        detections=tuple(dets),
    )


class TestProperty5EphemeralRoundTrip:
    """Hypothesis PBT for Ephemeral Fingerprint Injection/Clear Round-Trip.

    For any valid Fingerprint, inject_ephemeral(fp) → get_ephemeral() contains fp
    → load_fingerprints() contains fp → clear_ephemeral() → get_ephemeral() empty
    → load_fingerprints() excludes fp.
    """

    @given(fp=valid_fingerprint())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_inject_get_load_clear_round_trip(self, fp: Fingerprint) -> None:
        """Full round-trip: inject → get contains → load contains → clear → get empty → load excludes."""
        # Clean state
        clear_ephemeral()

        # Step 1: inject
        inject_ephemeral(fp)

        # Step 2: get_ephemeral() contains fp
        ephemeral = get_ephemeral()
        assert fp in ephemeral, f"Expected {fp.slug} in get_ephemeral() after inject"

        # Step 3: load_fingerprints() includes fp
        all_fps = load_fingerprints()
        assert fp in all_fps, f"Expected {fp.slug} in load_fingerprints() after inject"

        # Step 4: clear_ephemeral() returns count >= 1
        count = clear_ephemeral()
        assert count >= 1, f"Expected clear_ephemeral() to return >= 1, got {count}"

        # Step 5: get_ephemeral() returns empty
        ephemeral_after = get_ephemeral()
        assert len(ephemeral_after) == 0, f"Expected empty get_ephemeral() after clear, got {len(ephemeral_after)}"

        # Step 6: load_fingerprints() excludes fp
        all_fps_after = load_fingerprints()
        assert fp not in all_fps_after, f"Expected {fp.slug} NOT in load_fingerprints() after clear"

    @given(
        fps=st.lists(
            valid_fingerprint(),
            min_size=1,
            max_size=5,
            unique_by=lambda fingerprint: fingerprint.slug,
        )
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_multiple_inject_clear_round_trip(self, fps: list[Fingerprint]) -> None:
        """Multiple injections → clear returns correct count → all removed."""
        clear_ephemeral()

        for fp in fps:
            inject_ephemeral(fp)

        # All should be present
        ephemeral = get_ephemeral()
        assert len(ephemeral) == len(fps)

        # Clear should return correct count
        count = clear_ephemeral()
        assert count == len(fps)

        # All should be gone
        assert get_ephemeral() == ()
