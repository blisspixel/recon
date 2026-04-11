"""Unit tests for resolver orchestration."""

from __future__ import annotations

import pytest

from recon_tool.models import (
    ReconLookupError,
    SourceResult,
)
from recon_tool.resolver import SourcePool, default_pool, resolve_tenant

# ---------------------------------------------------------------------------
# Helpers: fake sources
# ---------------------------------------------------------------------------

class FakeSource:
    """A configurable fake LookupSource for testing."""

    def __init__(self, name: str, result: SourceResult) -> None:
        self._name = name
        self._result = result
        self.called = False
        self.call_kwargs: dict = {}

    @property
    def name(self) -> str:
        return self._name

    async def lookup(self, domain: str, **kwargs) -> SourceResult:
        self.called = True
        self.call_kwargs = kwargs
        return self._result


class ExplodingSource:
    """A source that raises an unexpected exception."""

    def __init__(self, name: str = "exploding") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    async def lookup(self, domain: str, **kwargs) -> SourceResult:
        raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# SourcePool tests
# ---------------------------------------------------------------------------

class TestSourcePool:
    def test_empty_pool(self) -> None:
        pool = SourcePool()
        assert len(pool) == 0
        assert list(pool) == []

    def test_init_with_sources(self) -> None:
        s1 = FakeSource("a", SourceResult(source_name="a"))
        s2 = FakeSource("b", SourceResult(source_name="b"))
        pool = SourcePool([s1, s2])
        assert len(pool) == 2
        assert list(pool) == [s1, s2]

    def test_register(self) -> None:
        pool = SourcePool()
        s = FakeSource("x", SourceResult(source_name="x"))
        pool.register(s)
        assert len(pool) == 1
        assert list(pool)[0] is s

    def test_iteration_order(self) -> None:
        sources = [
            FakeSource(f"s{i}", SourceResult(source_name=f"s{i}"))
            for i in range(5)
        ]
        pool = SourcePool(sources)
        assert list(pool) == sources


# ---------------------------------------------------------------------------
# default_pool tests
# ---------------------------------------------------------------------------

class TestDefaultPool:
    def test_default_pool_has_five_sources(self) -> None:
        pool = default_pool()
        assert len(pool) == 5

    def test_default_pool_order(self) -> None:
        pool = default_pool()
        names = [s.name for s in pool]
        assert names == [
            "oidc_discovery", "user_realm", "google_workspace",
            "google_identity", "dns_records",
        ]


# ---------------------------------------------------------------------------
# resolve_tenant tests
# ---------------------------------------------------------------------------

class TestResolveTenant:
    @pytest.mark.asyncio
    async def test_empty_pool_raises_lookup_error(self) -> None:
        pool = SourcePool()
        with pytest.raises(ReconLookupError) as exc_info:
            await resolve_tenant("example.com", pool=pool)
        assert exc_info.value.error_type == "not_found"
        assert "No lookup sources configured" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_single_successful_source(self) -> None:
        result = SourceResult(
            source_name="test",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        pool = SourcePool([FakeSource("test", result)])
        info, results = await resolve_tenant("example.com", pool=pool)

        assert info.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert info.queried_domain == "example.com"
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_first_fails_second_succeeds(self) -> None:
        fail = SourceResult(source_name="s1", error="HTTP 404")
        ok = SourceResult(
            source_name="s2",
            tenant_id="11111111-2222-3333-4444-555555555555",
            display_name="Contoso",
        )
        pool = SourcePool([FakeSource("s1", fail), FakeSource("s2", ok)])
        info, results = await resolve_tenant("contoso.com", pool=pool)

        assert info.tenant_id == "11111111-2222-3333-4444-555555555555"
        assert info.display_name == "Contoso"
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_all_sources_fail_raises_lookup_error(self) -> None:
        fail1 = SourceResult(source_name="s1", error="fail")
        fail2 = SourceResult(source_name="s2", error="fail")
        pool = SourcePool([FakeSource("s1", fail1), FakeSource("s2", fail2)])

        with pytest.raises(ReconLookupError) as exc_info:
            await resolve_tenant("bad.com", pool=pool)
        assert exc_info.value.error_type == "all_sources_failed"

    @pytest.mark.asyncio
    async def test_exploding_source_does_not_abort(self) -> None:
        ok = SourceResult(
            source_name="good",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        pool = SourcePool([ExplodingSource("bad"), FakeSource("good", ok)])
        info, results = await resolve_tenant("example.com", pool=pool)

        assert info.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert len(results) == 2
        assert results[0].error is not None  # exploding source captured

    @pytest.mark.asyncio
    async def test_tenant_id_not_forwarded_in_parallel(self) -> None:
        """In parallel mode, sources don't receive tenant_id from prior sources."""
        first = SourceResult(
            source_name="oidc",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        second_result = SourceResult(
            source_name="metadata",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            region="NA",
        )
        s1 = FakeSource("oidc", first)
        s2 = FakeSource("metadata", second_result)
        pool = SourcePool([s1, s2])

        info, results = await resolve_tenant("example.com", pool=pool)

        # In parallel mode, tenant_id is NOT forwarded between sources
        assert "tenant_id" not in s2.call_kwargs
        assert info.region == "NA"

    @pytest.mark.asyncio
    async def test_client_passed_to_sources(self) -> None:
        result = SourceResult(
            source_name="test",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        s = FakeSource("test", result)
        pool = SourcePool([s])

        sentinel = object()  # stand-in for an httpx.AsyncClient
        await resolve_tenant("example.com", pool=pool, client=sentinel)  # type: ignore[arg-type]

        assert s.call_kwargs.get("client") is sentinel

    @pytest.mark.asyncio
    async def test_returns_all_results_including_failures(self) -> None:
        r1 = SourceResult(source_name="s1", error="timeout")
        r2 = SourceResult(
            source_name="s2",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        r3 = SourceResult(source_name="s3", m365_detected=True)
        pool = SourcePool([
            FakeSource("s1", r1),
            FakeSource("s2", r2),
            FakeSource("s3", r3),
        ])

        info, results = await resolve_tenant("example.com", pool=pool)
        assert len(results) == 3
        assert results[0].error == "timeout"
        assert results[1].tenant_id is not None
        assert results[2].m365_detected is True


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis) for resolver orchestration
# ---------------------------------------------------------------------------

from hypothesis import given, settings
from hypothesis import strategies as st


class TestPropertyPrimaryFailureFallback:
    """Property 7: Primary source failure triggers fallback.

    **Validates: Requirements 2.4, 6.2**
    """

    @pytest.mark.asyncio
    @settings(max_examples=100)
    @given(status_code=st.integers(min_value=400, max_value=599))
    async def test_primary_failure_triggers_fallback(self, status_code: int) -> None:
        """For any HTTP status code 400-599 from the primary source,
        the resolver proceeds to fallback sources and uses their data."""
        primary_fail = SourceResult(
            source_name="primary",
            error=f"HTTP {status_code}",
        )
        fallback_ok = SourceResult(
            source_name="fallback",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            display_name="Fallback Corp",
        )
        s1 = FakeSource("primary", primary_fail)
        s2 = FakeSource("fallback", fallback_ok)
        pool = SourcePool([s1, s2])

        info, results = await resolve_tenant("example.com", pool=pool)

        assert s2.called, "Fallback source must be called when primary fails"
        assert info.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert len(results) == 2
        assert results[0].error is not None


class TestPropertyUnparseableOIDCFallback:
    """Property 8: Unparseable OIDC response triggers fallback.

    **Validates: Requirements 2.5, 6.2**
    """

    @pytest.mark.asyncio
    @settings(max_examples=100)
    @given(
        bad_json=st.fixed_dictionaries(
            {},
            optional={
                "issuer": st.text(min_size=0, max_size=30),
                "token_endpoint": st.text(min_size=0, max_size=30),
                "random_key": st.text(min_size=0, max_size=30),
            },
        ),
    )
    async def test_unparseable_oidc_triggers_fallback(self, bad_json: dict) -> None:
        """For any JSON dict without a valid authorization_endpoint,
        the OIDC source returns a failed SourceResult and the resolver
        proceeds to fallback sources."""
        from recon_tool.sources.oidc import parse_tenant_info_from_oidc

        # Confirm the JSON is indeed unparseable by the OIDC parser
        try:
            parse_tenant_info_from_oidc(bad_json)
            # If it somehow parses, skip this example
            return
        except ReconLookupError:
            pass  # Expected — this JSON is unparseable

        # Simulate the OIDC source returning a failed result for this bad JSON
        oidc_fail = SourceResult(
            source_name="oidc_discovery",
            error="Could not extract a valid tenant ID from OIDC discovery response",
        )
        fallback_ok = SourceResult(
            source_name="fallback",
            tenant_id="11111111-2222-3333-4444-555555555555",
        )
        s1 = FakeSource("oidc_discovery", oidc_fail)
        s2 = FakeSource("fallback", fallback_ok)
        pool = SourcePool([s1, s2])

        info, results = await resolve_tenant("example.com", pool=pool)

        assert s2.called, "Fallback source must be called when OIDC is unparseable"
        assert info.tenant_id == "11111111-2222-3333-4444-555555555555"
        assert results[0].error is not None


class TestPropertyAllSourcesExhausted:
    """Property 11: All sources exhausted produces structured error.

    **Validates: Requirements 6.3**
    """

    @pytest.mark.asyncio
    @settings(max_examples=100)
    @given(num_sources=st.integers(min_value=1, max_value=5))
    async def test_all_sources_exhausted_error(self, num_sources: int) -> None:
        """For any number of failing sources (1-5), the resolver raises
        a ReconLookupError with error_type == 'all_sources_failed'."""
        sources = []
        for i in range(num_sources):
            fail_result = SourceResult(
                source_name=f"source_{i}",
                error=f"Error from source {i}",
            )
            sources.append(FakeSource(f"source_{i}", fail_result))

        pool = SourcePool(sources)

        with pytest.raises(ReconLookupError) as exc_info:
            await resolve_tenant("bad.com", pool=pool)

        assert exc_info.value.error_type == "all_sources_failed"


class TestPropertySourceFailureIsolation:
    """Property 16: Individual source failure does not abort resolution.

    **Validates: Requirements 6.6**
    """

    @pytest.mark.asyncio
    @settings(max_examples=100)
    @given(
        n=st.integers(min_value=2, max_value=6),
        data=st.data(),
    )
    async def test_source_failure_does_not_abort(self, n: int, data: st.DataObject) -> None:
        """For any SourcePool of N sources where source K (K < N) raises
        an exception, the resolver continues to query sources K+1 through N."""
        k = data.draw(st.integers(min_value=0, max_value=n - 2), label="failing_index")

        sources = []
        for i in range(n):
            if i == k:
                sources.append(ExplodingSource(name=f"source_{i}"))
            else:
                result = SourceResult(
                    source_name=f"source_{i}",
                    tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                )
                sources.append(FakeSource(f"source_{i}", result))

        pool = SourcePool(sources)
        info, results = await resolve_tenant("example.com", pool=pool)

        # All N sources should have been queried (N results returned)
        assert len(results) == n

        # The exploding source should have an error captured
        assert results[k].error is not None

        # Sources after the exploding one should have been called
        for i in range(k + 1, n):
            src = sources[i]
            if isinstance(src, FakeSource):
                assert src.called, f"Source {i} after failing source {k} must be called"
