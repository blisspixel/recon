"""Tests for the chain resolver."""

import pytest

from recon_tool.chain import MAX_CHAIN_DEPTH, MAX_CHAIN_DOMAINS, _correlate_site_verification, chain_resolve
from recon_tool.models import ChainReport, ChainResult, ConfidenceLevel, TenantInfo


def _make_info(
    domain: str,
    related: tuple[str, ...] = (),
    insights: tuple[str, ...] = (),
    tokens: tuple[str, ...] = (),
) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        services=("svc",),
        related_domains=related,
        insights=insights,
        site_verification_tokens=tokens,
    )


class TestChainResolve:
    @pytest.mark.asyncio
    async def test_single_domain_no_related(self, monkeypatch):
        async def mock_resolve(domain, **kwargs):
            return _make_info(domain), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("example.com", depth=1)
        assert len(report.results) == 1
        assert report.results[0].domain == "example.com"
        assert report.results[0].chain_depth == 0
        assert not report.truncated

    @pytest.mark.asyncio
    async def test_follows_related_domains(self, monkeypatch):
        async def mock_resolve(domain, **kwargs):
            if domain == "example.com":
                return _make_info(domain, related=("related.invalid",)), []
            return _make_info(domain), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("example.com", depth=1)
        domains = [r.domain for r in report.results]
        assert "example.com" in domains
        assert "related.invalid" in domains

    @pytest.mark.asyncio
    async def test_no_duplicate_resolution(self, monkeypatch):
        call_count = {}

        async def mock_resolve(domain, **kwargs):
            call_count[domain] = call_count.get(domain, 0) + 1
            # Create a cycle: a -> b -> a
            if domain == "a.invalid":
                return _make_info(domain, related=("b.invalid",)), []
            return _make_info(domain, related=("a.invalid",)), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        await chain_resolve("a.invalid", depth=2)
        # Each domain should be resolved exactly once
        for count in call_count.values():
            assert count == 1

    @pytest.mark.asyncio
    async def test_depth_clamped(self, monkeypatch):
        async def mock_resolve(domain, **kwargs):
            return _make_info(domain), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        # Depth > MAX should be clamped
        report = await chain_resolve("example.com", depth=10)
        assert isinstance(report, ChainReport)

    @pytest.mark.asyncio
    async def test_oversized_depth_is_actually_bounded_by_max_chain_depth(self, monkeypatch):
        """Prevents an out-of-range depth running an unbounded recursive crawl.

        ``test_depth_clamped`` names the rule but its mock returns no related
        domains, so the walk stops at the seed whether or not the clamp exists
        and the assertion holds vacuously. This drives a chain that keeps
        discovering new domains, so an unclamped depth is observable as extra
        BFS levels and as an aggregate timeout scaled off the raw value.
        """
        counter = [0]

        async def mock_resolve(domain, **kwargs):
            counter[0] += 1
            return _make_info(domain, related=(f"link{counter[0]}.invalid",)), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("root.invalid", depth=10_000)

        assert report.max_depth_reached <= MAX_CHAIN_DEPTH
        assert all(result.chain_depth <= MAX_CHAIN_DEPTH for result in report.results)
        assert len(report.results) <= MAX_CHAIN_DEPTH + 1

    @pytest.mark.asyncio
    async def test_domain_cap(self, monkeypatch):
        counter = [0]

        async def mock_resolve(domain, **kwargs):
            counter[0] += 1
            # Each domain discovers 5 new related domains
            related = tuple(f"d{counter[0]}-{i}.invalid" for i in range(5))
            return _make_info(domain, related=related), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("root.invalid", depth=3)
        assert len(report.results) <= MAX_CHAIN_DOMAINS
        if len(report.results) == MAX_CHAIN_DOMAINS:
            assert report.truncated

    @pytest.mark.asyncio
    async def test_error_skips_domain(self, monkeypatch):
        from recon_tool.models import ReconLookupError

        async def mock_resolve(domain, **kwargs):
            if domain == "bad.invalid":
                raise ReconLookupError(domain=domain, message="fail", error_type="test")
            return _make_info(domain, related=("bad.invalid",)), []

        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("good.invalid", depth=1)
        domains = [r.domain for r in report.results]
        assert "good.invalid" in domains
        assert "bad.invalid" not in domains


class TestSiteVerificationCorrelation:
    def test_correlation_preserves_existing_insight_order(self):
        """merger.py inserts conflict warnings at index 0 on purpose.

        Regression coverage: the correlation pass re-sorted the whole insight
        list, alphabetizing the deliberately-first conflict warning away from
        the front on any domain sharing a verification token.
        """
        existing = (
            "Conflicting tenant IDs detected: a, b",
            "Zebra note",
            "Alpha note",
        )
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid", insights=existing, tokens=("token-1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid", tokens=("token-1",)),
                chain_depth=1,
            ),
        ]

        updated = _correlate_site_verification(results)
        merged = updated[0].info.insights

        assert merged[:3] == existing
        assert merged[3:] == ("Shares google-site-verification token with b.invalid",)

    def test_correlation_does_not_duplicate_existing_insight(self):
        insight = "Shares google-site-verification token with b.invalid"
        results = [
            ChainResult(
                domain="a.invalid",
                info=_make_info("a.invalid", insights=(insight,), tokens=("token-1",)),
                chain_depth=0,
            ),
            ChainResult(
                domain="b.invalid",
                info=_make_info("b.invalid", tokens=("token-1",)),
                chain_depth=1,
            ),
        ]

        updated = _correlate_site_verification(results)

        assert updated[0].info.insights == (insight,)
