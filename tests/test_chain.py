"""Tests for the chain resolver."""
import pytest

from recon_tool.chain import MAX_CHAIN_DEPTH, MAX_CHAIN_DOMAINS, chain_resolve
from recon_tool.models import ChainReport, ConfidenceLevel, TenantInfo


def _make_info(domain: str, related: tuple[str, ...] = ()) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        services=("svc",),
        related_domains=related,
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
                return _make_info(domain, related=("related.com",)), []
            return _make_info(domain), []
        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("example.com", depth=1)
        domains = [r.domain for r in report.results]
        assert "example.com" in domains
        assert "related.com" in domains

    @pytest.mark.asyncio
    async def test_no_duplicate_resolution(self, monkeypatch):
        call_count = {}
        async def mock_resolve(domain, **kwargs):
            call_count[domain] = call_count.get(domain, 0) + 1
            # Create a cycle: a -> b -> a
            if domain == "a.com":
                return _make_info(domain, related=("b.com",)), []
            return _make_info(domain, related=("a.com",)), []
        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("a.com", depth=2)
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
    async def test_domain_cap(self, monkeypatch):
        counter = [0]
        async def mock_resolve(domain, **kwargs):
            counter[0] += 1
            # Each domain discovers 5 new related domains
            related = tuple(f"d{counter[0]}-{i}.com" for i in range(5))
            return _make_info(domain, related=related), []
        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("root.com", depth=3)
        assert len(report.results) <= MAX_CHAIN_DOMAINS
        if len(report.results) == MAX_CHAIN_DOMAINS:
            assert report.truncated

    @pytest.mark.asyncio
    async def test_error_skips_domain(self, monkeypatch):
        from recon_tool.models import ReconLookupError
        async def mock_resolve(domain, **kwargs):
            if domain == "bad.com":
                raise ReconLookupError(domain=domain, message="fail", error_type="test")
            return _make_info(domain, related=("bad.com",)), []
        monkeypatch.setattr("recon_tool.chain.resolve_tenant", mock_resolve)

        report = await chain_resolve("good.com", depth=1)
        domains = [r.domain for r in report.results]
        assert "good.com" in domains
        assert "bad.com" not in domains
