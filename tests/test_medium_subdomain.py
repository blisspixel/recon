"""Tests for medium-tier subdomain enrichment (v0.10.2).

medium_subdomain_lookup adds MX + DKIM probing on top of the lightweight
CNAME + TXT tier for the handful of subdomains most likely to publish
their own verification records (auth, sso, login, idp, api, mail).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from recon_tool.models import SourceResult


@pytest.mark.asyncio
async def test_medium_subdomain_lookup_returns_source_result() -> None:
    """Basic shape: medium_subdomain_lookup returns a SourceResult."""
    from recon_tool.sources.dns import medium_subdomain_lookup

    with (
        patch("recon_tool.sources.dns._detect_cname_infra", new=AsyncMock()),
        patch("recon_tool.sources.dns._detect_txt", new=AsyncMock()),
        patch("recon_tool.sources.dns._detect_mx", new=AsyncMock()),
        patch("recon_tool.sources.dns._detect_dkim", new=AsyncMock()),
    ):
        result = await medium_subdomain_lookup("auth.example.com")

    assert isinstance(result, SourceResult)
    assert result.source_name == "dns_records"
    assert result.error is None


@pytest.mark.asyncio
async def test_medium_subdomain_lookup_runs_all_four_detectors() -> None:
    """All four detector functions must run (CNAME, TXT, MX, DKIM)."""
    from recon_tool.sources.dns import medium_subdomain_lookup

    calls: dict[str, int] = {"cname": 0, "txt": 0, "mx": 0, "dkim": 0}

    async def _cname(ctx, d):  # noqa: ANN001
        calls["cname"] += 1

    async def _txt(ctx, d):  # noqa: ANN001
        calls["txt"] += 1

    async def _mx(ctx, d):  # noqa: ANN001
        calls["mx"] += 1

    async def _dkim(ctx, d):  # noqa: ANN001
        calls["dkim"] += 1

    with (
        patch("recon_tool.sources.dns._detect_cname_infra", side_effect=_cname),
        patch("recon_tool.sources.dns._detect_txt", side_effect=_txt),
        patch("recon_tool.sources.dns._detect_mx", side_effect=_mx),
        patch("recon_tool.sources.dns._detect_dkim", side_effect=_dkim),
    ):
        await medium_subdomain_lookup("sso.example.com")

    assert calls == {"cname": 1, "txt": 1, "mx": 1, "dkim": 1}


@pytest.mark.asyncio
async def test_medium_subdomain_lookup_handles_exception() -> None:
    """Detector exceptions should surface as SourceResult.error, not crash."""
    from recon_tool.sources.dns import medium_subdomain_lookup

    async def _boom(ctx, d):  # noqa: ANN001
        raise RuntimeError("DNS explosion")

    with (
        patch("recon_tool.sources.dns._detect_cname_infra", side_effect=_boom),
        patch("recon_tool.sources.dns._detect_txt", new=AsyncMock()),
        patch("recon_tool.sources.dns._detect_mx", new=AsyncMock()),
        patch("recon_tool.sources.dns._detect_dkim", new=AsyncMock()),
    ):
        result = await medium_subdomain_lookup("api.example.com")

    assert result.error is not None
    assert "DNS explosion" in result.error
