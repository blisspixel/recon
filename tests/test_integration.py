"""Integration tests that hit real endpoints.

These are skipped by default. Run with:
    pytest tests/test_integration.py -m integration

Requires network access.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_resolve_real_domain():
    """Smoke test: resolve a well-known domain end-to-end."""
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("microsoft.com")
    assert info.tenant_id is not None
    assert info.display_name
    assert len(info.services) > 0
    assert len(results) > 0


@pytest.mark.asyncio
async def test_resolve_non_m365_domain():
    """Smoke test: resolve a domain with no M365 tenant."""
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("google.com")
    # google.com has no M365 tenant but should have DNS services
    assert info.tenant_id is None
    assert len(info.services) > 0


@pytest.mark.asyncio
async def test_resolve_nonexistent_domain():
    """Smoke test: a domain with no data should raise."""
    from recon_tool.models import ReconLookupError
    from recon_tool.resolver import resolve_tenant

    with pytest.raises(ReconLookupError):
        await resolve_tenant("thisdomain-definitely-does-not-exist-12345.com")
