"""Integration tests that hit real network endpoints.

These are skipped by default. Run with:
    pytest tests/test_integration.py -m integration

Requires network access. Uses only RFC-2606 reserved domains (example.com,
example.org) and a guaranteed-nonexistent domain to avoid referencing any
real organization.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_resolve_reserved_domain_pipeline_runs():
    """Smoke test: resolver completes end-to-end against a reserved domain.

    example.com is an IANA-reserved domain. This test verifies the full
    pipeline runs without crashing and returns source results; it does
    not assert tenant presence or absence — third parties have been
    observed registering M365 tenants against example.com, so the
    state of that specific field is outside our control.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("example.com")
    assert info is not None
    assert len(results) > 0


@pytest.mark.asyncio
async def test_resolve_second_reserved_domain():
    """Smoke test: resolver handles a second reserved domain.

    example.org is a second IANA-reserved domain. Running a second
    independent lookup catches per-run state leaks in caches, pools,
    or session handlers.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("example.org")
    assert info is not None
    assert len(results) > 0


@pytest.mark.asyncio
async def test_resolve_nonexistent_domain_returns_sparse_result():
    """Smoke test: a nonexistent domain returns a sparse result, not an error.

    v1.0.2 changed this behavior: when every source errors out and no
    tenant can be resolved, the resolver returns a TenantInfo with
    tenant_id=None rather than raising ReconLookupError. This keeps
    batch mode non-fatal on dead domains.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("thisdomain-definitely-does-not-exist-12345.com")
    assert info is not None
    assert info.tenant_id is None
    assert len(results) > 0
