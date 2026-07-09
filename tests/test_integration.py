"""Integration tests that hit real network endpoints.

These are skipped by default. Run with:
    pytest tests/test_integration.py -m integration

Requires network access. Uses RFC 2606 reserved domains (example.com,
example.org) and the reserved .invalid namespace to avoid referencing any real
organization.
"""

from __future__ import annotations

import pytest

from recon_tool.models import SourceResult, TenantInfo

pytestmark = pytest.mark.integration

_CT_HEALTHY_OUTCOMES = {"cache_hit", "live_success"}
_EXPECTED_RESERVED_DNS_SERVICES = {"DMARC", "SPF: strict (-all)"}


@pytest.fixture(autouse=True)
def _mock_crtsh() -> None:
    """Override the default test-suite CT patch so this live suite exercises CT."""


def _source(results: list[SourceResult], name: str) -> SourceResult:
    matches = [result for result in results if result.source_name == name]
    assert len(matches) == 1, f"expected exactly one {name} source result"
    return matches[0]


def _assert_reserved_domain_provider_health(info: TenantInfo, results: list[SourceResult]) -> None:
    """Assert source-level health without asserting ownership or tenant facts."""

    dns = _source(results, "dns_records")
    assert dns.error is None
    assert "dns_records" in info.sources
    assert set(dns.detected_services) >= _EXPECTED_RESERVED_DNS_SERVICES
    assert dns.ct_attempt_outcome in _CT_HEALTHY_OUTCOMES

    user_realm = _source(results, "user_realm")
    assert user_realm.error is None
    assert "user_realm" in info.sources


@pytest.mark.asyncio
async def test_resolve_reserved_domain_pipeline_runs():
    """Smoke test: resolver completes source-level checks for a reserved domain.

    example.com is an IANA-reserved domain. This test verifies the full
    pipeline runs without crashing and returns healthy DNS, CT, and identity
    source signals; it does not assert tenant presence or absence because
    third parties have been observed registering M365 tenants against
    example.com, so the state of that specific field is outside our control.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("example.com")
    assert info is not None
    _assert_reserved_domain_provider_health(info, results)


@pytest.mark.asyncio
async def test_resolve_second_reserved_domain():
    """Smoke test: resolver handles a second reserved domain source path.

    example.org is a second IANA-reserved domain. Running a second
    independent lookup catches per-run state leaks in caches, pools,
    or session handlers, and keeps the provider drift check from relying
    on one fixture.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("example.org")
    assert info is not None
    _assert_reserved_domain_provider_health(info, results)


@pytest.mark.asyncio
async def test_resolve_nonexistent_domain_returns_sparse_result():
    """Smoke test: a reserved invalid domain returns a sparse result, not an error.

    v1.0.2 changed this behavior: when every source errors out and no
    tenant can be resolved, the resolver returns a TenantInfo with
    tenant_id=None rather than raising ReconLookupError. This keeps
    batch mode non-fatal on dead domains.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant("this-domain-does-not-exist-12345.invalid")
    assert info is not None
    assert info.tenant_id is None
    assert info.services == ()
    assert info.slugs == ()
    assert _source(results, "dns_records").detected_services == ()
