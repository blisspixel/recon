"""Integration tests that hit real network endpoints.

These are skipped by default. Run with:
    pytest tests/test_integration.py -m integration

Requires network access. Uses RFC 2606 reserved domains (example.com,
example.org) and the reserved .invalid namespace to avoid referencing any real
organization.
"""

from __future__ import annotations

import asyncio

import pytest

from recon_tool.http import http_client
from recon_tool.models import SourceResult, TenantInfo
from recon_tool.sources.userrealm import _TENANT_NAMESPACE_TYPES, USERREALM_URL

pytestmark = pytest.mark.integration

_CT_HEALTHY_OUTCOMES = {"cache_hit", "live_success"}
_EXPECTED_RESERVED_DNS_SERVICES = {"DMARC", "SPF: strict (-all)"}
_IDENTITY_ATTEMPTS = 3
_IDENTITY_BACKOFF_SECONDS = 2.0


@pytest.fixture(autouse=True)
def _mock_crtsh() -> None:
    """Override the default test-suite CT patch so this live suite exercises CT."""


def _source(results: list[SourceResult], name: str) -> SourceResult:
    matches = [result for result in results if result.source_name == name]
    assert len(matches) == 1, f"expected exactly one {name} source result"
    return matches[0]


async def _observed_realm_namespace(domain: str) -> str:
    """Read ``NameSpaceType`` straight from the provider, bypassing recon's parser.

    This is the drift gate's ground truth. Asserting the raw response shape
    here is what catches a GetUserRealm contract change: if Microsoft renames
    the field or stops returning a JSON object, this fails loudly instead of
    letting ``UserRealmSource`` silently parse nothing and still look healthy.
    """

    async with http_client(None) as client:
        response = await client.get(USERREALM_URL, params={"login": f"user@{domain}", "json": "1"})

    assert response.status_code == 200, f"GetUserRealm answered {response.status_code} for {domain}"
    payload = response.json()
    assert isinstance(payload, dict), "GetUserRealm no longer returns a JSON object"
    assert "NameSpaceType" in payload, "GetUserRealm no longer reports NameSpaceType"
    namespace = payload["NameSpaceType"]
    assert isinstance(namespace, str), "GetUserRealm NameSpaceType is no longer a string"
    return namespace


async def _resolve_past_transient_identity_loss(domain: str) -> tuple[TenantInfo, list[SourceResult]]:
    """Resolve ``domain``, retrying only while the identity source is transport-unavailable.

    ``source_unavailable`` on ``user_realm`` is a transport outcome, not a
    provider answer: one rate-limited or dropped request from a shared CI
    egress address sets it while GetUserRealm itself keeps answering. This gate
    runs weekly and had no retry, so a single blip left ``main`` red until a
    human re-ran the job. Retrying a bounded number of times preserves the
    drift signal, because a source that stays unavailable across every attempt
    still fails, and ``_observed_realm_namespace`` still reads the provider
    directly so recon disagreeing with a healthy endpoint is what gets caught.
    """
    from recon_tool.resolver import resolve_tenant

    info, results = await resolve_tenant(domain)
    assert info is not None
    for _retry in range(_IDENTITY_ATTEMPTS - 1):
        if not _source(results, "user_realm").source_unavailable:
            break
        await asyncio.sleep(_IDENTITY_BACKOFF_SECONDS)
        info, results = await resolve_tenant(domain)
        assert info is not None
    return info, results


def _assert_reserved_domain_provider_health(
    info: TenantInfo, results: list[SourceResult], realm_namespace: str
) -> None:
    """Assert source-level health without asserting ownership or tenant facts."""

    dns = _source(results, "dns_records")
    assert dns.error is None
    assert "dns_records" in info.sources
    assert set(dns.detected_services) >= _EXPECTED_RESERVED_DNS_SERVICES
    assert dns.ct_attempt_outcome in _CT_HEALTHY_OUTCOMES

    user_realm = _source(results, "user_realm")
    # Whether a reserved domain carries a third-party M365 tenant is registration
    # state nobody here controls, and it changes without notice, so tenant
    # presence is never asserted. Identity drift instead shows up as a transport
    # failure or as recon disagreeing with the raw provider answer.
    assert user_realm.source_unavailable is False, (
        f"user_realm stayed transport-unavailable across {_IDENTITY_ATTEMPTS} attempts "
        f"while GetUserRealm answered {realm_namespace!r} directly"
    )
    assert "identity:user_realm" not in user_realm.degraded_sources

    if realm_namespace in _TENANT_NAMESPACE_TYPES:
        assert user_realm.auth_type == realm_namespace
        assert "user_realm" in info.sources
    else:
        # A stable negative. Per ``SourceResult.source_unavailable``, that case
        # carries an ``error`` string with the flag false, so absence of a
        # tenant must not be read as an unhealthy source.
        assert user_realm.auth_type is None


@pytest.mark.asyncio
async def test_resolve_reserved_domain_pipeline_runs():
    """Smoke test: resolver completes source-level checks for a reserved domain.

    example.com is an IANA-reserved domain. This test verifies the full
    pipeline runs without crashing and returns healthy DNS, CT, and identity
    source signals; it does not assert tenant presence or absence because
    third parties have been observed registering M365 tenants against
    example.com, so the state of that specific field is outside our control.
    """
    info, results = await _resolve_past_transient_identity_loss("example.com")
    _assert_reserved_domain_provider_health(info, results, await _observed_realm_namespace("example.com"))


@pytest.mark.asyncio
async def test_resolve_second_reserved_domain():
    """Smoke test: resolver handles a second reserved domain source path.

    example.org is a second IANA-reserved domain. Running a second
    independent lookup catches per-run state leaks in caches, pools,
    or session handlers, and keeps the provider drift check from relying
    on one fixture.
    """
    info, results = await _resolve_past_transient_identity_loss("example.org")
    _assert_reserved_domain_provider_health(info, results, await _observed_realm_namespace("example.org"))


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
