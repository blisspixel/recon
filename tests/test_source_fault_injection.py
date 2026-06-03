"""Source-boundary fault injection (Track B, B3).

The per-source tests (e.g. `test_sources/test_oidc.py`) already prove each
source turns a malformed / truncated / timed-out / non-object provider payload
into a clean `SourceResult` with an ``error`` rather than raising. This file
covers the *aggregate* contract: arbitrary combinations of source faults
flowing through `_safe_lookup`, `merge_results`, and `resolve_tenant`, asserting

  * exception hygiene — a source that raises never propagates; it becomes an
    error `SourceResult`;
  * degraded surfacing — a source reporting degradation shows up in the merged
    `TenantInfo.degraded_sources`;
  * hedged output — a result built off degraded / partial sources is never
    presented as HIGH confidence;
  * all-fail — when no source yields a tenant, `resolve_tenant` raises
    `ReconLookupError(all_sources_failed)`;
  * timeout — a hanging source trips the aggregate timeout cleanly;
  * partial failure — a good source still produces a tenant alongside crashing
    and erroring siblings.

A `_FaultySource` injects each fault mode deterministically with no network. One
test pairs a real `OIDCSource` (fed a truncated body via `httpx.MockTransport`)
with a good faulty source to show a malformed provider payload is isolated end
to end through `resolve_tenant`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from recon_tool.models import ConfidenceLevel, EvidenceRecord, ReconLookupError, SourceResult
from recon_tool.resolver import SourcePool, _safe_lookup, resolve_tenant
from recon_tool.sources.oidc import OIDCSource

_TENANT_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


class _FaultySource:
    """A LookupSource whose `lookup` exhibits a chosen fault mode."""

    def __init__(
        self,
        name: str,
        mode: str,
        *,
        tenant_id: str | None = None,
        degraded: tuple[str, ...] = (),
    ) -> None:
        self._name = name
        self._mode = mode
        self._tenant_id = tenant_id
        self._degraded = degraded

    @property
    def name(self) -> str:
        return self._name

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        if self._mode == "raise_generic":
            raise RuntimeError("synthetic source crash")
        if self._mode == "raise_value":
            raise ValueError("synthetic malformed-payload parse error")
        if self._mode == "hang":
            await asyncio.sleep(30)
            return SourceResult(source_name=self._name)  # unreachable under timeout
        if self._mode == "error":
            return SourceResult(source_name=self._name, error="synthetic upstream error")
        if self._mode == "degraded":
            return SourceResult(source_name=self._name, degraded_sources=self._degraded)
        if self._mode == "good":
            return SourceResult(
                source_name=self._name,
                tenant_id=self._tenant_id,
                evidence=(
                    EvidenceRecord(
                        source_type="HTTP",
                        raw_value=f"tenant_id={self._tenant_id}",
                        rule_name="synthetic",
                        slug="microsoft365",
                    ),
                ),
            )
        raise AssertionError(f"unknown fault mode: {self._mode}")


@pytest.mark.asyncio
async def test_safe_lookup_isolates_a_raising_source() -> None:
    """A source that raises is converted to an error SourceResult, not propagated."""
    result = await _safe_lookup(_FaultySource("boom", "raise_generic"), "example.com")
    assert result.source_name == "boom"
    assert result.error is not None
    assert "synthetic source crash" in result.error
    assert result.tenant_id is None


@pytest.mark.asyncio
async def test_partial_failure_preserves_the_good_source() -> None:
    """Crashing and erroring siblings do not stop a good source's tenant."""
    pool = SourcePool(
        [
            _FaultySource("good", "good", tenant_id=_TENANT_UUID),
            _FaultySource("crash", "raise_generic"),
            _FaultySource("upstream", "error"),
            _FaultySource("parse", "raise_value"),
        ]
    )
    info, results = await resolve_tenant("example.com", pool=pool, timeout=10.0)
    assert info.tenant_id == _TENANT_UUID
    # Three faulty sources each surface as an error result; none raised.
    errored = [r for r in results if r.error]
    assert len(errored) >= 3


@pytest.mark.asyncio
async def test_degraded_source_surfaces_and_hedges() -> None:
    """A degraded source shows up in degraded_sources and prevents HIGH confidence."""
    pool = SourcePool(
        [
            _FaultySource("good", "good", tenant_id=_TENANT_UUID),
            _FaultySource("ct", "degraded", degraded=("crt.sh", "certspotter")),
        ]
    )
    info, _results = await resolve_tenant("example.com", pool=pool, timeout=10.0)
    assert {"crt.sh", "certspotter"}.issubset(set(info.degraded_sources))
    assert info.confidence != ConfidenceLevel.HIGH


@pytest.mark.asyncio
async def test_all_sources_failing_raises_all_sources_failed() -> None:
    """When no source yields a tenant, the pipeline raises all_sources_failed."""
    pool = SourcePool(
        [
            _FaultySource("a", "error"),
            _FaultySource("b", "raise_generic"),
        ]
    )
    with pytest.raises(ReconLookupError) as exc_info:
        await resolve_tenant("example.com", pool=pool, timeout=10.0)
    assert exc_info.value.error_type == "all_sources_failed"


@pytest.mark.asyncio
async def test_hanging_source_trips_the_aggregate_timeout() -> None:
    """A source that hangs is cancelled and reported as a clean timeout error."""
    pool = SourcePool([_FaultySource("slow", "hang")])
    with pytest.raises(ReconLookupError) as exc_info:
        await resolve_tenant("example.com", pool=pool, timeout=0.05)
    assert exc_info.value.error_type == "timeout"


@pytest.mark.asyncio
async def test_resolve_tenant_isolates_a_malformed_oidc_payload() -> None:
    """A real OIDCSource fed a truncated body degrades; a good sibling still wins.

    This exercises the literal provider-payload boundary end to end: the OIDC
    source's `response.json()` raises on the truncated body, the source returns
    an error SourceResult, and resolve_tenant merges the good source's tenant
    without crashing.
    """
    transport = httpx.MockTransport(lambda _req: httpx.Response(200, content=b"{ truncated json"))
    async with httpx.AsyncClient(transport=transport) as client:
        pool = SourcePool(
            [
                OIDCSource(),
                _FaultySource("good", "good", tenant_id=_TENANT_UUID),
            ]
        )
        info, results = await resolve_tenant("example.com", pool=pool, client=client, timeout=10.0)
    assert info.tenant_id == _TENANT_UUID
    oidc_results = [r for r in results if r.source_name == "oidc_discovery"]
    assert oidc_results
    assert oidc_results[0].error is not None
    assert oidc_results[0].tenant_id is None
