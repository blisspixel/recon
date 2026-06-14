"""Passive-by-default contract: direct probes to target-controlled hosts are opt-in.

recon's collection is passive. The two requests that reach a host the queried
domain controls (the Google CSE discovery probe at ``cse.<domain>`` and the BIMI
VMC certificate fetch) are gated behind the ``active_probes`` opt-in
(``--direct-probes``). By default neither is performed, so the only request the
target's own servers see is the standard MTA-STS policy fetch. BIMI *presence* is
still read from the DNS TXT record either way.

Also covers the ``analyze_posture`` MCP tool's non-string ``profile`` guard:
MCP arguments arrive unenforced at runtime, so a truthy non-string profile must
not raise ``TypeError`` on the length slice.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch

import pytest

from recon_tool.constants import SVC_BIMI
from recon_tool.models import ConfidenceLevel, EvidenceRecord, SourceResult, TenantInfo
from recon_tool.resolver import SourcePool, resolve_tenant
from recon_tool.sources import dns as dns_mod
from recon_tool.sources import dns_email
from recon_tool.sources.google import GoogleSource

_TENANT_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


# ── Google CSE probe gating ──────────────────────────────────────────────


class _CSEResponse:
    """Minimal httpx.Response stand-in: a 200 carrying a CSE config dict."""

    status_code = 200

    def json(self) -> dict[str, Any]:
        return {"discovery_uri": "https://login.okta.com/oauth2/x"}


class _RecordingClient:
    """An httpx-client stand-in that records every ``get`` URL."""

    def __init__(self, calls: list[str], response: Any = None) -> None:
        self._calls = calls
        self._response = response

    async def get(self, url: str, **_kw: Any) -> Any:
        self._calls.append(url)
        return self._response


@pytest.mark.asyncio
async def test_google_source_passive_by_default_makes_no_cse_probe() -> None:
    """Without active_probes, GoogleSource makes no network call at all."""
    calls: list[str] = []
    client = _RecordingClient(calls)
    result = await GoogleSource().lookup("contoso.com", client=client)
    assert calls == [], "the CSE probe must not run by default"
    # A clean empty result, not a degraded error.
    assert result.error is None
    assert result.detected_slugs == ()


@pytest.mark.asyncio
async def test_google_source_probes_cse_when_active() -> None:
    """With active_probes=True, the CSE endpoint is queried and detected."""
    calls: list[str] = []
    client = _RecordingClient(calls, response=_CSEResponse())
    result = await GoogleSource().lookup("contoso.com", client=client, active_probes=True)
    assert calls == ["https://cse.contoso.com/.well-known/cse-configuration"]
    assert "google-cse" in result.detected_slugs


# ── BIMI VMC fetch gating ────────────────────────────────────────────────


class _Resp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _fake_http_client(resp: _Resp, calls: list[str]) -> Any:
    """Replacement for dns._http_client whose client records every ``get`` URL.

    If the BIMI gate or the SSRF guard refuses to fetch, the context manager is
    never entered and ``calls`` stays empty.
    """

    @asynccontextmanager
    async def _cm(*_args: Any, **_kwargs: Any) -> AsyncGenerator[Any, None]:
        class _Client:
            async def get(self, url: str, **_kw: Any) -> _Resp:
                calls.append(url)
                return resp

        yield _Client()

    return _cm


@pytest.mark.asyncio
async def test_bimi_vmc_not_fetched_by_default() -> None:
    """BIMI presence is recorded from DNS, but the VMC URL is not fetched."""
    ctx = dns_mod._DetectionCtx()  # active_probes defaults to False
    calls: list[str] = []
    with patch.object(dns_email, "_http_client", _fake_http_client(_Resp(200, "pem"), calls)):
        await dns_email._apply_bimi(ctx, ["v=BIMI1; a=https://logo.example/vmc.pem"], "contoso.com")
    assert SVC_BIMI in ctx.services, "BIMI presence must still be detected from the TXT record"
    assert calls == [], "the VMC fetch must not run by default"
    assert ctx.bimi_identity is None


@pytest.mark.asyncio
async def test_bimi_vmc_fetched_when_active() -> None:
    """With active_probes set on the context, the safe VMC URL is fetched."""
    ctx = dns_mod._DetectionCtx()
    ctx.active_probes = True
    calls: list[str] = []
    # A public-DNS https .pem host (fictional brand) that passes the SSRF guard.
    a_url = "https://bimi.fabrikam.com/vmc.pem"
    with patch.object(dns_email, "_http_client", _fake_http_client(_Resp(200, "not-a-real-pem"), calls)):
        await dns_email._apply_bimi(ctx, [f"v=BIMI1; a={a_url}"], "contoso.com")
    assert SVC_BIMI in ctx.services
    assert calls == [a_url], "the VMC fetch must run when opted in"


# ── resolver threads the opt-in to the sources ───────────────────────────


class _CapturingSource:
    """A LookupSource that records the kwargs it was called with and yields a tenant."""

    def __init__(self) -> None:
        self.kwargs_seen: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "capture"

    async def lookup(self, domain: str, **kwargs: Any) -> SourceResult:
        self.kwargs_seen.append(dict(kwargs))
        return SourceResult(
            source_name="capture",
            tenant_id=_TENANT_UUID,
            evidence=(
                EvidenceRecord(
                    source_type="HTTP",
                    raw_value=f"tenant_id={_TENANT_UUID}",
                    rule_name="synthetic",
                    slug="microsoft365",
                ),
            ),
        )


@pytest.mark.asyncio
async def test_resolve_tenant_passive_by_default() -> None:
    """resolve_tenant does not opt sources into active probes unless asked."""
    src = _CapturingSource()
    await resolve_tenant("contoso.com", pool=SourcePool([src]), timeout=10.0)
    assert src.kwargs_seen
    assert src.kwargs_seen[0].get("active_probes", False) is False


@pytest.mark.asyncio
async def test_resolve_tenant_threads_active_probes() -> None:
    """active_probes=True is forwarded to every source's lookup."""
    src = _CapturingSource()
    await resolve_tenant("contoso.com", pool=SourcePool([src]), timeout=10.0, active_probes=True)
    assert src.kwargs_seen[0].get("active_probes") is True


# ── analyze_posture non-string profile guard ─────────────────────────────

pytest.importorskip("mcp")

from recon_tool.server import _cache_clear, _rate_limit, analyze_posture

_POSTURE_INFO = TenantInfo(
    tenant_id=_TENANT_UUID,
    display_name="Contoso Ltd",
    default_domain="contoso.onmicrosoft.com",
    queried_domain="contoso.com",
    confidence=ConfidenceLevel.MEDIUM,
    services=("Microsoft 365", "DMARC"),
    slugs=("microsoft365", "dmarc"),
    dmarc_policy="reject",
)


@pytest.mark.asyncio
async def test_analyze_posture_non_string_profile_does_not_crash() -> None:
    """A truthy non-string profile (MCP args arrive unenforced) is ignored, not fatal.

    Before the guard, ``profile[:100]`` raised TypeError on a non-string. The
    function must instead treat it as "no lens" and return valid JSON.
    """
    _cache_clear()
    _rate_limit.clear()
    from unittest.mock import AsyncMock

    with patch("recon_tool.server.resolve_tenant", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = (_POSTURE_INFO, [])
        parsed = await analyze_posture("contoso.com", profile=123)  # type: ignore[arg-type]
    # A non-string profile is treated as no lens, so this returns the plain
    # observation list, not the "Unknown profile" ToolError.
    assert isinstance(parsed, list)
    _cache_clear()
    _rate_limit.clear()
