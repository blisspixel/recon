"""Destination and identity-integrity regressions for the BIMI VMC fetch.

``_parse_bimi_vmc`` fetches the VMC PEM from the BIMI TXT record's ``a=``
URL. That URL is attacker-controlled, so the fetch is destination-gated and a
syntactically valid certificate is recorded only as an observation. Subject
fields are not promoted to corporate identity without chain and VMC-profile
verification.

These tests stub the HTTP client so no real network call is made, and
assert the fetch is refused for unsafe URLs (the SSRF closure) and
performed for a legitimate public https URL.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch

import pytest

from recon_tool.sources import dns as dns_mod
from recon_tool.sources import dns_base, dns_email


class _Resp:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _fake_http_client(resp: _Resp, calls: list[tuple[str, dict[str, Any]]]) -> Any:
    """Return a replacement for ``_http_client`` whose client records every
    ``get`` call. If the walker refuses the URL it never enters the context
    manager, so ``calls`` stays empty."""

    @asynccontextmanager
    async def _cm(*_args: Any, **_kwargs: Any) -> AsyncGenerator[Any, None]:
        class _Client:
            async def get(self, url: str, **kw: Any) -> _Resp:
                calls.append((url, kw))
                return resp

        yield _Client()

    return _cm


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "a_url",
    [
        "http://attacker.example/vmc.pem",  # not https
        "https://10.0.0.1/vmc.pem",  # IP literal host
        "https://internal.corp/vmc.pem",  # internal suffix
        "https://user:pass@attacker.example/vmc.pem",  # embedded credentials
        "https://attacker.example:8443/vmc.pem",  # non-default port
        "https://localhost/vmc.pem",  # single-label, not a public DNS name
        # Malformed / out-of-range ports: urllib's .port raises ValueError.
        # These must be refused cleanly, not raise out of the helper and
        # abort the whole DNS source (regression for the v1.9.18 port bug).
        "https://attacker.example:bad/vmc.pem",
        "https://attacker.example:99999/vmc.pem",
    ],
)
async def test_refuses_unsafe_a_url(a_url: str):
    ctx = dns_mod._DetectionCtx()
    calls: list[tuple[str, dict[str, Any]]] = []
    with patch.object(dns_email, "_http_client", _fake_http_client(_Resp(200, "x"), calls)):
        # Must not raise: a crafted a= URL is an enrichment input, never a
        # source-aborting exception.
        await dns_email._parse_bimi_vmc(ctx, f"v=BIMI1; l=https://logo.example/l.svg; a={a_url}")
    assert calls == [], f"must not fetch unsafe a= URL: {a_url}"
    assert ctx.bimi_identity is None


@pytest.mark.asyncio
async def test_malformed_port_does_not_abort_email_security():
    # Defense in depth: even if BIMI VMC parsing raised, _detect_email_security
    # must keep the BIMI service detection and not propagate (which would turn
    # the whole DNS source into an error and drop valid SPF/DMARC/MX data).
    ctx = dns_mod._DetectionCtx()

    async def _boom(_ctx: Any, _txt: str) -> None:
        raise ValueError("simulated BIMI parse failure")

    async def _txt_for(domain: str, rdtype: str, **_kw: Any) -> list[str]:
        # Return a BIMI record only for the default._bimi.<domain> name.
        if rdtype == "TXT" and domain.startswith("default._bimi."):
            return ["v=BIMI1; a=https://attacker.example:bad/vmc.pem"]
        return []

    with (
        patch.object(dns_email, "_parse_bimi_vmc", _boom),
        patch.object(dns_base, "safe_resolve", _txt_for),
    ):
        # Must complete without raising; BIMI service still recorded.
        await dns_mod._detect_email_security(ctx, "example.com")

    assert dns_email.SVC_BIMI in ctx.services


@pytest.mark.asyncio
async def test_accepts_public_https_without_trusting_subject():
    ctx = dns_mod._DetectionCtx()
    calls: list[tuple[str, dict[str, Any]]] = []
    pem = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----"

    with patch.object(dns_email, "_http_client", _fake_http_client(_Resp(200, pem), calls)):
        await dns_email._parse_bimi_vmc(ctx, "v=BIMI1; a=https://amplify.alpha.example.com/vmc.pem")

    # A legitimate public https URL is fetched, with redirects disabled.
    assert len(calls) == 1
    assert calls[0][1].get("follow_redirects") is False
    assert ctx.bimi_identity is None
    assert "bimi-vmc" in ctx.slugs
    assert any(record.raw_value == "BIMI certificate document observed" for record in ctx.evidence)
