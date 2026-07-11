"""Regression tests for collection-aware declarative missingness.

Transient collection failures are provenance about what recon could observe,
not evidence that a domain lacks a declaration. These synthetic fixtures pin
the boundary from DNS status through ``TenantInfo`` into Bayesian masking.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.exception
import dns.resolver
import httpx
import pytest

from recon_tool.bayesian import (
    InferenceResult,
    NodePosterior,
    collection_masked_units,
    infer,
    infer_from_tenant_info,
    load_network,
)
from recon_tool.merger import merge_results
from recon_tool.models import SourceResult
from recon_tool.sources import dns_base, dns_email, dns_infra
from recon_tool.sources.dns import DNSSource

_POLICY_NODE = "email_security_policy_enforcing"


def _policy_posterior(result: InferenceResult) -> NodePosterior:
    return next(item for item in result.posteriors if item.name == _POLICY_NODE)


async def _mta_sts_only_resolve(domain: str, rdtype: str, **kwargs: object) -> list[str]:
    del kwargs
    if domain == "_mta-sts.example.com" and rdtype == "TXT":
        return ["v=STSv1; id=20260710"]
    return []


def _http_client_returning(status_code: int) -> AsyncMock:
    response = httpx.Response(
        status_code=status_code,
        request=httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt"),
    )
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _install_http_status(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    def client_factory(*, timeout: float) -> AsyncMock:
        del timeout
        return _http_client_returning(status_code)

    monkeypatch.setattr(dns_email, "_http_client", client_factory)


class _FailingResolver:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def resolve(self, domain: str, rdtype: str, *, lifetime: float) -> list[str]:
        del domain, rdtype, lifetime
        raise self.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        dns.exception.Timeout(),
        dns.resolver.NoNameservers("synthetic nameserver failure"),
        RuntimeError("synthetic resolver failure"),
    ],
    ids=["timeout", "no-nameservers", "unexpected"],
)
async def test_safe_resolve_records_transient_failure_as_unobserved(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    degraded: set[str] = set()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: _FailingResolver(error))

    records = await dns_base.safe_resolve(
        "example.com",
        "TXT",
        degraded_sources=degraded,
        degraded_name="dns:apex_txt",
    )

    assert records == []
    assert degraded == {"dns:apex_txt"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()],
    ids=["nxdomain", "no-answer"],
)
async def test_safe_resolve_keeps_successful_empty_as_observed_absence(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    degraded: set[str] = set()
    monkeypatch.setattr(dns_base, "get_resolver", lambda: _FailingResolver(error))

    records = await dns_base.safe_resolve(
        "missing.example.com",
        "TXT",
        degraded_sources=degraded,
        degraded_name="dns:dmarc",
    )

    assert records == []
    assert degraded == set()


@pytest.mark.asyncio
async def test_mx_detector_records_granular_resolver_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def unavailable_mx(
        domain: str,
        rdtype: str,
        **kwargs: object,
    ) -> list[str]:
        assert (domain, rdtype) == ("example.com", "MX")
        degraded = kwargs["degraded_sources"]
        assert isinstance(degraded, set)
        degraded.add(str(kwargs["degraded_name"]))
        return []

    monkeypatch.setattr(dns_base, "safe_resolve", unavailable_mx)
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_mx(ctx, "example.com")

    assert ctx.degraded_sources == {"dns:mx"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            dns.exception.Timeout(),
            {"dns:dkim", "dns:dmarc", "dns:bimi", "dns:mta_sts", "dns:tls_rpt", "dns:caa"},
        ),
        (dns.resolver.NoAnswer(), set()),
    ],
    ids=["transient-unobserved", "observed-empty"],
)
async def test_email_control_detectors_distinguish_failure_from_empty(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected: set[str],
) -> None:
    monkeypatch.setattr(dns_base, "get_resolver", lambda: _FailingResolver(error))
    ctx = dns_base.DetectionCtx()

    await dns_email.detect_dkim(ctx, "example.com")
    await dns_email.detect_email_security(ctx, "example.com")
    await dns_infra.detect_caa(ctx, "example.com")

    assert ctx.degraded_sources == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [408, 429, 500, 503, 599])
async def test_transient_mta_sts_http_status_is_unobserved_through_inference(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _mta_sts_only_resolve)
    _install_http_status(monkeypatch, status_code)

    source_result = await DNSSource().lookup("example.com", skip_ct=True)
    info = merge_results([source_result], "example.com")
    policy = _policy_posterior(infer_from_tenant_info(info, priors_override={}))

    assert "http:mta_sts_policy" in source_result.degraded_sources
    assert "http:mta_sts_policy" in info.degraded_sources
    assert "mta_sts_enforce" not in {item.unit for item in policy.unit_counterfactuals}


@pytest.mark.asyncio
async def test_mta_sts_404_is_observed_non_enforcement_through_inference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dns_base, "safe_resolve", _mta_sts_only_resolve)
    _install_http_status(monkeypatch, 404)

    source_result = await DNSSource().lookup("example.com", skip_ct=True)
    info = merge_results([source_result], "example.com")
    policy = _policy_posterior(infer_from_tenant_info(info, priors_override={}))
    absences = {item.unit: item for item in policy.unit_counterfactuals}

    assert "http:mta_sts_policy" not in source_result.degraded_sources
    assert "http:mta_sts_policy" not in info.degraded_sources
    assert absences["mta_sts_enforce"].observed == "absent"
    assert absences["mta_sts_enforce"].delta != 0.0


@pytest.mark.parametrize(
    ("marker", "units"),
    [
        ("dns:apex_txt", ("spf_strict",)),
        ("dns:dmarc", ("dmarc_policy",)),
        ("dns:mta_sts", ("mta_sts_enforce",)),
        ("http:mta_sts_policy", ("mta_sts_enforce",)),
        ("detector:txt", ("spf_strict",)),
        ("detector:email_security", ("dmarc_policy", "mta_sts_enforce")),
    ],
)
def test_degraded_channel_matches_structural_mask(marker: str, units: tuple[str, ...]) -> None:
    network = load_network()
    degraded = infer_from_tenant_info(
        SimpleNamespace(degraded_sources=(marker,)),
        network=network,
        priors_override={},
    )
    explicitly_masked = infer(
        network,
        observed_slugs=(),
        observed_signals=(),
        priors_override={},
        masked_units=units,
    )
    observed_empty = infer(network, observed_slugs=(), observed_signals=(), priors_override={})

    degraded_policy = _policy_posterior(degraded)
    assert degraded_policy == _policy_posterior(explicitly_masked)
    assert degraded_policy.posterior != _policy_posterior(observed_empty).posterior


@pytest.mark.parametrize("marker", ["dns", "dns_records"])
def test_whole_dns_failure_masks_every_declarative_unit(marker: str) -> None:
    if marker == "dns_records":
        info = merge_results(
            [
                SourceResult(source_name="oidc_discovery", tenant_id="00000000-0000-0000-0000-000000000001"),
                SourceResult(source_name="dns_records", error="synthetic timeout"),
            ],
            "example.com",
        )
        assert info.degraded_sources == ("dns_records",)
    else:
        info = SimpleNamespace(degraded_sources=(marker,))
    assert collection_masked_units(info.degraded_sources) == frozenset(
        {"spf_strict", "dmarc_policy", "mta_sts_enforce"}
    )
    policy = _policy_posterior(infer_from_tenant_info(info, priors_override={}))
    assert policy.posterior == 0.62
    assert policy.n_eff == 4.0
    assert policy.sparse is True
    assert policy.absence_informative is False
    assert policy.unit_counterfactuals == ()


def test_ct_degradation_does_not_mask_dns_policy_absence() -> None:
    network = load_network()
    ct_degraded = infer_from_tenant_info(
        SimpleNamespace(degraded_sources=("crt.sh",)),
        network=network,
        priors_override={},
    )
    observed_empty = infer(network, observed_slugs=(), observed_signals=(), priors_override={})

    assert _policy_posterior(ct_degraded) == _policy_posterior(observed_empty)
