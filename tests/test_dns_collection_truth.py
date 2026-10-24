# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none
"""DNS adapter truth: total transport failure versus observed empty (#221, #222).

These tests drive synthetic resolver behavior through the real DNS adapter
(``dns_base.safe_resolve`` via the ``get_resolver`` seam), the real
``DNSSource``, the merger, and the CLI / MCP surfaces. Earlier resolver tests
injected pre-errored ``SourceResult`` objects and so bypassed the seam where a
transport failure used to collapse into an empty, successful DNS result.

Every case is offline: DNS answers come from a fake resolver, and every HTTP
request made through recon's SSRF-safe transport fails before any socket is
opened (or receives a synthetic response).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import dns.exception
import dns.resolver
import httpx
import pytest
from typer.testing import CliRunner

from recon_tool import http as recon_http
from recon_tool import retry as recon_retry
from recon_tool.cli import app
from recon_tool.ct_cache import ct_cache_put
from recon_tool.formatter.collection_status import (
    NAME_NXDOMAIN_STATEMENT,
    collection_note_parts,
    project_collection_status,
)
from recon_tool.models import ConfidenceLevel, InfrastructureClusterReport, ReconLookupError, TenantInfo
from recon_tool.resolver import resolve_tenant
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base, dns_infra
from recon_tool.sources.dns import DNSSource

runner = CliRunner()

_APEX = "alpha.invalid"
_PARKED_NARRATION = "parked domain"


class _Rdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _Answer:
    """Minimal dnspython-shaped answer: canonical name plus iterable rdata."""

    def __init__(self, name: str, records: tuple[str, ...]) -> None:
        self.canonical_name = f"{name}."
        self._records = records

    def __iter__(self) -> Iterator[_Rdata]:
        return iter(_Rdata(record) for record in self._records)


Behavior = Callable[[str, str], "BaseException | _Answer"]


class _FakeResolver:
    def __init__(self, behavior: Behavior) -> None:
        self._behavior = behavior
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, name: str, rdtype: str, *, lifetime: float) -> _Answer:
        normalized = name.rstrip(".").lower()
        self.calls.append((normalized, rdtype))
        outcome = self._behavior(normalized, rdtype)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _timeout_everywhere(_name: str, _rdtype: str) -> BaseException:
    return dns.exception.Timeout()


def _no_nameservers_everywhere(_name: str, _rdtype: str) -> BaseException:
    return dns.resolver.NoNameservers()


def _no_answer_everywhere(_name: str, _rdtype: str) -> BaseException:
    return dns.resolver.NoAnswer()


def _nxdomain_everywhere(_name: str, _rdtype: str) -> BaseException:
    return dns.resolver.NXDOMAIN()


def _apex_ns_only_rest_timeout(name: str, rdtype: str) -> BaseException | _Answer:
    """Mixed control: one apex query answers, every other query times out."""
    if name == _APEX and rdtype == "NS":
        return _Answer(name, ("ns1.example.net.",))
    return dns.exception.Timeout()


def _apex_present_subdomain_nxdomain(name: str, rdtype: str) -> BaseException | _Answer:
    """A valid apex (NOERROR, empty) whose other names do not exist."""
    if name == _APEX:
        return dns.resolver.NoAnswer()
    return dns.resolver.NXDOMAIN()


@pytest.fixture
def offline_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail every HTTP request recon makes as a transport error, with no retry wait."""

    async def _refuse(self: Any, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic offline transport", request=request)

    async def _no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(recon_http._SSRFSafeTransport, "handle_async_request", _refuse)
    monkeypatch.setattr(recon_retry, "asyncio", SimpleNamespace(sleep=_no_sleep))


@pytest.fixture
def negative_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer every HTTP request with a clean 400, as identity endpoints do for unknown names."""

    async def _bad_request(self: Any, request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={}, request=request)

    monkeypatch.setattr(recon_http._SSRFSafeTransport, "handle_async_request", _bad_request)


def _install_resolver(monkeypatch: pytest.MonkeyPatch, behavior: Behavior) -> _FakeResolver:
    resolver = _FakeResolver(behavior)
    monkeypatch.setattr(dns_base, "get_resolver", lambda: resolver)
    return resolver


# ── Adapter ledger ──────────────────────────────────────────────────────


class TestDnsQueryLedger:
    @pytest.mark.asyncio
    async def test_ledger_retains_response_class_per_query(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def behavior(name: str, rdtype: str) -> BaseException | _Answer:
            return {
                "TXT": dns.resolver.NoAnswer(),
                "MX": dns.resolver.NXDOMAIN(),
                "NS": dns.exception.Timeout(),
                "A": _Answer(name, ("192.0.2.1",)),
            }[rdtype]

        _install_resolver(monkeypatch, behavior)
        with dns_base.dns_query_ledger() as ledger:
            for rdtype in ("TXT", "MX", "NS", "A"):
                await dns_base.safe_resolve(_APEX, rdtype)

        assert ledger.outcomes == [
            (_APEX, "TXT", "no_answer"),
            (_APEX, "MX", "nxdomain"),
            (_APEX, "NS", "unavailable"),
            (_APEX, "A", "answer"),
        ]
        assert ledger.clean_responses == 3
        assert not ledger.all_unavailable
        # A NOERROR response for the same name contradicts nonexistence.
        assert ledger.name_status(_APEX) is None

    @pytest.mark.asyncio
    async def test_private_canonical_suppression_counts_as_noerror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _PrivateAnswer(_Answer):
            def __init__(self) -> None:
                super().__init__("internal.corp", ("10.0.0.1",))

        _install_resolver(monkeypatch, lambda _n, _t: _PrivateAnswer())
        with dns_base.dns_query_ledger() as ledger:
            assert await dns_base.safe_resolve(_APEX, "A") == []
        assert ledger.outcomes == [(_APEX, "A", "answer")]

    @pytest.mark.asyncio
    async def test_name_status_requires_nxdomain_for_the_name_itself(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _apex_present_subdomain_nxdomain)
        with dns_base.dns_query_ledger() as ledger:
            await dns_base.safe_resolve(_APEX, "TXT")
            await dns_base.safe_resolve(f"www.{_APEX}", "A")
        assert ledger.name_status(_APEX) is None
        assert ledger.name_status(f"www.{_APEX}") == "nxdomain"

    @pytest.mark.asyncio
    async def test_transport_failure_never_establishes_nonexistence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        with dns_base.dns_query_ledger() as ledger:
            await dns_base.safe_resolve(_APEX, "TXT")
        assert ledger.all_unavailable
        assert ledger.name_status(_APEX) is None

    @pytest.mark.asyncio
    async def test_no_ledger_outside_a_dns_source_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        assert await dns_base.safe_resolve(_APEX, "TXT") == []
        empty = dns_base.DnsQueryLedger()
        assert not empty.all_unavailable
        assert empty.name_status(_APEX) is None


# ── DNS source boundary ─────────────────────────────────────────────────


class TestDnsSourceBoundary:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("behavior", [_timeout_everywhere, _no_nameservers_everywhere])
    async def test_total_transport_failure_is_a_source_error(
        self, monkeypatch: pytest.MonkeyPatch, behavior: Behavior
    ) -> None:
        _install_resolver(monkeypatch, behavior)
        result = await DNSSource().lookup(_APEX, skip_ct=True)
        assert result.error is not None
        assert "DNS resolution unavailable" in result.error
        assert result.source_unavailable
        assert result.dns_name_status is None
        assert "dns:apex_txt" in result.degraded_sources

    @pytest.mark.asyncio
    async def test_successful_empty_dns_stays_a_clean_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        result = await DNSSource().lookup(_APEX, skip_ct=True)
        assert result.error is None
        assert not result.source_unavailable
        assert result.degraded_sources == ()
        assert result.dns_name_status is None

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure_stays_a_partial_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _apex_ns_only_rest_timeout)
        result = await DNSSource().lookup(_APEX, skip_ct=True)
        assert result.error is None
        assert not result.source_unavailable
        assert "dns:apex_txt" in result.degraded_sources

    @pytest.mark.asyncio
    async def test_apex_nxdomain_is_retained_and_is_not_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _nxdomain_everywhere)
        result = await DNSSource().lookup(_APEX, skip_ct=True)
        assert result.error is None
        assert not result.source_unavailable
        assert result.degraded_sources == ()
        assert result.dns_name_status == "nxdomain"

    @pytest.mark.asyncio
    async def test_missing_subdomain_under_a_valid_apex_is_not_apex_nxdomain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_resolver(monkeypatch, _apex_present_subdomain_nxdomain)
        result = await DNSSource().lookup(_APEX, skip_ct=True)
        assert result.error is None
        assert result.dns_name_status is None

    @pytest.mark.asyncio
    async def test_exact_queried_host_nxdomain_is_reported_for_that_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Under --exact the literal host is the queried name; its NXDOMAIN is
        # reported even though the parent apex resolves.
        _install_resolver(monkeypatch, _apex_present_subdomain_nxdomain)
        result = await DNSSource().lookup(f"missing.{_APEX}", skip_ct=True)
        assert result.dns_name_status == "nxdomain"

    @pytest.mark.asyncio
    async def test_ledger_does_not_leak_into_the_caller_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        await DNSSource().lookup(_APEX, skip_ct=True)
        assert dns_base._ACTIVE_LEDGER.get() is None


# ── Resolver pipeline ───────────────────────────────────────────────────


class TestResolverPipeline:
    @pytest.mark.asyncio
    @pytest.mark.usefixtures("offline_http")
    async def test_every_source_offline_raises_all_sources_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        with pytest.raises(ReconLookupError) as exc_info:
            await resolve_tenant(_APEX, skip_ct=True, timeout=30.0)
        error = exc_info.value
        assert error.error_type == "all_sources_failed"
        failed = {name for name, _detail in error.source_errors}
        assert "dns_records" in failed
        # The disabled opt-in CSE probe neither failed nor kept the lookup alive.
        assert "google_workspace" not in failed

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("offline_http")
    async def test_successful_empty_dns_with_offline_http_is_not_total_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        info, _results = await resolve_tenant(_APEX, skip_ct=True, timeout=30.0)
        assert info.dns_name_status is None
        assert "dns_records" not in info.degraded_sources

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("offline_http")
    async def test_mixed_dns_with_offline_http_is_not_total_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _apex_ns_only_rest_timeout)
        info, _results = await resolve_tenant(_APEX, skip_ct=True, timeout=30.0)
        assert info.degraded_sources
        assert "dns_records" not in info.degraded_sources

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("negative_http")
    async def test_apex_nxdomain_is_a_clean_observed_empty_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _nxdomain_everywhere)
        info, _results = await resolve_tenant(_APEX, skip_ct=True, timeout=30.0)
        assert info.dns_name_status == "nxdomain"
        assert info.confidence == ConfidenceLevel.LOW
        assert not any(source.startswith("dns") for source in info.degraded_sources)
        assert not any(_PARKED_NARRATION in insight for insight in info.insights)
        assert not any(insight.startswith("Sparse public signal") for insight in info.insights)

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("negative_http")
    async def test_apex_noanswer_keeps_the_existing_narration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        info, _results = await resolve_tenant(_APEX, skip_ct=True, timeout=30.0)
        assert info.dns_name_status is None
        assert any(_PARKED_NARRATION in insight for insight in info.insights)


# ── CLI and MCP surfaces ────────────────────────────────────────────────


@pytest.mark.usefixtures("offline_http")
class TestTotalFailureSurfaces:
    @pytest.mark.parametrize("review", [False, True])
    def test_empty_ct_cache_does_not_hide_failure_of_the_default_source_pool(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, review: bool
    ) -> None:
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        ct_cache_put(
            _APEX, [], None, "synthetic", infrastructure_clusters=InfrastructureClusterReport((), 0, "skipped", 0, 0)
        )
        _install_resolver(monkeypatch, _timeout_everywhere)
        command = ["review", _APEX, "--json"] if review else [_APEX, "--no-cache"]
        with patch.object(dns_source, "_detect_cert_intel", dns_infra.detect_cert_intel):
            result = runner.invoke(app, command)
        assert result.exit_code == 4, result.output
        assert "1 matched" not in result.output
        if review:
            assert json.loads(result.stdout)["workflow"]["status"] == "failed"

    def test_lookup_exits_4_with_all_sources_failed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct"])
        assert result.exit_code == 4, result.output
        output = " ".join(result.output.split())
        assert "No information could be resolved for alpha.invalid" in output
        assert "All sources returned errors" in output

    def test_lookup_json_exits_4(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 4, result.output

    def test_review_exits_4_with_failed_workflow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _timeout_everywhere)
        result = runner.invoke(app, ["review", _APEX, "--json", "--no-ct"])
        assert result.exit_code == 4, result.output
        bundle = json.loads(result.stdout)
        assert bundle["workflow"]["status"] == "failed"

    def test_successful_empty_dns_lookup_still_exits_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 0, result.output

    @pytest.mark.usefixtures("_fresh_mcp_state")
    def test_mcp_lookup_reports_the_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool.mcp_client.sdk_compat import ToolError
        from recon_tool.server import lookup_tenant

        _install_resolver(monkeypatch, _timeout_everywhere)
        with pytest.raises(ToolError) as exc_info:
            asyncio.run(lookup_tenant(_APEX))
        assert "all passive sources returned errors" in str(exc_info.value)

    @pytest.mark.usefixtures("_fresh_mcp_state")
    def test_mcp_review_bundle_is_a_failed_workflow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from recon_tool.server import build_review_bundle

        _install_resolver(monkeypatch, _timeout_everywhere)
        bundle = asyncio.run(build_review_bundle(_APEX, no_ct=True))
        assert bundle["workflow"]["status"] == "failed"


@pytest.fixture
def _fresh_mcp_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from recon_tool.network_policy import CollectionPolicy
    from recon_tool.server import _cache_clear, _rate_limit_clear
    from recon_tool.server import app as server_app

    # These cases supply an offline resolver at the shared adapter seam.
    monkeypatch.setattr(
        server_app, "MCP_COLLECTION_POLICY", CollectionPolicy("caller-safe", ("192.0.2.53",), "dns.example.org")
    )

    _cache_clear()
    _rate_limit_clear()
    yield
    _cache_clear()
    _rate_limit_clear()


@pytest.mark.usefixtures("negative_http")
class TestApexNxdomainSurfaces:
    @pytest.mark.parametrize("flags", [[], ["--plain"], ["--md"], ["--full"], ["--plain", "--full"]])
    def test_human_surfaces_state_nxdomain(self, monkeypatch: pytest.MonkeyPatch, flags: list[str]) -> None:
        _install_resolver(monkeypatch, _nxdomain_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct", *flags])
        assert result.exit_code == 0, result.output
        if flags == ["--plain", "--full"]:
            assert "dns_name_status: nxdomain" in result.output
        else:
            assert NAME_NXDOMAIN_STATEMENT in " ".join(result.output.split())
        assert _PARKED_NARRATION not in result.output

    def test_json_carries_the_additive_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _nxdomain_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["dns_name_status"] == "nxdomain"
        assert payload["partial"] is False

    def test_noanswer_apex_carries_no_nxdomain_statement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _no_answer_everywhere)
        result = runner.invoke(app, [_APEX, "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 0, result.output
        assert "dns_name_status" not in json.loads(result.stdout)

    def test_reduced_subdomain_with_valid_apex_has_no_statement(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _apex_present_subdomain_nxdomain)
        result = runner.invoke(app, [f"missing.{_APEX}", "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 0, result.output
        assert "dns_name_status" not in json.loads(result.stdout)

    def test_exact_missing_subdomain_reports_its_own_nxdomain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_resolver(monkeypatch, _apex_present_subdomain_nxdomain)
        result = runner.invoke(app, [f"missing.{_APEX}", "--exact", "--no-cache", "--no-ct", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["dns_name_status"] == "nxdomain"


# ── Collection note wording ─────────────────────────────────────────────


def _info(degraded: tuple[str, ...], **overrides: Any) -> TenantInfo:
    base: dict[str, Any] = {
        "tenant_id": None,
        "display_name": _APEX,
        "default_domain": _APEX,
        "queried_domain": _APEX,
        "confidence": ConfidenceLevel.LOW,
        "sources": (),
        "degraded_sources": degraded,
    }
    base.update(overrides)
    return TenantInfo(**base)


class TestCollectionNoteQuantifier:
    _ALL = ("dns:apex_txt", "dns_records", "source:google_identity", "source:oidc_discovery", "source:user_realm")

    def test_every_default_source_unavailable_says_all(self) -> None:
        notes = collection_note_parts(project_collection_status(_info(self._ALL)))
        assert notes[0].startswith(f"All {len(self._ALL)} sources unavailable (")

    def test_partial_unavailability_counts_without_all(self) -> None:
        notes = collection_note_parts(project_collection_status(_info(self._ALL[:-1])))
        assert notes[0].startswith(f"{len(self._ALL) - 1} sources unavailable (")

    def test_any_observation_counts_without_all(self) -> None:
        info = _info(self._ALL, services=("Synthetic Service",))
        notes = collection_note_parts(project_collection_status(info))
        assert notes[0].startswith(f"{len(self._ALL)} sources unavailable (")

    def test_markdown_and_mcp_text_share_the_quantifier(self) -> None:
        from recon_tool.formatter.markdown import format_tenant_markdown
        from recon_tool.server.lookup import _lookup_tenant_text  # pyright: ignore[reportPrivateUsage]

        info = _info(self._ALL)
        assert f"All {len(self._ALL)} sources were unavailable (" in format_tenant_markdown(info)
        assert f"All {len(self._ALL)} sources unavailable (" in _lookup_tenant_text(info)
