"""MCP progress notifications stay counts and stage names."""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import ProgressNotification

from recon_tool.chain import ChainOptions, ChainProgress, ChainReport, ChainResult, resolve_chain
from recon_tool.collection_progress import emit
from recon_tool.mcp_client.sdk_compat import ToolContext, ToolError, tool_schemas
from recon_tool.models import TenantInfo
from recon_tool.server import app, graph, lookup, review
from recon_tool.server.app import resolve_domains_for_tool
from recon_tool.server.tool_progress import (
    ToolProgress,
    bind_domains,
    chain_message,
    domain_message,
    source_message,
    source_progress,
)

_MESSAGE = re.compile(
    r"\A(?:"
    r"depth [0-3]: [1-9][0-9]{0,2} of [1-9][0-9]{0,2}"
    r"|domain [1-9][0-9]{0,2} of [1-9][0-9]{0,2}"
    r"|(?:dns|certificate transparency|mta-sts|oidc discovery|user realm|"
    r"google identity|google workspace|collection): (?:started|done)"
    r")\Z"
)
_PROGRESS_TOOLS = (
    "lookup_tenant",
    "build_review_bundle",
    "chain_lookup",
    "cluster_verification_tokens",
    "compare_postures",
)
_STUB_SERVER = Path(__file__).with_name("mcp_progress_stub_server.py")


class _Sink:
    def __init__(self, *, fail: BaseException | None = None) -> None:
        self.sent: list[tuple[float, str]] = []
        self._fail = fail

    async def report_progress(
        self,
        progress: float,
        total: float | None = None,
        message: str | None = None,
    ) -> None:
        if self._fail is not None:
            raise self._fail
        self.sent.append((progress, message or ""))


def _ctx(sink: _Sink) -> ToolContext:
    """Hand a progress sink to a tool whose parameter must stay the SDK Context."""
    return cast(ToolContext, sink)


def _info(domain: str, related: tuple[str, ...] = ()) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Synthetic",
        default_domain=domain,
        queried_domain=domain,
        related_domains=related,
    )


def test_source_labels_are_fixed_stage_names() -> None:
    assert source_message("dns_records", "start") == "dns: started"
    assert source_message("ct", "done") == "certificate transparency: done"
    assert source_message("mta_sts", "start") == "mta-sts: started"
    assert source_message("oidc_discovery", "done") == "oidc discovery: done"
    assert source_message("user_realm", "start") == "user realm: started"
    assert source_message("google_identity", "done") == "google identity: done"
    assert source_message("google_workspace", "start") == "google workspace: started"
    assert source_message("not-a-collector", "start") == "collection: started"
    assert source_message("dns_records", "later") == "dns: started"
    assert _MESSAGE.fullmatch(chain_message(0, 1, 2))
    assert _MESSAGE.fullmatch(domain_message(1, 2))


def test_reserve_drops_unsafe_or_non_increasing_updates(monkeypatch: pytest.MonkeyPatch) -> None:
    now = {"t": 10.0}
    monkeypatch.setattr("recon_tool.server.tool_progress.time.monotonic", lambda: now["t"])
    progress = ToolProgress(_Sink())

    assert progress.reserve(1, "alpha.invalid") is None
    assert progress.reserve(1, "203.0.113.1") is None
    assert progress.reserve(1, "dns: started") == (1, None, "dns: started")
    now["t"] = 10.4
    assert progress.reserve(2, "dns: done") is None
    now["t"] = 10.5
    assert progress.reserve(2, "certificate transparency: started") == (
        2,
        None,
        "certificate transparency: started",
    )
    assert progress.reserve(2, "ct: done") is None
    progress.close()
    now["t"] = 20.0
    assert progress.reserve(3, "dns: done") is None


def test_silent_context_and_closed_sender_drop_updates() -> None:
    assert ToolProgress.from_context(None).reserve(1, "dns: started") is None
    assert ToolProgress.from_context(object()).reserve(1, "dns: started") is None
    progress = ToolProgress.from_context(_Sink())
    assert progress.reserve(1, "dns: started") == (1, None, "dns: started")


@pytest.mark.asyncio
async def test_send_swallows_notification_errors_and_reraises_cancellation() -> None:
    failing = ToolProgress(_Sink(fail=RuntimeError("down")), min_interval=0)
    await failing.advance(1, "dns: started")

    cancelling = ToolProgress(_Sink(fail=asyncio.CancelledError()), min_interval=0)
    with pytest.raises(asyncio.CancelledError):
        await cancelling.advance(1, "dns: started")


@pytest.mark.asyncio
async def test_source_progress_drains_before_close(monkeypatch: pytest.MonkeyPatch) -> None:
    now = {"t": 5.0}
    monkeypatch.setattr("recon_tool.server.tool_progress.time.monotonic", lambda: now["t"])
    sink = _Sink()
    progress = ToolProgress(sink)
    async with source_progress(progress):
        emit("dns_records", "start")
        emit("ct", "start")
        now["t"] = 5.6
        emit("ct", "done")
    assert sink.sent == [(1.0, "dns: started"), (3.0, "certificate transparency: done")]
    frozen = len(sink.sent)
    await asyncio.sleep(0)
    assert len(sink.sent) == frozen
    assert progress.reserve(4, "dns: done") is None


@pytest.mark.asyncio
async def test_chain_progress_counts_names_and_survives_callback_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(domain: str, **_kwargs: object) -> tuple[TenantInfo, list[object]]:
        related = ("related.invalid",) if domain == "alpha.invalid" else ()
        return _info(domain, related), []

    monkeypatch.setattr("recon_tool.chain.resolve_tenant", resolve)
    seen: list[tuple[int, int, int]] = []

    async def on_progress(snapshot: ChainProgress) -> None:
        seen.append((snapshot.depth, snapshot.completed, snapshot.known))

    report = await resolve_chain("alpha.invalid", ChainOptions(depth=1, on_progress=on_progress))
    assert seen == [(0, 1, 1), (1, 2, 2)]
    assert [result.chain_depth for result in report.results] == [0, 1]

    async def fail(_snapshot: ChainProgress) -> None:
        raise RuntimeError("progress down")

    failed = await resolve_chain("alpha.invalid", ChainOptions(depth=1, on_progress=fail))
    assert len(failed.results) == 2

    async def cancel(_snapshot: ChainProgress) -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await resolve_chain("alpha.invalid", ChainOptions(depth=1, on_progress=cancel))


@pytest.mark.asyncio
async def test_domain_callback_runs_after_validation_and_cannot_fail_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []

    async def on_domain(index: int, total: int) -> None:
        order.append(f"progress {index} {total}")
        if index == 1:
            raise RuntimeError("progress down")

    async def resolve(domain: str, _request_id: str) -> TenantInfo:
        order.append(domain)
        return _info(domain)

    monkeypatch.setattr(app, "_resolve_validated_domain_for_tool", resolve)
    resolved = await resolve_domains_for_tool(("alpha.invalid", "beta.invalid"), "req", on_domain=on_domain)
    assert order == ["progress 1 2", "alpha.invalid", "progress 2 2", "beta.invalid"]
    assert [item.queried_domain for item in resolved] == ["alpha.invalid", "beta.invalid"]

    async def invalid_first(_index: int, _total: int) -> None:
        raise AssertionError("progress before validation")

    with pytest.raises(ToolError, match="Error:"):
        await resolve_domains_for_tool(("not a domain", "beta.invalid"), "req", on_domain=invalid_first)


@pytest.mark.asyncio
@pytest.mark.usefixtures("approved_mcp_dns")
async def test_lookup_progress_follows_only_the_network_path(monkeypatch: pytest.MonkeyPatch) -> None:
    entered: list[bool] = []

    from collections.abc import AsyncGenerator
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def watching(progress: ToolProgress) -> AsyncGenerator[None, None]:
        entered.append(True)
        async with source_progress(progress):
            yield

    monkeypatch.setattr(lookup, "source_progress", watching)
    cached = _info("alpha.invalid")
    from recon_tool.server import runtime

    runtime.cache_set("alpha.invalid", cached, [])
    await lookup.lookup_tenant("alpha.invalid", ctx=_ctx(_Sink()))
    assert entered == []

    runtime.cache_clear()

    async def resolve(domain: str, **_kwargs: object) -> tuple[TenantInfo, list[object]]:
        emit("dns_records", "start")
        return _info(domain), []

    monkeypatch.setattr(app, "resolve_tenant", resolve)
    sink = _Sink()
    await lookup.lookup_tenant("alpha.invalid", ctx=_ctx(sink))
    assert entered == [True]
    assert sink.sent == [(1.0, "dns: started")]


@pytest.mark.asyncio
@pytest.mark.usefixtures("approved_mcp_dns")
async def test_review_bundle_listens_on_every_call(monkeypatch: pytest.MonkeyPatch) -> None:
    entered: list[bool] = []

    from collections.abc import AsyncGenerator
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def watching(progress: ToolProgress) -> AsyncGenerator[None, None]:
        entered.append(True)
        async with source_progress(progress):
            yield

    async def resolve(domain: str, **_kwargs: object) -> tuple[TenantInfo, list[object]]:
        emit("dns_records", "start")
        emit("ct", "done")
        return _info(domain), []

    monkeypatch.setattr(review, "source_progress", watching)
    monkeypatch.setattr(app, "resolve_tenant", resolve)
    from recon_tool.server import runtime

    runtime.rate_limit_clear()
    sink = _Sink()
    await review.build_review_bundle("alpha.invalid", ctx=_ctx(sink))
    assert entered == [True]
    assert sink.sent == [(1.0, "dns: started")]


@pytest.mark.asyncio
@pytest.mark.usefixtures("approved_mcp_dns")
async def test_chain_lookup_sends_the_forwarded_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(domain: str, options: ChainOptions) -> ChainReport:
        assert options.on_progress is not None
        await options.on_progress(ChainProgress(0, 1, 1))
        return ChainReport(results=(ChainResult(domain, _info(domain), 0),), max_depth_reached=0, truncated=False)

    monkeypatch.setattr("recon_tool.chain.resolve_chain", resolve)
    sink = _Sink()
    payload = await graph.chain_lookup("alpha.invalid", ctx=_ctx(sink))
    assert "alpha.invalid" in payload
    assert sink.sent == [(1.0, "depth 0: 1 of 1")]


@pytest.mark.asyncio
async def test_compare_and_cluster_use_domain_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve_pair(
        domains: tuple[str, ...],
        _request_id: str,
        *,
        on_domain: Any = None,
    ) -> tuple[TenantInfo, TenantInfo]:
        assert on_domain is not None
        await on_domain(1, 2)
        await on_domain(2, 2)
        return _info(domains[0]), _info(domains[1])

    monkeypatch.setattr(app, "resolve_domains_for_tool", resolve_pair)
    sink = _Sink()
    from recon_tool.server.posture import compare_postures

    compared_result = await compare_postures("alpha.invalid", "beta.invalid", ctx=_ctx(sink))
    assert compared_result["domain_a"] == "alpha.invalid"
    assert compared_result["domain_b"] == "beta.invalid"
    assert sink.sent[0] == (1.0, "domain 1 of 2")

    async def resolve_or_cache(domain: str) -> tuple[TenantInfo, list[object]]:
        return _info(domain), []

    monkeypatch.setattr(app, "resolve_or_cache", resolve_or_cache)
    cluster_sink = _Sink()
    # Two immediate calls: the second is inside the rate-limit window.
    clustered = await graph.cluster_verification_tokens(["alpha.invalid", "beta.invalid"], ctx=_ctx(cluster_sink))
    assert set(clustered["clusters"]) <= {"alpha.invalid", "beta.invalid"}
    assert cluster_sink.sent == [(1.0, "domain 1 of 2")]
    bound = bind_domains(ToolProgress(cluster_sink, min_interval=0))
    await bound(2, 2)
    assert cluster_sink.sent[-1] == (2.0, "domain 2 of 2")


@pytest.mark.asyncio
async def test_progress_parameter_is_absent_from_tool_schemas() -> None:
    tools = {tool.name: tool for tool in await app.mcp.list_tools()}
    assert len(tools) == 23
    for name in _PROGRESS_TOOLS:
        schema, _output = tool_schemas(tools[name])
        assert "ctx" not in schema["properties"]


def test_progress_docs_name_the_tools_and_the_timeout_limit() -> None:
    root = Path(__file__).resolve().parents[1]
    guide = (root / "docs" / "mcp.md").read_text(encoding="utf-8")
    section = guide.split("## Progress", 1)[1].split("## Available Tools", 1)[0]
    for name in _PROGRESS_TOOLS:
        assert name in section
    assert "500 ms" in section
    assert "reset-on-progress" in section
    assert "tool_timeout_sec" in section
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = changelog.split("## [2.26.1]", 1)[0]
    assert "(#317)" in unreleased


@pytest.mark.asyncio
async def test_stdio_chain_progress_requires_a_token_and_stops(tmp_path: Path) -> None:
    home = tmp_path / "home"
    config = tmp_path / "config"
    home.mkdir()
    config.mkdir()
    notes: list[ProgressNotification] = []

    async def on_message(message: object) -> None:
        if isinstance(message, ProgressNotification):
            notes.append(message)

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "RECON_CONFIG_DIR": str(config),
        "RECON_MCP_FORCE_STDIO": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(_STUB_SERVER)],
        env=env,
        cwd=str(tmp_path),
    )
    received: list[tuple[float, str]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        del total
        received.append((progress, message or ""))

    async with (
        asyncio.timeout(60),
        stdio_client(params) as (reader, writer),
        ClientSession(reader, writer, message_handler=on_message) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        assert len(listed.tools) == 23
        chain_tool = next(tool for tool in listed.tools if tool.name == "chain_lookup")
        properties = chain_tool.input_schema.get("properties", {})
        assert "ctx" not in properties

        silent = await session.call_tool("chain_lookup", {"domain": "alpha.invalid", "depth": 1})
        assert getattr(silent, "is_error", None) is not True
        await asyncio.sleep(0.3)
        assert notes == []

        heard = await session.call_tool(
            "chain_lookup",
            {"domain": "alpha.invalid", "depth": 1},
            progress_callback=on_progress,
        )
        assert getattr(heard, "is_error", None) is not True
        assert [progress for progress, _message in received] == [1.0, 2.0]
        assert received[0][0] < received[1][0]
        for _progress, message in received:
            assert _MESSAGE.fullmatch(message)
            assert "." not in message
            assert "invalid" not in message
        frozen = len(received)
        await asyncio.sleep(0.3)
        assert len(received) == frozen
