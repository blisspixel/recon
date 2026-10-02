"""Operator timeout choices bound each chain lookup and its remaining budget."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from recon_tool import chain
from recon_tool.cli import app
from recon_tool.models import ChainReport, ConfidenceLevel, ReconLookupError, TenantInfo


def _info(domain: str, related: tuple[str, ...] = ()) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.LOW,
        related_domains=related,
    )


@pytest.mark.parametrize("json_output", [False, True])
def test_cli_forwards_chain_timeout(json_output: bool) -> None:
    resolve = AsyncMock(return_value=ChainReport(results=(), max_depth_reached=0, truncated=False))
    with patch("recon_tool.chain.resolve_chain", new=resolve):
        result = CliRunner().invoke(
            app, ["example.com", "--chain", "--timeout", "2.5", *(["--json"] if json_output else [])]
        )
    assert result.exit_code == 0, result.output
    assert resolve.await_args.args[1].timeout == 2.5


@pytest.mark.asyncio
async def test_chain_caps_each_lookup_to_remaining_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    elapsed = 0.0
    calls: list[tuple[str, float]] = []

    async def resolve(domain: str, *, timeout: float, **_kwargs: object):
        nonlocal elapsed
        calls.append((domain, timeout))
        if domain == "seed.invalid":
            elapsed += 4.0
            return _info(domain, ("first.invalid", "unstarted.invalid")), []
        elapsed += 6.0
        return _info(domain), []

    monkeypatch.setattr(chain, "time", SimpleNamespace(monotonic=lambda: elapsed))
    monkeypatch.setattr(chain, "resolve_tenant", resolve)
    report = await chain.resolve_chain("seed.invalid", chain.ChainOptions(timeout=10.0))
    assert calls == [("seed.invalid", 10.0), ("first.invalid", 6.0)]
    assert [result.domain for result in report.results] == ["seed.invalid", "first.invalid"]
    assert report.truncated


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf"), True])
async def test_chain_rejects_invalid_timeout_before_resolution(timeout: float) -> None:
    resolve = AsyncMock()
    with patch("recon_tool.chain.resolve_tenant", new=resolve), pytest.raises(ValueError, match="timeout"):
        await chain.resolve_chain("seed.invalid", chain.ChainOptions(timeout=timeout))
    resolve.assert_not_awaited()


@pytest.mark.asyncio
async def test_final_child_timeout_keeps_partial_results_and_marks_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    elapsed = 0.0

    async def resolve(domain: str, *, timeout: float, **_kwargs: object):
        nonlocal elapsed
        if domain == "seed.invalid":
            elapsed += 1.0
            return _info(domain, ("child.invalid",)), []
        assert timeout == 1.0
        elapsed += timeout
        raise ReconLookupError(domain=domain, message="timeout", error_type="timeout")

    monkeypatch.setattr(chain, "time", SimpleNamespace(monotonic=lambda: elapsed))
    monkeypatch.setattr(chain, "resolve_tenant", resolve)
    report = await chain.resolve_chain("seed.invalid", chain.ChainOptions(timeout=2.0))
    assert [result.domain for result in report.results] == ["seed.invalid"]
    assert report.truncated


@pytest.mark.asyncio
async def test_chain_depth_scales_total_budget_without_extending_one_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    elapsed = 0.0
    budgets: list[float] = []

    async def resolve(domain: str, *, timeout: float, **_kwargs: object):
        nonlocal elapsed
        budgets.append(timeout)
        elapsed += 2.0
        return _info(domain, (f"next-{len(budgets)}.invalid",)), []

    monkeypatch.setattr(chain, "time", SimpleNamespace(monotonic=lambda: elapsed))
    monkeypatch.setattr(chain, "resolve_tenant", resolve)
    report = await chain.resolve_chain("seed.invalid", chain.ChainOptions(timeout=2.0, depth=2))
    assert budgets == [2.0, 2.0]
    assert len(report.results) == 2
    assert report.truncated
