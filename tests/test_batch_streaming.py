"""Bounded-memory behavior for streaming batch output."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from recon_tool.cli.batch import _batch_emit_ndjson, _batch_process_one
from recon_tool.models import ConfidenceLevel, TenantInfo


@pytest.mark.asyncio
async def test_ndjson_uses_a_bounded_rolling_task_window(capsys: pytest.CaptureFixture[str]) -> None:
    active = 0
    maximum_active = 0

    async def process_one(domain: str) -> dict[str, str]:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.001)
        active -= 1
        return {"domain": domain}

    domains = [f"domain-{index}.example" for index in range(50)]
    await _batch_emit_ndjson(domains, process_one, "\x00ERR:", max_pending=4)

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert maximum_active == 4
    assert len(records) == len(domains)
    assert {record["domain"] for record in records} == set(domains)


@pytest.mark.asyncio
@patch("recon_tool.resolver.resolve_tenant", new_callable=AsyncMock)
async def test_streaming_process_releases_success_without_batch_retention(mock_resolve: AsyncMock) -> None:
    info = TenantInfo(
        tenant_id="00000000-0000-0000-0000-000000000000",
        display_name="Example Organization",
        default_domain="example.com",
        queried_domain="example.com",
        confidence=ConfidenceLevel.HIGH,
    )
    mock_resolve.return_value = (info, [])

    result = await _batch_process_one(
        "example.com",
        semaphore=asyncio.Semaphore(1),
        batch_infos=None,
        timeout=1.0,
        skip_ct=True,
        fusion=False,
        json_output=False,
        ndjson=True,
        csv_output=False,
        markdown=False,
        include_unclassified=False,
        error_prefix="\x00ERR:",
    )

    assert isinstance(result, dict)
    assert result["queried_domain"] == "example.com"


@pytest.mark.asyncio
async def test_ndjson_cancellation_cancels_and_awaits_every_worker() -> None:
    all_started = asyncio.Event()
    blocker = asyncio.Event()
    started = 0
    cancelled = 0
    finished = 0

    async def process_one(_domain: str) -> dict[str, str]:
        nonlocal started, cancelled, finished
        started += 1
        if started == 4:
            all_started.set()
        try:
            await blocker.wait()
        except asyncio.CancelledError:
            cancelled += 1
            raise
        finally:
            finished += 1
        return {}

    streaming = asyncio.create_task(
        _batch_emit_ndjson([f"domain-{index}.example" for index in range(20)], process_one, "\x00ERR:", max_pending=4)
    )
    await asyncio.wait_for(all_started.wait(), timeout=1.0)
    streaming.cancel()

    with pytest.raises(asyncio.CancelledError):
        await streaming

    assert started == cancelled == finished == 4


@pytest.mark.asyncio
async def test_ndjson_worker_exception_cleans_up_other_workers() -> None:
    all_started = asyncio.Event()
    blocker = asyncio.Event()
    started = 0
    cancelled = 0
    finished = 0

    async def process_one(domain: str) -> dict[str, str]:
        nonlocal started, cancelled, finished
        started += 1
        if started == 4:
            all_started.set()
        try:
            await all_started.wait()
            if domain == "fail.example":
                raise RuntimeError("synthetic worker failure")
            await blocker.wait()
        except asyncio.CancelledError:
            cancelled += 1
            raise
        finally:
            finished += 1
        return {"domain": domain}

    with pytest.raises(RuntimeError, match="synthetic worker failure"):
        await _batch_emit_ndjson(
            ["fail.example", "a.example", "b.example", "c.example"],
            process_one,
            "\x00ERR:",
            max_pending=4,
        )

    assert started == finished == 4
    assert cancelled == 3
