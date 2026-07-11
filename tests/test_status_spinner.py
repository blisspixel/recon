"""The lookup status must stay truthful and outcome-neutral."""

from __future__ import annotations

import asyncio

import pytest

from recon_tool.cli_lookup import _CHAIN_STATUS_MESSAGE, _STATUS_MESSAGE, _run_with_status


def test_status_message_is_general_and_truthful() -> None:
    assert _STATUS_MESSAGE == "Collecting and correlating public evidence..."
    lower = _STATUS_MESSAGE.lower()
    for unobserved_phase in ("dns", "certificate", "identity", "posture", "passive"):
        assert unobserved_phase not in lower


def test_chain_status_describes_the_selected_operation() -> None:
    assert _CHAIN_STATUS_MESSAGE == "Following related-domain evidence..."


class _FakeStatus:
    def __enter__(self) -> _FakeStatus:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class _FakeConsole:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def status(self, message: str) -> _FakeStatus:
        self.messages.append(message)
        return _FakeStatus()


def test_returns_coroutine_result_unchanged() -> None:
    async def quick() -> str:
        return "result"

    console = _FakeConsole()
    out = asyncio.run(_run_with_status(console, quick()))

    assert out == "result"
    assert console.messages == [_STATUS_MESSAGE]


def test_propagates_exceptions() -> None:
    async def boom() -> None:
        raise ValueError("lookup failed")

    with pytest.raises(ValueError, match="lookup failed"):
        asyncio.run(_run_with_status(_FakeConsole(), boom()))


def test_slow_lookup_does_not_simulate_phase_changes() -> None:
    async def slow() -> str:
        await asyncio.sleep(0.02)
        return "done"

    console = _FakeConsole()
    out = asyncio.run(_run_with_status(console, slow()))

    assert out == "done"
    assert console.messages == [_STATUS_MESSAGE]
