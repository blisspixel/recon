"""The rotating status spinner must never change a lookup's outcome.

``_run_with_rotating_status`` cycles spinner messages while a lookup
runs. It is purely cosmetic, so these tests pin the contract that
matters: the awaited result is returned unchanged, exceptions
propagate, a slow lookup actually rotates the message, and a broken
status object still lets the lookup finish.
"""

from __future__ import annotations

import asyncio

import pytest

from recon_tool.cli import _STATUS_MESSAGES, _run_with_rotating_status


class _FakeStatus:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def __enter__(self) -> _FakeStatus:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def update(self, message: str) -> None:
        self.messages.append(message)


class _FakeConsole:
    def __init__(self, status: _FakeStatus) -> None:
        self._status = status

    def status(self, message: str) -> _FakeStatus:
        self._status.messages.append(message)
        return self._status


class _BrokenStatus(_FakeStatus):
    def update(self, message: str) -> None:
        raise RuntimeError("renderer exploded")


def test_returns_coroutine_result_unchanged() -> None:
    async def quick() -> str:
        return "result"

    status = _FakeStatus()
    out = asyncio.run(_run_with_rotating_status(_FakeConsole(status), quick()))
    assert out == "result"


def test_propagates_exceptions() -> None:
    async def boom() -> None:
        raise ValueError("lookup failed")

    status = _FakeStatus()
    with pytest.raises(ValueError, match="lookup failed"):
        asyncio.run(_run_with_rotating_status(_FakeConsole(status), boom()))


def test_rotates_message_while_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    # Shrink the rotation interval so a short sleep crosses several ticks.
    monkeypatch.setattr("recon_tool.cli._STATUS_ROTATE_SECONDS", 0.01)

    async def slow() -> str:
        await asyncio.sleep(0.05)
        return "done"

    status = _FakeStatus()
    out = asyncio.run(_run_with_rotating_status(_FakeConsole(status), slow()))
    assert out == "done"
    # The initial message plus at least one rotation.
    assert len(status.messages) >= 2
    assert all(m in _STATUS_MESSAGES for m in status.messages)


def test_broken_status_update_still_finishes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("recon_tool.cli._STATUS_ROTATE_SECONDS", 0.01)

    async def slow() -> str:
        await asyncio.sleep(0.05)
        return "ok"

    status = _BrokenStatus()
    out = asyncio.run(_run_with_rotating_status(_FakeConsole(status), slow()))
    assert out == "ok"
