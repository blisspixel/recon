"""Tests for the source-level retry helper."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from recon_tool.retry import retry_on_transient  # type: ignore[reportPrivateImportUsage]


@pytest.mark.asyncio
async def test_success_on_first_attempt_no_retry() -> None:
    """A successful call should not trigger any retries."""
    call_count = 0

    @retry_on_transient()
    async def ok() -> str:
        nonlocal call_count
        call_count += 1
        return "ok"

    assert await ok() == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retries_on_transient_then_succeeds() -> None:
    """A transient failure is retried and the next success is returned."""
    call_count = 0

    @retry_on_transient(attempts=2, delays=(0.01, 0.01))
    async def flaky() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise httpx.ConnectError("reset by peer")
        return "recovered"

    assert await flaky() == "recovered"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retries_exhausted_reraises() -> None:
    """After exhausting retries, the last transient exception is raised."""
    call_count = 0

    @retry_on_transient(attempts=2, delays=(0.01, 0.01))
    async def always_fails() -> str:
        nonlocal call_count
        call_count += 1
        raise httpx.TimeoutException("timed out")

    with pytest.raises(httpx.TimeoutException):
        await always_fails()
    assert call_count == 3  # original + 2 retries


@pytest.mark.asyncio
async def test_non_transient_exception_not_retried() -> None:
    """A non-transient exception (e.g. ValueError) is raised immediately."""
    call_count = 0

    @retry_on_transient(attempts=2, delays=(0.01, 0.01))
    async def bad() -> str:
        nonlocal call_count
        call_count += 1
        raise ValueError("semantic failure")

    with pytest.raises(ValueError, match="semantic failure"):
        await bad()
    assert call_count == 1  # no retries for non-transient


@pytest.mark.asyncio
async def test_asyncio_timeout_is_transient() -> None:
    """asyncio.TimeoutError is treated as transient and retried."""
    call_count = 0

    @retry_on_transient(attempts=2, delays=(0.01, 0.01))
    async def timing_out() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise asyncio.TimeoutError()
        return "ok"

    assert await timing_out() == "ok"
    assert call_count == 3


@pytest.mark.asyncio
async def test_httpx_read_error_is_transient() -> None:
    """httpx.ReadError is treated as transient and retried."""
    call_count = 0

    @retry_on_transient(attempts=1, delays=(0.01,))
    async def read_err() -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.ReadError("eof")
        return "ok"

    assert await read_err() == "ok"
    assert call_count == 2


@pytest.mark.asyncio
async def test_attempts_zero_means_no_retry() -> None:
    """attempts=0 means the decorator is a pass-through — original call only."""
    call_count = 0

    @retry_on_transient(attempts=0, delays=())
    async def fails_once() -> str:
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("nope")

    with pytest.raises(httpx.ConnectError):
        await fails_once()
    assert call_count == 1


@pytest.mark.asyncio
async def test_delays_tuple_too_short_raises_at_decoration_time() -> None:
    """If delays has fewer entries than attempts, decoration fails loudly."""
    with pytest.raises(ValueError, match="delays"):
        retry_on_transient(attempts=3, delays=(0.1,))


@pytest.mark.asyncio
async def test_negative_attempts_raises_at_decoration_time() -> None:
    """Negative attempts is a programming error, not a runtime one."""
    with pytest.raises(ValueError, match="attempts"):
        retry_on_transient(attempts=-1, delays=())


@pytest.mark.asyncio
async def test_decorator_preserves_kwargs_and_args() -> None:
    """The decorator is transparent to argument forwarding."""

    @retry_on_transient(attempts=1, delays=(0.01,))
    async def echo(a: int, *, b: str = "x") -> tuple[int, str]:
        return (a, b)

    assert await echo(42, b="hello") == (42, "hello")


@pytest.mark.asyncio
async def test_method_on_class_works() -> None:
    """The decorator works on instance methods (self is correctly bound)."""

    class Source:
        def __init__(self) -> None:
            self.calls = 0

        @retry_on_transient(attempts=2, delays=(0.01, 0.01))
        async def lookup(self, domain: str) -> str:
            self.calls += 1
            if self.calls < 2:
                raise httpx.ConnectError("flaky")
            return f"ok:{domain}"

    s = Source()
    result = await s.lookup("example.com")
    assert result == "ok:example.com"
    assert s.calls == 2


@pytest.mark.asyncio
async def test_oserror_is_transient() -> None:
    """OSError (e.g. socket.gaierror subclass) is treated as transient."""
    call_count = 0

    @retry_on_transient(attempts=1, delays=(0.01,))
    async def oserr() -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise OSError("temp DNS failure")
        return "ok"

    assert await oserr() == "ok"
    assert call_count == 2
