"""MCP import and runtime logging preserve host state and explicit opt-in."""

from __future__ import annotations

import logging
import subprocess
import sys

import pytest

from recon_tool.server.runtime import log_structured


@pytest.mark.parametrize("enabled", [False, True])
def test_embedded_request_events_require_opt_in(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, enabled: bool
) -> None:
    monkeypatch.setenv("RECON_MCP_LOG_REQUESTS", str(enabled))
    with caplog.at_level(logging.INFO, logger="recon"):
        log_structured(logging.INFO, "resolved", domain="example.com")
    expected = '{"msg": "resolved", "domain": "example.com"}'
    assert caplog.messages == ([expected] if enabled else [])


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_http_request_logging_requires_opt_in_and_restores_host(configured: bool, enabled: bool) -> None:
    probe = f"""
import io
import logging
import os
from contextlib import redirect_stderr
import httpx

os.environ["RECON_MCP_LOG_REQUESTS"] = {str(enabled)!r}
root = logging.getLogger()
stream = io.StringIO()
handler = logging.StreamHandler(stream)
if {configured!r}:
    root.addHandler(handler)
    root.setLevel(logging.INFO)
before = (root.handlers[:], root.level)
import recon_tool.server as server
assert (root.handlers, root.level) == before
names = ("recon", "recon_tool", "httpx", "httpcore")
levels = [logging.getLogger(name).level for name in names]
try:
    with redirect_stderr(stream), server._runtime_logging():
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            client.get("https://example.com/private-query")
        raise RuntimeError("synthetic failure")
except RuntimeError:
    pass
assert (root.handlers, root.level) == before
assert [logging.getLogger(name).level for name in names] == levels
expected = 'HTTP Request: GET https://example.com/private-query "HTTP/1.1 200 OK"' + chr(10)
assert stream.getvalue() == (expected if {enabled!r} else "")
"""
    result = subprocess.run(  # noqa: S603 - fixed interpreter and synthetic, test-owned probe.
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr
