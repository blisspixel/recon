"""Shared test fixtures.

Auto-patches the cert intel HTTP calls in all non-integration tests to avoid
real network calls and timeouts per test. Also resets the global Rich Console
between tests so CliRunner-based tests get a fresh stdout binding rather than
inheriting a stale one from earlier tests that called set_console().
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _mock_crtsh():
    """Disable cert intel HTTP calls in all tests by default.

    Integration tests that need real cert intel can override this fixture.
    The cert intel detector is a bonus source — tests for DNS fingerprinting
    shouldn't depend on it or be slowed by its timeout.
    """

    async def _noop_cert_intel(ctx, domain):
        pass

    with patch("recon_tool.sources.dns._detect_cert_intel", _noop_cert_intel):
        yield


@pytest.fixture(autouse=True)
def _reset_global_console():
    """Reset the formatter's global Rich Console between tests.

    Several tests use ``set_console()`` to inject a StringIO-backed Console
    for output capture. If the previous test forgot to restore it, a later
    CliRunner-based test will write into the orphaned StringIO and see
    empty result.stdout. Setting _console = None forces ``get_console()``
    to construct a fresh Console bound to whatever sys.stdout the current
    test framework has captured.
    """
    import recon_tool.formatter as _formatter
    _formatter._console = None
    yield
    _formatter._console = None
