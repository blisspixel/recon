"""Shared test fixtures.

Auto-patches the cert intel HTTP calls in all non-integration tests to avoid
real network calls and timeouts per test.
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
