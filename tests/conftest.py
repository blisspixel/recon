"""Shared test fixtures.

Auto-patches the crt.sh HTTP call in all non-integration tests to avoid
real network calls and 8-second timeouts per test.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _mock_crtsh():
    """Disable crt.sh HTTP calls in all tests by default.

    Integration tests that need real crt.sh can override this fixture.
    The crt.sh detector is a bonus source — tests for DNS fingerprinting
    shouldn't depend on it or be slowed by its timeout.
    """
    async def _noop_crtsh(ctx, domain):
        pass

    with patch("recon_tool.sources.dns._detect_crtsh", _noop_crtsh):
        yield
