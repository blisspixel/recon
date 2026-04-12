"""Validation corpus integration tests.

Parametrized over JSON fixture files in tests/validation/fixtures/ (gitignored).
Each fixture defines a domain and subset expectations — listed items
must be present in the resolved output, additional items are acceptable.

Marked with @pytest.mark.integration — skipped by default.
Run with: pytest tests/validation/ -m integration
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recon_tool.resolver import resolve_tenant

_FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _discover_fixtures() -> list[Path]:
    """Find all fixture JSON files, returning empty list if dir missing."""
    if not _FIXTURE_DIR.is_dir():
        return []
    return sorted(_FIXTURE_DIR.glob("*.json"))


def _fixture_ids(fixtures: list[Path]) -> list[str]:
    return [f.stem for f in fixtures]


_FIXTURES = _discover_fixtures()


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fixture_path",
    _FIXTURES,
    ids=_fixture_ids(_FIXTURES),
)
async def test_validation_fixture(fixture_path: Path):
    """Validate a domain against its fixture expectations."""
    with open(fixture_path) as f:
        fixture = json.load(f)

    domain = fixture["domain"]
    info, _results = await resolve_tenant(domain)

    # Services: substring matching
    missing_services = [
        s for s in fixture["expected_services"] if not any(s.lower() in svc.lower() for svc in info.services)
    ]
    assert not missing_services, f"{domain}: missing services: {missing_services}"

    # Slugs: exact matching
    missing_slugs = [s for s in fixture["expected_slugs"] if s not in set(info.slugs)]
    assert not missing_slugs, f"{domain}: missing slugs: {missing_slugs}"

    # Signals: substring matching against insights
    missing_signals = [s for s in fixture["expected_signals"] if not any(s.lower() in i.lower() for i in info.insights)]
    assert not missing_signals, f"{domain}: missing signals: {missing_signals}"

    # Confidence range
    order = {"low": 0, "medium": 1, "high": 2}
    lo, hi = fixture["expected_confidence_range"]
    actual = order[info.confidence.value]
    assert order[lo] <= actual <= order[hi], f"{domain}: confidence {info.confidence.value} outside [{lo}, {hi}]"
