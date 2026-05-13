"""Tests for the MCP catalog resources.

Agents browse `recon://fingerprints`, `recon://signals`, and
`recon://profiles` to learn what recon can detect without spending a
tool invocation on introspection. Each resource is expected to return
a deterministic JSON projection over the respective in-memory catalog.

These tests exercise the underlying resource functions directly
(they are module-level callables registered via `@mcp.resource`).
"""

from __future__ import annotations

import json

from recon_tool.fingerprints import load_fingerprints
from recon_tool.profiles import list_profiles
from recon_tool.server import (
    _resource_fingerprints,
    _resource_profiles,
    _resource_signals,
)
from recon_tool.signals import load_signals


class TestFingerprintsResource:
    def test_returns_valid_json(self) -> None:
        payload = json.loads(_resource_fingerprints())

        assert isinstance(payload, dict)
        assert "count" in payload
        assert "fingerprints" in payload

    def test_count_matches_loaded_catalog(self) -> None:
        payload = json.loads(_resource_fingerprints())

        assert payload["count"] == len(load_fingerprints())
        assert len(payload["fingerprints"]) == payload["count"]

    def test_entry_shape_is_agent_friendly(self) -> None:
        payload = json.loads(_resource_fingerprints())
        entry = payload["fingerprints"][0]

        for key in (
            "slug",
            "name",
            "category",
            "confidence",
            "m365",
            "match_mode",
            "detection_count",
            "detection_types",
        ):
            assert key in entry, f"missing field: {key}"
        assert isinstance(entry["detection_types"], list)
        assert entry["detection_count"] >= 1


class TestSignalsResource:
    def test_returns_valid_json(self) -> None:
        payload = json.loads(_resource_signals())

        assert isinstance(payload, dict)
        assert "count" in payload
        assert "signals" in payload

    def test_count_matches_loaded_catalog(self) -> None:
        payload = json.loads(_resource_signals())

        assert payload["count"] == len(load_signals())
        assert len(payload["signals"]) == payload["count"]

    def test_entry_includes_relationships(self) -> None:
        payload = json.loads(_resource_signals())
        entry = payload["signals"][0]

        for key in (
            "name",
            "category",
            "confidence",
            "description",
            "candidates",
            "min_matches",
            "contradicts",
            "requires_signals",
            "positive_when_absent",
        ):
            assert key in entry, f"missing field: {key}"


class TestProfilesResource:
    def test_returns_valid_json(self) -> None:
        payload = json.loads(_resource_profiles())

        assert isinstance(payload, dict)
        assert "count" in payload
        assert "profiles" in payload

    def test_count_matches_loaded_catalog(self) -> None:
        payload = json.loads(_resource_profiles())

        assert payload["count"] == len(list_profiles())
        assert len(payload["profiles"]) == payload["count"]

    def test_built_in_profiles_present(self) -> None:
        payload = json.loads(_resource_profiles())
        names = {p["name"] for p in payload["profiles"]}

        # Documented built-ins — if any of these disappear, surface it.
        for expected in {"fintech", "healthcare", "saas-b2b", "high-value-target"}:
            assert expected in names, f"missing built-in profile: {expected}"

    def test_boost_maps_are_serializable(self) -> None:
        payload = json.loads(_resource_profiles())

        for entry in payload["profiles"]:
            assert isinstance(entry["category_boost"], dict)
            assert isinstance(entry["signal_boost"], dict)
            for v in entry["category_boost"].values():
                assert isinstance(v, int | float)
