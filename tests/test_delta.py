"""Tests for the delta engine."""

import json
from pathlib import Path

import pytest

from recon_tool.delta import compute_delta, load_previous
from recon_tool.models import ConfidenceLevel, DeltaReport, TenantInfo


def _make_info(**overrides) -> TenantInfo:
    """Create a minimal TenantInfo with overrides."""
    defaults = dict(
        tenant_id="test-id",
        display_name="Test Corp",
        default_domain="test.com",
        queried_domain="test.com",
        confidence=ConfidenceLevel.HIGH,
        services=("ServiceA", "ServiceB"),
        slugs=("slug-a", "slug-b"),
        insights=("Signal One: slug-a, slug-b",),
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=5,
    )
    defaults.update(overrides)
    return TenantInfo(**defaults)


def _make_previous(**overrides) -> dict:
    """Create a minimal previous JSON dict with overrides."""
    defaults = dict(
        tenant_id="test-id",
        display_name="Test Corp",
        default_domain="test.com",
        queried_domain="test.com",
        confidence="high",
        services=["ServiceA", "ServiceB"],
        slugs=["slug-a", "slug-b"],
        insights=["Signal One: slug-a, slug-b"],
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=5,
    )
    defaults.update(overrides)
    return defaults


class TestLoadPrevious:
    def test_load_valid_json(self, tmp_path: Path):
        f = tmp_path / "prev.json"
        f.write_text(json.dumps({"services": ["A"]}))
        result = load_previous(f)
        assert result == {"services": ["A"]}

    def test_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_previous(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path: Path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_previous(f)

    def test_non_object_json(self, tmp_path: Path):
        f = tmp_path / "array.json"
        f.write_text(json.dumps([1, 2, 3]))
        with pytest.raises(ValueError, match="Expected JSON object"):
            load_previous(f)


class TestComputeDelta:
    def test_no_changes(self):
        info = _make_info()
        prev = _make_previous()
        delta = compute_delta(prev, info)
        assert not delta.has_changes
        assert delta.added_services == ()
        assert delta.removed_services == ()

    def test_added_services(self):
        info = _make_info(services=("ServiceA", "ServiceB", "ServiceC"))
        prev = _make_previous(services=["ServiceA", "ServiceB"])
        delta = compute_delta(prev, info)
        assert delta.has_changes
        assert "ServiceC" in delta.added_services

    def test_removed_services(self):
        info = _make_info(services=("ServiceA",))
        prev = _make_previous(services=["ServiceA", "ServiceB"])
        delta = compute_delta(prev, info)
        assert "ServiceB" in delta.removed_services

    def test_added_and_removed_slugs(self):
        info = _make_info(slugs=("slug-a", "slug-c"))
        prev = _make_previous(slugs=["slug-a", "slug-b"])
        delta = compute_delta(prev, info)
        assert "slug-c" in delta.added_slugs
        assert "slug-b" in delta.removed_slugs

    def test_changed_auth_type(self):
        info = _make_info(auth_type="Managed")
        prev = _make_previous(auth_type="Federated")
        delta = compute_delta(prev, info)
        assert delta.changed_auth_type == ("Federated", "Managed")

    def test_changed_dmarc_policy(self):
        info = _make_info(dmarc_policy="none")
        prev = _make_previous(dmarc_policy="reject")
        delta = compute_delta(prev, info)
        assert delta.changed_dmarc_policy == ("reject", "none")

    def test_changed_confidence(self):
        info = _make_info(confidence=ConfidenceLevel.LOW)
        prev = _make_previous(confidence="high")
        delta = compute_delta(prev, info)
        assert delta.changed_confidence == ("high", "low")

    def test_changed_domain_count(self):
        info = _make_info(domain_count=10)
        prev = _make_previous(domain_count=5)
        delta = compute_delta(prev, info)
        assert delta.changed_domain_count == (5, 10)

    def test_missing_fields_in_old_json(self):
        """Older JSON missing newer fields should not error."""
        info = _make_info()
        prev = {"services": ["ServiceA", "ServiceB"]}  # minimal old format
        delta = compute_delta(prev, info)
        # Should not raise, missing fields treated as absent
        assert isinstance(delta, DeltaReport)

    def test_signal_extraction(self):
        info = _make_info(insights=("Signal One: slug-a", "Signal Two: slug-b, slug-c"))
        prev = _make_previous(insights=["Signal One: slug-a"])
        delta = compute_delta(prev, info)
        assert "Signal Two" in delta.added_signals

    def test_ordering_independent(self):
        """Services in different order should not show as changes."""
        info = _make_info(services=("B", "A", "C"))
        prev = _make_previous(services=["C", "A", "B"])
        delta = compute_delta(prev, info)
        assert not delta.added_services
        assert not delta.removed_services
