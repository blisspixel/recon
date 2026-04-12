"""Tests for custom signals loading from ~/.recon/signals.yaml."""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.models import SignalContext
from recon_tool.signals import evaluate_signals, load_signals, reload_signals


def _ctx(slugs: set[str]) -> SignalContext:
    return SignalContext(detected_slugs=frozenset(slugs))


@pytest.fixture(autouse=True)
def _clear_signal_cache():
    """Clear signal cache before and after each test."""
    reload_signals()
    yield
    reload_signals()


@pytest.fixture
def custom_signals_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Create a temp dir and point RECON_CONFIG_DIR at it."""
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    return tmp_path


class TestCustomSignalsLoading:
    def test_custom_signals_are_additive(self, custom_signals_dir: Path):
        """Custom signals should be added to built-in signals."""
        builtin_count = len(load_signals())
        reload_signals()

        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text(
            "signals:\n"
            "  - name: Custom Test Signal\n"
            "    category: Custom\n"
            "    confidence: high\n"
            "    description: A test custom signal\n"
            "    requires:\n"
            "      any: [custom-slug-a, custom-slug-b]\n"
            "    min_matches: 1\n",
            encoding="utf-8",
        )
        reload_signals()
        all_signals = load_signals()
        assert len(all_signals) == builtin_count + 1
        names = {s.name for s in all_signals}
        assert "Custom Test Signal" in names

    def test_custom_signal_fires(self, custom_signals_dir: Path):
        """Custom signals should evaluate correctly."""
        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text(
            "signals:\n"
            "  - name: Healthcare Stack\n"
            "    category: Vertical\n"
            "    confidence: medium\n"
            "    requires:\n"
            "      any: [okta, crowdstrike, knowbe4]\n"
            "    min_matches: 2\n",
            encoding="utf-8",
        )
        reload_signals()
        results = evaluate_signals(_ctx({"okta", "crowdstrike"}))
        names = {r.name for r in results}
        assert "Healthcare Stack" in names

    def test_custom_signal_does_not_fire_below_threshold(self, custom_signals_dir: Path):
        """Custom signal should not fire if min_matches not met."""
        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text(
            "signals:\n"
            "  - name: Needs Three\n"
            "    requires:\n"
            "      any: [a, b, c]\n"
            "    min_matches: 3\n",
            encoding="utf-8",
        )
        reload_signals()
        results = evaluate_signals(_ctx({"a", "b"}))
        names = {r.name for r in results}
        assert "Needs Three" not in names

    def test_invalid_custom_signal_skipped(self, custom_signals_dir: Path):
        """Invalid custom signals should be skipped without breaking loading."""
        builtin_count = len(load_signals())
        reload_signals()

        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text(
            "signals:\n"
            "  - name: Valid Signal\n"
            "    requires:\n"
            "      any: [slug-x]\n"
            "  - bad_entry: true\n"
            "  - name: \"\"\n",
            encoding="utf-8",
        )
        reload_signals()
        all_signals = load_signals()
        # Only the valid one should be added
        assert len(all_signals) == builtin_count + 1

    def test_missing_custom_file_is_fine(self, custom_signals_dir: Path):
        """No custom file should not break loading."""
        signals = load_signals()
        assert len(signals) > 0  # Built-in signals still load

    def test_malformed_yaml_skipped(self, custom_signals_dir: Path):
        """Malformed YAML should be skipped with a warning."""
        builtin_count = len(load_signals())
        reload_signals()

        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text("{{{{not valid yaml", encoding="utf-8")
        reload_signals()
        all_signals = load_signals()
        assert len(all_signals) == builtin_count

    def test_empty_custom_file(self, custom_signals_dir: Path):
        """Empty custom file should not break loading."""
        builtin_count = len(load_signals())
        reload_signals()

        custom_yaml = custom_signals_dir / "signals.yaml"
        custom_yaml.write_text("", encoding="utf-8")
        reload_signals()
        all_signals = load_signals()
        assert len(all_signals) == builtin_count
