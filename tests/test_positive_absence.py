"""Tests for the legacy positive_when_absent comparison-set engine.

Covers:
- Signal schema parses positive_when_absent correctly.
- evaluate_positive_absence fires only when the parent signal fires AND
  none of the listed slugs are detected.
- Bounded non-observation language is present in the emitted description.
- The observation does NOT fire when any one of the listed slugs is present.
- Signals without positive_when_absent never produce absence observations.
- No built-in rule uses this context-poor comparison feature.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.absence import evaluate_positive_absence
from recon_tool.models import SignalContext
from recon_tool.signals import Signal, SignalMatch, evaluate_signals, load_signals, reload_signals


def _ctx(slugs: set[str]) -> SignalContext:
    return SignalContext(detected_slugs=frozenset(slugs))


def _names(matches: list[SignalMatch]) -> set[str]:
    return {m.name for m in matches}


# ── Schema ──────────────────────────────────────────────────────────────


class TestSchema:
    def test_signal_has_positive_when_absent_field(self):
        sig = Signal(
            name="T",
            category="Test",
            confidence="low",
            description="",
            candidates=("x",),
            min_matches=1,
            positive_when_absent=("slack", "notion"),
        )
        assert sig.positive_when_absent == ("slack", "notion")

    def test_default_is_empty_tuple(self):
        sig = Signal(
            name="T",
            category="Test",
            confidence="low",
            description="",
            candidates=("x",),
            min_matches=1,
        )
        assert sig.positive_when_absent == ()

    def test_loads_from_yaml(self):
        """Built-in rules do not infer meaning from generic non-observation."""
        reload_signals()
        assert not any(signal.positive_when_absent for signal in load_signals())


# ── Evaluation ──────────────────────────────────────────────────────────


class TestEvaluation:
    def test_fires_when_parent_fires_and_slugs_absent(self):
        parent = Signal(
            name="P",
            category="Test",
            confidence="high",
            description="",
            candidates=("a", "b"),
            min_matches=2,
            positive_when_absent=("consumer",),
        )
        fired = [SignalMatch(name="P", category="Test", confidence="high", matched=("a", "b"))]
        out = evaluate_positive_absence(fired, (parent,), frozenset({"a", "b"}))
        assert len(out) == 1
        assert "P: Configured Indicators Not Observed" in _names(out)
        assert out[0].category == "Absence"
        assert out[0].confidence == "low"

    def test_does_not_fire_when_any_listed_slug_present(self):
        parent = Signal(
            name="P",
            category="Test",
            confidence="high",
            description="",
            candidates=("a",),
            min_matches=1,
            positive_when_absent=("consumer-x", "consumer-y"),
        )
        fired = [SignalMatch(name="P", category="Test", confidence="high", matched=("a",))]
        # A listed comparison indicator disqualifies the absence observation.
        out = evaluate_positive_absence(fired, (parent,), frozenset({"a", "consumer-x"}))
        assert out == []

    def test_does_not_fire_when_parent_did_not_fire(self):
        parent = Signal(
            name="P",
            category="Test",
            confidence="high",
            description="",
            candidates=("a",),
            min_matches=1,
            positive_when_absent=("consumer",),
        )
        # Parent not in fired list, so there is no derived observation.
        out = evaluate_positive_absence([], (parent,), frozenset({"a"}))
        assert out == []

    def test_does_not_fire_for_signals_without_field(self):
        parent = Signal(
            name="P",
            category="Test",
            confidence="high",
            description="",
            candidates=("a",),
            min_matches=1,
        )  # no positive_when_absent
        fired = [SignalMatch(name="P", category="Test", confidence="high", matched=("a",))]
        out = evaluate_positive_absence(fired, (parent,), frozenset({"a"}))
        assert out == []

    def test_description_is_bounded_and_non_inferential(self):
        parent = Signal(
            name="P",
            category="Test",
            confidence="high",
            description="",
            candidates=("a",),
            min_matches=1,
            positive_when_absent=("x",),
        )
        fired = [SignalMatch(name="P", category="Test", confidence="high", matched=("a",))]
        out = evaluate_positive_absence(fired, (parent,), frozenset({"a"}))
        desc = out[0].description.lower()
        assert "bounded non-observation" in desc
        assert "does not establish" in desc
        assert not any(term in desc for term in ("hardening", "dormant", "parked", "small shop"))

    def test_name_has_configured_absence_suffix(self):
        parent = Signal(
            name="My Signal",
            category="Test",
            confidence="high",
            description="",
            candidates=("a",),
            min_matches=1,
            positive_when_absent=("x",),
        )
        fired = [SignalMatch(name="My Signal", category="Test", confidence="high", matched=("a",))]
        out = evaluate_positive_absence(fired, (parent,), frozenset({"a"}))
        assert out[0].name.startswith("My Signal")
        assert "Configured Indicators Not Observed" in out[0].name


# ── End-to-end retirement for built-in Edge Layering ───────────────────


class TestEdgeLayeringIntegration:
    def test_does_not_infer_hardening_on_proxy_only_target(self):
        reload_signals()
        ctx = _ctx({"cloudflare", "akamai"})
        fired = evaluate_signals(ctx)
        observations = evaluate_positive_absence(fired, load_signals(), ctx.detected_slugs)
        assert observations == []

    def test_does_not_fire_when_consumer_saas_present(self):
        """No built-in comparison observation fires with extra SaaS either."""
        reload_signals()
        ctx = _ctx({"cloudflare", "akamai", "slack"})
        fired = evaluate_signals(ctx)
        observations = evaluate_positive_absence(fired, load_signals(), ctx.detected_slugs)
        assert observations == []

    def test_does_not_fire_without_edge_layering(self):
        """Only one edge indicator also yields no comparison observation."""
        reload_signals()
        ctx = _ctx({"cloudflare"})
        fired = evaluate_signals(ctx)
        observations = evaluate_positive_absence(fired, load_signals(), ctx.detected_slugs)
        assert observations == []


# ── Invalid YAML handling ───────────────────────────────────────────────


class TestYamlValidation:
    def test_non_list_positive_when_absent_falls_back_to_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A non-list value for positive_when_absent should log a warning
        and fall back to empty tuple, not crash the loader."""
        cfg = tmp_path / "signals.yaml"
        cfg.write_text(
            "signals:\n"
            "  - name: Custom Bad\n"
            "    category: Test\n"
            "    confidence: low\n"
            "    description: test\n"
            "    requires:\n"
            "      any: [aws-ses]\n"
            "    positive_when_absent: not-a-list\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        reload_signals()
        sigs = {s.name: s for s in load_signals()}
        assert "Custom Bad" in sigs
        assert sigs["Custom Bad"].positive_when_absent == ()
        reload_signals()
        monkeypatch.delenv("RECON_CONFIG_DIR", raising=False)
        reload_signals()

    def test_non_string_entry_falls_back_to_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        cfg = tmp_path / "signals.yaml"
        cfg.write_text(
            "signals:\n"
            "  - name: Custom Bad 2\n"
            "    category: Test\n"
            "    confidence: low\n"
            "    description: test\n"
            "    requires:\n"
            "      any: [aws-ses]\n"
            "    positive_when_absent:\n"
            "      - slack\n"
            "      - 42\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        reload_signals()
        sigs = {s.name: s for s in load_signals()}
        assert sigs["Custom Bad 2"].positive_when_absent == ()
        reload_signals()
        monkeypatch.delenv("RECON_CONFIG_DIR", raising=False)
        reload_signals()
