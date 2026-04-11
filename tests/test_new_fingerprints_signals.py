"""Tests for fingerprints and signals added in v0.1.1."""

from __future__ import annotations

from recon_tool.fingerprints import load_fingerprints
from recon_tool.signals import evaluate_signals, load_signals


class TestNewFingerprints:
    def test_fingerprint_count_increased(self):
        fps = load_fingerprints()
        assert len(fps) >= 155  # was 143, added 13

    def test_new_fingerprints_loaded(self):
        slugs = {fp.slug for fp in load_fingerprints()}
        for expected in ("box", "egnyte", "glean", "datadog", "newrelic",
                         "pagerduty", "render", "ping-identity", "cyberark",
                         "lakera", "cato", "rippling", "deel"):
            assert expected in slugs, f"Missing fingerprint: {expected}"


class TestNewSignals:
    def test_signal_count_increased(self):
        sigs = load_signals()
        assert len(sigs) >= 19  # was 16, added 3

    def test_observability_sre(self):
        results = evaluate_signals({"datadog", "pagerduty"})
        names = {r.name for r in results}
        assert "Observability & SRE" in names

    def test_observability_sre_needs_two(self):
        results = evaluate_signals({"datadog"})
        names = {r.name for r in results}
        assert "Observability & SRE" not in names

    def test_ai_security_posture(self):
        results = evaluate_signals({"openai", "lakera", "zscaler"})
        names = {r.name for r in results}
        assert "AI Security Posture" in names

    def test_ai_security_posture_needs_three(self):
        results = evaluate_signals({"openai", "lakera"})
        names = {r.name for r in results}
        assert "AI Security Posture" not in names

    def test_file_collaboration_sprawl(self):
        results = evaluate_signals({"dropbox", "box"})
        names = {r.name for r in results}
        assert "File Collaboration Sprawl" in names

    def test_file_collaboration_sprawl_needs_two(self):
        results = evaluate_signals({"dropbox"})
        names = {r.name for r in results}
        assert "File Collaboration Sprawl" not in names

    def test_zero_trust_includes_new_slugs(self):
        """Zero Trust should fire with new security slugs."""
        results = evaluate_signals({"ping-identity", "cato", "cyberark"})
        names = {r.name for r in results}
        assert "Zero Trust Posture" in names
