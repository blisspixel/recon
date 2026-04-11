"""Tests for the new composite and consistency signals added in v0.1.1."""

from __future__ import annotations

from recon_tool.signals import evaluate_signals


class TestNewSignals:
    def test_shadow_it_risk(self):
        results = evaluate_signals({"canva", "dropbox", "zoom"})
        names = {r.name for r in results}
        assert "Shadow IT Risk" in names

    def test_shadow_it_risk_needs_three(self):
        results = evaluate_signals({"canva", "dropbox"})
        names = {r.name for r in results}
        assert "Shadow IT Risk" not in names

    def test_zero_trust_posture(self):
        results = evaluate_signals({"okta", "zscaler", "crowdstrike"})
        names = {r.name for r in results}
        assert "Zero Trust Posture" in names

    def test_zero_trust_posture_needs_three(self):
        results = evaluate_signals({"okta", "zscaler"})
        names = {r.name for r in results}
        assert "Zero Trust Posture" not in names

    def test_startup_tool_mix(self):
        results = evaluate_signals({"vercel", "github", "slack", "figma"})
        names = {r.name for r in results}
        assert "Startup Tool Mix" in names

    def test_startup_tool_mix_needs_four(self):
        results = evaluate_signals({"vercel", "github", "slack"})
        names = {r.name for r in results}
        assert "Startup Tool Mix" not in names

    def test_dual_email_provider(self):
        results = evaluate_signals({"microsoft365", "google-workspace"})
        names = {r.name for r in results}
        assert "Dual Email Provider" in names

    def test_dual_email_provider_needs_both(self):
        results = evaluate_signals({"microsoft365"})
        names = {r.name for r in results}
        assert "Dual Email Provider" not in names
