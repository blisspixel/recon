"""Unit tests for the v1.8 vertical-baseline anomaly rules in profiles.py.

Covers:
- Profile YAML loader picks up expected_categories and expected_motifs.
- compute_baseline_anomalies returns no observations when profile is None
  or when the profile has no expectations.
- Each missing expected category surfaces one observation.
- Each missing expected motif surfaces one observation.
- Observations are hedged ("absence is observable, not a verdict") and
  use category="consistency" / salience="medium".
- Detected categories / motifs suppress their respective expectation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_tool.profiles import (
    Profile,
    compute_baseline_anomalies,
    load_profile,
    reload_profiles,
)


class TestProfileSchemaExtension:
    @pytest.fixture(autouse=True)
    def _reset_profile_cache(self):
        reload_profiles()
        yield
        reload_profiles()

    def test_fintech_has_expected_categories(self):
        p = load_profile("fintech")
        assert p is not None
        assert len(p.expected_categories) >= 1

    def test_fintech_has_expected_motifs(self):
        p = load_profile("fintech")
        assert p is not None
        assert "cloudflare_to_aws" in p.expected_motifs

    def test_loader_handles_missing_fields(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        # A profile without expected_* fields should still load.
        custom_dir = tmp_path / "profiles"
        custom_dir.mkdir()
        (custom_dir / "minimal.yaml").write_text("name: minimal\n")
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        reload_profiles()
        p = load_profile("minimal")
        assert p is not None
        assert p.expected_categories == ()
        assert p.expected_motifs == ()


class TestComputeBaselineAnomalies:
    def test_none_profile_returns_empty(self):
        assert compute_baseline_anomalies(None, ("microsoft365",), ()) == ()

    def test_profile_without_expectations_returns_empty(self):
        p = Profile(name="empty")
        assert compute_baseline_anomalies(p, ("microsoft365",), ()) == ()

    def test_missing_expected_category_fires(self):
        p = Profile(name="strict", expected_categories=("Security",))
        anomalies = compute_baseline_anomalies(p, ("microsoft365",), ())
        assert len(anomalies) == 1
        assert anomalies[0].category == "consistency"
        assert anomalies[0].salience == "medium"
        assert "Security" in anomalies[0].statement
        assert "absence is observable" in anomalies[0].statement

    def test_present_category_suppresses_anomaly(self):
        # microsoft365 lives in "Email & Communication" category.
        p = Profile(name="strict", expected_categories=("Email & Communication",))
        anomalies = compute_baseline_anomalies(p, ("microsoft365",), ())
        assert anomalies == ()

    def test_missing_expected_motif_fires(self):
        p = Profile(name="strict", expected_motifs=("cloudflare_to_aws",))
        anomalies = compute_baseline_anomalies(p, (), ())
        assert len(anomalies) == 1
        assert "cloudflare_to_aws" in anomalies[0].statement
        assert "absence is observable" in anomalies[0].statement

    def test_present_motif_suppresses_anomaly(self):
        p = Profile(name="strict", expected_motifs=("cloudflare_to_aws",))
        anomalies = compute_baseline_anomalies(p, (), ("cloudflare_to_aws",))
        assert anomalies == ()

    def test_motif_match_case_insensitive(self):
        p = Profile(name="strict", expected_motifs=("Cloudflare_to_AWS",))
        anomalies = compute_baseline_anomalies(p, (), ("cloudflare_to_aws",))
        assert anomalies == ()

    def test_multiple_missing_each_surface(self):
        p = Profile(
            name="strict",
            expected_categories=("Security", "Identity & Auth"),
            expected_motifs=("cloudflare_to_aws", "fastly_to_aws"),
        )
        anomalies = compute_baseline_anomalies(p, (), ())
        assert len(anomalies) == 4

    def test_observation_language_is_neutral(self):
        p = Profile(name="strict", expected_categories=("Security",))
        anomalies = compute_baseline_anomalies(p, (), ())
        statement = anomalies[0].statement
        # Hedge keywords present
        assert "absence is observable" in statement
        assert "verdict" in statement
        # Verdict / commanding language NOT present
        for forbidden in ("must", "should fix", "vulnerability", "broken"):
            assert forbidden not in statement.lower()
