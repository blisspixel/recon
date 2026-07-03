"""Tests for the fingerprint freshness mechanism (verified date + auditor).

The ``verified`` date is advisory metadata: it does not affect matching, but it
drives a no-network freshness summary so the catalog's staleness is visible.
"""

from __future__ import annotations

from recon_tool.fingerprint_audit import _verified_age_days, summarize_fingerprint_freshness
from recon_tool.fingerprints import DetectionRule, Fingerprint, _parse_verified, load_fingerprints


def test_parse_verified_accepts_iso_date_and_drops_junk() -> None:
    assert _parse_verified("2026-07-03", "x", "src") == "2026-07-03"
    assert _parse_verified("", "x", "src") == ""
    assert _parse_verified(None, "x", "src") == ""
    # A present-but-malformed value is dropped, never raised.
    assert _parse_verified("not-a-date", "x", "src") == ""
    assert _parse_verified("07/03/2026", "x", "src") == ""


def test_verified_age_days() -> None:
    assert _verified_age_days("2026-07-01", "2026-07-03") == 2
    assert _verified_age_days("2025-07-03", "2026-07-03") == 365
    # Passes the loader's format regex but is not a real calendar date.
    assert _verified_age_days("2026-13-45", "2026-07-03") is None


def _fp(slug: str, verified: str) -> Fingerprint:
    return Fingerprint(
        name=slug,
        slug=slug,
        category="Cloud",
        confidence="high",
        m365=False,
        detections=(DetectionRule(type="cname_target", pattern=f"{slug}.example.com", verified=verified),),
    )


def test_summarize_fingerprint_freshness_counts() -> None:
    fps = (_fp("a", "2026-06-01"), _fp("b", "2020-01-01"), _fp("c", ""))
    summary = summarize_fingerprint_freshness(fps, today="2026-07-03", stale_after_days=365)
    assert summary["total_detections"] == 3
    assert summary["dated_detections"] == 2
    assert summary["undated_detections"] == 1
    # b (2020-01-01) is older than a year; a (2026-06-01) is not.
    assert summary["stale_detections"] == 1
    assert summary["coverage_pct"] == round(100 * 2 / 3, 1)


def test_summarize_runs_on_real_catalog() -> None:
    summary = summarize_fingerprint_freshness(load_fingerprints(), today="2026-07-03")
    assert summary["total_detections"] > 0
    assert 0.0 <= summary["coverage_pct"] <= 100.0
