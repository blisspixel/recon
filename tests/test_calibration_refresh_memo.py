from __future__ import annotations

from pathlib import Path

from scripts.check_validation_hygiene import find_violations

ROOT = Path(__file__).resolve().parents[1]
MEMO = ROOT / "validation" / "2026-06-28-full-corpus-calibration-refresh.md"


def test_full_corpus_refresh_memo_is_aggregate_only_and_current() -> None:
    text = MEMO.read_text(encoding="utf-8")

    for required in (
        "No apexes, subdomains, organization names, tenant IDs, or per-domain rows are included.",
        "ECE fixed-bin",
        "ECE equal-mass",
        "0.0761",
        "0.0651",
        "0.3747",
        "0.3263",
        "0.0471",
        "0.044",
        "0.3636",
    ):
        assert required in text

    for forbidden in (
        "runs-private",
        "corpus-private",
        "validation/local",
        "run_dir",
        "queried_domain",
        "default_domain",
        "tenant_id",
    ):
        assert forbidden not in text


def test_full_corpus_refresh_memo_passes_validation_hygiene() -> None:
    violations = find_violations(ROOT, [str(MEMO.relative_to(ROOT))])

    assert violations == []
