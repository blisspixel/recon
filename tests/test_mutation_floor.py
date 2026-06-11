"""The mutation-gate floor script decides the gate; pin its arithmetic.

`scripts/mutation_floor.py` reads a cosmic-ray session DB and decides
pass/fail for the mutation gate. Its whole reason to exist is that
`cr-rate` counts filter-skipped jobs as non-kills and inflates the rate;
this script scores survival over *tested* mutants only and fails outright
on pending or incompetent jobs. These tests build synthetic session DBs
(no cosmic-ray, no real mutants) and pin the survival math and every
exit condition, so a change to the gate's decision logic cannot slip
through untested.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = REPO_ROOT / "scripts" / "mutation_floor.py"


def _make_db(
    path: Path,
    *,
    killed: int = 0,
    survived: int = 0,
    incompetent: int = 0,
    skipped: int = 0,
    pending: int = 0,
) -> Path:
    """Build a minimal cosmic-ray-shaped session DB.

    ``work_items`` has one row per generated mutant; ``work_results`` has
    one row per completed mutant (killed / survived / incompetent /
    skipped). ``pending`` adds work_items with no result, the shape a
    half-finished sweep leaves behind.
    """
    rows: list[tuple[str | None, str]] = []
    rows += [("KILLED", "NORMAL")] * killed
    rows += [("SURVIVED", "NORMAL")] * survived
    rows += [("INCOMPETENT", "EXCEPTION")] * incompetent
    rows += [(None, "SKIPPED")] * skipped  # the operators-filter shape: no test_outcome
    total_jobs = len(rows) + pending

    conn = sqlite3.connect(path)
    try:
        conn.execute("create table work_items (job_id text)")
        conn.execute("create table work_results (test_outcome text, worker_outcome text, job_id text)")
        conn.executemany("insert into work_items values (?)", [(str(i),) for i in range(total_jobs)])
        conn.executemany(
            "insert into work_results values (?, ?, ?)",
            [(t, w, str(i)) for i, (t, w) in enumerate(rows)],
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _run(db: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script.
        [sys.executable, str(_SCRIPT), str(db), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_summary_line_counts(tmp_path: Path) -> None:
    # The printed summary is the audit trail in the CI log; pin every count.
    db = _make_db(tmp_path / "s.sqlite", killed=10, survived=3, incompetent=1, skipped=4, pending=2)
    out = _run(db, "--fail-over", "5").stdout
    assert "jobs=20" in out
    assert "tested=13" in out  # killed + survived
    assert "killed=10" in out
    assert "survived=3" in out
    assert "skipped=4" in out
    assert "incompetent=1" in out
    assert "pending=2" in out


def test_clean_pass_under_floor(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", killed=99, survived=1)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 0, r.stdout
    assert "OK:" in r.stdout
    assert "1.00%" in r.stdout


def test_floor_exceeded_fails(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", killed=90, survived=10)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 1
    assert "survival exceeds the floor" in r.stdout
    assert "10.00%" in r.stdout


def test_skipped_are_excluded_from_the_denominator(tmp_path: Path) -> None:
    # 5 survived of 95 tested is 5.26%, over the floor. If the 100 skipped
    # counted in the denominator (the cr-rate bug), the rate would read
    # 2.5% and wrongly pass. This pins the survived/(killed+survived) rule.
    db = _make_db(tmp_path / "s.sqlite", killed=90, survived=5, skipped=100)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 1
    assert "5.26%" in r.stdout


def test_pending_jobs_fail_even_under_floor(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", killed=100, survived=0, pending=10)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 1
    assert "never ran" in r.stdout


def test_incompetent_over_tolerance_fails(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", killed=98, survived=0, incompetent=2)
    r = _run(db, "--fail-over", "5", "--max-incompetent", "1")
    assert r.returncode == 1
    assert "incompetent result" in r.stdout


def test_one_incompetent_within_tolerance_passes(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", killed=98, survived=1, incompetent=1)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 0, r.stdout
    assert "OK:" in r.stdout


def test_no_tested_mutants_fails(tmp_path: Path) -> None:
    db = _make_db(tmp_path / "s.sqlite", skipped=50)
    r = _run(db, "--fail-over", "5")
    assert r.returncode == 1
    assert "no tested mutants" in r.stdout


def test_missing_session_file_fails(tmp_path: Path) -> None:
    r = _run(tmp_path / "does-not-exist.sqlite", "--fail-over", "5")
    assert r.returncode == 1
    assert "not found" in r.stdout
