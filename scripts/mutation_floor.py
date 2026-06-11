"""Mutation-gate score floor with explicit semantics.

Reads a cosmic-ray session DB and fails when the survival rate exceeds
the floor. Replaces ``cr-rate`` in the gate because cr-rate divides
kills by every recorded result, which counts filter-SKIPPED jobs (the
equivalent-by-construction annotation mutants) as if they had survived
and silently inflates the rate. Here the semantics are explicit:

    rate = survived / (killed + survived)

Skipped jobs are excluded (they were never tested); incompetent results
(worker errors) are reported and also fail the gate when present in
quantity, since a broken worker means the score measures nothing.

Usage::

    python scripts/mutation_floor.py mutation.sqlite --fail-over 5
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def summarize(session: Path) -> dict[str, int]:
    db = sqlite3.connect(f"file:{session}?mode=ro", uri=True)
    try:
        rows = db.execute("select test_outcome, worker_outcome from work_results").fetchall()
        (total_jobs,) = db.execute("select count(*) from work_items").fetchone()
    finally:
        db.close()
    counts = {
        "total_jobs": total_jobs,
        "killed": sum(1 for t, _ in rows if t == "KILLED"),
        "survived": sum(1 for t, _ in rows if t == "SURVIVED"),
        "incompetent": sum(1 for t, _ in rows if t == "INCOMPETENT"),
        "skipped": sum(1 for _, w in rows if w == "SKIPPED"),
        "results": len(rows),
    }
    counts["pending"] = total_jobs - counts["results"]
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", type=Path, help="cosmic-ray session DB")
    parser.add_argument(
        "--fail-over",
        type=float,
        default=5.0,
        help="Maximum tested-mutant survival rate, as a percentage (default 5).",
    )
    parser.add_argument(
        "--max-incompetent",
        type=int,
        default=1,
        help=(
            "Incompetent results tolerated before failing (default 1: cosmic-ray "
            "8.4.6's ExceptionReplacer deterministically crashes on one parso node "
            "shape in this module, recorded in validation/mutation-gate.md). More "
            "than the tolerance means a broken worker environment."
        ),
    )
    args = parser.parse_args()
    if not args.session.is_file():
        print(f"FAIL: session file not found: {args.session}")
        return 1

    c = summarize(args.session)
    tested = c["killed"] + c["survived"]
    rate = (100.0 * c["survived"] / tested) if tested else 0.0
    print(
        f"jobs={c['total_jobs']} tested={tested} killed={c['killed']} survived={c['survived']} "
        f"skipped={c['skipped']} incompetent={c['incompetent']} pending={c['pending']}"
    )
    print(f"survival rate over tested mutants: {rate:.2f}% (floor {args.fail_over:.2f}%)")

    if c["pending"]:
        print(f"FAIL: {c['pending']} job(s) never ran; the score is not a full-sweep number.")
        return 1
    if c["incompetent"] > args.max_incompetent:
        print(
            f"FAIL: {c['incompetent']} incompetent result(s) (tolerance {args.max_incompetent}); "
            "fix the worker environment before scoring."
        )
        return 1
    if not tested:
        print("FAIL: no tested mutants; nothing was measured.")
        return 1
    if rate > args.fail_over:
        print(
            "FAIL: survival exceeds the floor. Kill the survivors with tests, or accept any genuine "
            "equivalents explicitly in validation/mutation-gate.md."
        )
        return 1
    print("OK: survival is at or under the floor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
