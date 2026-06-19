#!/usr/bin/env python3
"""Run the CI gate locally, one command with exact parity to CI.

The point is "green here means green in CI." The stages mirror the workflow's
deterministic, no-network jobs (lint, typecheck over the SAME scope CI uses,
the coverage-gated test run, and the catalog/label checks). Run it before every
push:

    python scripts/check.py          # full gate (what CI gates on)
    python scripts/check.py --fast   # skip the test run (lint + types + quick checks)

Each stage streams its own output; a summary table and a non-zero exit on any
failure follow. Network-only jobs (pip-audit) and binary-dependent ones
(actionlint) are intentionally out of scope here. They have their own CI jobs
and don't gate code correctness.

History: this exists because a local `pyright recon_tool/` (narrower than CI's
`pyright recon_tool/ tests/`) let a test-file type error reach CI red. The fix
is parity, encoded here once.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PY = sys.executable

# (group, label, argv): argv mirrors the CI run: commands and scopes exactly.
_CORE = "core"
_TEST = "test"
_STAGES: list[tuple[str, str, list[str]]] = [
    (_CORE, "ruff", [_PY, "-m", "ruff", "check", "."]),
    (_CORE, "pyright", [_PY, "-m", "pyright", "src/recon_tool/", "tests/"]),
    (
        _TEST,
        "pytest+cov",
        [_PY, "-m", "pytest", "tests/", "--cov=src/recon_tool", "--cov-branch", "--cov-fail-under=82", "-q"],
    ),
    (
        _CORE,
        "validate-fingerprints",
        [_PY, "scripts/validate_fingerprint.py", "src/recon_tool/data/fingerprints/", "--quiet"],
    ),
    (_CORE, "metadata-coverage", [_PY, "scripts/check_metadata_coverage.py"]),
    (_CORE, "validation-hygiene", [_PY, "scripts/check_validation_hygiene.py"]),
    (_CORE, "workflow-pins", [_PY, "scripts/check_workflow_pins.py"]),
    (_CORE, "surface-inventory", [_PY, "scripts/generate_surface_inventory.py", "--check"]),
    (_CORE, "cli-surface-doc", [_PY, "scripts/generate_surface_inventory.py", "--check-cli-surface"]),
    (_CORE, "no-experimental-labels", [_PY, "scripts/check_no_experimental_labels.py"]),
    (_CORE, "file-size-ratchet", [_PY, "scripts/check_file_size.py"]),
    (_CORE, "plr-ratchet", [_PY, "scripts/check_plr_ratchet.py"]),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CI gate locally (parity with ci.yml).")
    parser.add_argument("--fast", action="store_true", help="Skip the test run; lint + types + quick checks only.")
    args = parser.parse_args(argv)

    stages = [s for s in _STAGES if not (args.fast and s[0] == _TEST)]
    results: list[tuple[str, bool, float]] = []
    for _group, name, cmd in stages:
        print(f"\n\033[1m==> {name}\033[0m  ({' '.join(cmd[1:])})", flush=True)
        start = time.monotonic()
        rc = subprocess.run(cmd, cwd=_ROOT, check=False).returncode  # noqa: S603 - fixed dev-tool argv
        results.append((name, rc == 0, time.monotonic() - start))

    print("\n" + "=" * 60)
    failed = [n for n, ok, _ in results if not ok]
    for name, ok, dur in results:
        mark = "\033[32mok  \033[0m" if ok else "\033[31mFAIL\033[0m"
        print(f"  {mark} {name:<24} {dur:6.1f}s")
    print("=" * 60)
    if failed:
        print(f"\033[31m{len(failed)} stage(s) failed: {', '.join(failed)}\033[0m")
        if args.fast:
            print("(--fast skipped the test run; run without --fast before pushing)")
        return 1
    print("\033[32mAll gate stages passed." + (" (--fast: test run skipped)" if args.fast else "") + "\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
