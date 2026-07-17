#!/usr/bin/env python3
"""Ratchet guard against god files in recon_tool/.

A module that grows to thousands of lines is hard to read, review, and test —
the classic "god file" smell. This guard caps NEW modules at SOFT_CAP lines and
records the current oversized modules in BASELINE as ceilings that may only
*shrink*: a baselined file fails CI if it grows past its recorded size, and the
``--update`` mode refuses to raise any ceiling (decomposition ratchets down,
never back up). Lines are counted live, so the check is always accurate.

    python scripts/check_file_size.py            # enforce (CI / parity gate)
    python scripts/check_file_size.py --update    # lock in shrinkage after a split

Exit 0 when every module is within its ceiling; non-zero otherwise.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "src" / "recon_tool"

# New modules must come in under this. Mature guidance puts a module that needs
# splitting somewhere around here; recon's own already-decomposed modules sit
# well below it.
SOFT_CAP = 1000

# Ceilings for the modules that predate the guard. These are a to-do list, not
# a blessing: each may only decrease. Lower them (via --update) as the
# decomposition track in docs/roadmap.md splits each file. Goal state: every
# entry gone, every module under SOFT_CAP.
BASELINE: dict[str, int] = {
    "formatter/panel.py": 1974,
    "exposure.py": 859,
    "merger.py": 805,
}


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _current_sizes() -> dict[str, int]:
    out: dict[str, int] = {}
    for p in sorted(_PKG.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        out[p.relative_to(_PKG).as_posix()] = _line_count(p)
    return out


def _enforce() -> int:
    sizes = _current_sizes()
    violations: list[str] = []
    for rel, n in sizes.items():
        ceiling = BASELINE.get(rel, SOFT_CAP)
        if n > ceiling:
            kind = "over baseline ceiling" if rel in BASELINE else f"over the {SOFT_CAP}-line cap for new modules"
            violations.append(f"  {rel}: {n} lines {kind} ({ceiling})")
    # A baselined file that shrank below its ceiling should have its ceiling
    # lowered — surface it as a (non-failing) nudge so the ratchet keeps tightening.
    nudges = [f"  {rel}: now {sizes.get(rel, 0)} lines, baseline {b} — run --update to lock it in"
              for rel, b in BASELINE.items() if rel in sizes and sizes[rel] < b]
    if violations:
        print("FAIL: file-size ratchet violated:")
        print("\n".join(violations))
        print("\nSplit the module (see docs/engineering-practices.md) — do not raise the cap.")
        return 1
    print(f"OK: all {len(sizes)} modules within their ceilings (SOFT_CAP={SOFT_CAP}).")
    if nudges:
        print("Ratchet can tighten:")
        print("\n".join(nudges))
    return 0


def _update() -> int:
    """Rewrite this file's BASELINE to current sizes — but only ever lowering."""
    sizes = _current_sizes()
    new_baseline: dict[str, int] = {}
    for rel, old in BASELINE.items():
        cur = sizes.get(rel)
        if cur is None:  # file split away entirely — drop it
            print(f"  dropped {rel} (no longer present)")
            continue
        if cur > old:
            print(f"FAIL: {rel} grew {old} -> {cur}; fix the growth, do not bless it.")
            return 1
        new_baseline[rel] = cur
    # Any module now over SOFT_CAP that is not already baselined would need a new
    # entry — but we refuse to add one automatically; it must be split instead.
    for rel, n in sizes.items():
        if rel not in BASELINE and n > SOFT_CAP:
            print(f"FAIL: {rel} is {n} lines (> {SOFT_CAP}) and not baselined; split it, do not baseline new debt.")
            return 1
    _rewrite_baseline(new_baseline)
    print(f"Updated BASELINE ({len(new_baseline)} entries).")
    return 0


def _rewrite_baseline(new_baseline: dict[str, int]) -> None:
    text = Path(__file__).read_text(encoding="utf-8")
    start = text.index("BASELINE: dict[str, int] = {")
    end = text.index("}", start) + 1
    body = "\n".join(f'    "{rel}": {n},' for rel, n in sorted(new_baseline.items(), key=lambda kv: -kv[1]))
    block = "BASELINE: dict[str, int] = {\n" + body + "\n}"
    Path(__file__).write_text(text[:start] + block + text[end:], encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ratchet guard against god files.")
    parser.add_argument("--update", action="store_true", help="Lock in shrinkage (lower ceilings only).")
    args = parser.parse_args(argv)
    return _update() if args.update else _enforce()


if __name__ == "__main__":
    sys.exit(main())
