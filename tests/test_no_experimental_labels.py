"""The EXPERIMENTAL-label CI gate must catch labels and allow prose.

`scripts/check_no_experimental_labels.py` enforces the v2.0 bar of zero
active EXPERIMENTAL labels on user-facing surfaces, while deliberately
allowing past-tense prose discussion of the historical label. The line
between "active label" and "allowed prose" is the gate's whole job, so
these tests pin both sides against synthetic fixtures (via the script's
optional path argument) plus a sanity run over the real surfaces.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = REPO_ROOT / "scripts" / "check_no_experimental_labels.py"

# Shapes the gate must flag as an active label.
_ACTIVE_LABELS = [
    "Fusion layer (EXPERIMENTAL) ships behind a flag.",
    "Fusion layer [EXPERIMENTAL] ships behind a flag.",
    "EXPERIMENTAL: this surface may change.",
    "EXPERIMENTAL -- this surface may change.",
    "EXPERIMENTAL at the start of a line.",
    "Stable, EXPERIMENTAL, and deprecated tiers exist.",
    "The flag is EXPERIMENTAL )",
    "| Fusion | **experimental** | behind a flag |",
    "Help text: [EXPERIMENTAL v1.9] fusion posteriors.",
]

# Shapes the gate must NOT flag: past-tense / process prose.
_ALLOWED_PROSE = [
    "The fusion layer was experimental in v1.9.x before the v2.0 lock.",
    "This documents the experimental to stable transition.",
    "Earlier releases marked these surfaces experimental; v2.0 promoted them.",
    "An experimental design was considered and rejected.",
]


def _run(*paths: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script.
        [sys.executable, str(_SCRIPT), *[str(p) for p in paths]],
        capture_output=True,
        text=True,
        check=False,
    )


def _write(tmp_path: Path, name: str, lines: list[str]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_each_active_label_shape_is_flagged(tmp_path: Path) -> None:
    for i, line in enumerate(_ACTIVE_LABELS):
        f = _write(tmp_path, f"label_{i}.md", ["intro line", line, "trailing line"])
        result = _run(f)
        assert result.returncode == 1, f"missed active label: {line!r}\n{result.stdout}"
        assert "FAIL:" in result.stdout


def test_allowed_prose_does_not_trip_the_gate(tmp_path: Path) -> None:
    f = _write(tmp_path, "prose.md", _ALLOWED_PROSE)
    result = _run(f)
    assert result.returncode == 0, f"prose wrongly flagged:\n{result.stdout}"
    assert "OK:" in result.stdout


def test_reports_line_numbers_for_each_hit(tmp_path: Path) -> None:
    f = _write(tmp_path, "mixed.md", ["clean line", "feature (EXPERIMENTAL) here", "clean", "EXPERIMENTAL: note"])
    result = _run(f)
    assert result.returncode == 1
    assert "  2: " in result.stdout
    assert "  4: " in result.stdout


def test_missing_file_is_skipped_not_an_error(tmp_path: Path) -> None:
    # scan_file returns no hits for a non-existent path, so an absent
    # target is silently clean rather than a crash.
    result = _run(tmp_path / "does-not-exist.md")
    assert result.returncode == 0
    assert "OK:" in result.stdout


def test_real_surfaces_pass() -> None:
    # The default (no-argument) run over the real user-facing surfaces
    # must stay green: this is the gate as CI invokes it.
    result = subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script.
        [sys.executable, str(_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "OK:" in result.stdout
