"""Section-link gate: every correlation.md cross-reference resolves.

``scripts/check_section_links.py`` parses correlation.md's headings and verifies
that every prose section reference and Markdown anchor across the repo points at
a real heading. The first test IS the CI gate, so a renumbering that orphans a
reference fails the build, the way the traceability matrix is gated.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = REPO_ROOT / "scripts" / "check_section_links.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script, no untrusted input.
        [sys.executable, str(_CHECKER), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def test_all_correlation_section_references_resolve() -> None:
    result = _run()
    assert result.returncode == 0, (
        f"dangling correlation.md section references:\n{result.stdout}\n"
        "Repoint them to a real section, or add the section to correlation.md."
    )
    assert "OK:" in result.stdout


def test_checker_catches_a_dead_section_reference(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    # Assemble the number at runtime so this test's own source does not read as a
    # real dead reference when the checker scans the repo (it scans tests/ too).
    bad = "9" + "9.9"
    doc.write_text(f"See correlation.md section {bad} for details.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert bad in result.stdout


def test_checker_catches_a_dead_whole_number_section_reference(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    bad = "9" + "99"
    doc.write_text(f"See correlation.md section {bad} for details.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert f"section {bad}" in result.stdout


def test_checker_validates_every_identifier_in_a_mixed_section_list(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    bad = "9" + "99"
    doc.write_text(f"See correlation.md sections 3.4 and {bad} for details.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert f"section {bad}" in result.stdout


def test_checker_accepts_current_whole_and_dotted_section_list(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("See correlation.md sections 3.4 and 5 for details.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout


def test_checker_catches_a_dead_markdown_anchor(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    anchor = "missing" + "-correlation-heading"
    doc.write_text(f"See [the model](correlation.md#{anchor}).", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert anchor in result.stdout


def test_checker_accepts_a_current_markdown_anchor(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "See [output semantics](correlation.md#11-orthogonal-output-semantics).",
        encoding="utf-8",
    )
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout


def test_checker_ignores_external_citations(tmp_path: Path) -> None:
    # A bare section mark on another work (not "correlation.md ...") is a
    # citation, not a self-reference, and must not be flagged.
    doc = tmp_path / "doc.md"
    doc.write_text("the virtual-evidence factor (Pearl 1988 section 2.3.3).", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout


def test_checker_ignores_version_numbers(tmp_path: Path) -> None:
    # A version near the file name is not a section reference.
    doc = tmp_path / "doc.md"
    doc.write_text("Final correlation.md proofread against the v2.0 bar.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout
