"""Traceability gate: the trust docs' references must resolve.

``docs/assurance-case.md`` and ``docs/traceability-matrix.md`` map each
promise to the test that proves it. The first test below IS the CI
gate: it runs ``scripts/check_traceability.py`` over both docs, so a
renamed or deleted test breaks the build instead of silently orphaning
the doc row. The remaining tests prove the checker actually catches a
broken reference and ignores prose, so a green gate means "every
reference resolves", not "the checker matched nothing".
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = REPO_ROOT / "scripts" / "check_traceability.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script, no untrusted input.
        [sys.executable, str(_CHECKER), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def test_trust_docs_references_all_resolve() -> None:
    result = _run()
    assert result.returncode == 0, (
        f"traceability references broke:\n{result.stdout}\n"
        "Update docs/assurance-case.md / docs/traceability-matrix.md to match the renamed or moved test/code."
    )
    assert "OK:" in result.stdout


def test_checker_catches_a_missing_test_reference(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("Proven by `test_no_such_file::test_no_such_function`.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert "test_no_such_file::test_no_such_function" in result.stdout


def test_checker_catches_a_missing_source_constant(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text("Bound by `recon_tool/http.py::_NO_SUCH_CONSTANT`.", encoding="utf-8")
    result = _run(str(doc))
    assert result.returncode == 1
    assert "_NO_SUCH_CONSTANT" in result.stdout


def test_checker_accepts_method_referenced_without_its_class(tmp_path: Path) -> None:
    # The assurance case references methods as file::method without the
    # class; the checker accepts a single-segment chain anywhere in the
    # file but stays strict on Class::method chains.
    doc = tmp_path / "doc.md"
    doc.write_text(
        "`test_security::test_cname_target_match_is_label_aware` and `test_resilience_hardening::TestHttpBounds`.",
        encoding="utf-8",
    )
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout


def test_checker_ignores_prose_and_flags(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "Prose tokens like `--fusion`, `sparse=true`, `recon doctor`, "
        "`data/fingerprints/*`, and `NodeConflict.magnitude` are not references.",
        encoding="utf-8",
    )
    result = _run(str(doc))
    assert result.returncode == 0, result.stdout
