"""Doc-rot gate: Markdown that renders wrong on github.com fails the build.

``scripts/check_doc_rot.py`` rejects two silent failure classes taken from a
real incident: LaTeX delimiters GitHub does not render as math, and sections
hollowed out into pointers that still satisfy the section-link check. The first
test IS the CI gate, so a regression in the shipped docs fails the build.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.check_doc_rot import Finding, check_paths

REPO_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = REPO_ROOT / "scripts" / "check_doc_rot.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter + repo-local script, no untrusted input.
        [sys.executable, str(_CHECKER), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def _write(tmp_path: Path, body: str) -> Path:
    doc = tmp_path / "doc.md"
    doc.write_text(body, encoding="utf-8")
    return doc


def test_shipped_documentation_is_free_of_rot() -> None:
    result = _run()
    assert result.returncode == 0, (
        f"Markdown rendering or content defects:\n{result.stdout}\n"
        "Use $...$ or $$...$$ for math, and restore any section reduced to a pointer."
    )
    assert "OK:" in result.stdout


def test_inline_math_delimiter_is_rejected(tmp_path: Path) -> None:
    # Assembled at runtime so this test's own source stays clean for the gate.
    opener = "\\" + "("
    findings = check_paths([_write(tmp_path, f"## Heading\n\nThe value {opener}x{opener[0]})$ is set.\n")])

    assert [finding.check for finding in findings] == ["math-delimiter"]
    assert "$...$" in findings[0].detail


def test_display_math_delimiter_is_rejected(tmp_path: Path) -> None:
    opener = "\\" + "["
    findings = check_paths([_write(tmp_path, f"## Heading\n\n{opener}\nx = 1\n\\]\n")])

    assert [finding.check for finding in findings] == ["math-delimiter"]
    assert "$$...$$" in findings[0].detail


def test_dollar_math_is_accepted(tmp_path: Path) -> None:
    doc = _write(tmp_path, "## Heading\n\nInline $x$ and display:\n\n$$\ny = 2x\n$$\n\nDone.\n")

    assert check_paths([doc]) == []


def test_math_delimiters_inside_a_code_fence_are_ignored(tmp_path: Path) -> None:
    opener = "\\" + "["
    doc = _write(tmp_path, f"## Heading\n\n```latex\n{opener}\nx = 1\n\\]\n```\n\nProse.\n")

    assert check_paths([doc]) == []


def test_math_delimiters_inside_inline_code_are_ignored(tmp_path: Path) -> None:
    opener = "\\" + "("
    doc = _write(tmp_path, f"## Heading\n\nGitHub does not render `{opener} ... \\)` as math.\n")

    assert check_paths([doc]) == []


def test_unclosed_display_math_is_rejected(tmp_path: Path) -> None:
    findings = check_paths([_write(tmp_path, "## Heading\n\n$$\ny = 2x\n\nStranded prose.\n")])

    assert [finding.check for finding in findings] == ["display-math"]


def test_unsupported_math_macro_is_rejected(tmp_path: Path) -> None:
    doc = _write(tmp_path, "## Heading\n\n$\\operatorname{Atoms}(U)$ is defined.\n")

    findings = check_paths([doc])

    assert [finding.check for finding in findings] == ["math-macro"]
    assert "supported primitive notation" in findings[0].detail


def test_unsupported_math_macro_in_code_is_ignored(tmp_path: Path) -> None:
    doc = _write(
        tmp_path,
        "## Heading\n\nUse `\\operatorname` only when another renderer supports it.\n\n"
        "```latex\n\\operatorname{Atoms}(U)\n```\n",
    )

    assert check_paths([doc]) == []


def test_mermaid_reserved_class_name_is_rejected(tmp_path: Path) -> None:
    doc = _write(
        tmp_path,
        "## Heading\n\n```mermaid\nflowchart LR\n  A --> B\n  classDef graph fill:#fff\n```\n",
    )

    findings = check_paths([doc])

    assert [finding.check for finding in findings] == ["mermaid-identifier"]
    assert "does not render on github.com" in findings[0].detail


def test_mermaid_nonreserved_class_name_is_accepted(tmp_path: Path) -> None:
    doc = _write(
        tmp_path,
        "## Heading\n\n```mermaid\nflowchart LR\n  A --> B\n  classDef cooccurrence fill:#fff\n```\n",
    )

    assert check_paths([doc]) == []


def test_pointer_stub_section_is_rejected(tmp_path: Path) -> None:
    # The shape that survived three weeks: a heading kept only so historical
    # cross-references still resolve, carrying no content of its own.
    body = (
        "## Real section\n\n" + ("Substantive content. " * 40) + "\n\n### 4.4 Legacy validation-strategy anchor\n\n"
        "Historical changelog and validation records cite the former section 4.4. The\n"
        "current validation contract is section 8.\n"
    )
    findings = check_paths([_write(tmp_path, body)])

    assert [finding.check for finding in findings] == ["pointer-stub"]
    assert "4.4" in findings[0].detail


def test_short_section_without_redirect_language_is_accepted(tmp_path: Path) -> None:
    # Genuinely terse sections exist in this repository and must stay legal.
    doc = _write(tmp_path, "## Reporting vulnerabilities\n\nEmail the maintainer. Do not open a public issue.\n")

    assert check_paths([doc]) == []


def test_container_heading_with_subsections_is_accepted(tmp_path: Path) -> None:
    # A parent heading whose body is empty because subsections follow it is
    # ordinary structure, not a hollowed-out section.
    doc = _write(tmp_path, "## 3. Bayesian evidence semantics\n\n### 3.1 Units\n\n" + ("Content. " * 40) + "\n")

    assert check_paths([doc]) == []


def test_long_section_mentioning_another_section_is_accepted(tmp_path: Path) -> None:
    # Cross-referencing is normal writing. Only a section that is *nothing but*
    # a redirect is rejected, so length is what separates the two.
    doc = _write(
        tmp_path,
        "## Analysis\n\n" + ("Real analytical content. " * 40) + "\nFor the derivation see section 8.\n",
    )

    assert check_paths([doc]) == []


def test_findings_render_as_navigable_references(tmp_path: Path) -> None:
    opener = "\\" + "["
    findings = check_paths([_write(tmp_path, f"## Heading\n\n{opener}\nx\n\\]\n")])
    rendered = findings[0].render()

    # A path outside the repository must still report rather than raise, since
    # check_paths accepts arbitrary files.
    assert rendered.startswith(tmp_path.as_posix())
    assert f":{findings[0].line}: math-delimiter:" in rendered


def test_repository_findings_render_relative_to_the_root() -> None:
    finding = Finding(REPO_ROOT / "docs" / "correlation.md", 42, "math-delimiter", "detail")

    assert finding.render() == "docs/correlation.md:42: math-delimiter: detail"
