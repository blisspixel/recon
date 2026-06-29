from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED_DIRS = (
    ROOT / "src" / "recon_tool",
    ROOT / "scripts",
    ROOT / "tests",
    ROOT / "validation",
)
FORBIDDEN_PLACEHOLDER_MARKERS = tuple(
    "".join(parts)
    for parts in (
        ("TO", "DO"),
        ("FIX", "ME"),
        ("X", "XX"),
        ("HA", "CK"),
        ("Not", "Implemented"),
    )
)
FORBIDDEN_PLACEHOLDER_PATTERNS = {
    marker: re.compile(rf"\b{re.escape(marker)}\b") for marker in FORBIDDEN_PLACEHOLDER_MARKERS
}


def _python_files() -> list[Path]:
    paths: list[Path] = []
    for directory in SCANNED_DIRS:
        paths.extend(path for path in directory.rglob("*.py") if "__pycache__" not in path.parts)
    return sorted(paths)


def test_runtime_tests_and_maintainer_python_have_no_pass_statements() -> None:
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Pass):
                rel = path.relative_to(ROOT).as_posix()
                offenders.append(f"{rel}:{node.lineno}")

    assert offenders == []


def test_runtime_tests_and_maintainer_python_have_no_placeholder_markers() -> None:
    offenders: list[str] = []
    for path in _python_files():
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for marker, pattern in FORBIDDEN_PLACEHOLDER_PATTERNS.items():
                if pattern.search(line):
                    offenders.append(f"{rel}:{lineno}: {marker}")

    assert offenders == []
