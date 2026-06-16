"""Traceability checker: doc-referenced tests and code must exist.

``docs/assurance-case.md`` and ``docs/traceability-matrix.md`` map each
promise recon makes to the mechanism that implements it and the test
that proves it. Those references rot silently: a renamed test keeps
passing CI while the doc points at nothing. This gate parses every
backticked reference in the trust docs and verifies the target still
exists, via the AST, without importing or running anything.

Reference forms checked (anything else in backticks is ignored):

- ``tests/test_x.py::Node::node`` / ``test_x::Node`` / ``test_x.py``:
  the test file must exist and each ``::`` segment must be a class,
  function, or method defined in it (decorated and async defs count).
- ``::Node`` continuation: resolved against the most recent file
  reference earlier on the same line (the assurance case's shorthand).
- ``recon_tool/path.py::NAME``: the source file must define NAME as a
  function, class, or assignment target.
- bare ``test_*`` / ``Test*`` names: must be defined somewhere under
  ``tests/`` (a global AST index).
- bare file names with a known suffix (``.py``, ``.yml``, ``.yaml``,
  ``.md``, ``.toml``, ``.json``): must exist at the given path, or be
  findable in the conventional locations (workflows for YAML, ``docs/``
  / ``validation/`` for markdown, the package tree for Python).

Tokens containing spaces, globs, flags, or ``=`` are prose, not
references, and are skipped.

Usage::

    python scripts/check_traceability.py            # check the trust docs
    python scripts/check_traceability.py FILE...     # check specific files
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_DEFAULT_DOCS = (
    REPO_ROOT / "docs" / "assurance-case.md",
    REPO_ROOT / "docs" / "traceability-matrix.md",
)

_BACKTICK_RE = re.compile(r"`([^`]+)`")

# A backticked token that is prose or code, not a checkable reference.
_SKIP_CHARS = (" ", "*", "=", "(", "<", ">", "{", "$", ",", "|")

_KNOWN_SUFFIXES = (".py", ".yml", ".yaml", ".md", ".toml", ".json")

# Where a bare file name of each suffix may legitimately live.
_SEARCH_DIRS = {
    ".yml": (".github/workflows", "."),
    ".yaml": (".github/workflows", "src/recon_tool/data", "src/recon_tool/data/fingerprints", "."),
    ".md": ("docs", "validation", "."),
    ".toml": (".",),
    ".json": ("docs", "validation", "."),
    ".py": ("tests", "scripts", "validation", "src/recon_tool", "src/recon_tool/sources", "."),
}


def _defined_names(tree: ast.Module) -> dict[str, set[str]]:
    """Top-level defs/classes/assign targets, plus per-class member names.

    Returns ``{"": top_level_names, "ClassName": member_names, ...}``.
    """
    out: dict[str, set[str]] = {"": set()}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out[""].add(node.name)
        elif isinstance(node, ast.ClassDef):
            out[""].add(node.name)
            members: set[str] = set()
            for sub in node.body:
                if isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                    members.add(sub.name)
                elif isinstance(sub, ast.Assign):
                    members.update(t.id for t in sub.targets if isinstance(t, ast.Name))
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    members.add(sub.target.id)
            out[node.name] = members
        elif isinstance(node, ast.Assign):
            out[""].update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out[""].add(node.target.id)
    return out


class _Index:
    """Lazy AST index over the repo's Python files."""

    def __init__(self) -> None:
        self._files: dict[Path, dict[str, set[str]] | None] = {}
        self._global_test_names: set[str] | None = None

    def names(self, path: Path) -> dict[str, set[str]] | None:
        if path not in self._files:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                self._files[path] = None
            else:
                self._files[path] = _defined_names(tree)
        return self._files[path]

    def has_node_chain(self, path: Path, chain: list[str]) -> bool:
        names = self.names(path)
        if names is None:
            return False
        if len(chain) == 1:
            # ``file::name`` shorthand: accept the name wherever it is
            # defined in the file (top level or inside a class), the way
            # the assurance case references methods without their class.
            return any(chain[0] in scope_names for scope_names in names.values())
        scope = ""
        for segment in chain:
            if segment not in names.get(scope, set()):
                return False
            # Descend if the segment is an indexed class; otherwise any
            # further segment must be a member of it (one level deep).
            scope = segment if segment in names else ""
            if scope == "" and segment != chain[-1] and segment not in names:
                return False
        return True

    def test_name_defined_anywhere(self, name: str) -> bool:
        if self._global_test_names is None:
            found: set[str] = set()
            for path in (REPO_ROOT / "tests").rglob("test_*.py"):
                names = self.names(path)
                if names is None:
                    continue
                for scope_names in names.values():
                    found.update(scope_names)
            self._global_test_names = found
        return name in self._global_test_names


def _resolve_file(token_path: str) -> Path | None:
    """Resolve a file-shaped reference to an existing path, or None."""
    direct = REPO_ROOT / token_path
    if direct.is_file():
        return direct
    # src layout: the docs reference the package by its logical path
    # (recon_tool/x.py), which lives under src/. Resolve that rooted form too.
    src_rooted = REPO_ROOT / "src" / token_path
    if src_rooted.is_file():
        return src_rooted
    if "/" in token_path or "\\" in token_path:
        return None
    suffix = Path(token_path).suffix
    for base in _SEARCH_DIRS.get(suffix, ()):
        candidate = REPO_ROOT / base / token_path
        if candidate.is_file():
            return candidate
    return None


def _looks_like_reference(token: str) -> bool:
    if any(c in token for c in _SKIP_CHARS):
        return False
    if token.startswith("-"):
        return False
    return any(c.isalpha() for c in token)


def _check_token(token: str, last_file: Path | None, index: _Index) -> tuple[bool | None, Path | None]:
    """Check one token. Returns (ok, file_for_continuations).

    ``ok`` is None when the token is not a checkable reference.
    """
    if not _looks_like_reference(token):
        return None, last_file

    if "::" in token:
        file_part, *chain = token.split("::")
        if not file_part:
            if last_file is None:
                return False, None
            return index.has_node_chain(last_file, chain), last_file
        if not file_part.endswith(".py"):
            file_part += ".py"
        path = _resolve_file(file_part)
        if path is None and "/" not in file_part:
            path = _resolve_file(f"tests/{file_part}")
        if path is None:
            return False, None
        return index.has_node_chain(path, chain), path

    suffix = Path(token).suffix
    if suffix in _KNOWN_SUFFIXES:
        path = _resolve_file(token)
        if path is None:
            return False, last_file
        return True, path if suffix == ".py" else last_file

    if re.fullmatch(r"test_\w+", token):
        path = _resolve_file(f"tests/{token}.py")
        if path is not None:
            return True, path
        return index.test_name_defined_anywhere(token), last_file
    if re.fullmatch(r"Test[A-Z]\w*", token):
        return index.test_name_defined_anywhere(token), last_file

    return None, last_file


def check_file(doc: Path, index: _Index) -> list[str]:
    """Return a list of broken-reference messages for one document."""
    problems: list[str] = []
    try:
        display = str(doc.relative_to(REPO_ROOT))
    except ValueError:
        display = str(doc)
    for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), start=1):
        last_file: Path | None = None
        for match in _BACKTICK_RE.finditer(line):
            token = match.group(1)
            ok, last_file = _check_token(token, last_file, index)
            if ok is False:
                problems.append(f"{display}:{lineno}: unresolved reference `{token}`")
    return problems


def main(argv: list[str]) -> int:
    docs = [Path(a).resolve() for a in argv] if argv else [p for p in _DEFAULT_DOCS if p.exists()]
    index = _Index()
    problems: list[str] = []
    for doc in docs:
        if not doc.is_file():
            problems.append(f"{doc}: file not found")
            continue
        problems.extend(check_file(doc, index))
    if problems:
        print(f"FAIL: {len(problems)} unresolved traceability reference(s):")
        for p in problems:
            print(f"  {p}")
        print("Fix the reference, or rename it to match the moved test/code.")
        return 1
    print(f"OK: every checkable reference in {len(docs)} doc(s) resolves to existing tests/code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
