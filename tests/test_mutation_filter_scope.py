"""Deterministic scope checks for the Bayesian mutation exclusions."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_BAYESIAN = _ROOT / "src" / "recon_tool" / "bayesian.py"


def _annotation_nodes(tree: ast.AST) -> set[ast.AST]:
    annotations: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            typed_args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if node.args.vararg is not None:
                typed_args.append(node.args.vararg)
            if node.args.kwarg is not None:
                typed_args.append(node.args.kwarg)
            for arg in typed_args:
                if arg.annotation is not None:
                    annotations.update(ast.walk(arg.annotation))
            if node.returns is not None:
                annotations.update(ast.walk(node.returns))
        elif isinstance(node, ast.AnnAssign):
            annotations.update(ast.walk(node.annotation))
    return annotations


def test_no_mutate_pragmas_cover_only_postponed_annotation_unions() -> None:
    source = _BAYESIAN.read_text(encoding="utf-8")
    tree = ast.parse(source)
    future_annotations = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    annotation_nodes = _annotation_nodes(tree)
    bit_or_nodes = {
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
    }
    annotation_lines = {node.lineno for node in bit_or_nodes if node in annotation_nodes}
    runtime_lines = {node.lineno for node in bit_or_nodes if node not in annotation_nodes}
    pragma_lines = {
        line_number
        for line_number, line in enumerate(source.splitlines(), start=1)
        if "# pragma: no mutate" in line
    }

    assert future_annotations
    assert annotation_lines
    assert runtime_lines
    assert pragma_lines == annotation_lines
    assert pragma_lines.isdisjoint(runtime_lines)


def test_mutation_config_keeps_runtime_unions_in_scope() -> None:
    config = tomllib.loads((_ROOT / "mutation.toml").read_text(encoding="utf-8"))
    exclusions = config["cosmic-ray"]["filters"]["operators-filter"]["exclude-operators"]
    workflow = (_ROOT / ".github" / "workflows" / "mutation.yml").read_text(encoding="utf-8")

    assert all("BitOr" not in exclusion for exclusion in exclusions)
    assert "cr-filter-pragma mutation.sqlite" in workflow
