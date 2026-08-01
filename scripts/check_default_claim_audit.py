#!/usr/bin/env python3
"""Fail closed when a material default claim surface lacks an audit owner."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_PATH = ROOT / "docs" / "default-claim-audit.json"
_SURFACE_INVENTORY_PATH = ROOT / "docs" / "surface-inventory.json"
_SCHEMA_PATH = ROOT / "docs" / "recon-schema.json"
_SCORE_FIELD = re.compile(
    r"(?:score|confidence|posterior|probability|modularity|n_eff|band|interval|"
    r"likelihood|llr|influence|entropy|stability|delta|(?:^|_)points?(?:_|$))",
    re.IGNORECASE,
)
_AUDIT_STATUSES = frozenset({"complete", "open"})
_CLASSIFICATIONS = frozenset(
    {
        "bounded_absence",
        "direct_observation",
        "documented_derivation",
        "non_claim_transport",
        "static_product_contract",
        "unresolved_when_unobservable",
    }
)
_LINEAGE_STATUSES = frozenset({"exact", "incomplete", "static"})
_REQUIRED_FAMILY_KEYS = frozenset(
    {
        "claim_id",
        "material",
        "classification",
        "subject_scope",
        "producer_paths",
        "evidence_path",
        "renderer_obligations",
        "regression_tests",
        "lineage_status",
        "audit_status",
        "limits",
    }
)
_EXPECTED_COVERAGE_GROUPS = frozenset(
    {
        "agent_guidance_sections",
        "insight_generators",
        "json_fields",
        "mcp_tools",
        "panel_producers",
        "recommendation_producers",
        "score_fields",
        "server_instruction_sections",
    }
)
_COMPACT_COVERAGE_GROUPS = frozenset({"json_fields", "mcp_tools"})
_EXPECTED_CONTRACT_KEYS = frozenset(
    {"json_definition_owners", "mcp_json_root_tools", "surface_digest_algorithm", "surface_digests"}
)
_SURFACE_DIGEST_ALGORITHM = "sha256(sorted UTF-8 surface IDs joined by LF)"
_ALLOWED_ROOT_REFERENCES = frozenset(
    {
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "ROADMAP.md",
        "SECURITY.md",
        "pyproject.toml",
    }
)
_REFERENCE_ROLE_DIRECTORIES = {
    "evidence_path": frozenset({"docs", "scripts", "src"}),
    "producer_paths": frozenset({"agents", "docs", "scripts", "src"}),
    "regression_tests": frozenset({"tests"}),
}
_MATERIAL_FORMATTER_FUNCTIONS = frozenset(
    {
        "format_chain_dict",
        "format_comparison_dict",
        "format_explanations_list",
        "format_posture_observations",
    }
)


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def load_claim_inventory(path: Path = DEFAULT_AUDIT_PATH) -> dict[str, Any]:
    """Load the canonical claim audit and reject malformed top-level shapes."""
    inventory = _json_object(path)
    if inventory.get("schema_version") != 1:
        raise ValueError("default claim audit schema_version must be 1")
    if not isinstance(inventory.get("coverage"), dict):
        raise ValueError("default claim audit coverage must be an object")
    if not isinstance(inventory.get("claim_families"), dict):
        raise ValueError("default claim audit claim_families must be an object")
    if not isinstance(inventory.get("coverage_contract"), dict):
        raise ValueError("default claim audit coverage_contract must be an object")
    return inventory


def _top_level_names(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return frozenset(names)


def _insight_generators() -> frozenset[str]:
    path = ROOT / "src" / "recon_tool" / "insights.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "_INSIGHT_GENERATORS" for target in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            raise ValueError("_INSIGHT_GENERATORS must remain a literal list for audit discovery")
        names = {item.id for item in node.value.elts if isinstance(item, ast.Name)}
        if len(names) != len(node.value.elts):
            raise ValueError("every _INSIGHT_GENERATORS entry must be a direct function reference")
        return frozenset(names)
    raise ValueError("_INSIGHT_GENERATORS was not found")


def _markdown_sections(path: Path) -> frozenset[str]:
    sections: set[str] = set()
    in_frontmatter = False
    fence_character: str | None = None
    fence_length = 0
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if index == 0 and line.strip() == "---":
            in_frontmatter = True
            continue
        if in_frontmatter:
            if line.strip() == "---":
                in_frontmatter = False
            continue
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence_character is not None:
            closing = re.match(r"^ {0,3}(`{3,}|~{3,})\s*$", line)
            if closing and closing.group(1)[0] == fence_character and len(closing.group(1)) >= fence_length:
                fence_character = None
                fence_length = 0
            continue
        if fence:
            fence_character = fence.group(1)[0]
            fence_length = len(fence.group(1))
            continue
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            sections.add(f"{path.relative_to(ROOT).as_posix()}#{match.group(2)}")
    return frozenset(sections)


def _agent_guidance_sections(surface_inventory: Mapping[str, Any]) -> frozenset[str]:
    agent_surfaces = surface_inventory.get("agent_surfaces")
    if not isinstance(agent_surfaces, Mapping):
        raise ValueError("surface inventory has no agent_surfaces object")
    files = agent_surfaces.get("guidance_files")
    if not isinstance(files, list):
        raise ValueError("surface inventory has no guidance_files array")
    configured_paths = {
        str(entry["path"]) for entry in files if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
    }
    discovered_paths = {
        "AGENTS.md",
        *((path.relative_to(ROOT).as_posix()) for path in (ROOT / "agents").rglob("*.md")),
    }
    if configured_paths != discovered_paths:
        missing = ", ".join(sorted(discovered_paths - configured_paths)) or "none"
        stale = ", ".join(sorted(configured_paths - discovered_paths)) or "none"
        raise ValueError(f"surface inventory guidance files differ from disk; missing={missing}; stale={stale}")
    sections: set[str] = set()
    for relative in discovered_paths:
        sections.update(_markdown_sections(ROOT / relative))
    return frozenset(sections)


def _server_instruction_sections() -> frozenset[str]:
    path = ROOT / "src" / "recon_tool" / "server" / "app.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "SERVER_INSTRUCTIONS" for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, str):
            raise ValueError("SERVER_INSTRUCTIONS must remain a literal string for audit discovery")
        headings = list(re.finditer(r"^##\s+(.+?)\s*$", value, re.MULTILINE))
        sections = {match.group(1).strip() for match in headings}
        if headings and value[: headings[0].start()].strip():
            sections.add("<preamble>")
        return frozenset(sections)
    raise ValueError("SERVER_INSTRUCTIONS was not found")


def _panel_producers() -> frozenset[str]:
    names: set[str] = set()
    formatter_root = ROOT / "src" / "recon_tool" / "formatter"
    for path in formatter_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(ROOT).as_posix()
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name.startswith(("_render_", "render_")) or node.name in _MATERIAL_FORMATTER_FUNCTIONS:
                names.add(f"{relative}#{node.name}")
    return frozenset(names)


def _recommendation_producers() -> frozenset[str]:
    names: set[str] = set()
    for path in (ROOT / "src" / "recon_tool").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        functions = tuple(node for node in tree.body if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)))
        producer_names = {
            node.name
            for node in functions
            if any(
                isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "HardeningGap"
                for child in ast.walk(node)
            )
        }
        while True:
            wrapper_names = {
                node.name
                for node in functions
                if any(
                    isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in producer_names
                    for child in ast.walk(node)
                )
            }
            expanded = producer_names | wrapper_names
            if expanded == producer_names:
                break
            producer_names = expanded
        relative = path.relative_to(ROOT).as_posix()
        names.update(f"{relative}#{name}" for name in producer_names)
    return frozenset(names)


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _json_property_fields(value: object, path: tuple[str, ...] = ()) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, Mapping):
        for raw_name, child in value.items():
            name = str(raw_name)
            child_path = (*path, _json_pointer_token(name))
            if path and path[-1] == "properties":
                pointer = "/".join(child_path)
                fields.add(f"docs/recon-schema.json#/{pointer}")
            fields.update(_json_property_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            fields.update(_json_property_fields(child, (*path, str(index))))
    return fields


def _typed_dict_score_fields() -> set[str]:
    names: set[str] = set()
    server_root = ROOT / "src" / "recon_tool" / "server"
    for path in server_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(ROOT).as_posix()
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            is_typed_dict = any(
                (isinstance(base, ast.Name) and base.id == "TypedDict")
                or (isinstance(base, ast.Attribute) and base.attr == "TypedDict")
                for base in node.bases
            )
            if not is_typed_dict:
                continue
            for child in node.body:
                if (
                    isinstance(child, ast.AnnAssign)
                    and isinstance(child.target, ast.Name)
                    and _SCORE_FIELD.search(child.target.id)
                ):
                    names.add(f"{relative}#{node.name}.{child.target.id}")
    return names


def _cli_score_fields() -> set[str]:
    fields: set[str] = set()
    cli_root = ROOT / "src" / "recon_tool" / "cli"
    for path in cli_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(ROOT).as_posix()
        for function in tree.body:
            if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(function):
                if not isinstance(node, ast.Dict):
                    continue
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and _SCORE_FIELD.search(key.value):
                        fields.add(f"{relative}#{function.name}.{key.value}")
    return fields


def _mcp_surfaces(tools: object) -> set[str]:
    if not isinstance(tools, list):
        raise ValueError("surface inventory has no MCP tools array")
    surfaces: set[str] = set()
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            raise ValueError("surface inventory MCP tool entries must have string names")
        name = str(tool["name"])
        surfaces.add(name)
        output_schema = tool.get("output_schema")
        if not isinstance(output_schema, Mapping) or not isinstance(output_schema.get("properties"), list):
            raise ValueError(f"surface inventory MCP tool {name} has no output-schema property list")
        for field in output_schema["properties"]:
            if not isinstance(field, str) or not field:
                raise ValueError(f"surface inventory MCP tool {name} has an invalid output property")
            surfaces.add(f"{name}#{field}")
    return surfaces


def discover_surfaces(root: Path = ROOT) -> dict[str, frozenset[str]]:
    """Return every fail-closed surface set governed by the claim audit."""
    if root.resolve() != ROOT.resolve():
        raise ValueError("surface discovery is anchored to the repository containing this script")
    schema = _json_object(_SCHEMA_PATH)
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        raise ValueError("root JSON schema has no properties object")
    surface_inventory = _json_object(_SURFACE_INVENTORY_PATH)
    mcp = surface_inventory.get("mcp")
    if not isinstance(mcp, Mapping):
        raise ValueError("surface inventory has no MCP object")
    json_fields = _json_property_fields(schema)
    score_names = {field for field in json_fields if _SCORE_FIELD.search(field.rsplit("/", maxsplit=1)[-1])}
    score_names.update(_typed_dict_score_fields())
    score_names.update(_cli_score_fields())
    return {
        "agent_guidance_sections": _agent_guidance_sections(surface_inventory),
        "insight_generators": _insight_generators(),
        "json_fields": frozenset(json_fields),
        "mcp_tools": frozenset(_mcp_surfaces(mcp.get("tools"))),
        "panel_producers": _panel_producers(),
        "recommendation_producers": _recommendation_producers(),
        "score_fields": frozenset(score_names),
        "server_instruction_sections": _server_instruction_sections(),
    }


def _mapping(value: object, label: str, problems: list[str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        problems.append(f"coverage.{label} must be an object")
        return {}
    mapped: dict[str, str] = {}
    for key, family in value.items():
        if not isinstance(key, str) or not isinstance(family, str) or not family:
            problems.append(f"coverage.{label} entries must map non-empty strings to claim-family IDs")
            continue
        mapped[key] = family
    return mapped


def _string_set(value: object, label: str, problems: list[str]) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        problems.append(f"coverage_contract.{label} must be an array of non-empty strings")
        return frozenset()
    if len(value) != len(set(value)):
        problems.append(f"coverage_contract.{label} must not contain duplicates")
    return frozenset(value)


def _surface_digest(surfaces: Iterable[str]) -> str:
    payload = "\n".join(sorted(surfaces)).encode()
    return hashlib.sha256(payload).hexdigest()


def _current_surface_digests() -> dict[str, str]:
    discovered = discover_surfaces()
    return {group: _surface_digest(discovered[group]) for group in sorted(_COMPACT_COVERAGE_GROUPS)}


def _contract_mappings(
    value: object,
    problems: list[str],
) -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    if not isinstance(value, Mapping):
        problems.append("coverage_contract must be an object")
        return {}, {}, frozenset()
    keys = frozenset(str(key) for key in value)
    missing = sorted(_EXPECTED_CONTRACT_KEYS - keys)
    extra = sorted(keys - _EXPECTED_CONTRACT_KEYS)
    if missing:
        problems.append(f"coverage_contract keys missing: {', '.join(missing)}")
    if extra:
        problems.append(f"unknown coverage_contract keys: {', '.join(extra)}")
    if value.get("surface_digest_algorithm") != _SURFACE_DIGEST_ALGORITHM:
        problems.append(f"coverage_contract.surface_digest_algorithm must be {_SURFACE_DIGEST_ALGORITHM!r}")
    owners = _mapping(value.get("json_definition_owners"), "contract.json_definition_owners", problems)
    digests = _mapping(value.get("surface_digests"), "contract.surface_digests", problems)
    mcp_json_root_tools = _string_set(value.get("mcp_json_root_tools"), "mcp_json_root_tools", problems)
    return owners, digests, mcp_json_root_tools


def _json_surface_owner_key(surface: str) -> tuple[str, str] | None:
    prefix = "docs/recon-schema.json#/"
    if not surface.startswith(prefix):
        return None
    parts = surface.removeprefix(prefix).split("/")
    if len(parts) >= 2 and parts[0] == "properties":
        return "root", parts[1]
    if len(parts) >= 3 and parts[0] == "$defs" and parts[2] == "properties":
        return "definition", parts[1]
    return None


def _expand_json_coverage(
    mapped: Mapping[str, str],
    owners: Mapping[str, str],
    expected: frozenset[str],
    problems: list[str],
) -> dict[str, str]:
    root_fields: set[str] = set()
    definitions: set[str] = set()
    expanded: dict[str, str] = {}
    for surface in expected:
        owner_key = _json_surface_owner_key(surface)
        if owner_key is None:
            problems.append(f"coverage.json_fields cannot resolve surface: {surface}")
            continue
        owner_kind, key = owner_key
        if owner_kind == "root":
            root_fields.add(key)
            family = mapped.get(key)
        else:
            definitions.add(key)
            family = owners.get(key)
        if family is not None:
            expanded[surface] = family
    missing_roots = sorted(root_fields - frozenset(mapped))
    stale_roots = sorted(frozenset(mapped) - root_fields)
    missing_definitions = sorted(definitions - frozenset(owners))
    stale_definitions = sorted(frozenset(owners) - definitions)
    if missing_roots:
        problems.append(f"coverage.json_fields missing root fields: {', '.join(missing_roots)}")
    if stale_roots:
        problems.append(f"coverage.json_fields has stale root fields: {', '.join(stale_roots)}")
    if missing_definitions:
        problems.append(f"coverage_contract.json_definition_owners missing: {', '.join(missing_definitions)}")
    if stale_definitions:
        problems.append(f"coverage_contract.json_definition_owners has stale entries: {', '.join(stale_definitions)}")
    return expanded


def _expand_mcp_coverage(
    mapped: Mapping[str, str],
    json_root_owners: Mapping[str, str],
    json_root_tools: frozenset[str],
    expected: frozenset[str],
    problems: list[str],
) -> dict[str, str]:
    tool_names = {surface.partition("#")[0] for surface in expected}
    missing = sorted(tool_names - frozenset(mapped))
    stale = sorted(frozenset(mapped) - tool_names)
    if missing:
        problems.append(f"coverage.mcp_tools missing tools: {', '.join(missing)}")
    if stale:
        problems.append(f"coverage.mcp_tools has stale tools: {', '.join(stale)}")
    stale_json_root_tools = sorted(json_root_tools - tool_names)
    if stale_json_root_tools:
        problems.append(f"coverage_contract.mcp_json_root_tools has stale entries: {', '.join(stale_json_root_tools)}")
    expanded: dict[str, str] = {}
    for surface in expected:
        tool, separator, field = surface.partition("#")
        family = mapped.get(tool)
        if separator and tool in json_root_tools:
            family = json_root_owners.get(field)
            if family is None:
                problems.append(f"coverage.mcp_tools {surface} has no matching JSON root-field owner")
        if family is not None:
            expanded[surface] = family
    return expanded


def _expand_exact_coverage(
    group: str,
    mapped: Mapping[str, str],
    expected: frozenset[str],
    problems: list[str],
) -> dict[str, str]:
    actual = frozenset(mapped)
    missing = sorted(expected - actual)
    stale = sorted(actual - expected)
    if missing:
        problems.append(f"coverage.{group} missing: {', '.join(missing)}")
    if stale:
        problems.append(f"coverage.{group} has stale entries: {', '.join(stale)}")
    return dict(mapped)


def _expand_coverage_group(
    group: str,
    mapped: Mapping[str, str],
    ownership: tuple[Mapping[str, str], Mapping[str, str], frozenset[str]],
    expected: frozenset[str],
    problems: list[str],
) -> dict[str, str]:
    definition_owners, json_root_owners, mcp_json_root_tools = ownership
    if group == "json_fields":
        return _expand_json_coverage(mapped, definition_owners, expected, problems)
    if group == "mcp_tools":
        return _expand_mcp_coverage(mapped, json_root_owners, mcp_json_root_tools, expected, problems)
    return _expand_exact_coverage(group, mapped, expected, problems)


def _audit_digest_contract(digests: Mapping[str, str], problems: list[str]) -> None:
    digest_groups = frozenset(digests)
    missing = sorted(_COMPACT_COVERAGE_GROUPS - digest_groups)
    extra = sorted(digest_groups - _COMPACT_COVERAGE_GROUPS)
    if missing:
        problems.append(f"coverage_contract.surface_digests missing: {', '.join(missing)}")
    if extra:
        problems.append(f"coverage_contract.surface_digests has unknown entries: {', '.join(extra)}")


def _audit_surface_digest(
    group: str,
    expected: frozenset[str],
    digests: Mapping[str, str],
    problems: list[str],
) -> None:
    if group in _COMPACT_COVERAGE_GROUPS and digests.get(group) != _surface_digest(expected):
        problems.append(f"coverage_contract.surface_digests.{group} digest differs from discovered surfaces")


def _reference_path(relative: str, reference_kind: str, root: Path) -> Path | None:
    candidate = PurePosixPath(relative)
    invalid_lexically = (
        "\\" in relative
        or candidate.is_absolute()
        or not candidate.parts
        or any(part in {"", ".", ".."} for part in candidate.parts)
    )
    if invalid_lexically:
        return None
    allowed_directories = _REFERENCE_ROLE_DIRECTORIES.get(reference_kind)
    allowed_root = reference_kind != "regression_tests" and relative in _ALLOWED_ROOT_REFERENCES
    allowed_directory = allowed_directories is not None and candidate.parts[0] in allowed_directories
    invalid_role = not (allowed_root or allowed_directory) or (
        reference_kind == "regression_tests" and candidate.suffix != ".py"
    )
    if invalid_role:
        return None
    path = root.joinpath(*candidate.parts)
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    if allowed_root:
        contained_by_role = resolved_path == resolved_root.joinpath(*candidate.parts)
    else:
        lexical_role_root = root / candidate.parts[0]
        resolved_role_root = lexical_role_root.resolve()
        contained_by_role = resolved_role_root == resolved_root / candidate.parts[0] and resolved_path.is_relative_to(
            resolved_role_root
        )
    if not contained_by_role:
        return None
    return path


def _validate_reference(reference: object, reference_kind: str, root: Path) -> str | None:
    if not isinstance(reference, str) or not reference:
        return "reference must be a non-empty string"
    relative, separator, symbol = reference.partition("#")
    path = _reference_path(relative, reference_kind, root)
    if path is None:
        return f"{reference_kind} reference path is not allowed: {relative}"
    if not path.is_file():
        return f"path does not exist: {relative}"
    if not separator:
        return None
    if not symbol:
        return f"symbol is empty: {reference}"
    error: str | None = None
    if path.suffix == ".py" and symbol not in _top_level_names(path):
        error = f"top-level Python symbol does not exist: {reference}"
    elif path.suffix != ".py" and symbol not in path.read_text(encoding="utf-8"):
        error = f"text anchor does not exist: {reference}"
    return error


def _iter_family_references(family: Mapping[str, object]) -> Iterable[tuple[str, object]]:
    for key in ("producer_paths", "evidence_path", "regression_tests"):
        values = family.get(key)
        if isinstance(values, list):
            for value in values:
                yield key, value


def _audit_coverage(
    coverage: Mapping[str, object],
    coverage_contract: object,
    families: Mapping[object, object],
    discovered: Mapping[str, frozenset[str]],
    problems: list[str],
) -> None:
    """Check exact discovered-set coverage and family ownership."""
    coverage_groups = frozenset(str(name) for name in coverage)
    missing_groups = sorted(_EXPECTED_COVERAGE_GROUPS - coverage_groups)
    extra_groups = sorted(coverage_groups - _EXPECTED_COVERAGE_GROUPS)
    if missing_groups:
        problems.append(f"coverage groups missing: {', '.join(missing_groups)}")
    if extra_groups:
        problems.append(f"unknown coverage groups: {', '.join(extra_groups)}")

    definition_owners, digests, mcp_json_root_tools = _contract_mappings(coverage_contract, problems)
    _audit_digest_contract(digests, problems)
    json_root_owners = _mapping(coverage.get("json_fields"), "json_fields", problems)
    ownership = (definition_owners, json_root_owners, mcp_json_root_tools)

    referenced_families: set[str] = set(definition_owners.values())
    for group in sorted(_EXPECTED_COVERAGE_GROUPS):
        mapped = json_root_owners if group == "json_fields" else _mapping(coverage.get(group), group, problems)
        expected = discovered[group]
        expanded = _expand_coverage_group(
            group,
            mapped,
            ownership,
            expected,
            problems,
        )
        _audit_surface_digest(group, expected, digests, problems)
        referenced_families.update(expanded.values())

    family_ids = {str(name) for name in families}
    unknown = sorted(referenced_families - family_ids)
    if unknown:
        problems.append(f"coverage references unknown claim families: {', '.join(unknown)}")
    unreferenced = sorted(family_ids - referenced_families)
    if unreferenced:
        problems.append(f"claim families have no governed surface: {', '.join(unreferenced)}")


def _audit_family_metadata(claim_id: str, raw_family: Mapping[str, object], problems: list[str]) -> None:
    """Validate the closed scalar vocabulary for one claim family."""
    if not isinstance(raw_family.get("material"), bool):
        problems.append(f"claim family {claim_id}.material must be boolean")
    subject_scope = raw_family.get("subject_scope")
    if not isinstance(subject_scope, str) or not subject_scope.strip():
        problems.append(f"claim family {claim_id}.subject_scope must be a non-empty string")
    classification = raw_family.get("classification")
    if classification not in _CLASSIFICATIONS:
        problems.append(f"claim family {claim_id}.classification must be one of {', '.join(sorted(_CLASSIFICATIONS))}")
    lineage_status = raw_family.get("lineage_status")
    if lineage_status not in _LINEAGE_STATUSES:
        problems.append(f"claim family {claim_id}.lineage_status must be one of {', '.join(sorted(_LINEAGE_STATUSES))}")
    audit_status = raw_family.get("audit_status")
    if audit_status not in _AUDIT_STATUSES:
        problems.append(f"claim family {claim_id}.audit_status must be one of {', '.join(sorted(_AUDIT_STATUSES))}")


def _audit_family_lists(claim_id: str, raw_family: Mapping[str, object], problems: list[str]) -> None:
    """Validate every non-empty string-list field for one claim family."""
    for list_key in ("producer_paths", "evidence_path", "renderer_obligations", "regression_tests", "limits"):
        value = raw_family.get(list_key)
        if not isinstance(value, list) or not value:
            problems.append(f"claim family {claim_id}.{list_key} must be a non-empty array")
        elif any(not isinstance(item, str) or not item.strip() for item in value):
            problems.append(f"claim family {claim_id}.{list_key} entries must be non-empty strings")


def _audit_family(claim_id: object, raw_family: object, root: Path, problems: list[str]) -> None:
    """Check one claim-family record and all of its repository references."""
    if not isinstance(claim_id, str) or not isinstance(raw_family, Mapping):
        problems.append(f"claim family {claim_id!r} must be an object")
        return
    missing_keys = sorted(_REQUIRED_FAMILY_KEYS - frozenset(raw_family))
    if missing_keys:
        problems.append(f"claim family {claim_id} missing keys: {', '.join(missing_keys)}")
        return
    if raw_family.get("claim_id") != claim_id:
        problems.append(f"claim family key and claim_id differ: {claim_id}")
    _audit_family_metadata(claim_id, raw_family, problems)
    _audit_family_lists(claim_id, raw_family, problems)
    for reference_kind, reference in _iter_family_references(raw_family):
        error = _validate_reference(reference, reference_kind, root)
        if error:
            problems.append(f"claim family {claim_id}.{reference_kind}: {error}")
    if (
        raw_family.get("material") is True
        and raw_family.get("audit_status") == "complete"
        and raw_family.get("lineage_status") == "incomplete"
    ):
        problems.append(f"material claim family {claim_id} cannot be complete with incomplete lineage")


def audit_claim_inventory(inventory: Mapping[str, Any], root: Path = ROOT) -> list[str]:
    """Return deterministic diagnostics for missing, stale, or invalid audit entries."""
    problems: list[str] = []
    coverage = inventory.get("coverage")
    families = inventory.get("claim_families")
    if not isinstance(coverage, Mapping):
        return ["coverage must be an object"]
    if not isinstance(families, Mapping):
        return ["claim_families must be an object"]

    for field in ("purpose", "scope", "subject_rule"):
        value = inventory.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{field} must be a non-empty string")

    discovered = discover_surfaces(root)
    _audit_coverage(coverage, inventory.get("coverage_contract"), families, discovered, problems)
    for claim_id, raw_family in sorted(families.items()):
        _audit_family(claim_id, raw_family, root, problems)
    return sorted(set(problems))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check fail-closed coverage of recon's material default claims.")
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT_PATH)
    parser.add_argument("--print-digests", action="store_true", help="print current compact surface digests and exit")
    args = parser.parse_args(argv)
    try:
        if args.print_digests:
            print(json.dumps(_current_surface_digests(), indent=2, sort_keys=True))
            return 0
        inventory = load_claim_inventory(args.audit)
        problems = audit_claim_inventory(inventory, ROOT)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"default claim audit failed: {exc}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"default claim audit failed: {problem}", file=sys.stderr)
        return 1
    print("Default claim audit covers every discovered material surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
