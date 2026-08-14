#!/usr/bin/env python3
"""Validate the schema-pinned Agent Plugins candidate without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from validation.agent_portability_contract import (  # noqa: E402 - direct script bootstrap
    ContractError,
    load_contract,
    validate_contract,
)

DEFAULT_PLUGIN_ROOT = ROOT / "agents" / "agent-plugin"
DEFAULT_SCHEMA_ROOT = ROOT / "vendor" / "agent-plugins" / "1.0.0"
DEFAULT_PROJECT = ROOT / "pyproject.toml"
DEFAULT_SURFACE_INVENTORY = ROOT / "docs" / "surface-inventory.json"

MAX_JSON_BYTES = 64 * 1024
MAX_SKILL_BYTES = 512 * 1024
MAX_SUPPORT_FILE_BYTES = 128 * 1024
EXPECTED_SKILLS = ("recon", "recon-fingerprint-triage")
EXPECTED_FILES = {
    "LICENSE",
    "README.md",
    "mcp.json",
    "plugin.json",
    "skills/recon/SKILL.md",
    "skills/recon-fingerprint-triage/SKILL.md",
}
EXPECTED_DIRS = {
    ".",
    "skills",
    "skills/recon",
    "skills/recon-fingerprint-triage",
}
PORTABLE_SKILL_FIELDS = {
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
}
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class CandidateError(ValueError):
    """Raised when the portable candidate violates a frozen package rule."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise CandidateError("YAML mapping keys must be scalar") from exc
        if duplicate:
            raise CandidateError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise CandidateError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise CandidateError(f"{label} must be a regular, non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise CandidateError(f"{label} size must be between 1 and {limit} bytes")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CandidateError(f"could not read {label}: {exc}") from exc


def _load_json(path: Path, label: str, *, limit: int = MAX_JSON_BYTES) -> dict[str, Any]:
    raw = _bounded_bytes(path, limit, label)
    try:
        payload: object = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"{label} must be valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
        raise CandidateError(f"{label} must be a JSON object")
    return payload


def _project_version(path: Path) -> str:
    raw = _bounded_bytes(path, MAX_SUPPORT_FILE_BYTES, "pyproject.toml")
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise CandidateError(f"pyproject.toml is invalid: {exc}") from exc
    version = payload.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise CandidateError("pyproject.toml project.version is missing")
    return version


def _relative_files(plugin_root: Path) -> set[str]:
    if plugin_root.is_symlink() or not plugin_root.is_dir():
        raise CandidateError("candidate root must be a regular, non-symlink directory")
    root = plugin_root.resolve()
    files: set[str] = set()
    directories = {"."}
    for path in plugin_root.rglob("*"):
        if path.is_symlink():
            raise CandidateError(f"candidate contains a symlink: {path.relative_to(plugin_root).as_posix()}")
        try:
            path.resolve().relative_to(root)
        except ValueError as exc:
            raise CandidateError("candidate path escapes its package root") from exc
        if path.is_file():
            files.add(path.relative_to(plugin_root).as_posix())
        elif path.is_dir():
            directories.add(path.relative_to(plugin_root).as_posix())
    if files != EXPECTED_FILES:
        missing = sorted(EXPECTED_FILES - files)
        extra = sorted(files - EXPECTED_FILES)
        raise CandidateError(f"candidate file set drifted: missing={missing}, extra={extra}")
    if directories != EXPECTED_DIRS:
        missing = sorted(EXPECTED_DIRS - directories)
        extra = sorted(directories - EXPECTED_DIRS)
        raise CandidateError(f"candidate directory set drifted: missing={missing}, extra={extra}")
    return files


def _schema_records(contract: dict[str, object]) -> dict[str, dict[str, object]]:
    standards = contract.get("standards")
    if not isinstance(standards, dict):
        raise CandidateError("contract standards are missing")
    plugins = standards.get("agent_plugins")
    if not isinstance(plugins, dict):
        raise CandidateError("contract Agent Plugins snapshot is missing")
    records = plugins.get("schemas")
    if not isinstance(records, list):
        raise CandidateError("contract schema records are missing")
    output: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
            raise CandidateError("contract schema record is malformed")
        output[record["kind"]] = record
    if set(output) != {"plugin", "mcp"}:
        raise CandidateError("contract must pin exactly plugin and mcp schemas")
    return output


def _load_pinned_schemas(
    schema_root: Path,
    contract: dict[str, object],
) -> dict[str, dict[str, Any]]:
    if schema_root.is_symlink() or not schema_root.is_dir():
        raise CandidateError("schema root must be a regular, non-symlink directory")
    resolved_root = schema_root.resolve()
    records = _schema_records(contract)
    output: dict[str, dict[str, Any]] = {}
    for kind, record in records.items():
        path = schema_root / f"{kind}.schema.json"
        try:
            path.resolve().relative_to(resolved_root)
        except ValueError as exc:  # pragma: no cover - closed filename table
            raise CandidateError(f"{kind} schema escapes its snapshot root") from exc
        raw = _bounded_bytes(path, MAX_JSON_BYTES, f"{kind} schema")
        expected_bytes = record.get("bytes")
        expected_digest = record.get("sha256")
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != expected_bytes or digest != expected_digest:
            raise CandidateError(f"{kind} schema snapshot drifted: bytes={len(raw)}, sha256={digest}")
        schema = _load_json(path, f"{kind} schema")
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise CandidateError(f"{kind} schema is not valid Draft 2020-12: {exc.message}") from exc
        output[kind] = schema
    return output


def _validate_json_schema(payload: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: "/".join(str(part) for part in error.path),
    )
    if errors:
        error: ValidationError = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise CandidateError(f"{label} violates its pinned schema at {location}: {error.message}")


def _parse_skill(path: Path) -> tuple[dict[str, Any], str]:
    raw = _bounded_bytes(path, MAX_SKILL_BYTES, path.as_posix())
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise CandidateError(f"{path.as_posix()} must be UTF-8") from exc
    if not text.startswith("---\n"):
        raise CandidateError(f"{path.as_posix()} is missing opening frontmatter")
    try:
        frontmatter_text, body = text[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise CandidateError(f"{path.as_posix()} is missing closing frontmatter") from exc
    loader = _UniqueKeyLoader(frontmatter_text)
    try:
        frontmatter = loader.get_single_data()
    except yaml.YAMLError as exc:
        raise CandidateError(f"{path.as_posix()} has invalid frontmatter: {exc}") from exc
    finally:
        loader.dispose()
    if not isinstance(frontmatter, dict) or not all(isinstance(key, str) for key in frontmatter):
        raise CandidateError(f"{path.as_posix()} frontmatter must be a string-keyed mapping")
    if not body.strip():
        raise CandidateError(f"{path.as_posix()} body must not be empty")
    return frontmatter, body


def _required_text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CandidateError(f"{label} must be non-empty and at most {maximum} characters")
    return value


def _validate_skill(path: Path, skill_id: str, version: str) -> None:
    frontmatter, body = _parse_skill(path)
    fields = set(frontmatter)
    if fields != PORTABLE_SKILL_FIELDS:
        raise CandidateError(
            f"{skill_id} frontmatter fields drifted: expected={sorted(PORTABLE_SKILL_FIELDS)}, actual={sorted(fields)}"
        )
    name = _required_text(frontmatter["name"], f"{skill_id}.name", maximum=64)
    if name != skill_id or not _SKILL_NAME.fullmatch(name):
        raise CandidateError(f"{skill_id} name must match its directory")
    _required_text(frontmatter["description"], f"{skill_id}.description", maximum=1024)
    _required_text(frontmatter["compatibility"], f"{skill_id}.compatibility", maximum=500)
    if frontmatter["license"] != "Apache-2.0":
        raise CandidateError(f"{skill_id} license must be Apache-2.0")
    metadata = frontmatter["metadata"]
    if metadata != {"author": "blisspixel", "version": version}:
        raise CandidateError(f"{skill_id} metadata or version has drifted")
    lowered = body.lower()
    if "portable agent plugins conformance" in lowered:
        raise CandidateError(f"{skill_id} contains an unqualified conformance claim")


def _validate_semantics(
    plugin: dict[str, Any],
    mcp: dict[str, Any],
    plugin_root: Path,
    version: str,
    surface_inventory: Path,
) -> None:
    if plugin.get("name") != "recon" or plugin.get("version") != version:
        raise CandidateError("plugin identity or version does not match pyproject.toml")
    expected_server = {"type": "stdio", "command": "recon", "args": ["mcp"]}
    if mcp.get("mcpServers") != {"recon": expected_server}:
        raise CandidateError("mcp.json must declare only the exact recon stdio launch")

    inventory = _load_json(surface_inventory, "surface inventory", limit=2 * 1024 * 1024)
    mcp_inventory = inventory.get("mcp")
    if not isinstance(mcp_inventory, dict) or mcp_inventory.get("tool_count") != 22:
        raise CandidateError("the generated runtime inventory must retain the complete 22-tool MCP surface")

    for skill_id in EXPECTED_SKILLS:
        _validate_skill(plugin_root / "skills" / skill_id / "SKILL.md", skill_id, version)

    readme = _bounded_bytes(plugin_root / "README.md", MAX_SUPPORT_FILE_BYTES, "candidate README")
    try:
        readme_text = readme.decode("utf-8")
    except UnicodeError as exc:
        raise CandidateError("candidate README must be UTF-8") from exc
    required_phrases = (
        "Agent Plugins v1.0.0 schemas",
        "Working Draft",
        "not an unqualified compatibility or conformance claim",
        "Open Knowledge Format v0.2",
    )
    if any(phrase not in readme_text for phrase in required_phrases):
        raise CandidateError("candidate README is missing a required interoperability boundary")
    if (
        _bounded_bytes(plugin_root / "LICENSE", MAX_SUPPORT_FILE_BYTES, "candidate LICENSE")
        != (ROOT / "LICENSE").read_bytes()
    ):
        raise CandidateError("candidate LICENSE must match the repository Apache-2.0 license")


def validate_candidate(
    plugin_root: Path = DEFAULT_PLUGIN_ROOT,
    schema_root: Path = DEFAULT_SCHEMA_ROOT,
    project_file: Path = DEFAULT_PROJECT,
    surface_inventory: Path = DEFAULT_SURFACE_INVENTORY,
) -> tuple[str, str]:
    """Validate the candidate and return the version and frozen contract digest."""

    contract = load_contract()
    try:
        contract_digest = validate_contract(contract)
    except ContractError as exc:
        raise CandidateError(f"frozen evaluation contract failed: {exc}") from exc
    _relative_files(plugin_root)
    version = _project_version(project_file)
    schemas = _load_pinned_schemas(schema_root, contract)
    plugin = _load_json(plugin_root / "plugin.json", "plugin.json")
    mcp = _load_json(plugin_root / "mcp.json", "mcp.json")
    _validate_json_schema(plugin, schemas["plugin"], "plugin.json")
    _validate_json_schema(mcp, schemas["mcp"], "mcp.json")
    _validate_semantics(plugin, mcp, plugin_root, version, surface_inventory)
    return version, contract_digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", type=Path, default=DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--schema-root", type=Path, default=DEFAULT_SCHEMA_ROOT)
    args = parser.parse_args(argv)
    try:
        version, digest = validate_candidate(args.plugin_root, args.schema_root)
    except (CandidateError, ContractError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(
        "PASS: schema-pinned Agent Plugins candidate "
        f"version={version} skills={len(EXPECTED_SKILLS)} mcp_tools=22 contract={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
