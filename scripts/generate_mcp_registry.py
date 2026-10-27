#!/usr/bin/env python3
"""Generate the MCP Registry server.json from the project version.

The Registry entry is a metadata pointer. It does not replace the attested
PyPI wheel. The declared launch is ``uvx --from recon-tool recon mcp``.
A client that inserts the package identifier between runtime arguments and
package arguments would build a different command. ``recon mcp install``
remains the interpreter-bound path.

The vendored schema is the 2025-12-11 server schema fetched on 2026-10-27.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import cast

from jsonschema import Draft7Validator, FormatChecker, validate
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = Path("server.json")
SCHEMA_PATH = Path("scripts/data/mcp-registry-server-2025-12-11.schema.json")
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"

SERVER_NAME = "io.github.blisspixel/recon"
TITLE = "recon"
DESCRIPTION = "Public DNS, certificate transparency, and identity observations."
WEBSITE_URL = "https://github.com/blisspixel/recon"
REPOSITORY_URL = "https://github.com/blisspixel/recon"
REPOSITORY_SOURCE = "github"
REPOSITORY_ID = "1207478328"
PACKAGE_IDENTIFIER = "recon-tool"
REGISTRY_TYPE = "pypi"
REGISTRY_BASE_URL = "https://pypi.org"
MCP_NAME_LINE = "<!-- mcp-name: io.github.blisspixel/recon -->"
DECLARED_ARGV = ("uvx", "--from", "recon-tool", "recon", "mcp")


class GenerationError(ValueError):
    """Raised when server.json cannot be published for this project version."""


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _project_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = _as_object_dict(payload.get("project"))
    if project is None:
        raise GenerationError("pyproject.toml is missing [project]")
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise GenerationError("pyproject.toml project.version is missing")
    return version


def _positional(value: str) -> dict[str, str]:
    return {"type": "positional", "value": value}


def registry_document(version: str) -> dict[str, object]:
    """Return the server.json object for one project version."""
    if not 1 <= len(DESCRIPTION) <= 100:
        raise GenerationError("registry description must be 1 to 100 characters")
    return {
        "$schema": SCHEMA_URL,
        "name": SERVER_NAME,
        "title": TITLE,
        "description": DESCRIPTION,
        "version": version,
        "repository": {
            "url": REPOSITORY_URL,
            "source": REPOSITORY_SOURCE,
            "id": REPOSITORY_ID,
        },
        "websiteUrl": WEBSITE_URL,
        "packages": [
            {
                "registryType": REGISTRY_TYPE,
                "registryBaseUrl": REGISTRY_BASE_URL,
                "identifier": PACKAGE_IDENTIFIER,
                "version": version,
                "runtimeHint": "uvx",
                "runtimeArguments": [
                    _positional("--from"),
                    _positional(PACKAGE_IDENTIFIER),
                    _positional("recon"),
                ],
                "packageArguments": [_positional("mcp")],
                "transport": {"type": "stdio"},
            }
        ],
    }


def schema_problems(document: dict[str, object]) -> list[str]:
    """Return schema violations for one server document."""
    try:
        payload = _read_json(ROOT / SCHEMA_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        return [str(exc)]
    schema = _as_object_dict(payload)
    if schema is None:
        return ["vendored MCP registry schema must be an object"]
    try:
        Draft7Validator.check_schema(schema)
        validate(document, schema, cls=Draft7Validator, format_checker=FormatChecker())
    except SchemaError as exc:
        return [f"vendored MCP registry schema is invalid: {exc.message}"]
    except ValidationError as exc:
        return [exc.message]
    return []


def _argument_values(value: object, label: str) -> list[str] | str:
    if not isinstance(value, list):
        return f"{label} must be a list of positional arguments"
    values: list[str] = []
    for item in cast(list[object], value):
        argument = _as_object_dict(item)
        if argument is None or argument.get("type") != "positional":
            return f"{label} must be fixed positional arguments"
        argument_value = argument.get("value")
        if not isinstance(argument_value, str) or not argument_value:
            return f"{label} must be fixed positional arguments"
        values.append(argument_value)
    return values


def _package(document: dict[str, object]) -> dict[str, object] | str:
    packages = document.get("packages")
    if not isinstance(packages, list):
        return "server.json must list exactly one package"
    entries = cast(list[object], packages)
    if len(entries) != 1:
        return "server.json must list exactly one package"
    package = _as_object_dict(entries[0])
    if package is None:
        return "server.json must list exactly one package"
    return package


def _launch_argv(package: dict[str, object]) -> list[str] | str:
    if package.get("runtimeHint") != "uvx":
        return "runtimeHint must be 'uvx'"
    runtime = _argument_values(package.get("runtimeArguments"), "runtimeArguments")
    if isinstance(runtime, str):
        return runtime
    package_args = _argument_values(package.get("packageArguments"), "packageArguments")
    if isinstance(package_args, str):
        return package_args
    return ["uvx", *runtime, *package_args]


def _readme_problem(root: Path) -> str | None:
    try:
        lines = (root / "README.md").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return str(exc)
    if MCP_NAME_LINE not in lines:
        return f"README.md must contain the line {MCP_NAME_LINE}"
    return None


def _identity_problems(document: dict[str, object], version: str) -> list[str]:
    problems: list[str] = []
    if document.get("name") != SERVER_NAME:
        problems.append(f"registry name {document.get('name')!r} does not match {SERVER_NAME!r}")
    if document.get("title") != TITLE:
        problems.append(f"registry title {document.get('title')!r} does not match {TITLE!r}")
    if document.get("description") != DESCRIPTION:
        problems.append("registry description does not match the generated description")
    if document.get("version") != version:
        problems.append(f"registry version {document.get('version')!r} does not match {version!r}")
    if document.get("websiteUrl") != WEBSITE_URL:
        problems.append(f"registry websiteUrl must be {WEBSITE_URL!r}")
    repository = _as_object_dict(document.get("repository"))
    if repository is None:
        problems.append("registry repository must be an object")
        return problems
    if repository.get("url") != REPOSITORY_URL or repository.get("source") != REPOSITORY_SOURCE:
        problems.append("registry repository url and source must match the GitHub project")
    if repository.get("id") != REPOSITORY_ID:
        problems.append(f"registry repository id {repository.get('id')!r} does not match {REPOSITORY_ID!r}")
    return problems


def _package_problems(document: dict[str, object], version: str) -> list[str]:
    package = _package(document)
    if isinstance(package, str):
        return [package]
    problems: list[str] = []
    if package.get("registryType") != REGISTRY_TYPE or package.get("identifier") != PACKAGE_IDENTIFIER:
        problems.append(f"registry package must be {REGISTRY_TYPE} {PACKAGE_IDENTIFIER}")
    if package.get("registryBaseUrl") != REGISTRY_BASE_URL:
        problems.append(f"registryBaseUrl must be {REGISTRY_BASE_URL!r}")
    if package.get("version") != version:
        problems.append(f"registry package version {package.get('version')!r} does not match {version!r}")
    transport = _as_object_dict(package.get("transport"))
    if transport is None or transport.get("type") != "stdio":
        problems.append("registry transport must be stdio")
    argv = _launch_argv(package)
    if isinstance(argv, str):
        problems.append(argv)
    elif argv != list(DECLARED_ARGV):
        problems.append(f"declared launch {argv!r} does not match {list(DECLARED_ARGV)!r}")
    return problems


def agreement_problems(root: Path) -> list[str]:
    """Return name, version, marker, and launch disagreements. Empty means they match."""
    problems: list[str] = []
    readme = _readme_problem(root)
    if readme is not None:
        problems.append(readme)
    try:
        version = _project_version(root)
        document = _as_object_dict(_read_json(root / REGISTRY_PATH))
    except (OSError, json.JSONDecodeError, GenerationError, tomllib.TOMLDecodeError) as exc:
        return [*problems, str(exc)]
    if document is None:
        return [*problems, "server.json must be an object"]
    return [*problems, *_identity_problems(document, version), *_package_problems(document, version)]


def rendered_bytes(root: Path) -> bytes:
    """Return the canonical server.json bytes for this checkout."""
    document = registry_document(_project_version(root))
    problems = schema_problems(document)
    if problems:
        raise GenerationError("; ".join(problems))
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    return text.encode()


def check(root: Path) -> list[str]:
    """Return drift messages. A clean result means the committed file matches the generator."""
    problems = agreement_problems(root)
    if problems:
        return problems
    try:
        expected = rendered_bytes(root)
    except (OSError, GenerationError, tomllib.TOMLDecodeError) as exc:
        return [str(exc)]
    if (root / REGISTRY_PATH).read_bytes() != expected:
        return [f"stale {REGISTRY_PATH.as_posix()}"]
    return []


def write(root: Path) -> None:
    """Write server.json. Refuse when the document does not match the schema."""
    path = root / REGISTRY_PATH
    path.write_bytes(rendered_bytes(root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the committed server.json is stale.")
    args = parser.parse_args(argv)
    if args.check:
        problems = check(ROOT)
        if problems:
            print("FAIL: " + "; ".join(problems), file=sys.stderr)
            return 1
        print(f"PASS: {REGISTRY_PATH.as_posix()} matches the project version.")
        return 0
    try:
        write(ROOT)
    except GenerationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {REGISTRY_PATH.as_posix()}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
