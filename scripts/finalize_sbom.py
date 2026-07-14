#!/usr/bin/env python3
"""Validate a CycloneDX dependency SBOM and attach the released project root."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_SEMVER_COMPONENT = r"(?:0|[1-9][0-9]*)"
_STABLE_VERSION = re.compile(rf"^{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}\.{_SEMVER_COMPONENT}$")


class SbomError(RuntimeError):
    """The generated SBOM is incomplete or malformed."""


def _component_refs(components: list[dict[str, Any]], root_ref: str) -> list[str]:
    refs: list[str] = []
    for component in components:
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref:
            raise SbomError("Every SBOM component must have a nonempty bom-ref")
        if ref == root_ref:
            raise SbomError("Dependency components must not reuse the project root bom-ref")
        refs.append(ref)
    if len(refs) != len(set(refs)):
        raise SbomError("SBOM component bom-ref values must be unique")
    return sorted(refs)


def _validate_dependencies(dependencies: list[dict[str, Any]], allowed_refs: set[str]) -> None:
    seen_refs: set[str] = set()
    for dependency in dependencies:
        dependency_ref = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if not isinstance(dependency_ref, str) or not dependency_ref:
            raise SbomError("Every SBOM dependency must have a nonempty ref")
        if dependency_ref not in allowed_refs:
            raise SbomError(f"SBOM dependency ref {dependency_ref!r} does not resolve to a component")
        if dependency_ref in seen_refs:
            raise SbomError(f"SBOM dependency ref {dependency_ref!r} is duplicated")
        seen_refs.add(dependency_ref)
        if not isinstance(depends_on, list) or not all(isinstance(item, str) and item for item in depends_on):
            raise SbomError("Every SBOM dependsOn value must be an array of nonempty refs")
        dangling = sorted(set(depends_on) - allowed_refs)
        if dangling:
            raise SbomError(f"SBOM dependsOn refs do not resolve to components: {dangling!r}")


def finalize_sbom(path: Path, version: str) -> dict[str, Any]:
    if _STABLE_VERSION.fullmatch(version) is None:
        raise SbomError("version must use stable X.Y.Z syntax")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise SbomError("SBOM must be a CycloneDX JSON object")
    if not isinstance(payload.get("specVersion"), str):
        raise SbomError("SBOM must declare specVersion")
    components = payload.get("components")
    if not isinstance(components, list) or not components or not all(isinstance(item, dict) for item in components):
        raise SbomError("SBOM components must be a nonempty array of objects")

    root_ref = f"pkg:pypi/recon-tool@{version}"
    metadata = payload.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise SbomError("SBOM metadata must be an object")
    metadata["component"] = {
        "type": "application",
        "bom-ref": root_ref,
        "name": "recon-tool",
        "version": version,
        "purl": root_ref,
    }

    component_refs = _component_refs(components, root_ref)
    dependencies = payload.setdefault("dependencies", [])
    if not isinstance(dependencies, list) or not all(isinstance(item, dict) for item in dependencies):
        raise SbomError("SBOM dependencies must be an array of objects")
    _validate_dependencies(dependencies, {root_ref, *component_refs})
    dependencies[:] = [item for item in dependencies if item.get("ref") != root_ref]
    dependencies.append({"ref": root_ref, "dependsOn": component_refs})
    try:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise SbomError(f"cannot write completed SBOM to {path}: {exc}") from exc
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        finalize_sbom(args.path, args.version)
    except SbomError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {args.path} is a complete CycloneDX SBOM for recon-tool {args.version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
