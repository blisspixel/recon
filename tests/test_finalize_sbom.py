"""CycloneDX release SBOM regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.finalize_sbom import SbomError, finalize_sbom, validate_completed_sbom


def test_finalize_sbom_adds_project_root_and_dependency_edge(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "httpx", "bom-ref": "pkg:pypi/httpx@1"}],
                "dependencies": [],
            }
        ),
        encoding="utf-8",
    )
    payload = finalize_sbom(path, "2.5.9")
    root = payload["metadata"]["component"]
    assert root["name"] == "recon-tool"
    assert root["version"] == "2.5.9"
    assert payload["dependencies"][-1] == {
        "ref": "pkg:pypi/recon-tool@2.5.9",
        "dependsOn": ["pkg:pypi/httpx@1"],
    }
    assert json.loads(path.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
    assert validate_completed_sbom(path, "2.5.9") == payload


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing-root", "root component"),
        ("wrong-version", "mismatched field"),
        ("missing-edge", "exactly one project root"),
        ("incomplete-edge", "reference every component"),
    ],
)
def test_completed_sbom_validation_fails_without_repair(tmp_path: Path, case: str, message: str) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": "httpx", "bom-ref": "pkg:pypi/httpx@1"},
                    {"type": "library", "name": "rich", "bom-ref": "pkg:pypi/rich@1"},
                ],
                "dependencies": [],
            }
        ),
        encoding="utf-8",
    )
    payload = finalize_sbom(path, "2.5.9")
    if case == "missing-root":
        payload["metadata"].pop("component")
    elif case == "wrong-version":
        payload["metadata"]["component"]["version"] = "9.9.9"
    elif case == "missing-edge":
        payload["dependencies"].clear()
    else:
        payload["dependencies"][-1]["dependsOn"] = ["pkg:pypi/httpx@1"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SbomError, match=message):
        validate_completed_sbom(path, "2.5.9")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        {"bomFormat": "CycloneDX", "specVersion": "1.6"},
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
    ],
)
def test_finalize_sbom_rejects_incomplete_payloads(tmp_path: Path, payload: object) -> None:
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SbomError):
        finalize_sbom(path, "2.5.9")


def test_completed_sbom_validation_rejects_non_utf8_bytes(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(SbomError, match="cannot read valid JSON"):
        validate_completed_sbom(path, "2.5.9")


@pytest.mark.parametrize(
    "components",
    [
        [{"type": "library", "name": "missing-ref"}],
        [
            {"type": "library", "name": "one", "bom-ref": "duplicate"},
            {"type": "library", "name": "two", "bom-ref": "duplicate"},
        ],
    ],
)
def test_finalize_sbom_rejects_invalid_component_refs(tmp_path: Path, components: list[dict[str, str]]) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}),
        encoding="utf-8",
    )
    with pytest.raises(SbomError, match="bom-ref"):
        finalize_sbom(path, "2.5.9")


@pytest.mark.parametrize(
    ("dependencies", "message"),
    [
        ([{"ref": "missing", "dependsOn": []}], "does not resolve"),
        ([{"ref": "component", "dependsOn": ["missing"]}], "dependsOn refs do not resolve"),
        (
            [
                {"ref": "component", "dependsOn": []},
                {"ref": "component", "dependsOn": []},
            ],
            "duplicated",
        ),
    ],
)
def test_finalize_sbom_rejects_invalid_dependency_graph(
    tmp_path: Path,
    dependencies: list[dict[str, object]],
    message: str,
) -> None:
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "component", "bom-ref": "component"}],
                "dependencies": dependencies,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SbomError, match=message):
        finalize_sbom(path, "2.5.9")


def test_finalize_sbom_rejects_leading_zero_version(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
    with pytest.raises(SbomError, match=r"stable X\.Y\.Z"):
        finalize_sbom(path, "02.5.9")
