"""Regressions for the schema-pinned Agent Plugins candidate."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

from scripts import check_agent_plugin as candidate
from scripts import generate_agent_plugin as generator

ROOT = Path(__file__).resolve().parents[1]


def _copy_candidate(tmp_path: Path) -> Path:
    output = tmp_path / "agent-plugin"
    shutil.copytree(candidate.DEFAULT_PLUGIN_ROOT, output)
    return output


def _json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_committed_candidate_is_current_and_valid() -> None:
    assert generator.main(["--check"]) == 0

    version, digest = candidate.validate_candidate()

    assert version == "2.14.0"
    assert digest == "403a5860dc547ab0fd8961023d196e0b72ec6524ed2c1cb7da4253899628eafe"


@pytest.mark.parametrize(
    ("name", "size", "digest"),
    [
        (
            "plugin.schema.json",
            1805,
            "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883",
        ),
        (
            "mcp.schema.json",
            3408,
            "6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb",
        ),
    ],
)
def test_vendored_schema_snapshot_is_exact_and_valid(name: str, size: int, digest: str) -> None:
    raw = (candidate.DEFAULT_SCHEMA_ROOT / name).read_bytes()
    schema = json.loads(raw)

    assert len(raw) == size
    assert hashlib.sha256(raw).hexdigest() == digest
    Draft202012Validator.check_schema(schema)


def test_candidate_has_only_the_frozen_complete_package_files() -> None:
    assert candidate._relative_files(candidate.DEFAULT_PLUGIN_ROOT) == candidate.EXPECTED_FILES
    assert sorted(path.name for path in (candidate.DEFAULT_PLUGIN_ROOT / "skills").iterdir()) == sorted(
        candidate.EXPECTED_SKILLS
    )


def test_generated_skills_remove_client_only_and_experimental_frontmatter() -> None:
    for skill_id in candidate.EXPECTED_SKILLS:
        frontmatter, body = candidate._parse_skill(candidate.DEFAULT_PLUGIN_ROOT / "skills" / skill_id / "SKILL.md")
        assert set(frontmatter) == candidate.PORTABLE_SKILL_FIELDS
        assert frontmatter["name"] == skill_id
        assert frontmatter["license"] == "Apache-2.0"
        assert "argument-hint" not in frontmatter
        assert "allowed-tools" not in frontmatter
        assert body.strip()


def test_candidate_uses_one_explicit_complete_surface_stdio_server() -> None:
    mcp = _json(candidate.DEFAULT_PLUGIN_ROOT / "mcp.json")

    assert mcp == {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {
            "recon": {
                "type": "stdio",
                "command": "recon",
                "args": ["mcp"],
            }
        },
    }
    inventory = _json(ROOT / "docs" / "surface-inventory.json")
    assert inventory["mcp"]["tool_count"] == 22


def test_unknown_plugin_field_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    manifest = _json(root / "plugin.json")
    manifest["unsupported"] = True
    _write_json(root / "plugin.json", manifest)

    with pytest.raises(candidate.CandidateError, match="pinned schema"):
        candidate.validate_candidate(root)


def test_duplicate_manifest_key_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    path = root / "plugin.json"
    text = path.read_text(encoding="utf-8")
    path.write_bytes(text.replace('  "name": "recon",', '  "name": "first",\n  "name": "recon",', 1).encode())

    with pytest.raises(candidate.CandidateError, match="duplicate JSON key"):
        candidate.validate_candidate(root)


def test_unsupported_schema_version_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    manifest = _json(root / "plugin.json")
    manifest["$schema"] = "https://agent-plugins.org/schemas/2.0.0/plugin.schema.json"
    _write_json(root / "plugin.json", manifest)

    with pytest.raises(candidate.CandidateError, match="pinned schema"):
        candidate.validate_candidate(root)


@pytest.mark.parametrize(
    "server",
    [
        {"type": "stdio", "command": "recon mcp"},
        {"type": "stdio", "command": "recon", "args": ["mcp"], "env": {"TOKEN": "x"}},
        {"type": "streamable-http", "url": "https://example.invalid/mcp"},
    ],
)
def test_noncanonical_server_launch_fails_closed(tmp_path: Path, server: dict[str, Any]) -> None:
    root = _copy_candidate(tmp_path)
    mcp = _json(root / "mcp.json")
    mcp["mcpServers"] = {"recon": server}
    _write_json(root / "mcp.json", mcp)

    with pytest.raises(candidate.CandidateError, match="exact recon stdio launch"):
        candidate.validate_candidate(root)


def test_client_only_skill_field_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    path = root / "skills" / "recon" / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    path.write_bytes(text.replace("---\n", "---\nargument-hint: <domain>\n", 1).encode())

    with pytest.raises(candidate.CandidateError, match="frontmatter fields drifted"):
        candidate.validate_candidate(root)


def test_duplicate_skill_key_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    path = root / "skills" / "recon" / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    path.write_bytes(text.replace("---\n", "---\nname: duplicate\n", 1).encode())

    with pytest.raises(candidate.CandidateError, match="duplicate YAML key"):
        candidate.validate_candidate(root)


def test_skill_directory_name_mismatch_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    path = root / "skills" / "recon" / "SKILL.md"
    text = path.read_text(encoding="utf-8")
    path.write_bytes(text.replace("name: recon\n", "name: other\n", 1).encode())

    with pytest.raises(candidate.CandidateError, match="name must match its directory"):
        candidate.validate_candidate(root)


def test_version_drift_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")

    with pytest.raises(candidate.CandidateError, match="version does not match"):
        candidate.validate_candidate(project_file=project)


def test_schema_snapshot_tampering_fails_before_validation(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(candidate.DEFAULT_SCHEMA_ROOT, schema_root)
    path = schema_root / "plugin.schema.json"
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(candidate.CandidateError, match="schema snapshot drifted"):
        candidate.validate_candidate(schema_root=schema_root)


def test_extra_package_file_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(candidate.CandidateError, match="file set drifted"):
        candidate.validate_candidate(root)


def test_extra_empty_package_directory_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    (root / "unexpected").mkdir()

    with pytest.raises(candidate.CandidateError, match="directory set drifted"):
        candidate.validate_candidate(root)


def test_oversized_manifest_fails_closed(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    (root / "plugin.json").write_bytes(b" " * (candidate.MAX_JSON_BYTES + 1))

    with pytest.raises(candidate.CandidateError, match=r"plugin\.json size"):
        candidate.validate_candidate(root)


def test_symlink_fails_closed_when_supported(tmp_path: Path) -> None:
    root = _copy_candidate(tmp_path)
    link = root / "unexpected-link"
    try:
        link.symlink_to(root / "README.md")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(candidate.CandidateError, match="symlink"):
        candidate.validate_candidate(root)


def test_cli_reports_only_aggregate_package_state(capsys: pytest.CaptureFixture[str]) -> None:
    assert candidate.main([]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "PASS: schema-pinned Agent Plugins candidate" in captured.out
    assert "skills=2 mcp_tools=22" in captured.out
    assert ".invalid" not in captured.out


def test_cli_fails_closed_for_missing_package(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert candidate.main(["--plugin-root", str(tmp_path / "missing")]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAIL: candidate root" in captured.err


def test_readme_keeps_standards_and_claim_boundaries_separate() -> None:
    readme = (candidate.DEFAULT_PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Working Draft" in readme
    assert "not an unqualified compatibility or conformance claim" in readme
    assert "Open Knowledge Format v0.2 projection" in readme
    assert "permissions" in readme
    assert "https://agent-plugins.org/specification" in readme
    assert "agent-portability-evaluation-declaration.md" in readme


def test_active_docs_publish_offline_candidate_state_and_client_gate() -> None:
    active_paths = (
        ROOT / "README.md",
        ROOT / "ROADMAP.md",
        ROOT / "agents" / "README.md",
        ROOT / "docs" / "roadmap.md",
        ROOT / "docs" / "engineering-refinement-plan.md",
        ROOT / "docs" / "strategic-gap-audit.md",
        ROOT / "docs" / "agent-portability-evaluation-declaration.md",
        ROOT / "validation" / "README.md",
    )
    documents = [path.read_text(encoding="utf-8") for path in active_paths]
    normalized = [" ".join(document.lower().split()) for document in documents]

    assert all("candidate" in document for document in normalized)
    assert all("client" in document for document in normalized)
    assert all("conformance claim" in document or "compatibility claim" in document for document in normalized)
    stale_phrases = (
        "build the schema-pinned portable candidate",
        "next operation is the schema-pinned portable candidate",
        "does not ship a portable package",
        "before building or collecting the v2.15 portable-package candidate",
    )
    assert all(phrase not in document for document in normalized for phrase in stale_phrases)
