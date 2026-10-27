"""The Claude Code marketplace stays tied to the plugin manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.generate_claude_marketplace import (
    DESCRIPTION,
    MARKETPLACE_NAME,
    PLUGIN_SOURCE,
    GenerationError,
    agreement_problems,
    check,
    rendered_bytes,
    write,
)

ROOT = Path(__file__).resolve().parents[1]


def _root(tmp_path: Path, *, plugin_version: str = "2.2.8", project_version: str = "2.2.8") -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "recon-tool"\nversion = "{project_version}"\n',
        encoding="utf-8",
    )
    manifest = tmp_path / "agents" / "claude-code" / ".claude-plugin"
    manifest.mkdir(parents=True)
    (manifest / "plugin.json").write_text(
        json.dumps({"name": "recon", "version": plugin_version}) + "\n",
        encoding="utf-8",
    )
    return tmp_path


def test_render_uses_the_plugin_version_and_fixed_marketplace_identity(tmp_path: Path) -> None:
    document = json.loads(rendered_bytes(_root(tmp_path)))

    assert document["name"] == MARKETPLACE_NAME
    assert document["description"] == DESCRIPTION
    assert document["owner"] == {"name": "blisspixel"}
    assert document["plugins"] == [
        {
            "name": "recon",
            "source": PLUGIN_SOURCE,
            "description": DESCRIPTION,
            "version": "2.2.8",
        }
    ]


def test_write_then_check_is_clean_and_a_version_edit_is_not(tmp_path: Path) -> None:
    root = _root(tmp_path)
    write(root)
    assert check(root) == []

    path = root / ".claude-plugin" / "marketplace.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["plugins"][0]["version"] = "9.9.9"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    problems = agreement_problems(root)
    assert any("9.9.9" in problem and "2.2.8" in problem for problem in problems)


def test_plugin_version_must_match_pyproject(tmp_path: Path) -> None:
    root = _root(tmp_path, plugin_version="2.2.7", project_version="2.2.8")

    with pytest.raises(GenerationError, match=r"2\.2\.7"):
        rendered_bytes(root)


def test_committed_marketplace_matches_the_generator() -> None:
    assert check(ROOT) == []
