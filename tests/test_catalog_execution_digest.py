"""Execution commitments cover sampling code, not unrelated repository files."""

from __future__ import annotations

from pathlib import Path

import pytest

from validation import prepare_catalog_round as round_preparer


def _isolated_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    validation_root = tmp_path / "validation"
    validation_root.mkdir()
    for source in (round_preparer.REPO_ROOT / "validation").glob("*.py"):
        (validation_root / source.name).write_text("# Initial synthetic implementation.\n", encoding="utf-8")
    package_root = tmp_path / "src" / "recon_tool"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("# Synthetic package.\n", encoding="utf-8")
    for filename in ("pyproject.toml", "uv.lock"):
        (tmp_path / filename).write_text("# Synthetic dependency input.\n", encoding="utf-8")
    monkeypatch.setattr(round_preparer, "REPO_ROOT", tmp_path)


@pytest.mark.parametrize("filename", ["ranked_sampling.py", "prepare_catalog_rank_frame.py"])
def test_execution_digest_binds_rank_selection_implementation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    _isolated_repository(tmp_path, monkeypatch)
    before = round_preparer.execution_digest_sha256()
    assert round_preparer.execution_digest_sha256() == before

    (tmp_path / "validation" / filename).write_text("# Changed synthetic selection rule.\n", encoding="utf-8")

    assert round_preparer.execution_digest_sha256() != before


@pytest.mark.parametrize("relative_path", ["README.md", "validation/unrelated_fixture.py"])
def test_execution_digest_ignores_unrelated_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative_path: str
) -> None:
    _isolated_repository(tmp_path, monkeypatch)
    before = round_preparer.execution_digest_sha256()
    unrelated = tmp_path / relative_path
    unrelated.write_text("# Unrelated fixture.\n", encoding="utf-8")
    assert round_preparer.execution_digest_sha256() == before

    unrelated.write_text("# Changed unrelated fixture.\n", encoding="utf-8")

    assert round_preparer.execution_digest_sha256() == before
