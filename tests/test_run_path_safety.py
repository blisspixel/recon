from __future__ import annotations

from pathlib import Path

import pytest

from validation.run_path_safety import contained_child, validate_private_output_root, validate_run_stamp


@pytest.mark.parametrize("stamp", ["20260619-000000Z", "safe-run_20260619.1", "a" * 80])
def test_validate_run_stamp_accepts_safe_segment(stamp: str) -> None:
    assert validate_run_stamp(stamp) == stamp


@pytest.mark.parametrize(
    "stamp",
    [
        "",
        "../outside",
        "..\\outside",
        "/absolute/path",
        "-leading-dash",
        "with space",
        "a" * 81,
    ],
)
def test_validate_run_stamp_rejects_unsafe_segment(stamp: str) -> None:
    with pytest.raises(ValueError, match="run stamp must be 1-80"):
        validate_run_stamp(stamp)


def test_contained_child_resolves_safe_child_under_parent(tmp_path: Path) -> None:
    assert contained_child(tmp_path / "runs", "safe-run_20260619.1") == (
        tmp_path / "runs" / "safe-run_20260619.1"
    ).resolve(strict=False)


@pytest.mark.parametrize("child_name", [".", "../outside", "/absolute/path"])
def test_contained_child_rejects_escaped_child(tmp_path: Path, child_name: str) -> None:
    with pytest.raises(ValueError, match="run directory escapes output root"):
        contained_child(tmp_path / "runs", child_name)


def test_private_output_root_allows_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "operator-private"

    assert validate_private_output_root(
        outside,
        repo_root=repo,
        allowed_roots=(repo / "validation" / "runs-private",),
    ) == outside.resolve(strict=False)


def test_private_output_root_allows_ignored_repository_workspace(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    output_root = repo / "validation" / "runs-private" / "monthly"

    assert validate_private_output_root(
        output_root,
        repo_root=repo,
        allowed_roots=(repo / "validation" / "runs-private",),
    ) == output_root.resolve(strict=False)


def test_private_output_root_rejects_public_repository_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    output_root = repo / "docs" / "calibration-output"

    with pytest.raises(ValueError, match="validation/runs-private"):
        validate_private_output_root(
            output_root,
            repo_root=repo,
            allowed_roots=(repo / "validation" / "runs-private",),
        )
