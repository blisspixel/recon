"""Release-script regressions."""

from __future__ import annotations

from scripts import release


def test_release_script_points_at_src_layout_init() -> None:
    assert release.INIT_PY == release.ROOT / "src" / "recon_tool" / "__init__.py"
    assert release.INIT_PY.exists()


def test_release_script_version_consistency_reads_src_layout_init() -> None:
    assert release._check_version_consistency() == release._read_current_version()
