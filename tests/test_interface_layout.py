from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_interface_layout as layout


def _minimal_root(tmp_path: Path) -> Path:
    root = tmp_path
    pkg = root / "src" / "recon_tool"
    for package in layout.REQUIRED_PACKAGES:
        package_dir = pkg / package
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
    return root


def test_interface_layout_accepts_package_local_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _minimal_root(tmp_path)
    monkeypatch.setattr(layout, "ROOT", root)
    monkeypatch.setattr(layout, "PKG", root / "src" / "recon_tool")

    assert layout.main() == 0


def test_interface_layout_rejects_legacy_monolith_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _minimal_root(tmp_path)
    pkg = root / "src" / "recon_tool"
    (pkg / "formatter.py").write_text("# old monolith\n", encoding="utf-8")
    monkeypatch.setattr(layout, "ROOT", root)
    monkeypatch.setattr(layout, "PKG", pkg)

    assert layout.main() == 1
    assert "legacy interface implementation module is not allowed" in capsys.readouterr().out
