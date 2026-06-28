from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]


def _load_checker() -> Any:
    spec = importlib.util.spec_from_file_location(
        "workflow_pin_checker",
        ROOT / "scripts" / "check_workflow_pins.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    cast(Any, spec.loader).exec_module(module)
    return module


CHECKER = _load_checker()


def test_shorthand_uses_step_must_be_sha_pinned(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        """
name: demo
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
""",
        encoding="utf-8",
    )

    errors = cast(list[str], CHECKER._check_workflow(workflow))

    assert any("not pinned to a full SHA" in error for error in errors)


def test_shorthand_uses_step_accepts_sha_pin_with_version_comment(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        """
name: demo
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
""",
        encoding="utf-8",
    )

    assert CHECKER._check_workflow(workflow) == []


def test_named_uses_step_still_requires_version_comment(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        """
name: demo
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
""",
        encoding="utf-8",
    )

    errors = cast(list[str], CHECKER._check_workflow(workflow))

    assert any("version comment" in error for error in errors)


def test_installer_rejects_download_then_run_shell_pattern(tmp_path: Path) -> None:
    installer = tmp_path / "install.sh"
    installer.write_text("curl -LsSf https://example.test/install.sh | sh\n", encoding="utf-8")

    original = CHECKER.INSTALLERS
    CHECKER.INSTALLERS = (installer,)
    try:
        errors = cast(list[str], CHECKER._check_installers())
    finally:
        CHECKER.INSTALLERS = original

    assert any("remote installers" in error for error in errors)


def test_installer_rejects_download_then_run_powershell_pattern(tmp_path: Path) -> None:
    installer = tmp_path / "install.ps1"
    installer.write_text('Invoke-Expression (Invoke-RestMethod "https://example.test/install.ps1")\n', encoding="utf-8")

    original = CHECKER.INSTALLERS
    CHECKER.INSTALLERS = (installer,)
    try:
        errors = cast(list[str], CHECKER._check_installers())
    finally:
        CHECKER.INSTALLERS = original

    assert any("remote installers" in error for error in errors)
