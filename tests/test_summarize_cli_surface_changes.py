from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.summarize_cli_surface_changes import (
    CliSurfaceDiff,
    FlagToken,
    diff_cli_surfaces,
    load_inventory_from_text,
    main,
    summarize_cli_surface_changes,
)


def _inventory(commands: list[dict[str, object]]) -> dict[str, object]:
    return {"cli": {"commands": commands}}


def _command(usage: str, tokens: list[str] | None = None) -> dict[str, object]:
    parameters: list[dict[str, object]] = []
    if tokens is not None:
        parameters.append(
            {
                "name": "option",
                "kind": "option",
                "tokens": tokens,
                "required": False,
                "type": "boolean",
            }
        )
    return {"usage": usage, "parameters": parameters}


def test_diff_cli_surfaces_detects_command_and_flag_changes() -> None:
    old = _inventory(
        [
            _command("recon"),
            _command("recon lookup", ["--json", "--plain"]),
        ]
    )
    new = _inventory(
        [
            _command("recon"),
            _command("recon lookup", ["--json", "--exact"]),
            _command("recon mcp doctor"),
        ]
    )

    diff = diff_cli_surfaces(old, new)

    assert diff.added_commands == ("recon mcp doctor",)
    assert diff.removed_commands == ()
    assert diff.added_flags == (FlagToken("recon lookup", "--exact"),)
    assert diff.removed_flags == (FlagToken("recon lookup", "--plain"),)
    assert summarize_cli_surface_changes(diff) == (
        "Tool surface changes: added commands `recon mcp doctor`; "
        "added flags `--exact` on `recon lookup`; "
        "removed flags `--plain` on `recon lookup`."
    )


def test_summarize_cli_surface_changes_reports_no_changes() -> None:
    diff = CliSurfaceDiff(
        added_commands=(),
        removed_commands=(),
        added_flags=(),
        removed_flags=(),
    )

    assert summarize_cli_surface_changes(diff) == "Tool surface changes: no CLI command or flag changes."


def test_load_inventory_from_text_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="surface inventory must be a JSON object"):
        load_inventory_from_text("[]")


def test_main_emits_summary_for_inventory_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(_inventory([_command("recon lookup", ["--json"])])), encoding="utf-8")
    new_path.write_text(
        json.dumps(_inventory([_command("recon lookup", ["--json", "--exact"])])),
        encoding="utf-8",
    )

    assert main([str(old_path), str(new_path)]) == 0

    assert capsys.readouterr().out.strip() == ("Tool surface changes: added flags `--exact` on `recon lookup`.")


def test_main_emits_json_for_inventory_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(_inventory([_command("recon lookup", ["--json"])])), encoding="utf-8")
    new_path.write_text(
        json.dumps(_inventory([_command("recon lookup", ["--json", "--exact"])])),
        encoding="utf-8",
    )

    assert main([str(old_path), str(new_path), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["added_flags"] == [{"command": "recon lookup", "token": "--exact"}]
    assert payload["removed_flags"] == []


def test_main_requires_old_inventory_or_ref(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2

    assert "provide old_inventory or --old-ref" in capsys.readouterr().err


def test_git_ref_loader_reports_git_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    new_path = tmp_path / "new.json"
    new_path.write_text(json.dumps(_inventory([])), encoding="utf-8")

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["git", "show"], 128, "", "missing ref")

    monkeypatch.setattr("scripts.summarize_cli_surface_changes.subprocess.run", fake_run)

    with pytest.raises(ValueError, match=r"could not read docs/surface-inventory\.json from v0\.0\.0"):
        main(["--old-ref", "v0.0.0", str(new_path)])
