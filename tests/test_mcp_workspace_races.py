"""Workspace installation keeps filesystem authority inside its bound directory."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import struct
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from recon_tool.mcp_client import install as installer
from recon_tool.mcp_client import workspace as workspace_helpers
from recon_tool.mcp_client.workspace import workspace_directory


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory substitution; native Windows locking tested separately")
@pytest.mark.parametrize("stage", ["read", "write", "replace"])
@pytest.mark.parametrize("client", ["vscode", "kiro"])
def test_parent_substitution_cannot_redirect_workspace_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: str, stage: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    target = installer.resolve_config_path(client, "workspace")  # pyright: ignore[reportArgumentType]
    target.parent.mkdir(parents=True)
    target.write_text("{}\n")
    relative = target.relative_to(workspace)
    parent = workspace / relative.parts[0]
    outside = tmp_path / "outside"
    external = outside.joinpath(*relative.parts[1:])
    external.parent.mkdir(parents=True)
    original = '{"outside": "preserve"}\n'
    external.write_text(original)
    moved = workspace / "saved-parent"
    swapped = False

    def swap() -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(moved)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True

    read = installer._read_existing
    write = installer._atomic_write_text
    replace = os.replace
    reads = 0

    def read_hook(*args: Any, **kwargs: Any) -> dict[str, object]:
        nonlocal reads
        reads += 1
        if reads == 2 and stage == "read":
            swap()
        return read(*args, **kwargs)

    def write_hook(*args: Any, **kwargs: Any) -> None:
        if stage == "write":
            swap()
        write(*args, **kwargs)

    def replace_hook(*args: Any, **kwargs: Any) -> None:
        if stage == "replace":
            swap()
        replace(*args, **kwargs)

    monkeypatch.setattr(installer, "_read_existing", read_hook)
    monkeypatch.setattr(installer, "_atomic_write_text", write_hook)
    monkeypatch.setattr(installer.os, "replace", replace_hook)
    installer.install(client, "workspace")  # pyright: ignore[reportArgumentType]
    assert swapped
    assert external.read_text() == original
    written = moved.joinpath(*relative.parts[1:])
    assert "recon" in json.loads(written.read_text())[installer.servers_key(client)]  # pyright: ignore[reportArgumentType]
    assert not list(tmp_path.rglob("*.tmp"))


def test_workspace_planning_does_not_create_missing_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    installer.plan_install("kiro", "workspace")
    assert not (tmp_path / ".kiro").exists()
    result = installer.install("kiro", "workspace")
    assert result.path.is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX namespace substitution; native Windows guards deny it")
def test_planning_cannot_import_private_fields_through_a_substituted_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / ".vscode" / "mcp.json"
    target.parent.mkdir(parents=True)
    block = {**installer.build_recon_block("vscode"), "env": {"WORKSPACE": "keep"}}
    target.write_text(json.dumps({"servers": {"recon": block}}), encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    private = {**block, "env": {"PRIVATE": "must-not-copy"}}
    (outside / "mcp.json").write_text(json.dumps({"servers": {"recon": private}}), encoding="utf-8")
    monkeypatch.chdir(workspace)
    original = installer._read_existing

    def swap_before_read(*args: Any, **kwargs: Any) -> dict[str, object]:
        target.parent.rename(workspace / "saved")
        target.parent.symlink_to(outside, target_is_directory=True)
        return original(*args, **kwargs)

    monkeypatch.setattr(installer, "_read_existing", swap_before_read)
    plan = installer.plan_install("vscode", "workspace")
    assert plan.new_block["env"] == {"WORKSPACE": "keep"}


@pytest.mark.skipif(os.name != "nt", reason="Native Windows directory sharing contract")
def test_windows_holds_each_workspace_ancestor_through_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = installer.resolve_config_path("kiro", "workspace")
    with workspace_directory(target):
        for directory in [target.parent.parent, target.parent]:
            with pytest.raises(PermissionError):
                directory.rename(directory.with_name(directory.name + "-moved"))
        target.write_text("{}", encoding="utf-8")
    target.parent.rename(target.parent.with_name("renamed"))


@pytest.mark.skipif(os.name != "nt", reason="Native Windows junction contract")
def test_windows_workspace_junction_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = workspace / ".vscode"
    command = shutil.which("cmd.exe")
    assert command is not None
    subprocess.run(  # noqa: S603 - fixed native junction command and pytest-owned paths, no target data.
        [command, "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=True,
        capture_output=True,
        text=True,
    )
    monkeypatch.chdir(workspace)
    with pytest.raises((OSError, ValueError), match="reparse point"), workspace_directory(junction / "mcp.json"):
        pytest.fail("workspace junction was admitted")
    assert not list(outside.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Native Windows reparse mutation contract")
def test_windows_attribute_handle_cannot_reparse_locked_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    substitute = ("\\??\\" + str(outside)).encode("utf-16-le")
    printed = str(outside).encode("utf-16-le")
    names = substitute + b"\0\0" + printed + b"\0\0"
    payload = (
        struct.pack("<IHHHHHH", 0xA0000003, len(names) + 8, 0, 0, len(substitute), len(substitute) + 2, len(printed))
        + names
    )
    data = ctypes.create_string_buffer(payload)
    api = workspace_helpers._windows_api()
    api.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    api.DeviceIoControl.restype = wintypes.BOOL

    def set_junction(directory: Path) -> bool:
        handle = api.CreateFileW(str(directory), 0x100, 7, None, 3, 0x02200000, None)
        assert handle != ctypes.c_void_p(-1).value
        try:
            returned = wintypes.DWORD()
            return bool(api.DeviceIoControl(handle, 0x900A4, data, len(payload), None, 0, ctypes.byref(returned), None))
        finally:
            api.CloseHandle(handle)

    # The same attribute-only handle and valid payload must work unguarded.
    control = tmp_path / "control"
    control.mkdir()
    assert set_junction(control)
    control.rmdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    target = workspace / ".vscode" / "mcp.json"
    with workspace_directory(target):
        assert not set_junction(target.parent)
        target.write_text("{}", encoding="utf-8")
    assert not list(workspace.rglob("*.guard"))
    assert not list(outside.iterdir())
