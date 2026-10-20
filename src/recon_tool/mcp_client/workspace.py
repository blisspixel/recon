"""Keep implicit MCP workspace operations bound to admitted directories."""

from __future__ import annotations

import contextlib
import ctypes
import os
import secrets
from collections.abc import Generator
from ctypes import wintypes
from pathlib import Path
from typing import Any, Protocol, cast


class _WindowsCtypes(Protocol):
    def WinDLL(self, name: str, *, use_last_error: bool) -> Any: ...
    def get_last_error(self) -> int: ...
    def WinError(self, code: int) -> OSError: ...


class _AttributeTag(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


class _UnicodeString(ctypes.Structure):
    _fields_ = [("length", wintypes.USHORT), ("maximum", wintypes.USHORT), ("buffer", wintypes.LPWSTR)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root", wintypes.HANDLE),
        ("name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security", ctypes.c_void_p),
        ("quality", ctypes.c_void_p),
    ]


class _IoStatus(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]


@contextlib.contextmanager
def _windows_guard(api: Any, directory: int) -> Generator[None, None, None]:
    """Keep an anchored, nondeletable entry in the directory until close.

    Windows sharing does not deny FILE_WRITE_ATTRIBUTES. A nonempty directory
    cannot acquire a reparse point, so a held guard also mediates that route.
    NtCreateFile binds creation to the directory handle instead of its name.
    Delete-on-close removes the actual guard even if the namespace changes.
    """
    win = cast(_WindowsCtypes, ctypes)
    native = win.WinDLL("ntdll", use_last_error=True)
    native.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatus),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    native.NtCreateFile.restype = wintypes.LONG
    native.RtlNtStatusToDosError.argtypes = [wintypes.LONG]
    native.RtlNtStatusToDosError.restype = wintypes.ULONG
    name = ".recon-install-" + secrets.token_hex(16) + ".guard"
    buffer = ctypes.create_unicode_buffer(name)
    text = _UnicodeString(len(name) * 2, (len(name) + 1) * 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), directory, ctypes.pointer(text), 0x1000, None, None
    )
    handle, status_block = wintypes.HANDLE(), _IoStatus()
    # DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES, TEMPORARY, SHARE_READ,
    # FILE_CREATE; NON_DIRECTORY | DELETE_ON_CLOSE | SYNCHRONOUS | OPEN_REPARSE.
    status = native.NtCreateFile(
        ctypes.byref(handle),
        0x110080,
        ctypes.byref(attributes),
        ctypes.byref(status_block),
        None,
        0x100,
        1,
        2,
        0x201060,
        None,
        0,
    )
    if status < 0:
        raise win.WinError(native.RtlNtStatusToDosError(status))
    try:
        yield
    finally:
        api.CloseHandle(handle)


def _require_windows_directory(api: Any, handle: int, path: Path) -> None:
    info = _AttributeTag()
    win = cast(_WindowsCtypes, ctypes)
    if not api.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
        raise win.WinError(win.get_last_error())
    if not info.attributes & 0x10 or info.attributes & 0x400:
        raise OSError(f"workspace directory must not be a reparse point: {path}")


def _windows_api() -> Any:
    api = cast(_WindowsCtypes, ctypes).WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    api.GetFileInformationByHandleEx.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


@contextlib.contextmanager
def _locked_windows_directory(path: Path) -> Generator[None, None, None]:
    """Reject reparses and deny directory write/delete sharing until close.

    Holding every ancestor prevents rename, deletion and opening a handle to
    turn the admitted directory into a junction while name-based I/O runs.
    Unsupported filesystems or conflicting handles fail closed.
    """
    api = _windows_api()
    # FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
    # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
    handle = api.CreateFileW(str(path), 0x80, 0x1, None, 3, 0x02200000, None)
    win = cast(_WindowsCtypes, ctypes)
    if handle == ctypes.c_void_p(-1).value:
        raise win.WinError(win.get_last_error())
    try:
        _require_windows_directory(api, handle, path)
        with _windows_guard(api, handle):
            _require_windows_directory(api, handle, path)
            yield
    finally:
        api.CloseHandle(handle)


@contextlib.contextmanager
def workspace_directory(path: Path, *, create: bool = True) -> Generator[int | None, None, None]:
    """Create and retain a safe parent for one implicit workspace filename.

    POSIX consumers must use the returned descriptor for every read/write.
    Windows consumers use names only while all ancestor handles remain locked.
    Actual platform capabilities govern this boundary, not path-table previews.
    Read-only planning yields -1 when a parent does not exist, without creating it.
    Windows planning uses temporary guard entries in existing directories; they
    are deleted on handle close and never change client configuration.
    """
    root = Path.cwd()
    relative = path.relative_to(root)
    if any(part in {"", ".", ".."} for part in relative.parts) or not relative.parts:
        raise ValueError("invalid implicit workspace filename")
    with contextlib.ExitStack() as stack:
        if os.name == "nt":
            current = root
            stack.enter_context(_locked_windows_directory(current))
            for part in relative.parts[:-1]:
                current = current / part
                if create:
                    current.mkdir(exist_ok=True)
                try:
                    stack.enter_context(_locked_windows_directory(current))
                except FileNotFoundError:
                    if create:
                        raise
                    yield -1
                    return
            yield None
        else:
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise OSError("safe workspace directory operations are unavailable")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            directory_fd = os.open(".", flags)
            stack.callback(os.close, directory_fd)
            for part in relative.parts[:-1]:
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                try:
                    directory_fd = os.open(part, flags, dir_fd=directory_fd)
                except FileNotFoundError:
                    if create:
                        raise
                    yield -1
                    return
                stack.callback(os.close, directory_fd)
            yield directory_fd
