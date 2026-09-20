"""Release Windows launcher locks before running a verified update command.

The worker uses the base interpreter in isolated mode and imports only the
standard library. It must remain runnable while its package is being replaced.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Protocol, cast


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("pid", wintypes.DWORD),
        ("heap", ctypes.c_size_t),
        ("module", wintypes.DWORD),
        ("threads", wintypes.DWORD),
        ("parent_pid", wintypes.DWORD),
        ("priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
        ("name", wintypes.WCHAR * 260),
    ]


class _WindowsCtypes(Protocol):
    """ctypes exports available only when the Windows handoff is invoked."""

    def WinDLL(self, name: str, *, use_last_error: bool) -> Any: ...
    def get_last_error(self) -> int: ...
    def WinError(self, code: int) -> OSError: ...


_windows_ctypes = cast(_WindowsCtypes, ctypes)
_CREATE_NO_WINDOW = 0x08000000


def _last_error() -> int:
    return _windows_ctypes.get_last_error()


def _windows_error() -> OSError:
    return _windows_ctypes.WinError(_last_error())


def _windows_api() -> Any:
    api = _windows_ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ("Process32FirstW", "Process32NextW"):
        method = getattr(api, name)
        method.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
        method.restype = wintypes.BOOL
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


def _process_table() -> dict[int, tuple[int, str]]:
    api = _windows_api()
    snapshot = api.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        raise _windows_error()
    entry = _ProcessEntry()
    entry.size = ctypes.sizeof(entry)
    records: dict[int, tuple[int, str]] = {}
    try:
        more = api.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            records[int(entry.pid)] = (int(entry.parent_pid), str(entry.name))
            more = api.Process32NextW(snapshot, ctypes.byref(entry))
        if _last_error() != 18:  # ERROR_NO_MORE_FILES
            raise _windows_error()
    finally:
        api.CloseHandle(snapshot)
    return records


def _launcher_chain(pid: int, records: dict[int, tuple[int, str]]) -> list[int]:
    """Wait for this interpreter and its recon launchers, never the shell."""
    chain = [pid]
    while pid in records:
        parent = records[pid][0]
        if parent in chain or records.get(parent, (0, ""))[1].casefold() != "recon.exe":
            break
        chain.append(parent)
        pid = parent
    return chain


def requires_handoff() -> bool:
    # Console-script bootstraps may strip the .exe suffix from argv[0].
    return sys.platform == "win32" and Path(sys.argv[0]).name.casefold() in {"recon", "recon.exe"}


def start_update(command: list[str]) -> Path:
    """Start the already-authorized argv after this launcher has exited."""
    pids = _launcher_chain(os.getpid(), _process_table())
    interpreter = str(Path(sys._base_executable).resolve())  # type: ignore[attr-defined]
    worker = str(Path(__file__).resolve())
    working_directory = str(Path.cwd())
    with tempfile.NamedTemporaryFile(prefix="recon-update-", suffix=".log", delete=False) as log:
        log_path = Path(log.name)
        try:
            subprocess.Popen(  # noqa: S603 - isolated base interpreter and verified manager argv, no shell.
                [
                    interpreter,
                    "-I",
                    "-S",
                    "-X",
                    "utf8",
                    worker,
                    json.dumps(command),
                    json.dumps(pids),
                    working_directory,
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=log_path.parent,
                creationflags=_CREATE_NO_WINDOW,
                close_fds=True,
            )
        except OSError:
            log.close()
            log_path.unlink(missing_ok=True)
            raise
    return log_path


def _wait_for_exit(pids: list[int]) -> None:
    api = _windows_api()
    deadline = time.monotonic() + 60.0
    for pid in pids:
        handle = api.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            if _last_error() == 87:  # already exited
                continue
            raise _windows_error()
        try:
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            status = api.WaitForSingleObject(handle, remaining)
            if status == 258:
                raise TimeoutError("recon is still running; retry the update after it exits")
            if status != 0:
                raise _windows_error()
        finally:
            api.CloseHandle(handle)


def _run_update(command: list[str], pids: list[int], working_directory: str) -> int:
    print("Waiting for the recon launcher to exit...", flush=True)
    try:
        _wait_for_exit(pids)
        print("Installing the checked release...", flush=True)
        # Relative manager roots and configuration paths must retain the same
        # meaning they had during the caller's ownership verification.
        result = subprocess.run(command, cwd=working_directory, check=False)  # noqa: S603
    except (OSError, TimeoutError) as exc:
        print(f"Update failed: {exc}", flush=True)
        return 1
    if result.returncode:
        print(f"Update failed (exit {result.returncode}). Retry with recon update.", flush=True)
        return 1
    print("Update completed. Run recon --version to confirm.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_update(json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3]))
