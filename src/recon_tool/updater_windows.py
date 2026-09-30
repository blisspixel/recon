"""Apply a verified upgrade without depending on the package being replaced.

Windows locks the running ``recon.exe``. The handoff copies this module to a
private temp directory and runs that copy with the base interpreter in isolated
mode, after this process exits. macOS and Linux run the same installer,
verification, and recovery text in the foreground. The worker imports only the
standard library so it can keep running while pip, uv, or pipx replaces recon.
"""

from __future__ import annotations

import ctypes
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Protocol, cast

WHEELHOUSE_PREFIX = "recon-update-wheels-"
_HANDOFF_NAMES = {"recon", "recon.exe", "recon.cmd", "recon-script.py", "recon-script.pyw"}
_LAUNCHER_NAMES = {"recon", "recon.exe"}
_LOCK_MARKERS = ("winerror 32", "being used by another process", "text file busy", "resource busy")
_LOCK_ATTEMPTS = 3
_CREATE_NO_WINDOW = 0x08000000
_VERIFY_CODE = "import importlib.metadata as metadata\nimport recon_tool\nprint(metadata.version('recon-tool'))\n"


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
    """Windows console launchers have to exit before their files can be replaced."""
    return sys.platform == "win32" and Path(sys.argv[0]).name.casefold() in _HANDOFF_NAMES


def remove_wheelhouse(path: Path | str | None) -> None:
    """Delete a staging directory created for this update and nothing else."""
    if path is None or path == "":
        return
    directory = Path(path)
    try:
        info = directory.lstat()
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return
    try:
        resolved = directory.resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
    except OSError:
        return
    if resolved == temp_root or temp_root not in resolved.parents:
        return
    if not resolved.name.startswith(WHEELHOUSE_PREFIX):
        return
    shutil.rmtree(resolved, ignore_errors=True)


def _format_command(command: list[str]) -> str:
    if sys.platform == "win32":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def _manager_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INPUT"] = "1"
    return env


def _output_is_locked(output: str) -> bool:
    folded = output.casefold()
    return any(marker in folded for marker in _LOCK_MARKERS)


def _pinned_version(command: list[str]) -> str | None:
    marker = "recon-tool=="
    for arg in command:
        if arg.startswith(marker):
            version = arg[len(marker) :]
            if version and all(character not in version for character in " \t/\\"):
                return version
    return None


def _report_failure(
    command: list[str],
    message: str,
    output: str,
    alternate: list[str] | None = None,
) -> None:
    print(message, flush=True)
    if "externally-managed-environment" in output.casefold():
        print(
            "This Python is externally managed. Install with "
            "`uv tool install --upgrade recon-tool` or `pipx upgrade recon-tool`.",
            flush=True,
        )
    print("Run this command directly. It does not require the recon launcher:", flush=True)
    print(_format_command(command), flush=True)
    if alternate is not None and alternate != command:
        print("If that command can no longer see its downloaded files, run:", flush=True)
        print(_format_command(alternate), flush=True)


def _run_manager(command: list[str], cwd: str) -> tuple[int, str]:
    result = subprocess.run(  # noqa: S603 - argv was authorized by the parent update command; no shell.
        command,
        cwd=cwd,
        env=_manager_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    output = f"{getattr(result, 'stdout', None) or ''}{getattr(result, 'stderr', None) or ''}"
    if output:
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
    return result.returncode, output


def _install_with_retries(command: list[str], cwd: str) -> tuple[int, str]:
    code = 1
    output = ""
    for attempt in range(_LOCK_ATTEMPTS):
        print("Installing the checked release..." if attempt == 0 else "Retrying after a file lock...", flush=True)
        code, output = _run_manager(command, cwd)
        if code == 0 or not _output_is_locked(output) or attempt + 1 == _LOCK_ATTEMPTS:
            return code, output
        time.sleep(float(attempt + 1))
    return code, output


def _verify_install(interpreter: str, expected: str | None) -> str | None:
    """Return None when the installed package imports, else a short reason."""
    last = "recon-tool does not import"
    cwd = str(Path(interpreter).resolve().parent)
    for _attempt in range(2):
        try:
            result = subprocess.run(  # noqa: S603 - fixed interpreter and stdlib import check; no shell.
                [interpreter, "-c", _VERIFY_CODE],
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            last = str(exc)
            time.sleep(0.5)
            continue
        if result.returncode != 0:
            last = (result.stderr or result.stdout or last).strip()
            time.sleep(0.5)
            continue
        lines = (result.stdout or "").strip().splitlines()
        version = lines[-1].strip() if lines else ""
        if not version:
            return "recon-tool did not report a version"
        if expected is not None and version != expected:
            return f"installed {version}, expected {expected}"
        return None
    return last


def _pause_after_launcher_exit() -> None:
    # The process handle can close before Windows releases the executable image.
    time.sleep(0.3)


def _other_windows_launchers(finished: set[int]) -> list[int]:
    if sys.platform != "win32":
        return []
    ignored = {os.getpid(), *finished}
    found: list[int] = []
    for pid, (_parent, name) in _process_table().items():
        if pid in ignored or name.casefold() not in _LAUNCHER_NAMES:
            continue
        found.append(pid)
    return sorted(found)


def _wait_for_launchers(pids: list[int], recovery: list[str]) -> bool:
    if not pids:
        return True
    print("Waiting for the recon launcher to exit...", flush=True)
    try:
        _wait_for_exit(pids)
    except (OSError, TimeoutError) as exc:
        _report_failure(recovery, f"Update failed: {exc}", "")
        return False
    _pause_after_launcher_exit()
    blockers = _other_windows_launchers(set(pids))
    if not blockers:
        return True
    rendered = ", ".join(str(pid) for pid in blockers)
    _report_failure(
        recovery,
        f"Another recon launcher is still running (pid {rendered}). Close it before replacing the installation.",
        "",
    )
    return False


class _Job:
    """One authorized upgrade. Fields stay mutable so callers do not need a wide constructor."""

    def __init__(self, command: list[str], cwd: str, pids: list[int]) -> None:
        self.command = command
        self.cwd = cwd
        self.pids = pids
        self.interpreter = sys.executable
        self.wheelhouse = ""
        self.recovery = command


def _run_update(job: _Job) -> int:
    if not _wait_for_launchers(job.pids, job.recovery):
        remove_wheelhouse(job.wheelhouse)
        return 1
    code, output = _install_with_retries(job.command, job.cwd)
    if code != 0:
        # Leave a downloaded wheelhouse in place so this command can be repeated offline.
        _report_failure(job.command, f"Update failed (exit {code}).", output, job.recovery)
        return 1
    reason = _verify_install(job.interpreter, _pinned_version(job.command))
    if reason is not None:
        detail = f"Update failed: installation check did not pass ({reason})."
        _report_failure(job.command, detail, "", job.recovery)
        return 1
    remove_wheelhouse(job.wheelhouse)
    print("Update completed. Run recon --version to confirm.", flush=True)
    return 0


def apply_upgrade(
    command: list[str],
    *,
    wheelhouse: Path | None = None,
    recovery: list[str] | None = None,
    interpreter: str | None = None,
) -> int:
    """Run an authorized upgrade in this process. Used on macOS and Linux."""
    job = _Job(command, str(Path.cwd()), [])
    job.interpreter = interpreter or sys.executable
    if wheelhouse is not None:
        job.wheelhouse = str(wheelhouse)
    if recovery is not None:
        job.recovery = recovery
    return _run_update(job)


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


def _worker_request(
    command: list[str],
    wheelhouse: Path | None,
    recovery: list[str] | None,
    interpreter: str,
) -> dict[str, Any]:
    return {
        "command": command,
        "pids": _launcher_chain(os.getpid(), _process_table()),
        "cwd": str(Path.cwd()),
        "interpreter": interpreter,
        "wheelhouse": str(wheelhouse) if wheelhouse is not None else "",
        "recovery": recovery or command,
    }


def _json_object(argv: list[str]) -> dict[str, Any] | None:
    if len(argv) != 2:
        return None
    try:
        payload = json.loads(argv[1])
    except ValueError:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) for item in value)


def _request_fields_ok(payload: dict[str, Any]) -> bool:
    command = payload.get("command")
    pids = payload.get("pids")
    recovery = payload.get("recovery", command)
    wheelhouse = payload.get("wheelhouse", "")
    text_fields = (payload.get("cwd"), payload.get("interpreter"), wheelhouse)
    pids_ok = isinstance(pids, list) and all(isinstance(item, int) and not isinstance(item, bool) for item in pids)
    return (
        _string_list(command)
        and _string_list(recovery)
        and pids_ok
        and all(isinstance(item, str) for item in text_fields)
    )


def _load_request(argv: list[str]) -> dict[str, Any] | None:
    payload = _json_object(argv)
    if payload is None or not _request_fields_ok(payload):
        return None
    return payload


def start_update(
    command: list[str],
    *,
    wheelhouse: Path | None = None,
    recovery: list[str] | None = None,
    interpreter: str | None = None,
) -> Path:
    """Start the already-authorized argv after this launcher has exited."""
    runtime = interpreter or sys.executable
    payload = _worker_request(command, wheelhouse, recovery, runtime)
    directory = Path(tempfile.mkdtemp(prefix="recon-update-"))
    log_path = directory / "update.log"
    worker_path = directory / "worker.py"
    worker_path.write_bytes(Path(__file__).read_bytes())
    log_handle = log_path.open("w", encoding="utf-8")
    try:
        subprocess.Popen(  # noqa: S603 - isolated base interpreter and a private copy of this file; no shell.
            [
                str(Path(sys._base_executable).resolve()),  # type: ignore[attr-defined]
                "-I",
                "-S",
                "-X",
                "utf8",
                str(worker_path),
                json.dumps(payload),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            cwd=str(directory),
            creationflags=_CREATE_NO_WINDOW,
            close_fds=True,
        )
    except OSError:
        log_handle.close()
        shutil.rmtree(directory, ignore_errors=True)
        raise
    log_handle.close()
    return log_path


def main(argv: list[str]) -> int:
    payload = _load_request(argv)
    if payload is None:
        print("Update failed: the worker request was incomplete.", flush=True)
        return 1
    job = _Job(cast(list[str], payload["command"]), cast(str, payload["cwd"]), cast(list[int], payload["pids"]))
    job.interpreter = cast(str, payload["interpreter"])
    job.wheelhouse = cast(str, payload["wheelhouse"])
    job.recovery = cast(list[str], payload["recovery"])
    return _run_update(job)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
