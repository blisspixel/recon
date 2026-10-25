# Legacy typing exceptions are owned in docs/typing-exceptions.json.
# pyright: reportPrivateUsage=none, reportUnknownArgumentType=none, reportUnknownVariableType=none
"""Launch-contract regression matrix for the generated MCP launcher (issue 220).

The launcher that ``recon mcp install`` writes must start from any client
working directory, including the home directory and a filesystem root, while
still refusing a ``recon_tool`` package that was imported through the working
directory.

The subprocess tests build a synthetic per-user installation beneath a
temporary home directory whose path contains spaces: a fresh ``venv`` (no pip,
no network) with a copy of the ``recon_tool`` package in its own site-packages
and this test environment's dependency directory appended by a ``.pth`` line.
They ask that installation for the stanza its own ``build_recon_block`` would
write, then launch exactly that command, argument list, and environment entry
from each working directory. Successful launches are verified with the
repository's SDK-compatible doctor handshake (discovery, tools, resources); a
process that merely stays alive is not counted as success.

Everything is offline. Each launch is bounded by the doctor's 30-second budget
or an explicit subprocess timeout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

import recon_tool
from recon_tool.mcp_client.doctor import LaunchConfig, run_generated_launch_check
from recon_tool.server import launch_guard
from recon_tool.server.launch_guard import detect_cwd_shadow_install, refusal_message

# ── Unit matrix: benign ancestors versus imported shadows ───────────


def _fake_package(root: Path) -> Path:
    pkg = root / "recon_tool"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("# synthetic\n", encoding="utf-8")
    return pkg


def _point_package_at(monkeypatch: pytest.MonkeyPatch, pkg: Path) -> None:
    monkeypatch.setattr(recon_tool, "__file__", str(pkg / "__init__.py"))


class TestGuardBenignAncestors:
    """The loaded package sits below the cwd but was not imported through it."""

    def test_per_user_install_under_home_is_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home with space"
        site_dir = home / ".local" / "share" / "uv" / "tools" / "recon-tool" / "lib" / "site-packages"
        _point_package_at(monkeypatch, _fake_package(site_dir))
        monkeypatch.chdir(home)
        # ``''`` is what ``python -c`` adds without PYTHONSAFEPATH; it resolves
        # to the home directory, which is not where the package came from.
        monkeypatch.setattr(sys, "path", ["", str(site_dir)])

        assert detect_cwd_shadow_install() is None

    def test_filesystem_root_cwd_is_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        site_dir = tmp_path / "venv dir" / "lib" / "site-packages"
        _point_package_at(monkeypatch, _fake_package(site_dir))
        monkeypatch.chdir(Path(tmp_path.anchor))
        monkeypatch.setattr(sys, "path", [str(site_dir)])

        assert detect_cwd_shadow_install() is None

    def test_project_venv_below_cwd_is_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        site_dir = tmp_path / ".venv" / "Lib" / "site-packages"
        _point_package_at(monkeypatch, _fake_package(site_dir))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "path", [str(tmp_path), str(site_dir)])

        assert detect_cwd_shadow_install() is None

    def test_import_root_that_is_an_installation_root_is_allowed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A client whose cwd is the interpreter's own site-packages imports the
        # installed package through cwd; that copy is the installed one.
        site_dir = tmp_path / "site-packages"
        _point_package_at(monkeypatch, _fake_package(site_dir))
        monkeypatch.chdir(site_dir)
        monkeypatch.setattr(launch_guard, "_installation_roots", lambda: [site_dir.resolve()])

        assert detect_cwd_shadow_install() is None

    def test_installation_roots_include_running_purelib(self) -> None:
        purelib = Path(sysconfig.get_paths()["purelib"]).resolve()
        roots = launch_guard._installation_roots()
        assert any(launch_guard._same_path(purelib, root) for root in roots)
        assert all(root.is_absolute() for root in roots)


class TestGuardImportedShadows:
    """The loaded package was imported through the working directory."""

    def test_package_directly_in_cwd_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _point_package_at(monkeypatch, _fake_package(tmp_path))
        monkeypatch.chdir(tmp_path)

        result = detect_cwd_shadow_install()
        assert result is not None
        assert "refusing to start" in result

    def test_relative_sys_path_entry_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # ``PYTHONPATH=src`` style entries resolve against the cwd at import time.
        _point_package_at(monkeypatch, _fake_package(tmp_path / "src"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "path", ["src"])

        result = detect_cwd_shadow_install()
        assert result is not None
        assert "refusing to start" in result

    def test_symlinked_cwd_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        real = tmp_path / "real workspace"
        pkg = _fake_package(real)
        link = tmp_path / "linked workspace"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"directory symlinks are unavailable here: {exc}")
        _point_package_at(monkeypatch, pkg)
        monkeypatch.chdir(link)

        assert detect_cwd_shadow_install() is not None

    def test_case_variant_cwd_is_refused_on_case_insensitive_filesystems(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        workspace = tmp_path / "Workspace"
        pkg = _fake_package(workspace)
        variant = tmp_path / "wORKSPACE"
        if not variant.is_dir():
            pytest.skip("filesystem is case-sensitive; case variants name different directories")
        # The package path is reported in one spelling and the cwd in another.
        _point_package_at(monkeypatch, pkg)
        monkeypatch.chdir(variant)

        assert detect_cwd_shadow_install() is not None

    def test_source_checkout_remains_allowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _point_package_at(monkeypatch, _fake_package(tmp_path))
        (tmp_path / "pyproject.toml").write_text('[project]\nname="recon-tool"\n', encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        assert detect_cwd_shadow_install() is None

    def test_unreadable_pyproject_is_not_a_source_checkout(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_bytes(b"\xff\xfe\xfa")
        assert launch_guard._is_source_checkout(tmp_path) is False


class TestGuardFallbacks:
    def test_unusable_cwd_is_not_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _point_package_at(monkeypatch, _fake_package(tmp_path))

        def _no_cwd() -> Path:
            raise OSError("cwd removed")

        monkeypatch.setattr(Path, "cwd", staticmethod(_no_cwd))
        assert detect_cwd_shadow_install() is None

    def test_missing_package_file_is_not_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(recon_tool, "__file__", None)
        assert detect_cwd_shadow_install() is None

    def test_same_path_falls_back_to_normalized_comparison(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        assert launch_guard._same_path(missing, missing)
        assert not launch_guard._same_path(missing, tmp_path)

    def test_unresolvable_relative_entry_is_skipped(self, tmp_path: Path) -> None:
        assert not launch_guard._cwd_dependent_entries(tmp_path / "pkgroot", tmp_path, ["\x00bad", 7])

    def test_refusal_is_bounded_printable_and_actionable(self) -> None:
        hostile = Path("/" + "a" * 5000 + "\x1b]52;c;x\x07")
        message = refusal_message(hostile / "recon_tool", hostile)

        assert len(message) < 1500
        assert "\x1b" not in message
        assert "\x07" not in message
        assert "refusing to start" in message
        assert "recon mcp install --client=<name>" in message
        assert "PYTHONPATH" in message
        assert "Python < 3.11" not in message


# ── Subprocess matrix: synthetic per-user install under HOME ───────

_LAUNCH_TIMEOUT_S = 60
# Editable-install finders and coverage hooks from the test environment must not
# leak into the synthetic install.
_SKIPPED_PTH_PREFIXES = ("_editable", "__editable__", "_recon", "a1_coverage", "coverage", "_virtualenv")


@dataclass(frozen=True)
class SyntheticInstall:
    home: Path
    python: Path
    site_packages: Path
    block: dict[str, object]
    env: dict[str, str]


def _client_env(home: Path) -> dict[str, str]:
    """Return a client-like environment rooted at the synthetic home."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "VIRTUAL_ENV", "COV_CORE", "COVERAGE", "XDG_", "RECON_", "UV_"))
    }
    env["HOME"] = str(home)
    if sys.platform == "win32":
        env["USERPROFILE"] = str(home)
    return env


def _venv_python(venv_dir: Path) -> Path:
    scripts = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    return scripts / ("python.exe" if sys.platform == "win32" else "python")


def _run_probe(python: Path, code: str, *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(  # noqa: S603 - argv list built locally, no shell.
        [str(python), "-I", "-c", code],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=_LAUNCH_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture(scope="module")
def synthetic_install(tmp_path_factory: pytest.TempPathFactory) -> SyntheticInstall:
    pytest.importorskip("mcp")
    base = tmp_path_factory.mktemp("launch cwd")
    home = base / "home dir with space"
    venv_dir = home / ".local" / "share" / "uv" / "tools" / "recon tool"
    created = subprocess.run(  # noqa: S603 - argv list built locally, no shell.
        [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"cannot create a synthetic venv here: {created.stderr.strip()[:300]}")
    python = _venv_python(venv_dir)
    env = _client_env(home)
    probe_cwd = base
    site_packages = Path(
        _run_probe(python, "import sysconfig; print(sysconfig.get_paths()['purelib'])", cwd=probe_cwd, env=env)
    )

    package_source = Path(recon_tool.__file__).resolve().parent
    shutil.copytree(package_source, site_packages / "recon_tool", ignore=shutil.ignore_patterns("__pycache__"))
    dependency_dirs = dict.fromkeys(str(Path(sysconfig.get_paths()[key]).resolve()) for key in ("purelib", "platlib"))
    # A plain path line appends the directory without processing its own .pth
    # files, so this environment's editable recon_tool finder stays inactive.
    # Dependency .pth files (pywin32 needs one on Windows) are replayed with
    # absolute paths, skipping the editable finder and coverage hooks.
    pth_lines = list(dependency_dirs)
    for directory in dependency_dirs:
        for pth in sorted(Path(directory).glob("*.pth")):
            if pth.name.startswith(_SKIPPED_PTH_PREFIXES):
                continue
            for line in pth.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                pth_lines.append(stripped if stripped.startswith("import") else str(Path(directory) / stripped))
    (site_packages / "zz_recon_test_dependencies.pth").write_text("\n".join(pth_lines) + "\n", encoding="utf-8")

    loaded_from = Path(_run_probe(python, "import recon_tool; print(recon_tool.__file__)", cwd=probe_cwd, env=env))
    assert loaded_from.resolve().parent == (site_packages / "recon_tool").resolve(), (
        f"synthetic install imported recon_tool from {loaded_from}, not its own site-packages"
    )
    # The SDK bounds server/discover at a fixed 10 seconds. Pay the one-time
    # costs of a fresh install (bytecode compilation and the first run of a new
    # interpreter, which Windows may scan) here, untimed, so the launch tests
    # measure the launcher rather than first-install warm-up (issue 303).
    compiled = subprocess.run(  # noqa: S603 - argv list built locally, no shell.
        [str(python), "-m", "compileall", "-q", str(site_packages / "recon_tool")],
        cwd=probe_cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    _run_probe(python, "import recon_tool.server", cwd=probe_cwd, env=env)
    block = json.loads(
        _run_probe(
            python,
            "import json; from recon_tool.mcp_client.install import build_recon_block; "
            "print(json.dumps(build_recon_block('cursor')))",
            cwd=probe_cwd,
            env=env,
        )
    )
    return SyntheticInstall(home=home, python=python, site_packages=site_packages, block=block, env=env)


def _launch_config(install: SyntheticInstall, cwd: Path) -> LaunchConfig:
    args = install.block["args"]
    block_env = install.block["env"]
    assert isinstance(args, list)
    assert isinstance(block_env, dict)
    return LaunchConfig(
        scope="generated",
        command=str(install.block["command"]),
        args=tuple(str(item) for item in args),
        env=tuple((str(key), str(value)) for key, value in block_env.items()),
        cwd=str(cwd),
    )


def _assert_handshake_ok(install: SyntheticInstall, cwd: Path, env: dict[str, str] | None = None) -> None:
    launch = _launch_config(install, cwd)
    report = run_generated_launch_check(launch=launch, base_env=install.env if env is None else env)

    failures = [check for check in report.checks if check.status != "ok"]
    assert report.ok, f"generated launch from {cwd} failed: {failures}\n{report.server_stderr_tail}"
    assert report.launch == launch
    details = {check.name: check.detail for check in report.checks}
    discovery = details.get("server/discover") or details.get("initialize handshake") or ""
    assert "server=recon-tool" in discovery
    assert details["required tools present"].startswith("5 of 5")
    assert details["required resources present"].startswith("6 of 6")


def _assert_clean_eof_exit(install: SyntheticInstall, cwd: Path) -> None:
    """Start the exact launch, close stdin, and require a prompt, quiet exit."""
    launch = _launch_config(install, cwd)
    env = dict(install.env)
    env.update(dict(launch.env))
    process = subprocess.Popen(  # noqa: S603 - argv list built locally, no shell.
        [launch.command, *launch.args],
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(input=b"", timeout=_LAUNCH_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        pytest.fail(f"server launched from {cwd} did not exit after stdin EOF")
    assert process.returncode == 0, stderr.decode("utf-8", "replace")[-2000:]
    # stdout belongs to JSON-RPC; with no requests sent it must stay empty.
    assert stdout == b"", stdout[:500]
    assert b"refusing to start" not in stderr


class TestGeneratedLaunchMatrix:
    def test_generated_stanza_is_the_safe_interpreter_bound_launcher(self, synthetic_install: SyntheticInstall) -> None:
        from recon_tool.mcp_client.install import _FALLBACK_LAUNCH_CODE

        assert Path(str(synthetic_install.block["command"])).parent == synthetic_install.python.parent
        assert synthetic_install.block["args"] == ["-c", _FALLBACK_LAUNCH_CODE]
        assert synthetic_install.block["env"] == {"PYTHONSAFEPATH": "1"}

    def test_launch_from_home(self, synthetic_install: SyntheticInstall) -> None:
        _assert_handshake_ok(synthetic_install, synthetic_install.home)
        _assert_clean_eof_exit(synthetic_install, synthetic_install.home)

    def test_launch_from_filesystem_root(self, synthetic_install: SyntheticInstall) -> None:
        root = Path(synthetic_install.home.anchor)
        if not root.is_dir() or (root / "recon_tool").exists():
            pytest.skip(f"filesystem root {root} is unusable as a launch directory here")
        _assert_handshake_ok(synthetic_install, root)
        _assert_clean_eof_exit(synthetic_install, root)

    def test_launch_from_unrelated_directory(self, synthetic_install: SyntheticInstall) -> None:
        unrelated = synthetic_install.home.parent / "unrelated project dir"
        unrelated.mkdir(exist_ok=True)
        _assert_handshake_ok(synthetic_install, unrelated)

    def test_hostile_shadow_in_cwd_never_executes(self, synthetic_install: SyntheticInstall) -> None:
        workspace = synthetic_install.home.parent / "hostile workspace"
        pkg = workspace / "recon_tool"
        pkg.mkdir(parents=True, exist_ok=True)
        marker = workspace / "SHADOW_EXECUTED"
        payload = f"open({str(marker)!r}, 'w').close()\n"
        (pkg / "__init__.py").write_text(payload, encoding="utf-8")
        (pkg / "server.py").write_text(payload, encoding="utf-8")

        _assert_handshake_ok(synthetic_install, workspace)
        assert not marker.exists(), "the workspace recon_tool package executed instead of the installed one"

    def test_imported_workspace_copy_is_refused(self, synthetic_install: SyntheticInstall) -> None:
        """A client env with ``PYTHONPATH=.`` puts the absolute cwd on sys.path.

        The generated launcher strips only ``''`` and ``'.'``, so a genuine
        recon_tool copy in that workspace is imported, and the runtime guard is
        the layer that must refuse it with bounded, actionable stderr and
        nothing on stdout.
        """
        workspace = synthetic_install.home.parent / "copied workspace"
        if not (workspace / "recon_tool").exists():
            shutil.copytree(
                synthetic_install.site_packages / "recon_tool",
                workspace / "recon_tool",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        launch = _launch_config(synthetic_install, workspace)
        env = dict(synthetic_install.env)
        env["PYTHONPATH"] = "."
        env.update(dict(launch.env))

        started = time.monotonic()
        result = subprocess.run(  # noqa: S603 - argv list built locally, no shell.
            [launch.command, *launch.args],
            cwd=workspace,
            env=env,
            input=b"",
            capture_output=True,
            timeout=_LAUNCH_TIMEOUT_S,
            check=False,
        )
        assert time.monotonic() - started < _LAUNCH_TIMEOUT_S
        stderr = result.stderr.decode("utf-8", "replace")
        assert result.returncode == 2, stderr[-2000:]
        assert result.stdout == b""
        assert "refusing to start" in stderr
        assert "recon mcp install --client=<name>" in stderr
        assert len(stderr) < 2000

        report = run_generated_launch_check(launch=launch, base_env={**synthetic_install.env, "PYTHONPATH": "."})
        assert not report.ok
        assert "refusing to start" in report.server_stderr_tail
