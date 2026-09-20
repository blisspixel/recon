"""Installer-script regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_INSTALL_SH = _ROOT / "scripts" / "install.sh"
_INSTALL_PS1 = _ROOT / "scripts" / "install.ps1"
_README = _ROOT / "README.md"
_GETTING_STARTED = _ROOT / "docs" / "getting-started.md"
_VERSION = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_installers_bootstrap_pinned_uv_without_system_pip() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")
    powershell = _INSTALL_PS1.read_text(encoding="utf-8")

    assert "sort -V" not in script
    assert "pip install" not in script
    assert "pip install" not in powershell
    assert "https://astral.sh/uv/install.sh" not in script
    assert "https://astral.sh/uv/install.ps1" not in powershell
    assert 'UV_VERSION="0.11.17"' in script
    assert '$UvVersion = "0.11.17"' in powershell
    assert "https://astral.sh/uv/$UV_VERSION/install.sh" in script
    assert "https://astral.sh/uv/$UvVersion/install.ps1" in powershell
    assert "Invoke-Expression (Invoke-RestMethod" not in powershell


def test_installers_preserve_the_offline_first_run_trust_sequence() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")
    powershell = _INSTALL_PS1.read_text(encoding="utf-8")

    for installer in (script, powershell):
        normalized = installer.lower()
        assert installer.index("--version") < installer.index("doctor")
        assert "offline install check" in normalized
        assert "online source connectivity" in normalized
        assert "DNS infrastructure" in installer
        assert "MTA-STS" in installer
        assert "Google CSE" in installer
        assert "BIMI" in installer
        assert "--direct-probes" in installer


def test_installers_bind_the_reviewed_release_version_and_owner() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")
    powershell = _INSTALL_PS1.read_text(encoding="utf-8")

    assert f'VERSION="{_VERSION}"' in script
    assert f'$Version = "{_VERSION}"' in powershell
    for installer in (script, powershell):
        assert "==${VERSION}" in installer or "==$Version" in installer
        assert "--force" in installer
        assert "both uv and pipx report an installed" in installer
        assert "is not owned by uv or pipx" in installer
    assert "2>/dev/null ||" not in script
    assert 'uv tool install "$PACKAGE"' not in script
    assert "uv tool install $Package" not in powershell


def test_helper_guidance_provides_one_command_and_reviewable_alternative() -> None:
    texts = {
        "README": _README.read_text(encoding="utf-8"),
        "Getting Started": _GETTING_STARTED.read_text(encoding="utf-8"),
        "PowerShell installer": _INSTALL_PS1.read_text(encoding="utf-8"),
        "Unix installer": _INSTALL_SH.read_text(encoding="utf-8"),
    }

    for label, text in texts.items():
        if label in {"README", "Getting Started"}:
            assert "raw.githubusercontent.com/blisspixel/recon/main/scripts/install.sh | bash" in text, label
            assert "raw.githubusercontent.com/blisspixel/recon/main/scripts/install.ps1 | iex" in text, label
            assert "review" in text.lower(), label
            assert "pip install recon-tool" in text, label
            assert "recon update" in text, label
    assert "blob/main/scripts/install" not in texts["README"]
    assert "https://github.com/blisspixel/recon/releases/latest" in texts["README"]
    assert "scripts/install.sh" in texts["README"]
    assert "scripts/install.ps1" in texts["README"]
    assert "bash scripts/install.sh" in texts["Unix installer"]
    assert "-File .\\scripts\\install.ps1" in texts["PowerShell installer"]


def test_onboarding_explains_exact_owner_preserving_helpers_and_release_verification() -> None:
    readme = _README.read_text(encoding="utf-8")
    getting_started = _GETTING_STARTED.read_text(encoding="utf-8")

    for text in (readme, getting_started):
        normalized = " ".join(text.split())
        assert "exact" in normalized
        assert "release tag" in normalized or "represented by that tag" in normalized
        assert "sole" in normalized
        assert "unmanaged" in normalized
        assert "supply-chain.md#consumer-verification-quick-path" in normalized
    assert "Python 3.11 through 3.14" in getting_started
    assert "Python 3.11 or newer" not in getting_started


def test_unix_installer_shell_syntax() -> None:
    if os.name == "nt":
        pytest.skip("checked on Unix runners")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")

    subprocess.run([bash, "-n", str(_INSTALL_SH)], check=True)  # noqa: S603


def _fake_manager(path: Path, manager: str) -> None:
    list_command = '"$1" = "tool" ] && [ "$2" = "list"' if manager == "uv" else '"$1" = "list"'
    prefix = manager.upper()
    path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "printf '%s %s\\n' \"" + manager + '" "$*" >> "$INSTALLER_LOG"',
                f"if [ {list_command} ]; then",
                f"  printf '%s\\n' \"${{FAKE_{prefix}_LIST:-}}\"",
                f'  exit "${{FAKE_{prefix}_LIST_STATUS:-0}}"',
                "fi",
                'if [ "$*" = "tool dir --bin" ] || [ "$*" = "environment --value PIPX_BIN_DIR" ]; then',
                '  printf "%s\\n" "$FAKE_BIN_DIR"',
                '  exit "${FAKE_BIN_STATUS:-0}"',
                "fi",
                'if [ "$*" = "tool update-shell" ] || [ "$*" = "ensurepath" ]; then',
                '  exit "${FAKE_PATH_STATUS:-0}"',
                "fi",
                f"printf '%s\\n' \"${{FAKE_{prefix}_INSTALL_OUTPUT:-{manager} install output}}\" >&2",
                f'if [ "${{FAKE_{prefix}_INSTALL_STATUS:-0}}" -eq 0 ] && [ "${{FAKE_CREATE_RECON:-1}}" = "1" ]; then',
                "  cat > \"$FAKE_RECON_PATH\" <<'RECON_EOF'",
                "#!/usr/bin/env bash",
                "printf '%s\\n' \"${FAKE_RECON_VERSION_OUTPUT:-}\"",
                'exit "${FAKE_RECON_VERSION_STATUS:-0}"',
                "RECON_EOF",
                '  chmod +x "$FAKE_RECON_PATH"',
                "fi",
                f'exit "${{FAKE_{prefix}_INSTALL_STATUS:-0}}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_unix_installer(
    tmp_path: Path,
    *,
    pipx: bool = True,
    recon: bool = False,
    stale_recon_output: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    if os.name == "nt":
        pytest.skip("behavioral installer execution runs on Unix CI")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    bin_on_path = (extra_env or {}).get("FAKE_BIN_OFF_PATH") != "1"
    bootstrap = (extra_env or {}).get("FAKE_BOOTSTRAP") == "1"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    tool_bin = fake_bin if bin_on_path else tmp_path / "tool bin"
    tool_bin.mkdir(exist_ok=True)
    manager_bin = tmp_path / "uv bin" if bootstrap else fake_bin
    manager_bin.mkdir(exist_ok=True)
    _fake_manager(manager_bin / "uv", "uv")
    if bootstrap:
        download = fake_bin / "curl"
        download.write_text(
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$INSTALLER_LOG"\n'
            "for output; do :; done\n"
            'printf \'echo "bootstrap executed" >> "$INSTALLER_LOG"\\n\' > "$output"\n'
            'exit "${FAKE_DOWNLOAD_FAILURE:-0}"\n',
            encoding="utf-8",
        )
        download.chmod(0o755)
    if pipx:
        _fake_manager(fake_bin / "pipx", "pipx")
    if recon:
        command = fake_bin / "recon"
        command.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        command.chmod(0o755)
    path_entries: list[str] = []
    if stale_recon_output is not None:
        stale_bin = tmp_path / "stale-bin"
        stale_bin.mkdir()
        stale = stale_bin / "recon"
        stale.write_text(
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{stale_recon_output}'\n",
            encoding="utf-8",
        )
        stale.chmod(0o755)
        path_entries.append(str(stale_bin))
    path_entries.extend((str(fake_bin), "/usr/bin", "/bin"))
    log = tmp_path / "manager.log"
    env = os.environ.copy()
    env.update(
        {
            "PATH": os.pathsep.join(path_entries),
            "INSTALLER_LOG": str(log),
            "FAKE_CREATE_RECON": "1",
            "FAKE_RECON_PATH": str(tool_bin / "recon"),
            "FAKE_BIN_DIR": str(tool_bin),
            "UV_INSTALL_DIR": str(manager_bin),
            "FAKE_RECON_VERSION_OUTPUT": f"recon {_VERSION}",
            "FAKE_RECON_VERSION_STATUS": "0",
        }
    )
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(  # noqa: S603
        [bash, str(_INSTALL_SH)],
        cwd=_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, log.read_text(encoding="utf-8") if log.exists() else ""


def test_unix_installer_preserves_existing_pipx_owner(tmp_path: Path) -> None:
    result, log = _run_unix_installer(
        tmp_path,
        extra_env={"FAKE_UV_LIST": "", "FAKE_PIPX_LIST": "package recon-tool 2.6.2"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"pipx install --force recon-tool=={_VERSION}" in log
    assert "uv tool install" not in log
    assert f"reports recon {_VERSION}" in result.stdout
    assert 'recon "<domain-you-want-to-review>"' in result.stdout
    assert "Syntax-only reserved example" in result.stdout


def test_unix_installer_refuses_ambiguous_dual_ownership(tmp_path: Path) -> None:
    result, log = _run_unix_installer(
        tmp_path,
        extra_env={"FAKE_UV_LIST": "recon-tool 2.6.2", "FAKE_PIPX_LIST": "package recon-tool 2.6.2"},
    )

    assert result.returncode == 1
    assert "both uv and pipx" in result.stderr
    assert " install --force " not in log


def test_unix_installer_refuses_unmanaged_existing_command(tmp_path: Path) -> None:
    result, _log = _run_unix_installer(tmp_path, recon=True)

    assert result.returncode == 1
    assert "is not owned by uv or pipx" in result.stderr
    assert "recon update" in result.stderr


def test_unix_installer_surfaces_native_install_failure(tmp_path: Path) -> None:
    result, log = _run_unix_installer(
        tmp_path,
        pipx=False,
        extra_env={"FAKE_UV_INSTALL_STATUS": "9", "FAKE_UV_INSTALL_OUTPUT": "native install failure"},
    )

    assert result.returncode == 1
    assert "native install failure" in result.stderr
    assert f"uv could not install recon-tool=={_VERSION}" in result.stderr
    assert f"uv tool install --force recon-tool=={_VERSION}" in log


def test_unix_installer_rejects_stale_first_launcher_and_lists_candidates(tmp_path: Path) -> None:
    result, log = _run_unix_installer(
        tmp_path,
        stale_recon_output="recon 2.6.3",
        extra_env={"FAKE_UV_LIST": "recon-tool 2.15.0", "FAKE_PIPX_LIST": ""},
    )

    assert result.returncode == 1
    assert f"uv tool install --force recon-tool=={_VERSION}" in log
    assert "reported recon\\ 2.6.3" in result.stderr
    assert f"expected recon\\ {_VERSION}" in result.stderr
    assert f"Resolved launcher: {tmp_path / 'stale-bin' / 'recon'}" in result.stderr
    assert "Discovered candidates:" in result.stderr
    assert str(tmp_path / "stale-bin" / "recon") in result.stderr
    assert str(tmp_path / "bin" / "recon") in result.stderr
    assert "==> Done." not in result.stdout


def test_unix_installer_rejects_missing_postinstall_launcher(tmp_path: Path) -> None:
    result, _log = _run_unix_installer(
        tmp_path,
        extra_env={"FAKE_CREATE_RECON": "0"},
    )

    assert result.returncode == 1
    assert "no 'recon' launcher resolves on PATH" in result.stderr
    assert "Resolved launcher: (not found)" in result.stderr
    assert "Discovered candidates:" in result.stderr
    assert "  (none)" in result.stderr


@pytest.mark.parametrize("version_output", ["unexpected output", f"recon {_VERSION} "])
def test_unix_installer_rejects_malformed_version_output(tmp_path: Path, version_output: str) -> None:
    result, _log = _run_unix_installer(
        tmp_path,
        extra_env={"FAKE_RECON_VERSION_OUTPUT": version_output},
    )

    assert result.returncode == 1
    assert "returned malformed output" in result.stderr
    assert f"Resolved launcher: {tmp_path / 'bin' / 'recon'}" in result.stderr
    assert str(tmp_path / "bin" / "recon") in result.stderr


def test_powershell_installer_parses() -> None:
    if os.name != "nt":
        pytest.skip("Windows PowerShell parser is available on Windows CI")
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows PowerShell is not available")
    path = str(_INSTALL_PS1).replace("'", "''")
    command = f"[scriptblock]::Create((Get-Content -Raw -LiteralPath '{path}')) | Out-Null"

    subprocess.run([powershell, "-NoProfile", "-Command", command], check=True)  # noqa: S603


def _fake_windows_manager(path: Path, manager: str) -> None:
    list_condition = 'if /I "%~1 %~2"=="tool list"' if manager == "uv" else 'if /I "%~1"=="list"'
    prefix = manager.upper()
    path.write_text(
        "\r\n".join(
            [
                "@echo off",
                f'>>"%INSTALLER_LOG%" echo {manager} %*',
                f"{list_condition} (",
                f"  echo(%FAKE_{prefix}_LIST%",
                f"  exit /b %FAKE_{prefix}_LIST_STATUS%",
                ")",
                'if /I "%~1 %~2 %~3"=="tool dir --bin" (',
                "  echo(%FAKE_BIN_DIR%",
                "  exit /b %FAKE_BIN_STATUS%",
                ")",
                'if /I "%~1 %~2 %~3"=="environment --value PIPX_BIN_DIR" (',
                "  echo(%FAKE_BIN_DIR%",
                "  exit /b %FAKE_BIN_STATUS%",
                ")",
                'if /I "%~1 %~2"=="tool update-shell" exit /b %FAKE_PATH_STATUS%',
                'if /I "%~1"=="ensurepath" exit /b %FAKE_PATH_STATUS%',
                f"1>&2 echo(%FAKE_{prefix}_INSTALL_OUTPUT%",
                f'if "%FAKE_{prefix}_INSTALL_STATUS%"=="0" if "%FAKE_CREATE_RECON%"=="1" (',
                '>"%FAKE_RECON_PATH%" echo @echo off',
                '>>"%FAKE_RECON_PATH%" echo echo(%%FAKE_RECON_VERSION_OUTPUT%%',
                '>>"%FAKE_RECON_PATH%" echo exit /b %%FAKE_RECON_VERSION_STATUS%%',
                ")",
                f"exit /b %FAKE_{prefix}_INSTALL_STATUS%",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _run_windows_installer(
    tmp_path: Path,
    *,
    pipx: bool = True,
    recon: bool = False,
    stale_recon_output: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    if os.name != "nt":
        pytest.skip("behavioral PowerShell installer execution runs on Windows CI")
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows PowerShell is not available")
    bin_on_path = (extra_env or {}).get("FAKE_BIN_OFF_PATH") != "1"
    bootstrap = (extra_env or {}).get("FAKE_BOOTSTRAP") == "1"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    tool_bin = fake_bin if bin_on_path else tmp_path / "tool bin"
    tool_bin.mkdir(exist_ok=True)
    manager_bin = tmp_path / "uv bin" if bootstrap else fake_bin
    manager_bin.mkdir(exist_ok=True)
    _fake_windows_manager(manager_bin / "uv.cmd", "uv")
    if pipx:
        _fake_windows_manager(fake_bin / "pipx.cmd", "pipx")
    if recon:
        (fake_bin / "recon.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    path_entries: list[str] = []
    if stale_recon_output is not None:
        stale_bin = tmp_path / "stale-bin"
        stale_bin.mkdir()
        (stale_bin / "recon.cmd").write_text(
            f"@echo off\r\necho {stale_recon_output}\r\nexit /b 0\r\n",
            encoding="utf-8",
        )
        path_entries.append(str(stale_bin))
    path_entries.extend((str(fake_bin), str(system_root / "System32"), str(system_root), str(Path(powershell).parent)))
    log = tmp_path / "manager.log"
    env = os.environ.copy()
    env.update(
        {
            "PATH": os.pathsep.join(path_entries),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "INSTALLER_LOG": str(log),
            "FAKE_CREATE_RECON": "1",
            "FAKE_RECON_PATH": str(tool_bin / "recon.cmd"),
            "FAKE_BIN_DIR": str(tool_bin),
            "FAKE_BIN_STATUS": "0",
            "FAKE_PATH_STATUS": "0",
            "UV_INSTALL_DIR": str(manager_bin),
            "FAKE_RECON_VERSION_OUTPUT": f"recon {_VERSION}",
            "FAKE_RECON_VERSION_STATUS": "0",
            "FAKE_UV_LIST": "",
            "FAKE_UV_LIST_STATUS": "0",
            "FAKE_UV_INSTALL_OUTPUT": "uv install output",
            "FAKE_UV_INSTALL_STATUS": "0",
            "FAKE_PIPX_LIST": "",
            "FAKE_PIPX_LIST_STATUS": "0",
            "FAKE_PIPX_INSTALL_OUTPUT": "pipx install output",
            "FAKE_PIPX_INSTALL_STATUS": "0",
        }
    )
    if extra_env:
        env.update(extra_env)
    script = _INSTALL_PS1
    if bootstrap:
        script = tmp_path / "bootstrap-test.ps1"
        quoted_script = str(_INSTALL_PS1).replace("'", "''")
        script.write_text(
            "function Invoke-WebRequest {\n"
            "  param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile)\n"
            "  Add-Content -LiteralPath $env:INSTALLER_LOG -Value $Uri\n"
            "  if ($env:FAKE_DOWNLOAD_FAILURE -eq '1') { throw 'download failed' }\n"
            "  Set-Content -LiteralPath $OutFile -Value 'exit 0'\n"
            "}\n"
            f"& '{quoted_script}'\n",
            encoding="utf-8",
        )
    result = subprocess.run(  # noqa: S603
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        cwd=_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, log.read_text(encoding="utf-8") if log.exists() else ""


def test_powershell_installer_preserves_existing_pipx_owner(tmp_path: Path) -> None:
    result, log = _run_windows_installer(
        tmp_path,
        extra_env={"FAKE_UV_LIST": "", "FAKE_PIPX_LIST": "package recon-tool 2.6.2"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"pipx install --force recon-tool=={_VERSION}" in log
    assert "uv tool install" not in log
    assert f"reports recon {_VERSION}" in result.stdout
    assert 'recon "<domain-you-want-to-review>"' in result.stdout
    assert "Syntax-only reserved example" in result.stdout


def test_powershell_installer_refuses_ambiguous_dual_ownership(tmp_path: Path) -> None:
    result, log = _run_windows_installer(
        tmp_path,
        extra_env={"FAKE_UV_LIST": "recon-tool 2.6.2", "FAKE_PIPX_LIST": "package recon-tool 2.6.2"},
    )

    assert result.returncode == 1
    assert "both uv and pipx" in result.stdout
    assert " install --force " not in log


def test_powershell_installer_refuses_unmanaged_existing_command(tmp_path: Path) -> None:
    result, _log = _run_windows_installer(tmp_path, recon=True)

    assert result.returncode == 1
    assert "is not owned by uv or pipx" in result.stdout
    assert "recon update" in result.stdout


def test_powershell_installer_surfaces_native_install_failure(tmp_path: Path) -> None:
    result, log = _run_windows_installer(
        tmp_path,
        pipx=False,
        extra_env={"FAKE_UV_INSTALL_STATUS": "9", "FAKE_UV_INSTALL_OUTPUT": "native install failure"},
    )

    assert result.returncode == 1
    assert "native install failure" in result.stdout
    assert f"uv could not install recon-tool=={_VERSION}" in result.stdout
    assert f"uv tool install --force recon-tool=={_VERSION}" in log


def test_powershell_installer_rejects_stale_first_launcher_and_lists_candidates(tmp_path: Path) -> None:
    result, log = _run_windows_installer(
        tmp_path,
        stale_recon_output="recon 2.6.3",
        extra_env={"FAKE_UV_LIST": "recon-tool 2.15.0", "FAKE_PIPX_LIST": ""},
    )

    assert result.returncode == 1
    assert f"uv tool install --force recon-tool=={_VERSION}" in log
    assert "reported 'recon 2.6.3'" in result.stdout
    assert f"expected 'recon {_VERSION}'" in result.stdout
    assert f"Resolved launcher: {tmp_path / 'stale-bin' / 'recon.cmd'}" in result.stdout
    assert "Discovered candidates:" in result.stdout
    assert str(tmp_path / "stale-bin" / "recon.cmd") in result.stdout
    assert str(tmp_path / "bin" / "recon.cmd") in result.stdout
    assert "==> Done." not in result.stdout


def test_powershell_installer_rejects_missing_postinstall_launcher(tmp_path: Path) -> None:
    result, _log = _run_windows_installer(
        tmp_path,
        extra_env={"FAKE_CREATE_RECON": "0"},
    )

    assert result.returncode == 1
    assert "no 'recon' launcher resolves on PATH" in result.stdout
    assert "Resolved launcher: (not found)" in result.stdout
    assert "Discovered candidates:" in result.stdout
    assert "  (none)" in result.stdout


@pytest.mark.parametrize("version_output", ["unexpected output", f"recon {_VERSION} "])
def test_powershell_installer_rejects_malformed_version_output(tmp_path: Path, version_output: str) -> None:
    result, _log = _run_windows_installer(
        tmp_path,
        extra_env={"FAKE_RECON_VERSION_OUTPUT": version_output},
    )

    assert result.returncode == 1
    assert "returned malformed output" in result.stdout
    assert f"Resolved launcher: {tmp_path / 'bin' / 'recon.cmd'}" in result.stdout
    assert str(tmp_path / "bin" / "recon.cmd") in result.stdout


@pytest.mark.parametrize("manager", ["uv", "pipx"])
def test_installer_adds_missing_tool_directory_to_path(tmp_path: Path, manager: str) -> None:
    run = _run_windows_installer if os.name == "nt" else _run_unix_installer
    result, log = run(
        tmp_path,
        extra_env={"FAKE_BIN_OFF_PATH": "1", "FAKE_PIPX_LIST": "package recon-tool 2.6.2" if manager == "pipx" else ""},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("uv tool update-shell" if manager == "uv" else "pipx ensurepath") in log
    assert f"reports recon {_VERSION}" in result.stdout
    assert "tool bin" in result.stdout


def test_installer_bootstraps_uv_on_a_fresh_machine(tmp_path: Path) -> None:
    run = _run_windows_installer if os.name == "nt" else _run_unix_installer
    result, log = run(tmp_path, pipx=False, extra_env={"FAKE_BOOTSTRAP": "1", "FAKE_BIN_OFF_PATH": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "https://astral.sh/uv/0.11.17/install." in log
    assert f"uv tool install --force recon-tool=={_VERSION} --python 3.14" in log
    assert f"reports recon {_VERSION}" in result.stdout


def test_installer_stops_when_bootstrap_download_fails(tmp_path: Path) -> None:
    run = _run_windows_installer if os.name == "nt" else _run_unix_installer
    result, log = run(tmp_path, pipx=False, extra_env={"FAKE_BOOTSTRAP": "1", "FAKE_DOWNLOAD_FAILURE": "1"})
    assert result.returncode != 0
    assert "uv tool install" not in log
    assert "bootstrap executed" not in log
    assert "==> Done." not in result.stdout


@pytest.mark.parametrize("failure", ["FAKE_BIN_STATUS", "FAKE_PATH_STATUS"])
def test_installer_does_not_claim_success_when_path_setup_fails(tmp_path: Path, failure: str) -> None:
    run = _run_windows_installer if os.name == "nt" else _run_unix_installer
    result, _ = run(tmp_path, extra_env={"FAKE_BIN_OFF_PATH": "1", failure: "1"})
    assert result.returncode != 0
    assert "==> Done." not in result.stdout
