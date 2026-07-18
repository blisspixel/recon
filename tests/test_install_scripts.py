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


def test_installers_do_not_bootstrap_pipx_with_unpinned_pip() -> None:
    script = _INSTALL_SH.read_text(encoding="utf-8")
    powershell = _INSTALL_PS1.read_text(encoding="utf-8")

    assert "sort -V" not in script
    assert "pip install" not in script
    assert "pip install" not in powershell
    assert "https://astral.sh/uv/install.sh" not in script
    assert "https://astral.sh/uv/install.ps1" not in powershell
    assert "install uv or pipx first" in script
    assert "install uv or pipx first" in powershell
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


def test_helper_guidance_requires_local_review_before_execution() -> None:
    texts = {
        "README": _README.read_text(encoding="utf-8"),
        "Getting Started": _GETTING_STARTED.read_text(encoding="utf-8"),
        "PowerShell installer": _INSTALL_PS1.read_text(encoding="utf-8"),
        "Unix installer": _INSTALL_SH.read_text(encoding="utf-8"),
    }

    for label, text in texts.items():
        assert "raw.githubusercontent.com/blisspixel/recon/main/scripts/install" not in text, label
        assert "review" in text.lower(), label
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
                'printf \'%s %s\\n\' "' + manager + '" "$*" >> "$INSTALLER_LOG"',
                f"if [ {list_command} ]; then",
                f'  printf \'%s\\n\' "${{FAKE_{prefix}_LIST:-}}"',
                f'  exit "${{FAKE_{prefix}_LIST_STATUS:-0}}"',
                "fi",
                f'printf \'%s\\n\' "${{FAKE_{prefix}_INSTALL_OUTPUT:-{manager} install output}}" >&2',
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
    uv: bool = True,
    pipx: bool = True,
    recon: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    if os.name == "nt":
        pytest.skip("behavioral installer execution runs on Unix CI")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    if uv:
        _fake_manager(fake_bin / "uv", "uv")
    if pipx:
        _fake_manager(fake_bin / "pipx", "pipx")
    if recon:
        command = fake_bin / "recon"
        command.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        command.chmod(0o755)
    log = tmp_path / "manager.log"
    env = os.environ.copy()
    env.update(
        {
            "PATH": os.pathsep.join((str(fake_bin), "/usr/bin", "/bin")),
            "INSTALLER_LOG": str(log),
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
    list_condition = (
        'if /I "%~1 %~2"=="tool list"' if manager == "uv" else 'if /I "%~1"=="list"'
    )
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
                f"1>&2 echo(%FAKE_{prefix}_INSTALL_OUTPUT%",
                f"exit /b %FAKE_{prefix}_INSTALL_STATUS%",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _run_windows_installer(
    tmp_path: Path,
    *,
    uv: bool = True,
    pipx: bool = True,
    recon: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    if os.name != "nt":
        pytest.skip("behavioral PowerShell installer execution runs on Windows CI")
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows PowerShell is not available")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    if uv:
        _fake_windows_manager(fake_bin / "uv.cmd", "uv")
    if pipx:
        _fake_windows_manager(fake_bin / "pipx.cmd", "pipx")
    if recon:
        (fake_bin / "recon.cmd").write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
    log = tmp_path / "manager.log"
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    env = os.environ.copy()
    env.update(
        {
            "PATH": os.pathsep.join((str(fake_bin), str(system_root / "System32"), str(system_root))),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "INSTALLER_LOG": str(log),
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
    result = subprocess.run(  # noqa: S603
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(_INSTALL_PS1)],
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
