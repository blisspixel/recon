"""v1.9.3.4 — MCP path-isolation regression tests.

Pins the three defense layers that close the audit finding "MCP doctor
/install can execute shadowed recon_tool package" (HIGH):

  1. ``mcp_doctor`` spawns the server with empty-tempdir cwd and
     ``PYTHONSAFEPATH=1`` env. A cwd-shadow attack cannot reach a
     subprocess that runs in an empty directory.

  2. ``mcp_install`` persists ``PYTHONSAFEPATH=1`` in the fallback
     launch block's ``env`` so future MCP-client launches on
     Python 3.11+ stay safe, and ``warn_if_fallback`` exposes a
     warning the CLI can surface to operators on Python 3.10.

  3. ``recon_tool.server._detect_cwd_shadow_install`` is the runtime
     guard. Regardless of how the server was launched, it checks
     whether the loaded package path is under cwd and whether cwd
     looks like the legitimate source repo. A shadow workspace
     triggers a refusal-to-start error.

The shadow-workspace integration test is the load-bearing one: it
actually spawns ``python -m recon_tool.server`` from a tempdir
containing a fake ``recon_tool/server.py`` and asserts the install
loads, not the shadow.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# Typed shutil.which replacements used by monkeypatching tests below.
# Hoisted to module level so they have static type info (pyright objects
# to inline lambdas under strict mode).
def _shutil_which_returns_none(name: str) -> str | None:
    """Stub for ``shutil.which`` that pretends nothing is on PATH."""
    return None


def _shutil_which_returns_fake_recon(name: str) -> str | None:
    """Stub for ``shutil.which`` that returns a fake absolute path so
    the install path picks the preferred (recon-on-PATH) launch form."""
    return "/fake/path/to/recon"


# ── Layer 1: mcp_doctor spawn parameters ────────────────────────────


class TestMcpDoctorSpawnsSafely:
    """``_run_handshake`` builds ``StdioServerParameters`` with a safe
    cwd and PYTHONSAFEPATH=1 env. We don't run the handshake here —
    that requires the full MCP SDK loop and a real subprocess.
    Instead, we assert the source of ``_run_handshake`` carries both
    safeguards. If a future refactor drops either, the test fails."""

    def test_mcp_doctor_source_sets_pythonsafepath_env(self):
        src = Path("recon_tool/mcp_doctor.py").read_text(encoding="utf-8")
        assert "PYTHONSAFEPATH" in src, (
            "mcp_doctor.py must reference PYTHONSAFEPATH on the subprocess "
            "env to disable cwd-prepend on Python 3.11+."
        )
        assert '"1"' in src, (
            "mcp_doctor.py must set PYTHONSAFEPATH to '1' (the value that "
            "disables cwd-prepend), not just reference the variable name."
        )

    def test_mcp_doctor_source_passes_cwd_to_subprocess(self):
        src = Path("recon_tool/mcp_doctor.py").read_text(encoding="utf-8")
        # The fix uses StdioServerParameters(..., cwd=safe_cwd) where
        # safe_cwd comes from tempfile.TemporaryDirectory.
        assert "cwd=safe_cwd" in src, (
            "mcp_doctor.py must pass cwd= to StdioServerParameters so "
            "the subprocess runs in an empty tempdir, not the caller's "
            "(potentially untrusted) workspace."
        )
        assert "tempfile.TemporaryDirectory" in src, (
            "mcp_doctor.py must create the safe cwd via "
            "tempfile.TemporaryDirectory for automatic cleanup."
        )


# ── Layer 2: mcp_install persisted env + warning ───────────────────


class TestMcpInstallPersistsSafeEnv:
    """``build_recon_block`` persists ``PYTHONSAFEPATH=1`` in the
    fallback launch block's env. ``warn_if_fallback`` exposes a
    warning when the fallback is in use."""

    def test_fallback_block_has_pythonsafepath_env(self, monkeypatch):
        # Force the fallback path: pretend ``recon`` is not on PATH.
        monkeypatch.setattr(
            "recon_tool.mcp_install.shutil.which",
            _shutil_which_returns_none,
        )
        from recon_tool.mcp_install import build_recon_block

        block = build_recon_block()
        assert block["command"] == sys.executable
        assert block["args"] == ["-m", "recon_tool.server"]
        # The new env entry — load-bearing for the audit fix.
        assert block.get("env") == {"PYTHONSAFEPATH": "1"}, (
            "fallback block must persist PYTHONSAFEPATH=1 in env so "
            "MCP clients launching the server on Python 3.11+ get "
            "cwd-shadow protection."
        )

    def test_recon_on_path_block_omits_env(self, monkeypatch):
        # When recon is on PATH, the block uses the `recon mcp` form
        # which has no -m and therefore no cwd-prepend concern. The
        # env block stays clean to avoid persisting unnecessary state.
        monkeypatch.setattr(
            "recon_tool.mcp_install.shutil.which",
            _shutil_which_returns_fake_recon,
        )
        from recon_tool.mcp_install import build_recon_block

        block = build_recon_block()
        assert block["command"] == "/fake/path/to/recon"
        assert block["args"] == ["mcp"]
        assert "env" not in block, (
            "preferred block (recon on PATH) should not carry an env "
            "key — it has no cwd-shadow concern to mitigate."
        )

    def test_warn_if_fallback_when_recon_missing(self, monkeypatch):
        monkeypatch.setattr(
            "recon_tool.mcp_install.shutil.which",
            _shutil_which_returns_none,
        )
        from recon_tool.mcp_install import warn_if_fallback

        warning = warn_if_fallback()
        assert warning is not None
        assert "PATH" in warning
        assert "PYTHONSAFEPATH" in warning, (
            "warning must mention the env-var-level mitigation so the "
            "operator can map it to their Python version's protection."
        )

    def test_warn_if_fallback_returns_none_when_recon_on_path(self, monkeypatch):
        monkeypatch.setattr(
            "recon_tool.mcp_install.shutil.which",
            _shutil_which_returns_fake_recon,
        )
        from recon_tool.mcp_install import warn_if_fallback

        assert warn_if_fallback() is None


# ── Layer 3: server-side runtime guard ─────────────────────────────


class TestServerRuntimeGuard:
    """``_detect_cwd_shadow_install`` returns None for safe installs
    and a refusal message for shadow installs. We test the function
    directly (cheap) plus a real subprocess from a shadow workspace
    (the integration check)."""

    def test_guard_returns_none_for_normal_install(self):
        # In the test runner's process, recon_tool is loaded from the
        # editable install path — should look safe.
        from recon_tool.server import _detect_cwd_shadow_install

        result = _detect_cwd_shadow_install()
        # In CI the test runs from the repo root, which has the
        # legitimate pyproject.toml. Confirms the "safe source
        # checkout" branch fires.
        assert result is None, (
            f"guard refused a legitimate install: {result!r}. The repo "
            "root contains a recon-tool pyproject.toml; the guard "
            "should recognize this as the legitimate source checkout."
        )

    def test_guard_refuses_shadow_install(self, tmp_path, monkeypatch):
        # Simulate the shadow case: chdir to a tempdir that contains
        # a recon_tool/ directory but NOT a legitimate pyproject.toml.
        # The guard inspects recon_tool.__file__ vs cwd; we need to
        # convince it the package is under cwd.
        fake_pkg = tmp_path / "recon_tool"
        fake_pkg.mkdir()
        (fake_pkg / "__init__.py").write_text("# shadow\n", encoding="utf-8")
        (fake_pkg / "server.py").write_text("# shadow\n", encoding="utf-8")

        # Monkeypatch the imported recon_tool module to look like it
        # loaded from the shadow dir.
        import recon_tool
        monkeypatch.setattr(
            recon_tool, "__file__", str(fake_pkg / "__init__.py")
        )
        monkeypatch.chdir(tmp_path)

        from recon_tool.server import _detect_cwd_shadow_install

        result = _detect_cwd_shadow_install()
        assert result is not None, (
            "guard failed to detect a shadow workspace — recon_tool was "
            f"under {tmp_path}, but the guard returned None."
        )
        assert "refusing to start" in result
        assert "cwd-shadow" in result.lower() or "shadow" in result.lower()

    def test_guard_allows_legitimate_source_checkout(self, tmp_path, monkeypatch):
        # Plant a recon_tool/ AND a recon-tool pyproject.toml at the
        # same level. The guard must accept this as a dev checkout.
        fake_pkg = tmp_path / "recon_tool"
        fake_pkg.mkdir()
        (fake_pkg / "__init__.py").write_text("# dev\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "recon-tool"\nversion = "0.0.0"\n',
            encoding="utf-8",
        )

        import recon_tool
        monkeypatch.setattr(
            recon_tool, "__file__", str(fake_pkg / "__init__.py")
        )
        monkeypatch.chdir(tmp_path)

        from recon_tool.server import _detect_cwd_shadow_install

        result = _detect_cwd_shadow_install()
        assert result is None, (
            f"guard refused a legitimate source checkout: {result!r}. "
            "The pyproject.toml name was 'recon-tool', which should "
            "have been accepted as the dev workflow."
        )


# ── Integration: shadow workspace launches installed module ────────


class TestShadowWorkspaceIntegration:
    """Spawn ``python -m recon_tool.server`` from a workspace that
    contains a malicious ``recon_tool/server.py``. With
    ``PYTHONSAFEPATH=1`` set (Python 3.11+), the installed module
    must load instead of the shadow.

    Architectural note on Python 3.10: ``PYTHONSAFEPATH`` was
    introduced in Python 3.11 (PEP 686 / commit-time decision). On
    3.10 the env var is a no-op, so direct ``python -m
    recon_tool.server`` from a hostile cwd will load the shadow —
    Python's lookup unavoidably prepends cwd to ``sys.path``. The
    v1.9.3.4 product defenses avoid this invocation pattern entirely:
    ``mcp_doctor`` sets ``cwd`` to an empty tempdir, and
    ``mcp_install``'s preferred form uses the ``recon`` script entry
    point (no ``-m``). The runtime guard in ``server.py`` is the
    third layer but cannot fire when a shadow's ``server.py`` is the
    code that actually loads. Hence this test only validates the
    PYTHONSAFEPATH path; the unit tests in
    ``TestServerRuntimeGuard`` cover the runtime-guard behaviour
    independently, and the source-inspection tests above pin the
    safe-cwd + env-var contract in ``mcp_doctor``.

    Skipped on Windows because subprocess + tempdir cleanup
    interacts poorly with test isolation; the unit-level guard
    tests cover the same path."""

    def _write_shadow_package(self, root: Path) -> None:
        pkg = root / "recon_tool"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            'SHADOW_LOADED = True\n', encoding="utf-8"
        )
        # The "server" submodule prints a marker that proves the
        # shadow ran. If we see this marker in stderr, the guard
        # failed.
        (pkg / "server.py").write_text(
            textwrap.dedent(
                """\
                import sys
                sys.stderr.write("RECON_SHADOW_EXECUTED\\n")
                sys.stderr.flush()
                sys.exit(0)
                """
            ),
            encoding="utf-8",
        )

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows subprocess + tempdir cleanup interacts poorly with "
        "test isolation; the unit-level guard tests cover the same path.",
    )
    @pytest.mark.skipif(
        sys.version_info < (3, 11),
        reason="PYTHONSAFEPATH was introduced in Python 3.11 (PEP 686). "
        "On 3.10 the env var is a no-op, so direct `python -m "
        "recon_tool.server` from a hostile cwd will load the shadow — "
        "this is architecturally unprotected on 3.10. The product code "
        "avoids the unprotected pattern: mcp_doctor sets a safe cwd, "
        "mcp_install prefers the `recon` script entry point. "
        "Operators on 3.10 should install recon to PATH and invoke "
        "`recon mcp` rather than `python -m recon_tool.server` from "
        "untrusted workspaces.",
    )
    def test_shadow_workspace_cannot_execute(self, tmp_path):
        self._write_shadow_package(tmp_path)

        env = dict(os.environ)
        env["PYTHONSAFEPATH"] = "1"
        env["RECON_MCP_FORCE_STDIO"] = "1"

        result = subprocess.run(
            [sys.executable, "-m", "recon_tool.server"],
            cwd=tmp_path,
            env=env,
            input="",
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        assert "RECON_SHADOW_EXECUTED" not in (result.stdout + result.stderr), (
            "Shadow recon_tool/server.py executed despite "
            "PYTHONSAFEPATH=1 — the cwd-prepend protection failed. "
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
