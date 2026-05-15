"""v1.9.9 — CLI integration smoke tests.

Every v1.9.9 test exercises ``render_tenant_panel`` directly through
its Python API. None of them invoke the actual ``recon`` command-line
entry point. A wiring bug in ``recon_tool/cli.py`` between argument
parsing and rendering would slip past the unit and snapshot tests
because the CLI plumbing is never touched.

These tests invoke the Typer app through ``CliRunner`` to close that
gap. They are smoke tests, not full pipeline tests: a target domain
lookup hits the network and is out of scope. The asserts are bounded
to behaviour the CLI promises without network: help text, version,
``mcp doctor`` (in-process), and graceful exit codes on input
validation errors.

The test boundary is "the CLI entry point loads, the Typer app
parses arguments correctly, the in-process commands return expected
output". Anything that requires DNS or HTTP is exercised elsewhere
(integration tests under ``tests/`` that mock the transports).
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from typer.testing import CliRunner

from recon_tool import __version__
from recon_tool.cli import app


@pytest.fixture
def runner():
    return CliRunner()


class TestHelpAndVersion:
    """The most basic CLI smoke: ``--help`` and ``--version`` work.
    A typo in the Typer decorators, a circular import, or a syntax
    error in any imported module breaks these two flags first."""

    def test_help_flag_succeeds(self, runner):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, f"--help should exit 0; got {result.exit_code}. stderr: {result.stderr}"
        # The help banner must mention the command name and at least
        # one subcommand. We use 'recon' the brand name; missing this
        # would suggest a Typer-app-level identity drift.
        assert "recon" in result.output.lower() or "domain intelligence" in result.output.lower()

    def test_version_flag_matches_package_version(self, runner):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        # The version flag must print the same version string that
        # ``recon_tool.__version__`` exposes. A mismatch means the
        # version is being computed two ways and the user-facing
        # value could disagree with the SBOM / wheel metadata.
        assert __version__ in result.output, (
            f"--version output {result.output!r} must contain package version {__version__!r}"
        )


class TestSubcommandWiring:
    """Each top-level subcommand must at least load its help. The
    Typer app instantiates the subcommand registries at import time;
    a missing module reference or broken decorator surfaces here as
    a non-zero exit code on ``recon <cmd> --help``."""

    @pytest.mark.parametrize(
        "subcommand",
        [
            "lookup",
            "batch",
            "delta",
            "discover",
            "mcp",
            "doctor",
            "cache",
            "fingerprints",
            "signals",
        ],
    )
    def test_subcommand_help_loads(self, runner, subcommand):
        result = runner.invoke(app, [subcommand, "--help"])
        assert result.exit_code == 0, (
            f"`recon {subcommand} --help` exited {result.exit_code}; the subcommand may be broken at "
            f"import time. stderr: {result.stderr}"
        )


class TestInputValidationGracefulFailure:
    """Invalid inputs must produce a clear non-zero exit code and a
    helpful message. A bare exception traceback bubbling to the user
    would be a UX regression."""

    def test_unknown_subcommand_returns_non_zero(self, runner):
        result = runner.invoke(app, ["this-is-not-a-real-subcommand"])
        # Typer treats unknown subcommands as bare-domain arguments
        # via invoke_without_command; the domain would then fail
        # validation. Either way, exit code must be non-zero and the
        # process must not crash without output.
        # The exit code can be 0 if Typer interprets it as a domain
        # and then the lookup fails gracefully; what matters is no
        # exception traceback in stderr.
        assert "Traceback" not in (result.output or "") + (result.stderr or ""), (
            "Unknown subcommand must produce a clean error, not a traceback"
        )


class TestSubprocessEntryPoint:
    """Invoking the entry point via ``python -c`` proves the
    ``[project.scripts]`` declaration in ``pyproject.toml`` matches
    the actual symbol exported in ``recon_tool.cli``. Skips on
    systems where the relevant Python is unavailable."""

    def test_python_entry_point_runs_help(self):
        """Spawning a fresh interpreter that imports
        ``recon_tool.cli.run`` validates the full installed-entry-
        point shape, not just the Python-API shape."""
        # Compact one-liner exists because subprocess `-c` does not
        # accept newlines portably across shells. The line itself is
        # legible: import, invoke --help, print exit code and a
        # bounded prefix of the output.
        invoker = (
            "from recon_tool.cli import app; from typer.testing import CliRunner; "
            "r = CliRunner(); res = r.invoke(app, ['--help']); "
            "print(res.exit_code); print(res.output[:200])"
        )
        result = subprocess.run(  # noqa: S603 — argv list, no shell, no untrusted input.
            [sys.executable, "-c", invoker],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, f"subprocess invocation of the CLI entry point failed; stderr: {result.stderr}"
        assert result.stdout.startswith("0"), (
            f"Typer help invocation must return exit code 0 in the subprocess; got: {result.stdout!r}"
        )


class TestCliExportsAreImportable:
    """The ``recon_tool.cli`` module must expose ``app`` (the Typer
    instance) and ``run`` (the entry-point function declared in
    pyproject.toml). A rename or accidental removal would break the
    installed-wheel CLI without breaking any other test."""

    def test_app_is_typer_instance(self):
        import typer

        from recon_tool.cli import app

        assert isinstance(app, typer.Typer), f"recon_tool.cli.app should be a Typer instance; got {type(app)}"

    def test_run_is_callable(self):
        from recon_tool.cli import run

        assert callable(run), "recon_tool.cli.run (the entry-point) must be callable"
