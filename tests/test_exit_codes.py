"""The CLI exit-code contract (docs/schema.md "Exit codes").

These pin the documented `0/1/2/3/4` contract so a scripter can rely on it,
and guard the single-source-of-truth constants in `recon_tool.exit_codes`
against drift with the CLI re-exports.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from recon_tool import cli, exit_codes

runner = CliRunner()


def test_exit_code_values() -> None:
    """The numeric contract is fixed; consumers branch on these."""
    assert exit_codes.EXIT_SUCCESS == 0
    assert exit_codes.EXIT_ERROR == 1
    assert exit_codes.EXIT_VALIDATION == 2
    assert exit_codes.EXIT_NO_DATA == 3
    assert exit_codes.EXIT_INTERNAL == 4


def test_cli_reexports_match_source() -> None:
    """`recon_tool.cli` re-exports the same constants for back-compat."""
    assert cli.EXIT_SUCCESS is exit_codes.EXIT_SUCCESS
    assert cli.EXIT_ERROR is exit_codes.EXIT_ERROR
    assert cli.EXIT_VALIDATION is exit_codes.EXIT_VALIDATION
    assert cli.EXIT_NO_DATA is exit_codes.EXIT_NO_DATA
    assert cli.EXIT_INTERNAL is exit_codes.EXIT_INTERNAL


def test_validation_exit_on_bad_domain() -> None:
    """A malformed domain is rejected before any lookup work: code 2."""
    result = runner.invoke(cli.app, ["lookup", "not a domain"])
    assert result.exit_code == exit_codes.EXIT_VALIDATION


def test_cache_clear_requires_target() -> None:
    """`cache clear` with neither a domain nor --all is a validation error."""
    result = runner.invoke(cli.app, ["cache", "clear"])
    assert result.exit_code == exit_codes.EXIT_VALIDATION


def test_fingerprint_validator_missing_path() -> None:
    """The bundled validator names its codes too: missing path -> 2."""
    from recon_tool.fingerprint_validator import validate_path

    missing = Path("does-not-exist-xyz.yaml")
    assert validate_path(missing, quiet=True) == exit_codes.EXIT_VALIDATION
