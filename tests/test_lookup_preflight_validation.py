"""Flag validation must happen before collection, not after it.

An unknown ``--profile`` and an invalid ``--explain-dag-format`` were both
caught only once the lookup had already resolved: the renderer and the posture
step each raised ``typer.Exit(EXIT_VALIDATION)`` after ``resolve_tenant``
returned. Exit 2 was correct, but it arrived after a full collection round
against the target.

That is a collection-boundary problem, not only a latency one. recon's
documented promise is that the operator knows what leaves the machine before it
leaves, and a misspelled flag is not consent to contact anyone. These tests
assert the resolver is never reached.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app

runner = CliRunner()


@pytest.fixture
def forbid_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to resolve a domain a hard test failure."""

    def _explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resolve_tenant was called; the flag should have been rejected before collection")

    # Patched at the definition site so every import path sees the trap.
    monkeypatch.setattr("recon_tool.resolver.resolve_tenant", _explode)


@pytest.mark.parametrize(
    "args",
    [
        ["alpha.invalid", "--explain-dag", "--explain-dag-format", "bogus"],
        # Also rejected without --explain-dag: silently ignoring a value the
        # caller explicitly passed reports success for something they asked
        # for, the same defect already fixed for an out-of-range --depth.
        ["alpha.invalid", "--explain-dag-format", "bogus"],
    ],
)
def test_invalid_explain_dag_format_exits_before_collection(
    args: list[str],
    forbid_resolution: None,
) -> None:
    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "--explain-dag-format must be one of dot, mermaid, text" in result.output


@pytest.mark.parametrize("fmt", ["text", "dot", "mermaid", "TEXT", "Dot"])
def test_supported_explain_dag_formats_are_accepted(fmt: str) -> None:
    """The pre-collection check must not reject a format the renderer supports.

    Case-insensitive, because the renderer lowercases before dispatching.
    """
    from recon_tool.cli.options import LookupInferenceOptions

    assert LookupInferenceOptions(explain_dag_format=fmt).validation_error() is None


def test_unknown_profile_exits_before_collection(forbid_resolution: None) -> None:
    result = runner.invoke(app, ["alpha.invalid", "--profile", "does-not-exist"])

    assert result.exit_code == 2
    assert "Unknown profile 'does-not-exist'" in result.output
    # The message must still name the real catalog so the operator can recover.
    assert "fintech" in result.output


def test_known_profile_passes_preflight() -> None:
    """A real profile must survive the new check and reach collection."""
    from recon_tool.cli.options import (
        LookupDisplayOptions,
        LookupExecutionOptions,
        LookupInferenceOptions,
        LookupOperationOptions,
        LookupOptions,
        LookupOutputOptions,
    )
    from recon_tool.cli.shared import lookup_validate

    options = LookupOptions(
        output=LookupOutputOptions(),
        display=LookupDisplayOptions(profile_name="fintech"),
        operation=LookupOperationOptions(),
        inference=LookupInferenceOptions(),
        execution=LookupExecutionOptions(),
    )

    assert lookup_validate("alpha.invalid", options=options) == "alpha.invalid"
