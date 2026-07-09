from __future__ import annotations

from recon_tool.cli.options import (
    LookupDisplayOptions,
    LookupExecutionOptions,
    LookupInferenceOptions,
    LookupOperationMode,
    LookupOperationOptions,
    LookupOptions,
    LookupOutputMode,
    LookupOutputOptions,
)


def _options(
    *,
    output: LookupOutputOptions | None = None,
    operation: LookupOperationOptions | None = None,
    display: LookupDisplayOptions | None = None,
) -> LookupOptions:
    return LookupOptions(
        output=output or LookupOutputOptions(),
        display=display or LookupDisplayOptions(),
        operation=operation or LookupOperationOptions(),
        inference=LookupInferenceOptions(),
        execution=LookupExecutionOptions(),
    )


def test_output_mode_selects_first_explicit_renderer() -> None:
    assert LookupOutputOptions().mode is LookupOutputMode.PANEL
    assert LookupOutputOptions(json_output=True).mode is LookupOutputMode.JSON
    assert LookupOutputOptions(markdown=True).mode is LookupOutputMode.MARKDOWN
    assert LookupOutputOptions(plain=True).mode is LookupOutputMode.PLAIN


def test_output_options_reject_multiple_renderers() -> None:
    options = _options(output=LookupOutputOptions(json_output=True, plain=True))

    assert options.validation_error() == "--json, --md, and --plain are mutually exclusive"


def test_display_options_normalize_full_and_profile() -> None:
    full = LookupDisplayOptions.from_flags(
        services=False,
        domains=False,
        full=True,
        verbose=False,
        sources=False,
        posture=False,
        explain=False,
        profile=None,
        confidence_mode="hedged",
    )
    profiled = LookupDisplayOptions.from_flags(
        services=False,
        domains=False,
        full=False,
        verbose=False,
        sources=False,
        posture=False,
        explain=False,
        profile="fintech",
        confidence_mode="strict",
    )

    assert full.show_services
    assert full.show_domains
    assert full.verbose
    assert full.show_posture
    assert profiled.show_posture
    assert profiled.profile_name == "fintech"
    assert profiled.confidence_mode == "strict"


def test_operation_mode_selects_requested_pipeline() -> None:
    assert LookupOperationOptions().mode is LookupOperationMode.STANDARD
    assert LookupOperationOptions(compare_file="snapshot.json").mode is LookupOperationMode.COMPARE
    assert LookupOperationOptions(chain_mode=True).mode is LookupOperationMode.CHAIN
    assert LookupOperationOptions(show_exposure=True).mode is LookupOperationMode.EXPOSURE
    assert LookupOperationOptions(show_gaps=True).mode is LookupOperationMode.GAPS


def test_operation_options_reject_ambiguous_modes() -> None:
    assert (
        _options(operation=LookupOperationOptions(chain_mode=True, compare_file="snapshot.json")).validation_error()
        == "--chain and --compare are mutually exclusive"
    )
    assert (
        _options(operation=LookupOperationOptions(show_exposure=True, show_gaps=True)).validation_error()
        == "--exposure and --gaps are mutually exclusive"
    )
    assert (
        _options(operation=LookupOperationOptions(chain_depth=2)).validation_error()
        == "--depth requires --chain"
    )


def test_non_standard_modes_reject_unimplemented_renderers() -> None:
    markdown_chain = _options(
        output=LookupOutputOptions(markdown=True),
        operation=LookupOperationOptions(chain_mode=True),
    )
    plain_exposure = _options(
        output=LookupOutputOptions(plain=True),
        operation=LookupOperationOptions(show_exposure=True),
    )

    assert markdown_chain.validation_error() == "--md cannot be combined with --chain/--compare/--exposure/--gaps"
    assert plain_exposure.validation_error() == "--plain cannot be combined with --chain/--compare/--exposure/--gaps"
