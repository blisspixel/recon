"""Runtime annotation introspection must not crash.

Modules that reference a typing construct (Callable, Mapping) in a runtime
annotation must import it at runtime, not only under TYPE_CHECKING. Otherwise
typing.get_type_hints() raises NameError, breaking documentation generators,
schema tooling, and plugins that introspect public functions or modules.
These tests pin the two sites that previously regressed.
"""

from __future__ import annotations

import typing


def test_schema_contract_function_hints_resolve() -> None:
    """classify_batch_record annotates `record: Mapping[...]`; hints must resolve."""
    from recon_tool import schema_contract

    hints = typing.get_type_hints(schema_contract.classify_batch_record)
    assert "record" in hints


def test_explanation_module_hints_resolve() -> None:
    """explanation.py annotates a module-level _INSIGHT_RULES with Callable[...]."""
    import recon_tool.explanation as explanation

    # Evaluates every module-level annotation; raised NameError before the fix.
    typing.get_type_hints(explanation)
