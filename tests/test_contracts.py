"""Design-by-Contract wiring tests (the `deal` adoption).

Three things are worth proving about contracts, because a contract that
never fires is no better than a comment:

1. The validator predicates are correct (accept valid shapes, reject
   invalid ones).
2. A contract actually raises when a decorated function returns a value
   that violates its postcondition, under a normal (``__debug__`` true)
   run.
3. Contracts are disabled under ``python -O`` so installed users pay no
   runtime cost, which is the whole reason `deal` is acceptable inside
   the pure-Python dependency floor.

The contracts themselves live on the inference math in
``recon_tool.bayesian``; the live inference tests in the bayesian suites
exercise them on real input. Here we test the guarantees directly.
"""

from __future__ import annotations

import subprocess
import sys

import deal
import pytest

from recon_tool.bayesian import (
    _factor_is_probabilities,
    _factor_is_strictly_positive,
    _interval_is_ordered,
    _marginal_in_unit_range,
)


class TestValidatorPredicates:
    """The named contract predicates accept valid shapes, reject invalid."""

    def test_factor_is_probabilities(self) -> None:
        ok = {frozenset({("n", "present")}): 0.3, frozenset({("n", "absent")}): 0.7}
        assert _factor_is_probabilities(ok)
        assert _factor_is_probabilities({frozenset({("n", "present")}): 0.0})
        assert _factor_is_probabilities({frozenset({("n", "present")}): 1.0})
        assert not _factor_is_probabilities({frozenset({("n", "present")}): 1.2})
        assert not _factor_is_probabilities({frozenset({("n", "present")}): -0.1})

    def test_factor_is_strictly_positive(self) -> None:
        assert _factor_is_strictly_positive(None)  # no factor is a valid result
        assert _factor_is_strictly_positive({frozenset({("n", "present")}): 0.4})
        # A zero is the degenerate factor the invariant forbids.
        assert not _factor_is_strictly_positive({frozenset({("n", "present")}): 0.0})
        assert not _factor_is_strictly_positive({frozenset({("n", "present")}): -0.2})

    def test_marginal_in_unit_range(self) -> None:
        assert _marginal_in_unit_range({"present": 0.6, "absent": 0.4})
        assert _marginal_in_unit_range({"present": 0.0, "absent": 0.0})
        assert not _marginal_in_unit_range({"present": 1.5, "absent": -0.5})

    def test_interval_is_ordered(self) -> None:
        assert _interval_is_ordered((0.0, 1.0))
        assert _interval_is_ordered((0.3, 0.3))
        assert _interval_is_ordered((0.2, 0.8))
        assert not _interval_is_ordered((0.8, 0.2))  # low > high
        assert not _interval_is_ordered((-0.1, 0.5))  # below 0
        assert not _interval_is_ordered((0.5, 1.1))  # above 1


class TestContractFires:
    """deal raises when a decorated function returns a violating value."""

    def test_post_contract_raises_on_violation(self) -> None:
        @deal.post(_interval_is_ordered)
        def _backwards() -> tuple[float, float]:
            return (0.9, 0.1)  # low > high, violates the postcondition

        with pytest.raises(deal.PostContractError):
            _backwards()

    def test_post_contract_passes_on_valid(self) -> None:
        @deal.post(_interval_is_ordered)
        def _ok() -> tuple[float, float]:
            return (0.1, 0.9)

        assert _ok() == (0.1, 0.9)


class TestContractsDisabledUnderO:
    """Under ``python -O`` importing recon_tool disables deal, so a
    contract violation does not raise: zero runtime cost in production."""

    def test_minus_O_disables_contracts(self) -> None:
        code = (
            "import recon_tool  # noqa: F401  -- import runs deal.disable() under -O\n"
            "import deal\n"
            "@deal.post(lambda r: r > 0)\n"
            "def f():\n"
            "    return -1\n"
            "f()\n"
            "print('NO_RAISE')\n"
        )
        # sys.executable is the project venv interpreter under `uv run pytest`.
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-O", "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "NO_RAISE" in result.stdout

    def test_contracts_enabled_without_O(self) -> None:
        # The complement: without -O the same violation raises, proving the
        # subprocess test above is meaningful (contracts are on by default).
        code = (
            "import recon_tool  # noqa: F401\n"
            "import deal\n"
            "@deal.post(lambda r: r > 0)\n"
            "def f():\n"
            "    return -1\n"
            "try:\n"
            "    f()\n"
            "    print('NO_RAISE')\n"
            "except deal.PostContractError:\n"
            "    print('RAISED')\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "RAISED" in result.stdout
