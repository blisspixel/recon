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
    _marginal_in_unit_range,
)
from recon_tool.bayesian_interval import interval_is_ordered as _interval_is_ordered
from recon_tool.fingerprints import Detection, _no_shadowed_pairs_survive
from recon_tool.specificity import SpecificityVerdict, _verdict_match_count_valid
from recon_tool.validator import _has_no_control_chars, _is_normalized_domain


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


class TestMatcherValidators:
    """The engine-matcher contract predicates (deal second pass)."""

    def _det(self, pattern: str, slug: str) -> Detection:
        return Detection(pattern=pattern, name=slug, slug=slug, category="email", confidence="high")

    def test_no_shadowed_pairs_survive(self) -> None:
        # Different slugs where one pattern is a strict substring of the
        # other is the double-count the filter must remove.
        bad = [self._det("salesforce.com", "salesforce"), self._det("force.com", "force_com")]
        assert not _no_shadowed_pairs_survive(bad)
        # Same slug, different patterns: allowed (slug accumulates once).
        same_slug = [self._det("a.example", "x"), self._det("a.example.long", "x")]
        assert _no_shadowed_pairs_survive(same_slug)
        # Non-overlapping vendor patterns: both survive.
        distinct = [self._det("outlook.com", "m365"), self._det("salesforce.com", "salesforce")]
        assert _no_shadowed_pairs_survive(distinct)
        assert _no_shadowed_pairs_survive([])

    def test_verdict_match_count_valid(self) -> None:
        assert _verdict_match_count_valid(
            SpecificityVerdict(pattern="p", detection_type="spf", matches=3, corpus_size=10, threshold_exceeded=False)
        )
        assert _verdict_match_count_valid(
            SpecificityVerdict(pattern="p", detection_type="spf", matches=0, corpus_size=0, threshold_exceeded=False)
        )
        # More matches than corpus entries is impossible.
        assert not _verdict_match_count_valid(
            SpecificityVerdict(pattern="p", detection_type="spf", matches=11, corpus_size=10, threshold_exceeded=False)
        )
        assert not _verdict_match_count_valid(
            SpecificityVerdict(pattern="p", detection_type="spf", matches=-1, corpus_size=10, threshold_exceeded=False)
        )


class TestBoundaryValidators:
    """The `validator.py` contract predicates (deal third pass)."""

    def test_has_no_control_chars(self) -> None:
        assert _has_no_control_chars("DigiCert Inc")
        assert _has_no_control_chars("Synthetic Alpha, Ltd.")
        assert _has_no_control_chars("")  # vacuously true
        # Café — non-control Unicode is preserved, so the predicate accepts it.
        assert _has_no_control_chars("Café")
        # C0 ESC, NUL, newline, DEL, and a C1 control are each rejected.
        assert not _has_no_control_chars("evil\x1b[31m")
        assert not _has_no_control_chars("a\x00b")
        assert not _has_no_control_chars("line1\nline2")
        assert not _has_no_control_chars("x\x7f")
        assert not _has_no_control_chars("x\x85")  # C1 NEL

    def test_is_normalized_domain(self) -> None:
        assert _is_normalized_domain("alpha.invalid")
        assert _is_normalized_domain("sub.gamma.invalid")
        assert _is_normalized_domain("xn--caf-dma.invalid")  # punycode IDN
        # Uppercase is not normalized (validate_domain lowercases before return).
        assert not _is_normalized_domain("Alpha.Invalid")
        # Not a domain grammar at all.
        assert not _is_normalized_domain("not a domain")
        assert not _is_normalized_domain("")
        assert not _is_normalized_domain("https://alpha.invalid")  # scheme not stripped


class TestContractFires:
    """deal raises when a decorated function returns a violating value."""

    def test_validator_post_raises_on_unnormalized_domain(self) -> None:
        @deal.post(_is_normalized_domain)
        def _bad() -> str:
            return "NotLowercased.invalid"  # violates the normalized-domain postcondition

        with pytest.raises(deal.PostContractError):
            _bad()

    def test_validator_post_raises_on_control_chars(self) -> None:
        @deal.post(_has_no_control_chars)
        def _leaky() -> str:
            return "issuer\x1b[2J"  # an ESC survived, violates the postcondition

        with pytest.raises(deal.PostContractError):
            _leaky()

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
