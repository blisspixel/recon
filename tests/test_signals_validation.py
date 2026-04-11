"""Tests for signal validation logic — covers the untested validation paths."""

from __future__ import annotations

from recon_tool.signals import Signal, _validate_and_build_signal, reload_signals


class TestSignalValidation:
    def test_non_dict_rejected(self):
        assert _validate_and_build_signal("not a dict", 0) is None

    def test_missing_name_rejected(self):
        assert _validate_and_build_signal({}, 0) is None

    def test_empty_name_rejected(self):
        assert _validate_and_build_signal({"name": ""}, 0) is None

    def test_non_string_name_rejected(self):
        assert _validate_and_build_signal({"name": 123}, 0) is None

    def test_missing_requires_rejected(self):
        assert _validate_and_build_signal({"name": "Test"}, 0) is None

    def test_requires_not_dict_rejected(self):
        assert _validate_and_build_signal({"name": "Test", "requires": "bad"}, 0) is None

    def test_empty_any_list_rejected(self):
        assert _validate_and_build_signal({"name": "Test", "requires": {"any": []}}, 0) is None

    def test_missing_any_key_rejected(self):
        assert _validate_and_build_signal({"name": "Test", "requires": {"all": ["a"]}}, 0) is None

    def test_invalid_min_matches_defaults_to_1(self):
        signal_dict = {"name": "Test", "requires": {"any": ["a"]}, "min_matches": -1}
        result = _validate_and_build_signal(signal_dict, 0)
        assert result is not None
        assert result.min_matches == 1
        # Verify the original dict was NOT mutated (frozen model pattern)
        assert signal_dict["min_matches"] == -1

    def test_non_int_min_matches_defaults_to_1(self):
        signal_dict = {"name": "Test", "requires": {"any": ["a"]}, "min_matches": "bad"}
        result = _validate_and_build_signal(signal_dict, 0)
        assert result is not None
        assert result.min_matches == 1
        # Verify the original dict was NOT mutated
        assert signal_dict["min_matches"] == "bad"

    def test_valid_signal_accepted(self):
        signal_dict = {"name": "Test", "requires": {"any": ["a", "b"]}, "min_matches": 2}
        result = _validate_and_build_signal(signal_dict, 0)
        assert result is not None
        assert isinstance(result, Signal)
        assert result.name == "Test"
        assert result.candidates == ("a", "b")
        assert result.min_matches == 2

    def test_valid_signal_defaults(self):
        """Signal with minimal fields gets correct defaults."""
        result = _validate_and_build_signal({"name": "X", "requires": {"any": ["a"]}}, 0)
        assert result is not None
        assert result.category == ""
        assert result.confidence == "medium"
        assert result.description == ""
        assert result.min_matches == 1

    def test_reload_signals_clears_cache(self):
        """reload_signals should not raise."""
        reload_signals()
