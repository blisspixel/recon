"""Tests for fingerprint loading, validation, and pattern matching."""

from __future__ import annotations

from recon_tool.fingerprints import (
    _validate_fingerprint,
    _validate_regex,
    get_cname_patterns,
    get_m365_names,
    get_mx_patterns,
    get_ns_patterns,
    get_spf_patterns,
    get_txt_patterns,
    load_fingerprints,
    match_txt,
)


class TestRegexValidation:
    def test_valid_pattern(self):
        assert _validate_regex(r"^openai-domain-verification=", "test") is True

    def test_empty_pattern_rejected(self):
        assert _validate_regex("", "test") is False

    def test_invalid_regex_rejected(self):
        assert _validate_regex(r"[invalid", "test") is False

    def test_excessively_long_pattern_rejected(self):
        assert _validate_regex("a" * 501, "test") is False

    def test_normal_length_pattern_accepted(self):
        assert _validate_regex("a" * 100, "test") is True


class TestFingerprintValidation:
    def test_valid_fingerprint(self):
        fp = {
            "name": "Test Service",
            "slug": "test",
            "category": "Misc",
            "confidence": "high",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.name == "Test Service"
        assert result.confidence == "high"

    def test_missing_name_rejected(self):
        fp = {"detections": [{"type": "txt", "pattern": "^test="}]}
        assert _validate_fingerprint(fp, "test") is None

    def test_missing_detections_rejected(self):
        fp = {"name": "Test"}
        assert _validate_fingerprint(fp, "test") is None

    def test_empty_detections_rejected(self):
        fp = {"name": "Test", "detections": []}
        assert _validate_fingerprint(fp, "test") is None

    def test_non_dict_rejected(self):
        assert _validate_fingerprint("not a dict", "test") is None  # type: ignore[arg-type]

    def test_invalid_detection_type_skipped(self):
        fp = {
            "name": "Test",
            "detections": [{"type": "invalid", "pattern": "^test="}],
        }
        assert _validate_fingerprint(fp, "test") is None

    def test_invalid_confidence_defaults_to_medium(self):
        fp = {
            "name": "Test",
            "confidence": "super-high",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.confidence == "medium"

    def test_empty_pattern_in_detection_skipped(self):
        fp = {
            "name": "Test",
            "detections": [
                {"type": "txt", "pattern": ""},
                {"type": "txt", "pattern": "^valid="},
            ],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert len(result.detections) == 1

    def test_all_invalid_detections_rejected(self):
        fp = {
            "name": "Test",
            "detections": [
                {"type": "txt", "pattern": ""},
                {"type": "txt", "pattern": "[invalid"},
            ],
        }
        assert _validate_fingerprint(fp, "test") is None


class TestLoadFingerprints:
    def test_loads_builtin_fingerprints(self):
        fps = load_fingerprints()
        assert len(fps) > 50
        names = {fp.name for fp in fps}
        assert "Microsoft 365" in names
        assert "Google Workspace" in names

    def test_all_fingerprints_have_required_fields(self):
        for fp in load_fingerprints():
            assert fp.name
            assert len(fp.detections) > 0


class TestPatternGetters:
    def test_txt_patterns_not_empty(self):
        assert len(get_txt_patterns()) > 0

    def test_spf_patterns_not_empty(self):
        assert len(get_spf_patterns()) > 0

    def test_mx_patterns_not_empty(self):
        assert len(get_mx_patterns()) > 0

    def test_ns_patterns_not_empty(self):
        assert len(get_ns_patterns()) > 0

    def test_cname_patterns_not_empty(self):
        assert len(get_cname_patterns()) > 0

    def test_m365_names_includes_microsoft365(self):
        assert "Microsoft 365" in get_m365_names()


class TestMatchTxt:
    def test_matches_openai(self):
        patterns = get_txt_patterns()
        result = match_txt("openai-domain-verification=abc123", patterns)
        assert result is not None
        # match_txt now returns a Detection NamedTuple
        assert result.name == "OpenAI Enterprise"
        assert result.slug == "openai"

    def test_no_match_returns_none(self):
        patterns = get_txt_patterns()
        result = match_txt("some-random-txt-record", patterns)
        assert result is None

    def test_case_insensitive(self):
        patterns = get_txt_patterns()
        result = match_txt("MS=ms12345678", patterns)
        assert result is not None
        assert "Microsoft" in result.name
