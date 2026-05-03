"""Tests for fingerprint loading, validation, and pattern matching."""

from __future__ import annotations

import pytest

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

    def test_match_mode_defaults_to_any(self):
        fp = {
            "name": "Test",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.match_mode == "any"

    def test_match_mode_any_accepted(self):
        fp = {
            "name": "Test",
            "match_mode": "any",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.match_mode == "any"

    def test_match_mode_all_accepted(self):
        fp = {
            "name": "Test",
            "match_mode": "all",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.match_mode == "all"

    def test_invalid_match_mode_skips_fingerprint(self):
        fp = {
            "name": "Test",
            "match_mode": "first",
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        assert _validate_fingerprint(fp, "test") is None

    def test_valid_subdomain_txt_pattern_accepted(self):
        fp = {
            "name": "MCP DNS Discovery",
            "slug": "mcp-discovery",
            "category": "AI & Generative",
            "confidence": "medium",
            "detections": [{"type": "subdomain_txt", "pattern": "_mcp:^v=mcp1;"}],
        }
        result = _validate_fingerprint(fp, "test")
        assert result is not None
        assert result.detections[0].pattern == "_mcp:^v=mcp1;"

    def test_subdomain_txt_missing_delimiter_rejected(self):
        fp = {
            "name": "MCP DNS Discovery",
            "slug": "mcp-discovery",
            "category": "AI & Generative",
            "confidence": "medium",
            "detections": [{"type": "subdomain_txt", "pattern": "^v=mcp1;"}],
        }
        assert _validate_fingerprint(fp, "test") is None

    @pytest.mark.parametrize("pattern", [":^v=mcp1;", "_mcp:"])
    def test_subdomain_txt_requires_non_empty_subdomain_and_regex(self, pattern: str):
        fp = {
            "name": "MCP DNS Discovery",
            "slug": "mcp-discovery",
            "category": "AI & Generative",
            "confidence": "medium",
            "detections": [{"type": "subdomain_txt", "pattern": pattern}],
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


# ── v1.8 relationship metadata ──────────────────────────────────────────


class TestRelationshipMetadata:
    """v1.8: optional product_family / parent_vendor / bimi_org fields."""

    def test_default_metadata_is_none(self):
        """Fingerprints without the fields populated have None metadata."""
        from pathlib import Path

        from recon_tool.fingerprints import _load_from_path

        path = Path(__file__).parent.parent / "recon_tool" / "data" / "fingerprints" / "ai.yaml"
        fps = _load_from_path(path)
        # AI fingerprints don't have metadata seeded — should all be None.
        assert all(fp.product_family is None for fp in fps)
        assert all(fp.parent_vendor is None for fp in fps)

    def _slug_with_metadata(self, slug: str):
        """Return the first fingerprint matching ``slug`` whose metadata is populated.

        A slug can appear in multiple YAML files (e.g. an apex
        fingerprint plus surface ``cname_target`` rules) — only the
        apex copy carries relationship metadata, so a flat
        ``{slug: fp}`` collapse can clobber the populated entry.
        """
        from recon_tool.fingerprints import load_fingerprints

        for fp in load_fingerprints():
            if fp.slug != slug:
                continue
            if fp.product_family or fp.parent_vendor or fp.bimi_org:
                return fp
        return None

    def test_microsoft365_has_seeded_metadata(self):
        fp = self._slug_with_metadata("microsoft365")
        assert fp is not None
        assert fp.product_family == "Microsoft 365"
        assert fp.parent_vendor == "Microsoft"

    def test_github_parent_is_microsoft(self):
        fp = self._slug_with_metadata("github")
        assert fp is not None
        assert fp.parent_vendor == "Microsoft"

    def test_slack_parent_is_salesforce(self):
        fp = self._slug_with_metadata("slack")
        assert fp is not None
        assert fp.parent_vendor == "Salesforce"

    def test_loader_strips_whitespace(self, tmp_path):
        """Whitespace-only metadata values normalise to None."""
        from recon_tool.fingerprints import _load_from_path

        path = tmp_path / "fp.yaml"
        path.write_text(
            """
fingerprints:
- name: TestSvc
  slug: test-svc
  category: Misc
  confidence: high
  parent_vendor: "   "
  product_family: "  ACME  "
  detections:
  - type: txt
    pattern: "^test=value"
"""
        )
        fps = _load_from_path(path)
        assert len(fps) == 1
        assert fps[0].parent_vendor is None  # whitespace-only → None
        assert fps[0].product_family == "ACME"  # stripped


class TestFingerprintMetadataInJson:
    """v1.8: fingerprint_metadata JSON envelope."""

    def test_only_detected_slugs_appear(self):
        """Only slugs present in info.slugs surface in fingerprint_metadata."""
        import json

        from recon_tool.formatter import format_tenant_json
        from recon_tool.models import ConfidenceLevel, TenantInfo

        info = TenantInfo(
            tenant_id=None,
            display_name="Example",
            default_domain="example.com",
            queried_domain="example.com",
            confidence=ConfidenceLevel.MEDIUM,
            slugs=("microsoft365",),
        )
        payload = json.loads(format_tenant_json(info))
        meta = payload["fingerprint_metadata"]
        assert "microsoft365" in meta
        assert meta["microsoft365"]["parent_vendor"] == "Microsoft"
        # github isn't detected on this domain — must not appear.
        assert "github" not in meta

    def test_empty_when_no_slug_has_metadata(self):
        """Detected slugs with no relationship metadata yield empty object."""
        import json

        from recon_tool.formatter import format_tenant_json
        from recon_tool.models import ConfidenceLevel, TenantInfo

        info = TenantInfo(
            tenant_id=None,
            display_name="X",
            default_domain="x.com",
            queried_domain="x.com",
            confidence=ConfidenceLevel.LOW,
            slugs=("zoho",),  # no relationship metadata seeded
        )
        payload = json.loads(format_tenant_json(info))
        assert payload["fingerprint_metadata"] == {}
