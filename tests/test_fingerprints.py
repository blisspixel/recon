"""Tests for fingerprint loading, validation, and pattern matching."""

from __future__ import annotations

import re

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
    match_txt_all,
)
from recon_tool.regex_safety import (
    _MAX_COMPILED_REGEX_CACHE_SIZE,
    _compile_regex_cached,
    clear_compiled_regex_cache,
    compile_regex,
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


class TestCompiledRegexCache:
    def test_cache_is_case_aware_and_reuses_compiled_objects(self) -> None:
        clear_compiled_regex_cache()
        try:
            plain = compile_regex("^mixed-case$")
            insensitive = compile_regex("^mixed-case$", re.IGNORECASE)

            assert plain is not None
            assert insensitive is not None
            assert plain.search("MIXED-CASE") is None
            assert insensitive.search("MIXED-CASE") is not None
            assert compile_regex("^mixed-case$", re.IGNORECASE) is insensitive
        finally:
            clear_compiled_regex_cache()

    def test_cache_rejects_invalid_inputs_and_stays_strictly_bounded(self) -> None:
        clear_compiled_regex_cache()
        try:
            assert compile_regex("[invalid") is None
            assert compile_regex("x" * 501) is None
            assert compile_regex("valid-pattern", re.LOCALE) is None
            for index in range(_MAX_COMPILED_REGEX_CACHE_SIZE + 17):
                assert compile_regex(rf"^cache-{index}$") is not None

            cache_info = _compile_regex_cached.cache_info()
            assert cache_info.maxsize == _MAX_COMPILED_REGEX_CACHE_SIZE
            assert cache_info.currsize == _MAX_COMPILED_REGEX_CACHE_SIZE
        finally:
            clear_compiled_regex_cache()


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

    def test_all_matches_preserves_same_record_corroboration(self):
        patterns = get_txt_patterns()
        result = match_txt_all("crowdstrike-falcon-site-verification=abc123", patterns)

        crowdstrike_patterns = [match.pattern for match in result if match.slug == "crowdstrike"]
        assert "^crowdstrike-falcon-site-verification=" in crowdstrike_patterns
        assert "crowdstrike" in crowdstrike_patterns

    def test_all_matches_honors_length_bound(self):
        patterns = get_txt_patterns()

        result = match_txt_all("crowdstrike" + ("a" * 5000), patterns)

        assert result == ()

    @pytest.mark.parametrize(
        "value",
        [
            "some-random-txt-record",
            "MS=ms12345678",
            "crowdstrike-falcon-site-verification=abc123",
            "OPENAI-DOMAIN-VERIFICATION=ABC123",
        ],
    )
    def test_compiled_matcher_equals_reference_regex_dispatch(self, value: str) -> None:
        patterns = get_txt_patterns()
        expected = tuple(det for det in patterns if re.search(det.pattern, value, re.IGNORECASE))

        assert match_txt_all(value, patterns) == expected


# ── Relationship metadata ──────────────────────────────────────────────


class TestRelationshipMetadata:
    """Optional product_family / parent_vendor / bimi_org fields."""

    def test_default_metadata_is_none(self, tmp_path):
        """Fingerprints without the relationship-metadata fields populated
        in YAML must produce ``None`` on the loaded dataclass.

        Uses a synthetic YAML — the built-in catalogs are partially
        seeded and growing, so they cannot be relied on
        as a "no metadata" baseline.
        """
        from recon_tool.fingerprints import _load_from_path

        path = tmp_path / "no_metadata.yaml"
        path.write_text(
            """
fingerprints:
- name: BareService
  slug: bare-svc
  category: Misc
  confidence: high
  detections:
  - type: txt
    pattern: "^bare-svc-verification="
"""
        )
        fps = _load_from_path(path)
        assert len(fps) == 1
        assert fps[0].product_family is None
        assert fps[0].parent_vendor is None
        assert fps[0].bimi_org is None

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
    """fingerprint_metadata JSON envelope."""

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


def test_discovered_cname_targets_classify():
    """cname_target rules harvested from the corpus discovery loop load with
    their expected slugs and match a representative CNAME terminal via the
    same substring rule the surface classifier applies."""
    from recon_tool.fingerprints import get_cname_target_rules

    by_pattern = {r.pattern: r.slug for r in get_cname_target_rules()}
    expected = {
        "hosted-by-discourse.com": "discourse",
        "substack-custom-domains.com": "substack",
        "beyondtrustcloud.com": "beyondtrust",
        "arcticwolf.net": "arctic-wolf",
        "usgovcloud.microsoft": "microsoft365-gov",
        "material.security": "material-security",
        "supabase.co": "supabase",
    }
    for pattern, slug in expected.items():
        assert by_pattern.get(pattern) == slug, f"missing/incorrect cname_target {pattern} -> {slug}"

    rules = get_cname_target_rules()
    terminal = "community.acme.hosted-by-discourse.com"
    assert "discourse" in [r.slug for r in rules if r.pattern in terminal]


def test_discovered_txt_verifications_classify():
    """TXT verification fingerprints harvested from the corpus TXT-prefix
    mine classify their domain-verification tokens (case-insensitive)."""
    from recon_tool.fingerprints import get_txt_patterns, match_txt

    pats = get_txt_patterns()
    expected = {
        "docker-verification=abc123": "docker",
        "h1-domain-verification=deadbeef": "hackerone",
        "teamviewer-sso-verification=xyz": "teamviewer",
        "Foxit-domain-verification=Z9": "foxit",  # mixed case
        "hibp-verify=tok": "hibp",
        "calendly-site-verification=ok": "calendly",
        "lovable_verification=tok": "lovable",
    }
    for token, slug in expected.items():
        m = match_txt(token, pats)
        assert getattr(m, "slug", None) == slug, f"{token} -> expected {slug}, got {getattr(m, 'slug', None)}"
