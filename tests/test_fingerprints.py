"""Tests for fingerprint loading, validation, and pattern matching."""

from __future__ import annotations

import re

import pytest
import yaml

from recon_tool.fingerprints import (
    DetectionRule,
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

    def test_non_string_match_mode_skips_fingerprint(self):
        fp = {
            "name": "Test",
            "match_mode": ["all"],
            "detections": [{"type": "txt", "pattern": "^test="}],
        }
        assert _validate_fingerprint(fp, "test") is None

    def test_non_string_detection_type_is_rejected_without_crashing(self):
        fp = {
            "name": "Test",
            "detections": [{"type": ["txt"], "pattern": "^test="}],
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

    @pytest.mark.parametrize(
        ("field", "value", "warning"),
        [
            ("confidence", ["high"], "invalid confidence"),
            ("slug", ["bad"], "invalid slug"),
            ("category", ["Misc"], "invalid category"),
            ("m365", "false", "invalid m365 flag"),
            ("match_mode", ["all"], "invalid match_mode"),
            ("detection.description", ["invalid"], "non-string detection field"),
            ("detection.reference", ["invalid"], "non-string detection field"),
        ],
    )
    def test_malformed_typed_fields_are_rejected_without_losing_valid_siblings(
        self, tmp_path, caplog, field: str, value: object, warning: str
    ) -> None:
        from recon_tool.fingerprints import _load_from_path

        invalid = {
            "name": "Invalid Service",
            "slug": "invalid-service",
            "category": "Misc",
            "confidence": "high",
            "m365": False,
            "detections": [{"type": "txt", "pattern": "^invalid-service="}],
        }
        if field.startswith("detection."):
            invalid["detections"][0][field.removeprefix("detection.")] = value
        else:
            invalid[field] = value
        path = tmp_path / "fingerprints.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "fingerprints": [
                        invalid,
                        {
                            "name": "Valid Sibling",
                            "slug": "valid-sibling",
                            "category": "Misc",
                            "confidence": "high",
                            "m365": False,
                            "detections": [{"type": "txt", "pattern": "^valid-sibling="}],
                        },
                    ]
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        loaded = _load_from_path(path)

        assert [fingerprint.slug for fingerprint in loaded] == ["valid-sibling"]
        assert warning in caplog.text


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
  product_family: "  SYNTHETIC  "
  detections:
  - type: txt
    pattern: "^test=value"
"""
        )
        fps = _load_from_path(path)
        assert len(fps) == 1
        assert fps[0].parent_vendor is None  # whitespace-only → None
        assert fps[0].product_family == "SYNTHETIC"  # stripped


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
            default_domain="x.invalid",
            queried_domain="x.invalid",
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
    terminal = "community.synthetic-delta.hosted-by-discourse.com"
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


def _rules_for_slug(slug: str, detection_type: str) -> dict[str, DetectionRule]:
    rules: dict[str, DetectionRule] = {}
    for fingerprint in load_fingerprints():
        if fingerprint.slug != slug:
            continue
        for detection in fingerprint.detections:
            if detection.type == detection_type:
                rules[detection.pattern] = detection
    return rules


def _mx_rules_for_slug(slug: str) -> dict[str, DetectionRule]:
    return _rules_for_slug(slug, "mx")


def test_google_workspace_mx_family_matches_current_vendor_page() -> None:
    rules = _mx_rules_for_slug("google-workspace")
    spf = _rules_for_slug("google-workspace", "spf")["_spf.google.com"]
    aspmx = rules["aspmx.l.google.com"]
    smtp = rules["smtp.google.com"]
    assert aspmx.verified == "2026-08-19"
    assert smtp.verified == "2026-08-19"
    assert "pre-2023" in aspmx.description
    assert "primary inbound" not in aspmx.description.lower()
    assert "smtp.google.com" in aspmx.description
    assert "default" in smtp.description.lower()
    assert "aspmx" in smtp.description
    assert aspmx.reference.startswith("https://knowledge.workspace.google.com/")
    assert smtp.reference.startswith("https://knowledge.workspace.google.com/")
    assert spf.verified == "2026-08-20"
    assert spf.reference == "https://support.google.com/a/answer/33786"


def test_microsoft365_mx_family_matches_current_vendor_pages() -> None:
    rules = _mx_rules_for_slug("microsoft365")
    spf = _rules_for_slug("microsoft365", "spf")["spf.protection.outlook.com"]
    txt = _rules_for_slug("microsoft365", "txt")
    targets = _rules_for_slug("microsoft365", "cname_target")
    outlook = rules["mail.protection.outlook.com"]
    mx_microsoft = rules["mx.microsoft"]
    assert outlook.verified == "2026-08-19"
    assert mx_microsoft.verified == "2026-08-19"
    assert "mx.microsoft" in outlook.description
    assert "mail.protection.outlook.com" in mx_microsoft.description
    assert "external-domain-name-system-records" in outlook.reference
    assert "how-dane-secures-email" in mx_microsoft.reference
    assert spf.verified == "2026-08-20"
    assert "external-domain-name-system-records" in spf.reference
    assert txt["^MS=ms"].verified == "2026-08-20"
    assert "create-dns-records-at-any-dns-hosting-provider" in txt["^MS=ms"].reference
    assert "^ms-domain-verification=" not in txt
    assert "outlook.com" not in targets
    assert targets["autodiscover.outlook.com"].verified == "2026-08-20"
    assert "create-dns-records-using-windows-based-dns" in targets["autodiscover.outlook.com"].reference
    assert targets["sharepoint.com"].verified == "2026-08-20"
    assert "cannot-access-sites-by-using-a-domain" in targets["sharepoint.com"].reference


def test_azure_communication_services_email_owns_its_current_verification_token() -> None:
    rule = _rules_for_slug("azure-communication-services-email", "txt")["^ms-domain-verification="]

    assert rule.verified == "2026-08-20"
    assert "email-domain-configuration-troubleshooting" in rule.reference
    assert "Azure Communication Services Email" in rule.description
    assert "not Microsoft 365 tenant verification" in rule.description


def test_microsoft365_government_family_matches_current_vendor_pages() -> None:
    mx = _rules_for_slug("microsoft365-gov", "mx")
    spf = _rules_for_slug("microsoft365-gov", "spf")
    targets = _rules_for_slug("microsoft365-gov", "cname_target")

    assert "office365.us" not in mx
    assert mx["mail.protection.office365.us"].verified == "2026-08-20"
    assert "dns-records-for-office-365-gcc-high" in mx["mail.protection.office365.us"].reference
    assert spf["spf.protection.office365.us"].verified == "2026-08-20"
    assert "email-authentication-spf-configure" in spf["spf.protection.office365.us"].reference
    assert targets["usgovcloud.microsoft"].verified == "2026-08-20"
    assert "microsoft-365-u-s-government-gcc-high-endpoints" in targets["usgovcloud.microsoft"].reference


def test_aws_ses_mail_family_matches_current_vendor_pages() -> None:
    mx = _mx_rules_for_slug("aws-ses")
    spf = _rules_for_slug("aws-ses", "spf")["amazonses.com"]
    txt = _rules_for_slug("aws-ses", "txt")["^amazonses:"]
    regions = {
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "af-south-1",
        "ap-southeast-3",
        "ap-south-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-northeast-1",
        "ca-central-1",
        "eu-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-south-1",
        "eu-west-3",
        "eu-north-1",
        "il-central-1",
        "me-south-1",
        "sa-east-1",
    }
    expected = {f"inbound-smtp.{region}.amazonaws.com" for region in regions}

    assert expected <= mx.keys()
    for pattern in expected:
        assert mx[pattern].verified == "2026-08-20"
        assert mx[pattern].reference == "https://docs.aws.amazon.com/general/latest/gr/ses.html"
        assert "email-receiving endpoint" in mx[pattern].description

    assert spf.verified == "2026-08-20"
    assert spf.reference == "https://docs.aws.amazon.com/ses/latest/dg/mail-from.html"
    assert "custom MAIL FROM" in spf.description
    assert txt.verified == ""
    assert "stays undated" in txt.description


def test_akamai_edge_family_matches_current_vendor_page() -> None:
    cname = _rules_for_slug("akamai", "cname")
    targets = _rules_for_slug("akamai", "cname_target")
    current = {"akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net"}

    for pattern in current & cname.keys():
        assert cname[pattern].verified == "2026-08-20"
        assert "modify-property-hostnames" in cname[pattern].reference
    for pattern in current & targets.keys():
        assert targets[pattern].verified == "2026-08-20"
        assert "modify-property-hostnames" in targets[pattern].reference

    assert targets["akamaiedge-staging.net"].verified == ""
    assert targets["akadns.net"].verified == ""


def test_okta_custom_domain_family_matches_current_vendor_pages() -> None:
    txt = _rules_for_slug("okta", "txt")
    cname = _rules_for_slug("okta", "cname")
    targets = _rules_for_slug("okta", "cname_target")
    owned = txt["^_oktaverification="]
    assert owned.verified == "2026-08-19"
    assert "_oktaverification" in owned.description
    assert "developer.okta.com/docs/guides/custom-url-domain" in owned.reference
    alternate = txt["^okta-domain-verification"]
    assert alternate.verified == ""
    assert "stays undated" in alternate.description
    okta_com = cname["okta.com"]
    preview = cname["oktapreview.com"]
    assert okta_com.verified == "2026-08-19"
    assert preview.verified == "2026-08-19"
    assert "okta-dnssec.com" in okta_com.description
    custom = targets["customdomains.okta.com"]
    dnssec = targets["okta-dnssec.com"]
    gov = targets["okta-gov.com"]
    assert custom.verified == "2026-08-19"
    assert dnssec.verified == "2026-08-19"
    assert gov.verified == "2026-08-19"
    assert "okta-dnssec.com" in dnssec.description
    assert "okta-gov.com" in gov.description
    assert "okta-for-government" not in gov.reference


def test_proofpoint_gateway_family_stays_undated_without_public_dns_page() -> None:
    mx = _rules_for_slug("proofpoint", "mx")
    spf = _rules_for_slug("proofpoint", "spf")
    txt = _rules_for_slug("proofpoint", "txt")
    assert mx["pphosted.com"].verified == ""
    assert mx["ppe-hosted.com"].verified == ""
    assert spf["spf.pphosted.com"].verified == ""
    assert spf["_spf.proofpoint.com"].verified == ""
    assert txt["^proofpoint-domain-verification="].verified == ""


def test_mimecast_gateway_family_matches_current_vendor_pages() -> None:
    mx = _rules_for_slug("mimecast", "mx")
    spf = _rules_for_slug("mimecast", "spf")
    txt = _rules_for_slug("mimecast", "txt")
    inbound = mx["mimecast.com"]
    za = mx["mimecast.co.za"]
    netblocks = spf["_netblocks.mimecast.com"]
    assert inbound.verified == "2026-08-20"
    assert za.verified == "2026-08-20"
    assert netblocks.verified == "2026-08-20"
    assert "us-smtp-inbound-1.mimecast.com" in inbound.description
    assert "za-smtp-inbound-1.mimecast.co.za" in za.description
    assert "_netblocks.mimecast.com" in netblocks.description
    assert "34000417366675" in inbound.reference
    assert "34000417366675" in za.reference
    assert "34000792642963" in netblocks.reference
    assert txt["^mimecast"].verified == ""
    assert "stays undated" in txt["^mimecast"].description
    assert spf["mim.ec"].verified == ""


def test_trendmicro_gateway_family_matches_current_vendor_pages() -> None:
    mx = _rules_for_slug("trendmicro", "mx")
    spf = _rules_for_slug("trendmicro", "spf")
    rua = _rules_for_slug("trendmicro", "dmarc_rua")
    expected_spf = {
        "spf.tmes.trendmicro.com",
        "spf-us.tmes.trendmicro.com",
        "spf.tmes.trendmicro.eu",
        "spf.tmes-anz.trendmicro.com",
        "spf.tmems-jp.trendmicro.com",
        "spf.tmes-sg.trendmicro.com",
        "spf.tmes-in.trendmicro.com",
        "spf.tmes-uae.trendmicro.com",
        "spf.tmes-uk.trendmicro.com",
        "spf.tmes-ca.trendmicro.com",
        "spf.tmes-za.trendmicro.com",
        "spf.tmes-id.trendmicro.com",
    }

    assert {"tmes.trendmicro.com", "trendmicro.com", "trendmicro.eu"} <= mx.keys()
    for pattern in ("tmes.trendmicro.com", "trendmicro.com", "trendmicro.eu"):
        assert mx[pattern].verified == "2026-08-20"
        assert "configuring-a-domain" in mx[pattern].reference
        assert "downstream mailbox provider" in mx[pattern].description

    assert expected_spf <= spf.keys()
    for pattern in expected_spf:
        assert spf[pattern].verified == "2026-08-20"
        assert "adding-spf-records" in spf[pattern].reference
        assert "does not establish inbound MX routing" in spf[pattern].description

    assert "recommends replacing" in spf["spf.tmes.trendmicro.com"].description
    assert rua["trendmicro.eu"].verified == ""


def test_barracuda_gateway_family_matches_current_vendor_page() -> None:
    mx = _rules_for_slug("barracuda", "mx")["barracudanetworks.com"]
    rua = _rules_for_slug("barracuda", "dmarc_rua")["barracudanetworks.com"]

    assert mx.verified == "2026-08-20"
    assert mx.description == (
        "MX terminating at Barracuda Email Gateway Defense (`*.ess.barracudanetworks.com`). Barracuda's current "
        "domain-status page tells operators to verify that MX records point to this suffix. This observes inbound "
        "mail routing through Barracuda. It does not identify a downstream mailbox provider."
    )
    assert "2850986" in mx.reference
    assert rua.verified == ""


def test_cisco_cloud_gateway_family_matches_current_vendor_page() -> None:
    current = _rules_for_slug("cisco-ironport", "mx")["iphmx.com"]
    legacy = _rules_for_slug("cisco-email", "mx")["ess.cisco.com"]

    assert current.verified == "2026-08-20"
    assert "mx1.*.iphmx.com" in current.description
    assert current.reference == "https://docs.ces.cisco.com/docs/hostnames"
    assert legacy.verified == ""
    assert "stays undated" in legacy.description
    assert legacy.description == (
        "Observed MX suffix associated with Cisco's earlier Email Security Service (`*.ess.cisco.com`). Cisco's "
        "current Cloud Gateway hostname page names `*.iphmx.com`, not this suffix, so this rule stays undated. A "
        "match still observes inbound mail routing through a Cisco-associated gateway. It does not identify a "
        "downstream mailbox provider."
    )


def test_hubspot_exact_current_rules_are_dated_without_family_stamping() -> None:
    spf = _rules_for_slug("hubspot", "spf")["hubspotemail.net"]
    cname = _rules_for_slug("hubspot", "cname")["hubspot.net"]
    target = _rules_for_slug("hubspot", "cname_target")["hubspot.net"]
    undated_patterns = {
        rule.pattern
        for rule_type in ("txt", "cname_target")
        for rule in _rules_for_slug("hubspot", rule_type).values()
        if rule.verified == ""
    }

    assert spf.verified == "2026-08-20"
    assert "manage-email-authentication-in-hubspot" in spf.reference
    assert spf.description == (
        "SPF include under hubspotemail.net. HubSpot's current email-authentication guide shows account- and "
        "pool-qualified values such as 123456.spf03.hubspotemail.net. This authorizes HubSpot email sending; it "
        "does not establish inbound routing or identify a licensed Hub."
    )
    for rule in (cname, target):
        assert rule.verified == "2026-08-20"
        assert rule.reference == "https://developers.hubspot.com/docs/api-reference/legacy/cms/domains/guide"
    assert cname.description == (
        "CNAME pointing into hubspot.net. HubSpot's current Domains API guide shows expectedCname values such as "
        "8675309.group39.sites.hubspot.net for a connected domain. This indicates HubSpot-hosted content under a "
        "branded hostname, not a specific product tier."
    )
    assert target.description == (
        "Discovered CNAME targets under hubspot.net. HubSpot's current Domains API guide shows expectedCname values "
        "such as 8675309.group39.sites.hubspot.net for a connected domain. This indicates HubSpot-hosted content "
        "under a branded hostname, not a specific product tier."
    )
    assert undated_patterns == {
        "^hubspot-developer-verification=",
        "^hubspot-domain-verification=",
        "hscoscdn-eu1.net",
        "hscoscdn-na2.net",
        "hs-sites.com",
        "hsforms.net",
        "hubspotpagebuilder.com",
    }


def test_marketo_exact_current_rules_are_dated_and_broad_rule_is_narrowed() -> None:
    spf = _rules_for_slug("marketo", "spf")["mktomail.com"]
    cname = _rules_for_slug("marketo", "cname")["mktoweb.com"]
    targets = _rules_for_slug("marketo", "cname_target")
    tracking_pattern = r"^mkto-[a-z][0-9]{4}\.com$"
    undated_patterns = {
        rule.pattern
        for rule_type in ("cname", "cname_target")
        for rule in _rules_for_slug("marketo", rule_type).values()
        if rule.verified == ""
    }

    for rule in (spf, cname, targets["mktoweb.com"], targets[tracking_pattern]):
        assert rule.verified == "2026-08-20"
        assert rule.reference == (
            "https://experienceleague.adobe.com/en/docs/marketo/using/getting-started/initial-setup/"
            "configure-protocols-for-marketo"
        )
    assert "include matching mktomail.com" in spf.description
    assert "[MunchkinID].mktoweb.com" in cname.description
    assert targets[tracking_pattern].description == (
        "Marketo tracking-link CNAME target in Adobe's documented mkto-[letter][four digits].com form, such as "
        "mkto-a0244.com. This indicates branded email tracking through Marketo, not campaign activity or a "
        "subscription tier."
    )
    assert "mkto-" not in targets
    assert undated_patterns == {
        "marketo.com",
        "mktoapps.com",
        "mktoresp.com",
        "mktosvc.com",
        "mktossl.com",
    }


def test_salesforce_marketing_cloud_current_rules_are_dated_and_scoped() -> None:
    cname = _rules_for_slug("salesforce-mc", "cname")
    targets = _rules_for_slug("salesforce-mc", "cname_target")
    spf = _rules_for_slug("salesforce-mc", "spf")["exacttarget.com"]
    txt = _rules_for_slug("sfmc", "txt")["^SFMC-"]
    allowlist = (
        "https://help.salesforce.com/s/articleView?id=mktg.mc_es_ip_addresses_for_inclusion.htm&language=en_US&type=5"
    )

    assert set(cname) == {"exacttarget.com", "sfmc-content.com", "sfmc-marketing.com"}
    assert set(targets) >= {
        "exacttarget.com",
        "exct.net",
        "marketingcloudapis.com",
        "sfmc-content.com",
        "sfmc-marketing.com",
    }
    for rule in (
        *cname.values(),
        *(
            targets[pattern]
            for pattern in (
                "exacttarget.com",
                "exct.net",
                "marketingcloudapis.com",
                "sfmc-content.com",
                "sfmc-marketing.com",
            )
        ),
    ):
        assert rule.verified == "2026-08-20"

    assert cname["exacttarget.com"].reference.endswith("id=000383566&language=en_US&type=1")
    assert "application host" in cname["exacttarget.com"].description
    assert cname["sfmc-content.com"].reference.endswith("id=000389721&language=en_US&type=1")
    assert "CloudPages" in cname["sfmc-content.com"].description
    assert cname["sfmc-marketing.com"].reference == allowlist
    assert "view-as-web-page" in cname["sfmc-marketing.com"].description
    assert targets["marketingcloudapis.com"].reference.startswith("https://developer.salesforce.com/")
    assert "tenant-specific" in targets["marketingcloudapis.com"].description
    assert targets["exct.net"].reference == allowlist
    assert "Subscription Center link" in targets["exct.net"].description

    assert spf.verified == ""
    assert "stays undated" in spf.description
    assert txt.verified == ""
    assert "stays undated" in txt.description


def test_aws_elbv2_surface_is_complete_without_claiming_alb_or_nlb() -> None:
    rules = _rules_for_slug("aws-nlb", "cname_target")
    pattern = r"\.elb\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"

    assert set(rules) == {pattern}
    rule = rules[pattern]
    assert rule.verified == "2026-08-20"
    assert rule.reference.endswith("network/network-load-balancers.html")
    assert "Application and Network Load Balancers" in rule.description
    assert "DNS cannot distinguish" in rule.description
    assert "stable `aws-nlb` slug" in rule.description
    assert "amazonaws.com.cn" in rule.description


def test_aws_api_gateway_surface_is_partition_aware_and_scoped() -> None:
    rules = _rules_for_slug("aws-api-gateway", "cname_target")
    pattern = r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"

    assert set(rules) == {pattern}
    rule = rules[pattern]
    assert rule.verified == "2026-08-20"
    assert rule.reference.endswith("how-to-custom-domains.html")
    assert "commercial, GovCloud, and China partitions" in rule.description
    assert "edge-optimized CloudFront targets" in rule.description
    assert "private VPC endpoint" in rule.description
