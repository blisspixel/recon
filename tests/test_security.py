"""Security-focused tests — XML injection, ReDoS, error sanitization, UUID validation."""

from __future__ import annotations

import pytest

from recon_tool.fingerprints import _validate_regex
from recon_tool.models import ReconLookupError


class TestXmlInjectionPrevention:
    """Verify XML-unsafe characters in domain names are escaped."""

    def test_xml_escape_in_autodiscover_body(self):
        from xml.sax.saxutils import escape as xml_escape

        malicious = "foo.com</Domain></Request></GetFederationInformationRequestMessage>"
        escaped = xml_escape(malicious)
        assert "</" not in escaped
        assert "&lt;" in escaped

    def test_domain_validator_rejects_xml_payloads(self):
        from recon_tool.validator import validate_domain

        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("foo.com</Domain>")


class TestReDoSPrevention:
    """Verify that dangerous regex patterns are rejected by the heuristic checker."""

    def test_nested_quantifier_rejected(self):
        # Classic ReDoS: (a+)+ causes exponential backtracking
        assert _validate_regex("(a+)+", "test") is False

    def test_nested_star_quantifier_rejected(self):
        assert _validate_regex("(a*)+", "test") is False

    def test_nested_quantifier_with_content_rejected(self):
        assert _validate_regex("(foo[a-z]+)+", "test") is False

    def test_normal_quantifier_accepted(self):
        # Non-nested quantifiers are fine
        assert _validate_regex("^openai-domain-verification=", "test") is True
        assert _validate_regex("[a-z]+", "test") is True
        assert _validate_regex("(foo|bar)+", "test") is True

    def test_bounded_nested_quantifier_rejected(self):
        # Bounded repetition of a quantified group, e.g. (a+){20}, is also
        # catastrophic; the heuristic now flags the {n} form, not just (a+)+.
        assert _validate_regex("(a+){20}", "test") is False
        assert _validate_regex("([a-z]+){15}", "test") is False

    def test_redundantly_nested_quantifier_group_rejected(self):
        # A quantified group wrapped in an extra paren bypassed the flat
        # heuristic (its [^)]* limbs cannot span the inner group); the
        # balanced-paren scan catches it. These are genuinely exponential, so
        # the input-length caps cannot contain them.
        assert _validate_regex("((a+))+", "test") is False
        assert _validate_regex("((\\d+))+", "test") is False
        assert _validate_regex("((a+)b)+", "test") is False
        assert _validate_regex("(a+b+)+", "test") is False

    def test_nested_group_without_inner_quantifier_accepted(self):
        # An inner group with no quantifier inside the outer-quantified group is
        # linear and stays allowed (no false positive from the scan).
        assert _validate_regex("(a(bc)d)+", "test") is True

    def test_overlapping_alternation_rejected(self):
        # (a|aa)+ backtracks catastrophically because one branch is a prefix of
        # another, making a partial match ambiguous. The earlier heuristic
        # missed this (no nested quantifier); the prefix-overlap check catches it.
        assert _validate_regex("(a|aa)+c", "test") is False
        assert _validate_regex("(a|ab)+", "test") is False
        assert _validate_regex("(foo|foobar)+", "test") is False
        assert _validate_regex("(x|xy){5,}", "test") is False

    def test_disjoint_alternation_accepted(self):
        # Quantified alternation with disjoint branches is linear, not ReDoS,
        # so it stays allowed (catalog cname patterns rely on this).
        assert _validate_regex("(foo|bar)+", "test") is True
        assert _validate_regex("(eu|us)[.]example[.]com", "test") is True

    def test_excessively_long_pattern_rejected(self):
        assert _validate_regex("a" * 501, "test") is False

    def test_invalid_regex_rejected(self):
        assert _validate_regex("[unclosed", "test") is False

    def test_empty_regex_rejected(self):
        assert _validate_regex("", "test") is False


class TestUUIDValidation:
    """Verify that azure_metadata validates tenant_id before URL interpolation."""

    @pytest.mark.asyncio
    async def test_path_traversal_rejected(self):
        from recon_tool.sources.azure_metadata import AzureMetadataSource

        source = AzureMetadataSource()
        result = await source.lookup("test.com", tenant_id="../../etc/passwd")
        assert result.error is not None
        assert "Invalid tenant_id" in result.error

    @pytest.mark.asyncio
    async def test_query_injection_rejected(self):
        from recon_tool.sources.azure_metadata import AzureMetadataSource

        source = AzureMetadataSource()
        result = await source.lookup("test.com", tenant_id="abc?redirect=evil.com")
        assert result.error is not None
        assert "Invalid tenant_id" in result.error

    @pytest.mark.asyncio
    async def test_valid_uuid_accepted(self):
        """Valid UUID format should not be rejected by validation (network may fail)."""
        from contextlib import asynccontextmanager
        from unittest.mock import AsyncMock, MagicMock, patch

        from recon_tool.sources.azure_metadata import AzureMetadataSource

        source = AzureMetadataSource()

        mock_response = MagicMock()
        mock_response.json.return_value = {"tenant_region_scope": "NA"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        @asynccontextmanager
        async def fake_http_client(provided=None, timeout=10.0):
            yield mock_client

        with patch("recon_tool.sources.azure_metadata.http_client", fake_http_client):
            result = await source.lookup(
                "test.com",
                tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            )
            assert result.error is None
            assert result.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class TestErrorSanitization:
    def test_recon_lookup_error_str(self):
        err = ReconLookupError(domain="test.com", message="No data found", error_type="not_found")
        assert str(err) == "No data found"
        assert "test.com" not in str(err)

    def test_recon_lookup_error_repr_has_all_fields(self):
        err = ReconLookupError(domain="test.com", message="No data found", error_type="not_found")
        r = repr(err)
        assert "test.com" in r
        assert "No data found" in r


class TestRenderErrorSanitization:
    """render_error must neutralize untrusted content (e.g. a batch-file domain
    echoed back in an error) so it cannot inject terminal escapes or rich markup."""

    def test_strips_control_bytes_and_neutralizes_markup(self):
        import contextlib
        import io

        from recon_tool.formatter import render_error

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            render_error("bad-domain\x1b[2J\x07 [blink]evil[/blink]")
        out = buf.getvalue()
        assert "\x1b" not in out  # terminal escape stripped
        assert "\x07" not in out  # bell stripped
        assert "bad-domain" in out  # legitimate text preserved


class TestOutputInjectionSweep:
    """Record-derived strings reaching the terminal or markdown must be
    sanitized: the siblings of the render_error bug, swept in 2.1.2."""

    def test_render_warning_sanitizes_domain_and_reason(self):
        import contextlib
        import io

        from recon_tool.formatter import render_warning
        from recon_tool.models import ReconLookupError

        err = ReconLookupError(domain="x", message="no data", error_type="not_found")
        err.source_errors = (("dns", "fail \x1b[2J [bold]evil[/bold]"),)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            render_warning("contoso.com\x1b[2J\x07", err)
        out = buf.getvalue()
        assert "\x1b" not in out
        assert "\x07" not in out
        assert "[bold]" in out  # markup neutralized (rendered literally, not interpreted)

    def test_markdown_escapes_autodiscover_domains(self):
        from recon_tool.formatter import format_tenant_markdown
        from recon_tool.models import ConfidenceLevel, TenantInfo

        info = TenantInfo(
            tenant_id=None,
            display_name="Contoso",
            default_domain="evil[x](http://h)",
            queried_domain="contoso.com",
            confidence=ConfidenceLevel.HIGH,
            tenant_domains=("a[b](c).com",),
            domain_count=1,
        )
        md = format_tenant_markdown(info)
        assert "](http://h)" not in md  # default_domain link breakout escaped
        assert "a[b](c)" not in md  # tenant-domain link breakout escaped

    def test_conflict_annotation_verbose_strips_control_chars(self):
        from recon_tool.formatter import render_conflict_annotation
        from recon_tool.models import CandidateValue, MergeConflicts

        conflicts = MergeConflicts(
            display_name=(
                CandidateValue(value="Contoso\x1b[2J", source="oidc", confidence="high"),
                CandidateValue(value="Other", source="userrealm", confidence="medium"),
            )
        )
        ann = render_conflict_annotation("display_name", conflicts, verbose=True)
        assert "\x1b" not in ann


class TestSecurityReviewFixes:
    """Regression tests for the 2026-06 external security-review batch."""

    def test_idna_lossy_mapping_rejected(self):
        # The stdlib idna codec is IDNA2003/nameprep: faß.de maps to fass.de, a
        # different registrable domain. The round-trip check must reject the lossy
        # mapping rather than silently query the wrong domain; non-lossy IDNs still
        # convert.
        from recon_tool.validator import validate_domain

        assert validate_domain("münchen.de") == "xn--mnchen-3ya.de"
        for lossy in ("faß.de", "straße.de"):
            with pytest.raises(ValueError, match="Invalid domain"):
                validate_domain(lossy)

    def test_cname_target_match_is_label_aware(self):
        # A bare-substring match let an attacker-controlled CNAME target like
        # manageengine.com.attacker.tld match the manageengine.com rule. Matching
        # must be DNS-label-aware (exact or proper subdomain).
        from types import SimpleNamespace

        from recon_tool.sources.dns import _classify_chain

        rule = SimpleNamespace(
            pattern="manageengine.com", tier="application", name="ManageEngine", slug="manageengine"
        )
        assert _classify_chain(["manageengine.com.attacker.tld"], [rule])[0] is None
        assert _classify_chain(["foo.manageengine.com"], [rule])[0] is rule
        assert _classify_chain(["manageengine.com"], [rule])[0] is rule

    def test_cache_write_uses_no_predictable_temp(self, tmp_path, monkeypatch):
        # The atomic write must not use a predictable <domain>.json.tmp (a
        # symlink-overwrite vector); mkstemp uses a random O_EXCL name, so a
        # pre-existing predictable temp is never followed or overwritten.
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        from recon_tool.cache import cache_dir, cache_get, cache_put
        from recon_tool.models import ConfidenceLevel, TenantInfo

        d = cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        sentinel = d / "ex.com.json.tmp"
        sentinel.write_text("SENTINEL", encoding="utf-8")
        info = TenantInfo(
            tenant_id=None,
            display_name="X",
            default_domain="ex.com",
            queried_domain="ex.com",
            confidence=ConfidenceLevel.LOW,
            domain_count=0,
        )
        cache_put("ex.com", info)
        assert cache_get("ex.com") is not None
        assert sentinel.read_text(encoding="utf-8") == "SENTINEL"

    def test_ct_budget_summary_streams_ndjson(self, tmp_path):
        # validation/scan.py must stream the NDJSON results line-by-line (memory
        # bounded) and count ct_attempt_outcome correctly.
        import importlib.util
        import json as _json
        from pathlib import Path

        repo = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location("scan_ref", repo / "validation" / "scan.py")
        assert spec is not None
        assert spec.loader is not None
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)

        results = tmp_path / "results.ndjson"
        results.write_text(
            '{"queried_domain":"a.com","ct_attempt_outcome":"cache_hit"}\n'
            "\n"
            '{"queried_domain":"b.com","ct_attempt_outcome":"live_success"}\n'
            '{"queried_domain":"c.com"}\n',
            encoding="utf-8",
        )
        scan._write_ct_budget_summary(results, tmp_path)
        summary = _json.loads((tmp_path / "ct_budget_summary.json").read_text(encoding="utf-8"))
        assert summary["records_total"] == 3
        assert summary["outcome_counts"]["cache_hit"] == 1
        assert summary["outcome_counts"]["live_success"] == 1
        assert summary["outcome_counts"]["not_attempted"] == 1


class TestBugHuntRound2:
    """Regression tests for the self-driven bug-hunt batch (2.1.5)."""

    def test_specificity_cname_target_uses_cname_corpus(self):
        # cname_target had no corpus entry and fell through to the mismatched
        # generic corpus, making the ephemeral-injection specificity gate
        # ineffective for the most common detection type.
        from recon_tool.specificity import PATTERN_TYPE_CORPORA, _cname_corpus, synthetic_corpus

        assert "cname_target" in PATTERN_TYPE_CORPORA
        assert synthetic_corpus("cname_target") == _cname_corpus()

    def test_validate_regex_rejects_noncapturing_alternation_redos(self):
        # (?:a|aa)+c (non-capturing overlapping alternation) slipped past the
        # alternation-overlap check because the "?:" corrupted the first branch.
        from recon_tool.fingerprints import _validate_regex

        assert _validate_regex("(?:a|aa)+c", "test") is False
        assert _validate_regex("(?:a|ab)+", "test") is False
        assert _validate_regex("(?:foo|bar)+", "test") is True  # disjoint branches stay allowed

    def test_merge_conflicts_survive_cache_round_trip(self):
        # merge_conflicts were serialized but never read back, so a cached result
        # silently lost all conflict data (and the Bayesian n_eff penalty).
        from recon_tool.cache import tenant_info_from_dict, tenant_info_to_dict
        from recon_tool.models import CandidateValue, ConfidenceLevel, MergeConflicts, TenantInfo

        mc = MergeConflicts(
            tenant_id=(
                CandidateValue(value="aaaaaaaa-aaaa", source="oidc", confidence="high"),
                CandidateValue(value="bbbbbbbb-bbbb", source="userrealm", confidence="high"),
            )
        )
        info = TenantInfo(
            tenant_id="aaaaaaaa-aaaa",
            display_name="X",
            default_domain="ex.com",
            queried_domain="ex.com",
            confidence=ConfidenceLevel.LOW,
            domain_count=0,
            merge_conflicts=mc,
        )
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.merge_conflicts is not None
        assert restored.merge_conflicts.has_conflicts
        assert len(restored.merge_conflicts.tenant_id) == 2
        assert restored.merge_conflicts.tenant_id[0].value == "aaaaaaaa-aaaa"
