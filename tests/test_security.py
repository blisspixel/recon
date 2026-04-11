"""Security-focused tests — XML injection, ReDoS, error sanitization, UUID validation."""

from __future__ import annotations

import pytest

from recon_tool.fingerprints import _validate_regex
from recon_tool.models import ReconLookupError


class TestXmlInjectionPrevention:
    """Verify XML-unsafe characters in domain names are escaped."""

    def test_xml_escape_in_autodiscover_body(self):
        from xml.sax.saxutils import escape as xml_escape

        malicious = 'foo.com</Domain></Request></GetFederationInformationRequestMessage>'
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
