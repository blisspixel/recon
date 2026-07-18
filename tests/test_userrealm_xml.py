"""Tests for the Autodiscover XML parser (ElementTree-based)."""

from __future__ import annotations

from recon_tool.sources.userrealm import _parse_autodiscover_domains

VALID_XML = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response>
        <Domains>
          <Domain>alpha.invalid</Domain>
          <Domain>synthetic-alpha.onmicrosoft.com</Domain>
          <Domain>synthetic-alpha-legacy.onmicrosoft.com</Domain>
        </Domains>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>"""


class TestParseAutodiscoverDomains:
    def test_extracts_all_domains(self):
        domains, _default = _parse_autodiscover_domains(VALID_XML)
        assert "alpha.invalid" in domains
        assert "synthetic-alpha.onmicrosoft.com" in domains
        assert "synthetic-alpha-legacy.onmicrosoft.com" in domains

    def test_extracts_default_onmicrosoft_domain(self):
        _domains, default = _parse_autodiscover_domains(VALID_XML)
        assert default is not None
        assert default.endswith(".onmicrosoft.com")

    def test_domains_are_lowercase(self):
        xml = VALID_XML.replace("alpha.invalid", "ALPHA.INVALID")
        domains, _ = _parse_autodiscover_domains(xml)
        assert "alpha.invalid" in domains

    def test_domains_are_sorted_and_deduped(self):
        domains, _ = _parse_autodiscover_domains(VALID_XML)
        assert domains == sorted(set(domains))

    def test_invalid_xml_returns_empty(self):
        domains, default = _parse_autodiscover_domains("not xml at all")
        assert domains == []
        assert default is None

    def test_empty_string_returns_empty(self):
        domains, default = _parse_autodiscover_domains("")
        assert domains == []
        assert default is None

    def test_xml_without_domain_elements(self):
        xml = '<?xml version="1.0"?><root><other>data</other></root>'
        domains, default = _parse_autodiscover_domains(xml)
        assert domains == []
        assert default is None

    def test_no_onmicrosoft_domain(self):
        xml = """<?xml version="1.0"?>
        <root xmlns="http://example.com">
          <Domain>example.com</Domain>
          <Domain>other.invalid</Domain>
        </root>"""
        domains, default = _parse_autodiscover_domains(xml)
        assert len(domains) == 2
        assert default is None

    def test_cdata_and_entities_handled(self):
        """ElementTree handles XML entities correctly unlike regex."""
        xml = """<?xml version="1.0"?>
        <root xmlns="http://example.com">
          <Domain>test&amp;co.invalid</Domain>
        </root>"""
        domains, _ = _parse_autodiscover_domains(xml)
        assert "test&co.invalid" in domains
