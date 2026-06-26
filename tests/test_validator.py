"""Unit tests for domain validation."""

import pytest

from recon_tool.validator import host_has_suffix, is_safe_dns_name, strip_control_chars, validate_domain


class TestHostHasSuffix:
    def test_exact_and_dotted_suffix_match(self):
        assert host_has_suffix("okta.com", "okta.com")
        assert host_has_suffix("login.okta.com", "okta.com")
        assert host_has_suffix("LOGIN.OKTA.COM.", "okta.com")

    def test_interior_label_and_lookalike_do_not_match(self):
        assert not host_has_suffix("okta.com.example.net", "okta.com")
        assert not host_has_suffix("notokta.com", "okta.com")
        assert not host_has_suffix("", "okta.com")


class TestValidateDomain:
    """Tests for validate_domain function."""

    # --- Happy path ---

    def test_simple_domain(self):
        assert validate_domain("contoso.com") == "contoso.com"

    def test_subdomain_reduced_to_apex(self):
        # By default a sub-host is reduced to its registrable apex, where
        # recon's signal (MX, tenant, _dmarc, CT) lives.
        assert validate_domain("mail.google.com") == "google.com"

    def test_subdomain_exact_preserves_host(self):
        # apex=False (recon --exact) keeps the literal sub-host.
        assert validate_domain("mail.google.com", apex=False) == "mail.google.com"

    def test_deep_subdomain_reduced_to_apex(self):
        assert validate_domain("autodiscover.mail.contoso.com") == "contoso.com"

    def test_cctld_apex_reduction(self):
        # Multi-label public suffixes (ccTLDs) reduce correctly — the whole
        # reason recon carries the Public Suffix List rather than a naive
        # last-two-labels rule.
        assert validate_domain("mail.acme.co.uk") == "acme.co.uk"

    def test_apex_input_idempotent(self):
        assert validate_domain("contoso.com") == "contoso.com"

    def test_apex_false_still_strips_www(self):
        # www. stripping is part of base normalization, independent of apex
        # reduction: --exact (apex=False) still drops www. but keeps a real
        # sub-host (see test_subdomain_exact_preserves_host).
        assert validate_domain("www.contoso.com", apex=False) == "contoso.com"

    def test_trailing_dot_fqdn_normalized(self):
        # An absolute FQDN with a trailing root-label dot is a common paste
        # form; it normalizes like the apex without the dot.
        assert validate_domain("contoso.com.") == "contoso.com"
        assert validate_domain("mail.contoso.com.") == "contoso.com"
        assert validate_domain("https://contoso.com./path") == "contoso.com"

    def test_public_suffix_input_falls_back_to_host(self):
        # A bare public suffix has no registrable part above it; rather than
        # returning None, to_apex falls back to the validated host so the
        # caller always has a usable value.
        assert validate_domain("co.uk") == "co.uk"

    def test_uppercase_normalized(self):
        assert validate_domain("Contoso.COM") == "contoso.com"

    def test_leading_trailing_whitespace_stripped(self):
        assert validate_domain("  contoso.com  ") == "contoso.com"

    # --- Internationalized domain names (IDN) ---
    # Raw-Unicode IDNs are IDNA-encoded to punycode rather than rejected.
    # Surfaced by the 2026-05 corpus validation, where an IDN apex was the
    # only rejected domain in a 200-domain run.

    def test_idn_unicode_converted_to_punycode(self):
        assert validate_domain("münchen.de") == "xn--mnchen-3ya.de"

    def test_idn_accented_converted(self):
        assert validate_domain("mehiläinen.com") == "xn--mehilinen-z2a.com"

    def test_punycode_passthrough(self):
        assert validate_domain("xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"

    def test_idn_with_scheme_and_www_stripped(self):
        assert validate_domain("https://www.münchen.de") == "xn--mnchen-3ya.de"

    def test_idn_uppercase_normalized(self):
        assert validate_domain("MÜNCHEN.DE") == "xn--mnchen-3ya.de"

    # --- Scheme stripping ---

    def test_strip_https(self):
        assert validate_domain("https://contoso.com") == "contoso.com"

    def test_strip_http(self):
        assert validate_domain("http://contoso.com") == "contoso.com"

    def test_strip_scheme_case_insensitive(self):
        assert validate_domain("HTTPS://Contoso.com") == "contoso.com"

    def test_strip_scheme_with_path(self):
        assert validate_domain("https://contoso.com/some/path") == "contoso.com"

    def test_strip_scheme_with_query(self):
        assert validate_domain("https://www.contoso.com?utm=1") == "contoso.com"

    def test_strip_scheme_with_fragment(self):
        assert validate_domain("https://www.contoso.com#section") == "contoso.com"

    def test_strip_scheme_with_port(self):
        assert validate_domain("https://www.contoso.com:443/some/path") == "contoso.com"

    def test_strip_bare_port(self):
        # A bare host with a port normalizes the same way the scheme form does
        # (urlsplit strips the port there); the colon must not fail the format check.
        assert validate_domain("contoso.com:8443") == "contoso.com"
        assert validate_domain("mail.contoso.com:443/login", apex=False) == "mail.contoso.com"

    def test_strip_bare_query(self):
        assert validate_domain("contoso.com?utm=1") == "contoso.com"

    def test_strip_bare_fragment(self):
        assert validate_domain("contoso.com#section") == "contoso.com"

    def test_strip_trailing_slash(self):
        assert validate_domain("contoso.com/") == "contoso.com"

    # --- www. stripping ---

    def test_strip_www_prefix(self):
        assert validate_domain("www.contoso.com") == "contoso.com"

    def test_strip_www_with_scheme(self):
        assert validate_domain("https://www.contoso.com/") == "contoso.com"

    def test_strip_www_case_insensitive(self):
        assert validate_domain("WWW.Contoso.COM") == "contoso.com"

    def test_www_registrable_label_not_clobbered(self):
        # ``www.com`` is itself a registrable domain; stripping ``www.`` would
        # leave a bare TLD that fails the format check. The strip only fires when
        # the remainder is still a valid domain.
        assert validate_domain("www.com") == "www.com"
        assert validate_domain("www.com", apex=False) == "www.com"

    # --- Empty / whitespace rejection ---

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="A valid domain is required"):
            validate_domain("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="A valid domain is required"):
            validate_domain("   ")

    def test_tabs_only_raises(self):
        with pytest.raises(ValueError, match="A valid domain is required"):
            validate_domain("\t\n")

    # --- Invalid format rejection ---

    def test_no_dot_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("localhost")

    def test_spaces_in_domain_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("con toso.com")

    def test_single_char_tld_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("contoso.c")

    def test_consecutive_dots_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("contoso..com")

    def test_leading_dot_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain(".contoso.com")

    def test_numeric_tld_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("contoso.123")

    # --- Input length limit ---

    def test_excessively_long_input_rejected(self):
        with pytest.raises(ValueError, match="Input too long"):
            validate_domain("a" * 501 + ".com")

    def test_max_length_input_accepted(self):
        # 499 chars + ".com" = 503 total, but after stripping it's just the domain
        # A domain at exactly 500 chars should be accepted
        domain = "a" * 490 + ".com"
        assert len(domain) < 500
        result = validate_domain(domain)
        assert result == domain


# --- Property-Based Tests (Hypothesis) ---

import hypothesis.strategies as st
from hypothesis import assume, given, settings


class TestWhitespaceDomainRejection:
    """Property 1: Whitespace domain rejection.

    For any string composed entirely of whitespace characters (spaces, tabs,
    newlines, or empty string), validate_domain should raise ValueError.

    **Validates: Requirements 1.2**
    """

    @given(
        s=st.text(
            alphabet=st.characters(
                whitelist_categories=("Zs",),
                whitelist_characters="\t\n\r ",
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(max_examples=100)
    def test_whitespace_only_raises_value_error(self, s: str):
        with pytest.raises(ValueError, match=r"(valid domain|Invalid domain)"):
            validate_domain(s)


class TestInvalidDomainFormatRejection:
    """Property 2: Invalid domain format rejection.

    For any string that does not match a valid domain format (no dot, contains
    spaces, missing TLD, consecutive dots), validate_domain should raise ValueError.

    **Validates: Requirements 1.3**
    """

    @given(s=st.text(min_size=1, max_size=50).filter(lambda x: x.strip() != ""))
    @settings(max_examples=100)
    def test_no_dot_raises(self, s: str):
        """A non-empty string with no dot is never a valid domain."""
        assume("." not in s)
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain(s)

    @given(
        label=st.from_regex(r"[a-z][a-z0-9]{0,10}", fullmatch=True),
        space_pos=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=100)
    def test_spaces_in_domain_raises(self, label: str, space_pos: int):
        """A domain containing interior spaces is always invalid."""
        pos = min(space_pos, len(label))
        domain_with_space = label[:pos] + " " + label[pos:] + ".com"
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain(domain_with_space)

    @given(
        label=st.from_regex(r"[a-z][a-z0-9]{1,10}", fullmatch=True),
        tld_char=st.from_regex(r"[a-z]", fullmatch=True),
    )
    @settings(max_examples=100)
    def test_single_char_tld_raises(self, label: str, tld_char: str):
        """A domain with a single-character TLD is invalid."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain(f"{label}.{tld_char}")

    @given(label=st.from_regex(r"[a-z][a-z0-9]{1,10}", fullmatch=True))
    @settings(max_examples=100)
    def test_consecutive_dots_raises(self, label: str):
        """A domain with consecutive dots is invalid."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain(f"{label}..com")


class TestSchemeStrippingPreservesDomain:
    """Property 3: Scheme stripping preserves domain.

    For any valid domain string d, validate_domain("http://" + d) and
    validate_domain("https://" + d) should both return d (lowercased).
    Also validate_domain(d) should return d (idempotence).

    **Validates: Requirements 1.4**
    """

    # Strategy that generates valid domain strings (excluding www. prefix
    # since the validator strips it, which would change the expected output)
    _valid_domain = st.from_regex(r"[a-z][a-z0-9]{0,10}\.[a-z]{2,6}", fullmatch=True).filter(
        lambda d: not d.startswith("www.")
    )

    @given(domain=_valid_domain)
    @settings(max_examples=100)
    def test_http_scheme_stripped(self, domain: str):
        assert validate_domain("http://" + domain) == domain.lower()

    @given(domain=_valid_domain)
    @settings(max_examples=100)
    def test_https_scheme_stripped(self, domain: str):
        assert validate_domain("https://" + domain) == domain.lower()

    @given(domain=_valid_domain)
    @settings(max_examples=100)
    def test_bare_domain_idempotent(self, domain: str):
        assert validate_domain(domain) == domain.lower()


class TestStripControlChars:
    """strip_control_chars removes C0/C1 control bytes and bounds length,
    so attacker-derived display strings (CT issuer names, VMC subject
    fields) cannot inject ANSI escapes or extra lines into terminal,
    markdown, or MCP output."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("DigiCert Inc", "DigiCert Inc"),  # printable preserved
            ("Contoso, Ltd.", "Contoso, Ltd."),  # punctuation preserved
            ("evil\x1b[31mred", "evil[31mred"),  # ESC removed, rest kept
            ("a\x00b", "ab"),  # NUL removed
            ("line1\nline2", "line1line2"),  # newline removed
            ("a\r\nb\tc\x07d", "abcd"),  # CR / LF / TAB / BEL removed
            ("x\x9bCSI", "xCSI"),  # C1 control (0x9b) removed
            ("café résumé", "café résumé"),  # non-control Unicode preserved
        ],
    )
    def test_strips_controls_preserves_printable(self, raw: str, expected: str):
        assert strip_control_chars(raw) == expected

    def test_bounds_default_length(self):
        assert len(strip_control_chars("a" * 5000)) == 200

    def test_custom_max_len(self):
        assert strip_control_chars("abcdef", max_len=3) == "abc"

    def test_empty(self):
        assert strip_control_chars("") == ""

    def test_no_escape_survives(self):
        # The load-bearing property: no ESC byte is ever returned.
        nasty = "name\x1b]0;title\x07\x1b[2J"
        assert "\x1b" not in strip_control_chars(nasty)


class TestIsSafeDnsName:
    """is_safe_dns_name accepts DNS-shaped names and rejects names carrying
    control bytes or other non-DNS characters. Used to drop unsafe CT SAN
    values before they reach output or further processing."""

    @pytest.mark.parametrize(
        "name",
        ["app.example.com", "sel._domainkey.example.com", "*.example.com", "App.Example.Com"],
    )
    def test_accepts_dns_safe(self, name: str):
        assert is_safe_dns_name(name)

    @pytest.mark.parametrize(
        "name",
        ["evil\x1bx.example.com", "a b.example.com", "a\nb.example.com", "a\x00b.example.com", ""],
    )
    def test_rejects_control_and_non_dns(self, name: str):
        assert not is_safe_dns_name(name)
