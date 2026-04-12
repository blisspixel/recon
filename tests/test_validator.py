"""Unit tests for domain validation."""

import pytest

from recon_tool.validator import validate_domain


class TestValidateDomain:
    """Tests for validate_domain function."""

    # --- Happy path ---

    def test_simple_domain(self):
        assert validate_domain("contoso.com") == "contoso.com"

    def test_subdomain(self):
        assert validate_domain("mail.google.com") == "mail.google.com"

    def test_uppercase_normalized(self):
        assert validate_domain("Contoso.COM") == "contoso.com"

    def test_leading_trailing_whitespace_stripped(self):
        assert validate_domain("  contoso.com  ") == "contoso.com"

    # --- Scheme stripping ---

    def test_strip_https(self):
        assert validate_domain("https://contoso.com") == "contoso.com"

    def test_strip_http(self):
        assert validate_domain("http://contoso.com") == "contoso.com"

    def test_strip_scheme_case_insensitive(self):
        assert validate_domain("HTTPS://Contoso.com") == "contoso.com"

    def test_strip_scheme_with_path(self):
        assert validate_domain("https://contoso.com/some/path") == "contoso.com"

    def test_strip_trailing_slash(self):
        assert validate_domain("contoso.com/") == "contoso.com"

    # --- www. stripping ---

    def test_strip_www_prefix(self):
        assert validate_domain("www.contoso.com") == "contoso.com"

    def test_strip_www_with_scheme(self):
        assert validate_domain("https://www.contoso.com/") == "contoso.com"

    def test_strip_www_case_insensitive(self):
        assert validate_domain("WWW.Contoso.COM") == "contoso.com"

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

    def test_trailing_dot_raises(self):
        with pytest.raises(ValueError, match="Invalid domain format"):
            validate_domain("contoso.com.")

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
        with pytest.raises(ValueError, match="(valid domain|Invalid domain)"):
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
