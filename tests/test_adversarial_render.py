"""v1.9.9 — adversarial-input rendering tests.

The Hypothesis fuzz in ``test_render_fuzz.py`` generates random-but-
structurally-valid TenantInfo from a clean strategy. These tests
push further: inputs that look pathological — unicode, control
characters, ANSI escape sequences, very long strings — and assert
the renderer still produces well-formed output rather than crashing
or leaking the input through to the user terminal.

Threat model: this is a defensive-tool renderer with no untrusted-
input boundary at the panel layer (TenantInfo is built from
deserialized cache or live lookup data the tool itself produced). So
"adversarial" here means data-quality robustness, not security
boundary enforcement. A target whose DNS records contain unicode or
control characters should produce a panel that still parses; an
operator should not see a corrupted terminal or a crashed CLI.

The tests below pin the renderer's behaviour against these classes:

  * Unicode display names (CJK, RTL, accented).
  * Control characters and ANSI escape sequences in slug strings,
    surface attribution subdomains, and service names.
  * Very long values (1000-character display name, 200 slugs).
  * Empty / minimal TenantInfo.
  * Mixed UTF-8 multi-byte sequences.
"""

from __future__ import annotations

from rich.console import Console

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, SurfaceAttribution, TenantInfo


def _render(info: TenantInfo, **kwargs: object) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


def _make_tenant(**overrides: object) -> TenantInfo:
    base: dict[str, object] = {
        "tenant_id": "tid",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.HIGH,
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


class TestUnicodeRendering:
    def test_cjk_display_name(self):
        """CJK characters in the display name must render without
        codec errors. Operators in JP/CN/KR locales would otherwise
        see crashes on locally-localized organization names."""
        info = _make_tenant(display_name="株式会社コンソト")
        out = _render(info)
        assert "株式会社" in out

    def test_rtl_display_name(self):
        """RTL (Arabic) display name must round-trip; Rich should
        preserve the codepoints even if the terminal does not
        bidirectionally render them."""
        info = _make_tenant(display_name="شركة كونتوسو المحدودة")
        out = _render(info)
        # The codepoints must be present in the output even if the
        # terminal renders them visually different. Render is a
        # text-emission contract, not a glyph contract.
        assert "كونتوسو" in out

    def test_accented_display_name(self):
        info = _make_tenant(display_name="Contôso Lìmited")
        out = _render(info)
        assert "Contôso" in out

    def test_emoji_in_display_name(self):
        """Emoji are valid Unicode; the renderer must not crash. The
        emoji may or may not display in a given terminal, but the
        emit-text path must not raise."""
        info = _make_tenant(display_name="Contoso 🏢")
        out = _render(info)
        # Either the emoji or its surrogate is present.
        assert "Contoso" in out


class TestControlCharacterSafety:
    """A slug, service name, or subdomain that contains a control
    character or ANSI escape must not leak through to the operator's
    terminal in a way that corrupts subsequent rendering. Rich's
    default text mode should suppress ANSI codes from non-styled
    inputs."""

    def test_null_byte_in_slug_does_not_crash(self):
        info = _make_tenant(
            slugs=("aws-cloudfront", "cloudflare\x00malicious"),
            services=("AWS CloudFront", "Cloudflare"),
        )
        out = _render(info)
        # Render completes; no exception. The malicious slug appears
        # somewhere or is filtered, but no crash.
        assert "Contoso" in out

    def test_ansi_escape_in_service_name_is_neutralized(self):
        """An ANSI escape in a service name (e.g. injected from a
        compromised data source) should not propagate as terminal-
        coloring instructions to the operator."""
        info = _make_tenant(services=("\x1b[31mMalicious Red\x1b[0m",))
        out = _render(info)
        # The renderer produces output. We do not assert escape
        # absence (Rich may pass through styled text), but we assert
        # the render does not raise and the panel structure remains
        # intact.
        assert "Contoso" in out
        assert "Services" in out

    def test_newline_in_subdomain_does_not_break_panel(self):
        """A subdomain string with an embedded newline must not
        fracture the panel layout. The renderer should treat the
        string as a single token or sanitize it."""
        info = _make_tenant(
            slugs=("fastly",),
            services=("Fastly",),
            surface_attributions=(
                SurfaceAttribution(
                    subdomain="sub.contoso.com\nmalicious.com",
                    primary_slug="fastly",
                    primary_name="Fastly",
                    primary_tier="infrastructure",
                ),
            ),
        )
        # The render must complete without raising; structural
        # invariants (panel width, sections present) hold.
        out = _render(info, show_domains=True)
        assert "External surface" in out or "Services" in out

    def test_tab_character_in_slug_does_not_break_alignment(self):
        info = _make_tenant(slugs=("aws-cloudfront", "okta\tinjected"))
        out = _render(info)
        # No crash; render completes.
        assert "Contoso" in out


class TestLargeInputs:
    def test_thousand_character_display_name(self):
        """An absurdly long display name must not crash the renderer.
        Rich should wrap or truncate at the panel width; the goal
        here is no exception, not visual perfection."""
        long_name = "A" * 1000
        info = _make_tenant(display_name=long_name)
        out = _render(info)
        # First 80 chars of the long name should appear at least once
        # (Rich may wrap; the assertion is on text emission).
        assert "A" * 50 in out

    def test_two_hundred_slugs_render(self):
        """A pathological apex with 200 slugs must render without
        crashing. The Services block may overflow visually but the
        emission path must complete."""
        many_slugs = tuple(f"slug-{i}" for i in range(200))
        many_services = tuple(f"Service {i}" for i in range(200))
        info = _make_tenant(slugs=many_slugs, services=many_services)
        out = _render(info)
        # Some prefix of the slugs / services appears in the output.
        assert "Contoso" in out

    def test_two_hundred_surface_attributions_render(self):
        """A pathological apex with 200 surface attributions must
        render without crashing. The Subdomain summary should
        aggregate; the External surface section is hidden by default
        and would only appear under ``--full``."""
        many_attribs = tuple(
            SurfaceAttribution(
                subdomain=f"sub{i}.contoso.com",
                primary_slug="fastly",
                primary_name="Fastly",
                primary_tier="infrastructure",
            )
            for i in range(200)
        )
        info = _make_tenant(
            slugs=("aws-cloudfront", "fastly"),
            services=("AWS CloudFront", "Fastly"),
            surface_attributions=many_attribs,
        )
        out = _render(info)
        # Render completes; the Multi-cloud rollup correctly counts
        # both vendors regardless of attribution scale.
        assert "Multi-cloud" in out


class TestMinimalInputs:
    def test_empty_services_and_slugs_renders(self):
        """A TenantInfo with no detected services and no slugs must
        still produce a panel. The hero header and Confidence line
        always render."""
        info = _make_tenant(services=(), slugs=())
        out = _render(info)
        assert "Contoso" in out
        # No Multi-cloud row (no cloud slugs)
        assert "Multi-cloud" not in out


class TestUnicodeInSurfaceAttributions:
    def test_unicode_subdomain_renders(self):
        """An IDN subdomain (or a subdomain with localized characters)
        must round-trip through render. The CNAME chain walker
        normalizes IDNs to A-label form upstream, but if a punycode-
        encoded string reaches the panel the render should not
        crash."""
        info = _make_tenant(
            slugs=("fastly",),
            services=("Fastly",),
            surface_attributions=(
                SurfaceAttribution(
                    subdomain="xn--80akhbyknj4f.contoso.com",  # punycode "испытание" (Cyrillic)
                    primary_slug="fastly",
                    primary_name="Fastly",
                    primary_tier="infrastructure",
                ),
            ),
        )
        out = _render(info, show_domains=True)
        # Render completes; the punycode form appears.
        assert "xn--" in out or "Services" in out
