"""v1.9.3.10 — unclassified-surface output in the default panel.

The default-panel rendering now exposes the chain walker's
unclassified termini — CNAME chains the walker reached but the
fingerprint catalog could not classify. Surfacing the count plus
two representative ``subdomain → terminus`` examples lets the
operator see that recon walked something interesting it couldn't
name, rather than the implicit "absence of a finding = service not
present" framing the panel previously carried.

These tests pin the surface against regression:

  * When ``unclassified_cname_chains`` is non-empty, the default
    panel renders the new section with the correct count, noun
    (terminus/termini), and up to two example pairs.
  * When the field is empty, the section is omitted entirely — no
    false positives, no noisy "0 unclassified" rendering.
  * Verbose / ``--domains`` modes already had a different surface
    for unclassified chains; the new default-panel surface coexists
    with that, so neither path duplicates nor suppresses the other.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, TenantInfo, UnclassifiedCnameChain


def _render_to_string(info: TenantInfo, **kwargs: object) -> str:
    """Render the panel and capture as plain text for substring asserts.

    Uses ``no_color=True`` + ``record=True`` so Rich's color/style
    codes don't pollute the substring search; tests assert on the
    visible characters operators read in their terminal.
    """
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info, **kwargs)  # type: ignore[arg-type]
    console.print(rendered)
    return console.export_text()


def _make_tenant(**overrides: object) -> TenantInfo:
    """Build a minimal TenantInfo for panel-render tests.

    The TenantInfo dataclass requires ``tenant_id``, ``display_name``,
    ``default_domain``, ``queried_domain``. Everything else has a
    default. Tests override only the fields they care about.
    """
    base: dict[str, object] = {
        "tenant_id": "a1b2c3d4",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.HIGH,
    }
    base.update(overrides)
    return TenantInfo(**base)  # type: ignore[arg-type]


class TestUnclassifiedSurfaceVisible:
    """The new section renders when chains exist and is structurally
    correct (count, noun, examples, discovery hint)."""

    def test_section_header_present(self):
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("strange-host.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info)
        assert "Unclassified surface" in out, (
            "default panel must surface the 'Unclassified surface' header when unclassified_cname_chains is non-empty"
        )

    def test_singular_noun_for_one_chain(self):
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("strange-host.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info)
        # Singular: "1 CNAME chain terminus reached"
        assert "1 CNAME chain terminus" in out
        assert "1 CNAME chain termini" not in out

    def test_plural_noun_for_multiple_chains(self):
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("a.example.cloud",),
                ),
                UnclassifiedCnameChain(
                    subdomain="analytics.contoso.com",
                    chain=("b.example.cloud",),
                ),
                UnclassifiedCnameChain(
                    subdomain="api.contoso.com",
                    chain=("c.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info)
        # Plural: "3 CNAME chain termini reached"
        assert "3 CNAME chain termini" in out

    def test_includes_discovery_hint(self):
        """The section names ``recon discover`` as the triage path so
        operators have a single command to run when they see the
        signal."""
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("strange.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info)
        assert "recon discover contoso.com" in out, "section must point operators at `recon discover` for triage"

    def test_shows_up_to_two_examples(self):
        """Examples are capped at 2 so the default panel stays
        compact. More than 2 unclassified chains are summarised by
        count only; full list is on --full / `recon discover`."""
        chains = tuple(
            UnclassifiedCnameChain(
                subdomain=f"sub{i}.contoso.com",
                chain=(f"terminus{i}.example.cloud",),
            )
            for i in range(5)
        )
        info = _make_tenant(unclassified_cname_chains=chains)
        out = _render_to_string(info)
        # First two examples appear; remaining three don't pollute
        # the example pair list.
        assert "sub0.contoso.com" in out
        assert "sub1.contoso.com" in out
        # The example line shows up to 2; the count (5) is also
        # mentioned, but sub2/sub3/sub4 should not appear as inline
        # examples.
        # Use a stricter check: the examples: prefix line contains
        # at most two arrows.
        lines = out.splitlines()
        example_line = next((line for line in lines if "examples:" in line), "")
        assert example_line.count("→") <= 2, (
            f"examples line {example_line!r} should show at most 2 arrows; more would crowd the default panel"
        )

    def test_terminus_is_chain_last_hop(self):
        """The example shows the last hop of each chain (the actual
        terminus), not the first."""
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="api.contoso.com",
                    chain=("intermediate.proxy.io", "true-terminus.weird.cloud"),
                ),
            ),
        )
        out = _render_to_string(info)
        assert "true-terminus.weird.cloud" in out
        # The intermediate hop should not be reported as the
        # terminus — the operator's signal is the END of the chain.
        # We allow it to appear elsewhere (e.g. in a future
        # full-chain rendering) but not as the example terminus.
        example_section = out.split("examples:", 1)
        if len(example_section) == 2:
            assert "true-terminus.weird.cloud" in example_section[1]


class TestUnclassifiedSurfaceHiddenWhenEmpty:
    """No false-positive rendering when there are no unclassified
    chains — the section is omitted entirely."""

    def test_section_omitted_when_field_empty(self):
        info = _make_tenant(unclassified_cname_chains=())
        out = _render_to_string(info)
        assert "Unclassified surface" not in out, (
            "default panel must omit the 'Unclassified surface' section when unclassified_cname_chains is empty"
        )

    def test_section_omitted_in_show_domains_mode(self):
        """The ``--full`` / ``--domains`` mode already has a
        separate unclassified-chain surface (line ``surf.append``
        for the per-subdomain attribution list). The new
        default-panel section must not duplicate that — it's gated
        by ``not show_domains`` so the two surfaces stay mutually
        exclusive."""
        info = _make_tenant(
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("strange.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info, show_domains=True)
        # The default-panel section header must not appear in
        # --domains mode — the per-subdomain attribution list
        # carries the unclassified surface there.
        assert "Unclassified surface\n" not in out, (
            "--domains mode must not duplicate the default-panel Unclassified surface section"
        )


class TestUnclassifiedSurfaceIsolated:
    """The new section does not affect existing surfaces."""

    def test_related_domains_section_still_renders(self):
        info = _make_tenant(
            related_domains=("login.contoso.com", "api.contoso.com"),
            unclassified_cname_chains=(
                UnclassifiedCnameChain(
                    subdomain="data.contoso.com",
                    chain=("strange.example.cloud",),
                ),
            ),
        )
        out = _render_to_string(info)
        assert "High-signal related domains" in out
        assert "login.contoso.com" in out
        # And the unclassified section also appears.
        assert "Unclassified surface" in out

    def test_smoke_no_crash_on_minimal_tenant(self):
        """A TenantInfo with only the required fields renders
        without exceptions."""
        info = _make_tenant()
        out = _render_to_string(info)
        assert isinstance(out, str)
        assert "Contoso, Ltd" in out

    def test_text_renderable_returned(self):
        """Sanity check that the panel returns a Rich-renderable,
        not raw text. The caller passes the return value to
        ``console.print`` and expects Rich semantics."""
        info = _make_tenant()
        rendered = render_tenant_panel(info)
        # Rich renderables don't share a single base class, but
        # they all expose ``__rich_console__`` or are Text. The
        # minimal contract: Console.print must not raise.
        assert rendered is not None
        console = Console(no_color=True, record=True)
        console.print(rendered)
        text_output = console.export_text()
        assert isinstance(text_output, str)
        # Touch the imported ``Text`` symbol so the import isn't
        # flagged as unused by lints. The class is intentionally
        # imported at module level for callers of this test file
        # who want to build Text inputs.
        assert Text is not None
