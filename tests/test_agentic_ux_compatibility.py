"""v1.9.9 — re-render the v1.9.2 agentic UX fixtures through v1.9.9.

The v1.9.2 agentic-UX milestone validated that AI agents read the panel
correctly on two reference fixtures: ``contoso-dense.json`` (rich
stack, dense evidence) and ``hardened-sparse.json`` (minimal-DNS
hardened target). v1.9.9 added two new panel surfaces (Multi-cloud
rollup, Passive-DNS ceiling).

The relevant compatibility question is: do the v1.9.9 surfaces behave
correctly on the v1.9.2 fixtures, and does any new output that appears
read as a legitimate enrichment rather than an alarmist regression?

Findings against the actual fixture contents:

  * ``contoso-dense`` has ``azure-dns`` on the apex and a single
    ``akamai`` surface attribution. The Multi-cloud rollup correctly
    fires (Azure + Akamai = 2 distinct vendors). This is a meaningful
    v1.9.9 enrichment: an agent reading the panel now sees the
    multi-cloud nature of the Contoso footprint without having to
    cross-reference the Cloud line with the Subdomain line. The
    ceiling does not fire because ``domain_count == 1`` keeps the
    conservative trigger silent on a single-tenant-domain fixture.
  * ``hardened-sparse`` has ``display_name: null`` and cannot
    round-trip through the cache deserializer (which requires a
    non-null display name). The v1.9.2 harness used a different
    loader path; the v1.9.9 compatibility test documents the loader
    contract rather than working around it.

The test suite below pins both outcomes so a future regression in
either direction (rollup mis-firing on single-vendor data, ceiling
firing on single-domain data, or loader unexpectedly accepting null
display name) is flagged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from recon_tool.cache import tenant_info_from_dict
from recon_tool.formatter import render_tenant_panel

_FIXTURE_DIR = Path(__file__).parent.parent / "validation" / "agentic_ux" / "fixtures"


def _load(name: str):
    data = json.loads((_FIXTURE_DIR / name).read_text(encoding="utf-8"))
    return tenant_info_from_dict(data)


def _render(info) -> str:
    console = Console(no_color=True, record=True, width=120)
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


class TestContosoDenseCompatibility:
    """contoso-dense.json — a v1.9.2 agentic-UX fixture for dense
    evidence. The fixture has Azure DNS on the apex plus an Akamai
    surface attribution, which means v1.9.9 correctly enriches the
    panel with a Multi-cloud row identifying both vendors."""

    def test_multi_cloud_correctly_fires_on_real_multi_cloud_data(self):
        """Two distinct canonicalized cloud vendors (Azure via
        ``azure-dns``, Akamai via the surface attribution) so the
        rollup must fire. This is the v1.9.9 enrichment in action on a
        v1.9.2 fixture — not a regression but a richness gain."""
        out = _render(_load("contoso-dense.json"))
        assert "Multi-cloud" in out
        assert "2 providers observed" in out
        assert "Azure" in out
        assert "Akamai" in out

    def test_ceiling_does_not_fire_single_domain(self):
        """``domain_count == 1`` on the fixture; the conservative
        trigger correctly suppresses. A regression here would alarm on
        legitimate small organizations."""
        out = _render(_load("contoso-dense.json"))
        assert "Passive-DNS ceiling" not in out

    def test_pre_existing_blocks_still_render(self):
        """Sanity: the panel still produces the structural blocks the
        v1.9.2 agentic-UX validation assumed (Services, Confidence,
        display name)."""
        out = _render(_load("contoso-dense.json"))
        assert "Contoso" in out
        assert "Services" in out
        assert "Confidence" in out

    def test_multi_cloud_appears_in_key_facts_block(self):
        """Layout: Multi-cloud is inserted into the key-facts block
        above Confidence. An agent that reads the key-facts header to
        decide whether to dive into Services should see the
        multi-cloud signal at the top."""
        out = _render(_load("contoso-dense.json"))
        mc = out.find("Multi-cloud")
        conf = out.find("Confidence")
        assert mc != -1
        assert conf != -1
        assert mc < conf


class TestHardenedSparseLoaderContract:
    """hardened-sparse.json has ``display_name: null``. The cache
    deserializer requires a non-null display name and rejects this
    shape with ``ValueError``. The test documents the contract so a
    future loader change that silently accepts null display names
    (which would create a different rendering path with its own
    edge-case risks) is visible at PR time."""

    def test_loader_rejects_null_display_name(self):
        with pytest.raises(ValueError, match="display_name"):
            _load("hardened-sparse.json")


class TestContosoDenseLoaderRoundTrip:
    """The contoso-dense fixture must continue to round-trip cleanly
    through the cache loader. The fixture is part of the v1.9.2
    publicly-reproducible artifact set and changing it is a
    contract-level change; a silent break here would invalidate the
    v1.9.2 transcripts."""

    def test_fixture_loads_with_expected_identity(self):
        info = _load("contoso-dense.json")
        assert info.display_name == "Contoso, Ltd"
        assert info.default_domain == "contoso.com"
        assert info.queried_domain == "contoso.com"

    def test_fixture_carries_v192_slug_set(self):
        """The slug set is part of the v1.9.2 fixture contract; any
        change shifts what agents see in the Services block. If a
        future patch needs to evolve the slug set, that is a deliberate
        v1.9.2-fixture refresh, not a side effect."""
        info = _load("contoso-dense.json")
        assert "azure-dns" in info.slugs
        assert "microsoft365" in info.slugs
