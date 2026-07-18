"""Re-render the v1.9.2 agentic UX fixtures through v1.9.9.

The v1.9.2 agentic-UX milestone validated that AI agents read the panel
correctly on two reference fixtures: ``synthetic-dense.json`` (rich
stack, dense evidence) and ``synthetic-sparse.json`` (minimal-DNS
hardened target). v1.9.9 added two new panel surfaces (Multi-cloud
rollup, Passive-DNS ceiling).

The relevant compatibility question is: do the v1.9.9 surfaces behave
correctly on the v1.9.2 fixtures, and does any new output that appears
read as a legitimate enrichment rather than an alarmist regression?

Findings against the actual fixture contents:

  * ``synthetic-dense`` has an unlined ``azure-dns`` catalog indicator on
    the apex and a single ``akamai`` CNAME surface attribution. DNS
    operation does not establish a hosted workload, and a cached slug
    without retained role evidence cannot repair that gap. The
    Multi-cloud summary therefore stays suppressed while both lower-level
    observations remain visible. The ceiling does not fire because
    ``domain_count == 1`` keeps the conservative trigger silent on a
    single-tenant-domain fixture.
  * ``synthetic-sparse`` has ``display_name: null`` and cannot
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


class TestSyntheticDenseCompatibility:
    """synthetic-dense.json - a v1.9.2 agentic-UX fixture for dense
    evidence. The fixture has an unlined Azure DNS catalog indicator on
    the apex plus an Akamai surface attribution. Only the latter has
    endpoint-binding lineage, so the panel must not synthesize a
    Multi-cloud claim from the pair."""

    def test_dns_role_plus_one_endpoint_does_not_claim_multi_cloud(self):
        """A DNS operator and one endpoint vendor are not two observed
        workload providers, especially when the cached DNS slug has no
        retained evidence record describing its role."""
        out = _render(_load("synthetic-dense.json"))
        assert "Multi-cloud" not in out
        assert "Azure DNS (role unavailable)" in out
        assert "Akamai" in out

    def test_ceiling_does_not_fire_single_domain(self):
        """``domain_count == 1`` on the fixture; the conservative
        trigger correctly suppresses. A regression here would alarm on
        legitimate small organizations."""
        out = _render(_load("synthetic-dense.json"))
        assert "Passive-DNS ceiling" not in out

    def test_pre_existing_blocks_still_render(self):
        """Sanity: the panel still produces the structural blocks the
        v1.9.2 agentic-UX validation assumed (Services, Confidence,
        display name)."""
        out = _render(_load("synthetic-dense.json"))
        assert "Synthetic Dense Namespace" in out
        assert "Services" in out
        assert "Confidence" in out

    def test_unresolved_cloud_role_stays_below_key_facts(self):
        """The key-facts block must not elevate an unresolved catalog
        indicator. Its role-qualified detail remains in Services after
        the deterministic Confidence field."""
        out = _render(_load("synthetic-dense.json"))
        conf = out.find("Confidence")
        azure = out.find("Azure DNS (role unavailable)")
        assert conf != -1
        assert azure != -1
        assert conf < azure


class TestSyntheticSparseLoaderContract:
    """synthetic-sparse.json has ``display_name: null``. The cache
    deserializer requires a non-null display name and rejects this
    shape with ``ValueError``. The test documents the contract so a
    future loader change that silently accepts null display names
    (which would create a different rendering path with its own
    edge-case risks) is visible at PR time."""

    def test_loader_rejects_null_display_name(self):
        with pytest.raises(ValueError, match="display_name"):
            _load("synthetic-sparse.json")


class TestSyntheticDenseLoaderRoundTrip:
    """The synthetic-dense fixture must continue to round-trip cleanly
    through the cache loader. The fixture is part of the v1.9.2
    publicly-reproducible artifact set and changing it is a
    contract-level change; a silent break here would invalidate the
    v1.9.2 transcripts."""

    def test_fixture_loads_with_expected_identity(self):
        info = _load("synthetic-dense.json")
        assert info.display_name == "Synthetic Dense Namespace"
        assert info.default_domain == "dense.example.invalid"
        assert info.queried_domain == "dense.example.invalid"

    def test_fixture_carries_v192_slug_set(self):
        """The slug set is part of the v1.9.2 fixture contract; any
        change shifts what agents see in the Services block. If a
        future patch needs to evolve the slug set, that is a deliberate
        v1.9.2-fixture refresh, not a side effect."""
        info = _load("synthetic-dense.json")
        assert "azure-dns" in info.slugs
        assert "microsoft365" in info.slugs

    def test_evidence_keeps_reasoning_grammar_without_target_values(self):
        data = json.loads((_FIXTURE_DIR / "synthetic-dense.json").read_text(encoding="utf-8"))
        evidence = data["evidence"]

        assert [(record["source_type"], record["rule_name"], record["slug"]) for record in evidence] == [
            ("HTTP", "OIDC Discovery", "microsoft365"),
            ("HTTP", "GetUserRealm", "microsoft365"),
            ("HTTP", "GetUserRealm", "microsoft365"),
            ("MX", "Microsoft 365", "microsoft365"),
            ("TXT", "Microsoft 365", "microsoft365"),
            ("TXT", "Microsoft 365", "microsoft365"),
            ("TXT", "Microsoft 365", "microsoft365"),
            ("TXT", "Microsoft 365", "microsoft365"),
            ("DMARC_RUA", "Agari (DMARC)", "agari"),
            ("A", "ADFS SSO hub", "adfs-sso-hub"),
            ("A", "Exchange Server (on-prem / hybrid)", "exchange-onprem"),
            ("CNAME", "Akamai", "akamai"),
        ]
        raw_values = [record["raw_value"] for record in evidence]
        assert raw_values == [
            "tenant_id=synthetic-dense-tenant",
            "FederationBrandName=Synthetic Dense Namespace",
            "NameSpaceType=Managed",
            "10 synthetic-dense.mail.protection.outlook.com",
            "MS=synthetic-ms-token-001",
            "ms-domain-verification=synthetic-domain-token-001",
            "MS=synthetic-ms-token-002",
            "MS=synthetic-ms-token-003",
            "rua=mailto:synthetic@rua.agari.com",
            "adfs.dense.example.invalid",
            "autodiscover.dense.example.invalid, mail.dense.example.invalid",
            "www.dense.example.invalid: origin.dense.example.invalid -> "
            "synthetic-dense.edgekey.net -> synthetic-dense.akamaiedge.net -> "
            "synthetic-dense.akamai.net",
        ]
