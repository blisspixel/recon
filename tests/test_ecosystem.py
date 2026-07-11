"""Unit tests for the batch-scope ecosystem hypergraph.

Covers each hyperedge type:
- top_issuer: domains sharing CT top-issuer
- legacy BIMI subject identity is never correlated
- parent_vendor: domains with detected slugs sharing parent_vendor metadata
- shared_slugs: pairwise slug overlap of at least 3

Plus invariants: empty input, single-domain input, output sorting, caps.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from recon_tool.ecosystem import (
    MAX_HYPEREDGES,
    Hyperedge,
    build_ecosystem_hyperedges,
)
from recon_tool.models import (
    BIMIIdentity,
    CertSummary,
    ConfidenceLevel,
    TenantInfo,
)
from recon_tool.sources.cert_providers import build_cert_summary


def _info(
    domain: str,
    *,
    top_issuer: str | None = None,
    bimi_org: str | None = None,
    slugs: tuple[str, ...] = (),
    degraded_sources: tuple[str, ...] = (),
) -> TenantInfo:
    cert_summary = None
    if top_issuer is not None:
        cert_summary = CertSummary(
            cert_count=1,
            issuer_diversity=1,
            issuance_velocity=1,
            newest_cert_age_days=0,
            oldest_cert_age_days=30,
            top_issuers=(top_issuer,),
        )
    bimi = BIMIIdentity(organization=bimi_org) if bimi_org else None
    return TenantInfo(
        tenant_id=None,
        display_name=domain,
        default_domain=domain,
        queried_domain=domain,
        confidence=ConfidenceLevel.MEDIUM,
        slugs=slugs,
        cert_summary=cert_summary,
        bimi_identity=bimi,
        degraded_sources=degraded_sources,
    )


class TestEmptyAndTrivial:
    def test_empty_input_returns_empty(self):
        assert build_ecosystem_hyperedges({}) == ()

    def test_single_domain_returns_empty(self):
        infos = {"a.com": _info("a.com", top_issuer="LE", slugs=("microsoft365",))}
        assert build_ecosystem_hyperedges(infos) == ()


class TestTopIssuer:
    def test_two_domains_same_issuer_fire(self):
        infos = {
            "a.com": _info("a.com", top_issuer="Lets Encrypt"),
            "b.com": _info("b.com", top_issuer="Lets Encrypt"),
        }
        edges = build_ecosystem_hyperedges(infos)
        types = {e.edge_type for e in edges}
        assert "top_issuer" in types
        edge = next(e for e in edges if e.edge_type == "top_issuer")
        assert edge.key == "Lets Encrypt"
        assert edge.members == ("a.com", "b.com")

    def test_different_issuers_dont_merge(self):
        infos = {
            "a.com": _info("a.com", top_issuer="LE"),
            "b.com": _info("b.com", top_issuer="DigiCert"),
        }
        edges = build_ecosystem_hyperedges(infos)
        # Each issuer has only one domain — no top_issuer edge.
        assert all(e.edge_type != "top_issuer" for e in edges)

    def test_no_cert_summary_skips_domain(self):
        infos = {
            "a.com": _info("a.com"),
            "b.com": _info("b.com", top_issuer="LE"),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "top_issuer"]
        assert edges == []

    def test_tied_issuer_order_is_deterministic_through_the_public_builder(self) -> None:
        now = datetime(2026, 7, 11, tzinfo=UTC)
        entries = [
            {
                "issuer_id": issuer,
                "issuer_name": issuer,
                "not_before": "2026-07-01T00:00:00Z",
                "not_after": "2026-10-01T00:00:00Z",
            }
            for issuer in ("Zulu CA", "Alpha CA")
        ]
        forward = build_cert_summary(entries, now)
        reverse = build_cert_summary(list(reversed(entries)), now)

        assert forward is not None
        assert reverse is not None
        assert forward.top_issuers == reverse.top_issuers == ("Alpha CA", "Zulu CA")
        infos = {
            "a.com": replace(_info("a.com"), cert_summary=forward),
            "b.com": replace(_info("b.com"), cert_summary=reverse),
        }

        edges = [edge for edge in build_ecosystem_hyperedges(infos) if edge.edge_type == "top_issuer"]

        assert len(edges) == 1
        assert edges[0].key == "Alpha CA"


class TestLegacyBimiOrgRetirement:
    def test_two_domains_same_legacy_bimi_do_not_fire(self):
        infos = {
            "a.com": _info("a.com", bimi_org="Example Corp"),
            "b.com": _info("b.com", bimi_org="Example Corp"),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "bimi_org"]
        assert edges == []

    def test_case_and_whitespace_do_not_restore_legacy_identity(self):
        infos = {
            "a.com": _info("a.com", bimi_org="Example  Corp"),
            "b.com": _info("b.com", bimi_org="example corp"),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "bimi_org"]
        assert edges == []

    def test_retirement_is_input_order_invariant(self):
        forward = {
            "a.com": _info("a.com", bimi_org="Example  Corp"),
            "b.com": _info("b.com", bimi_org="example corp"),
        }
        reverse = dict(reversed(tuple(forward.items())))

        forward_edges = tuple(edge for edge in build_ecosystem_hyperedges(forward) if edge.edge_type == "bimi_org")
        reverse_edges = tuple(edge for edge in build_ecosystem_hyperedges(reverse) if edge.edge_type == "bimi_org")

        assert forward_edges == reverse_edges
        assert forward_edges == ()

    def test_public_builder_masks_unavailable_bimi_channel(self):
        infos = {
            "a.com": _info("a.com", bimi_org="Example Corp"),
            "b.com": _info(
                "b.com",
                bimi_org="Example Corp",
                degraded_sources=("dns:bimi",),
            ),
        }

        edges = build_ecosystem_hyperedges(infos)

        assert all(edge.edge_type != "bimi_org" for edge in edges)


class TestParentVendor:
    def test_microsoft_family_groups(self):
        # microsoft365 (parent_vendor=Microsoft) + github (parent_vendor=Microsoft)
        # both seeded in built-in YAMLs.
        infos = {
            "a.com": _info("a.com", slugs=("microsoft365",)),
            "b.com": _info("b.com", slugs=("github",)),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "parent_vendor"]
        assert any(e.key == "Microsoft" and e.members == ("a.com", "b.com") for e in edges)

    def test_unknown_slugs_dont_fire(self):
        infos = {
            "a.com": _info("a.com", slugs=("not-a-real-slug",)),
            "b.com": _info("b.com", slugs=("also-fake",)),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "parent_vendor"]
        assert edges == []


class TestSharedSlugs:
    def test_schema_documents_runtime_overlap_threshold(self):
        schema = json.loads((Path(__file__).parents[1] / "docs" / "recon-schema.json").read_text(encoding="utf-8"))
        description = schema["$defs"]["EcosystemHyperedge"]["properties"]["edge_type"]["description"]
        assert "at least 3" in description

    def test_three_overlapping_slugs_fire(self):
        """MIN_SLUG_OVERLAP raised to 3 to suppress trivial pairs."""
        infos = {
            "a.com": _info("a.com", slugs=("slug1", "slug2", "slug3", "slug4")),
            "b.com": _info("b.com", slugs=("slug1", "slug2", "slug3", "slug5")),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        assert len(edges) == 1
        assert edges[0].members == ("a.com", "b.com")
        assert edges[0].key == "slug1,slug2,slug3"

    def test_unavailable_legacy_caa_slugs_cannot_form_an_overlap_edge(self) -> None:
        stale = ("letsencrypt", "digicert", "sectigo")
        infos = {domain: _info(domain, slugs=stale, degraded_sources=("dns:caa",)) for domain in ("a.com", "b.com")}

        edges = build_ecosystem_hyperedges(infos)

        assert all(edge.edge_type != "shared_slugs" for edge in edges)

    def test_two_overlap_no_longer_fires(self):
        """2-slug overlap is below MIN_SLUG_OVERLAP and stays silent."""
        infos = {
            "a.com": _info("a.com", slugs=("slug1", "slug2", "extra-a")),
            "b.com": _info("b.com", slugs=("slug1", "slug2", "extra-b")),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        assert edges == []

    def test_single_overlap_doesnt_fire(self):
        infos = {
            "a.com": _info("a.com", slugs=("slug1", "slug2")),
            "b.com": _info("b.com", slugs=("slug1", "slug3")),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        assert edges == []

    def test_baseline_slug_filter_strips_ubiquitous_overlap(self):
        """Slugs present on >50 % of the batch are baseline noise.

        Microsoft365 + Google-Site appear on every domain in this
        synthetic batch (frequency = 1.0) — pairs whose only overlap
        is those two slugs must NOT fire, even though the raw
        intersection is 3. Batch size must clear
        ``_MIN_BATCH_FOR_BASELINE`` for the filter to engage.
        """
        ubiquitous = ("microsoft365", "google-site", "spf-strict")
        infos = {
            f"d{i}.com": _info(f"d{i}.com", slugs=(*ubiquitous, f"unique-{i}-1", f"unique-{i}-2")) for i in range(8)
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        # Without the baseline filter every pair would fire on the 3
        # ubiquitous slugs. With it, no pair has any non-baseline
        # overlap left — silent.
        assert edges == []

    def test_baseline_denominator_includes_empty_slug_rows(self):
        shared = ("shared-1", "shared-2", "shared-3")
        infos = {
            **{f"empty-{i}.com": _info(f"empty-{i}.com") for i in range(97)},
            **{f"hit-{i}.com": _info(f"hit-{i}.com", slugs=shared) for i in range(3)},
        }

        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]

        assert {edge.members for edge in edges} == {
            ("hit-0.com", "hit-1.com"),
            ("hit-0.com", "hit-2.com"),
            ("hit-1.com", "hit-2.com"),
        }

    def test_pairs_not_transitive(self):
        """A∩B and B∩C fire independently; A↔C may stay silent if their
        non-baseline overlap is below the threshold."""
        infos = {
            "a.com": _info("a.com", slugs=("s1", "s2", "s3", "sa1", "sa2")),
            "b.com": _info("b.com", slugs=("s1", "s2", "s3", "s4", "s5")),
            "c.com": _info("c.com", slugs=("s3", "s4", "s5", "sc1", "sc2")),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        member_sets = {e.members for e in edges}
        # (a,b) shares s1,s2,s3 → 3 → fires.
        # (b,c) shares s3,s4,s5 → 3 → fires.
        # (a,c) shares s3 only → 1 → silent.
        assert ("a.com", "b.com") in member_sets
        assert ("b.com", "c.com") in member_sets
        assert ("a.com", "c.com") not in member_sets


class TestSortingAndCaps:
    def test_output_respects_documented_type_precedence(self):
        infos = {
            "a.com": _info("a.com", top_issuer="LE", slugs=("microsoft365",)),
            "b.com": _info("b.com", top_issuer="LE", slugs=("github",)),
        }
        edges = build_ecosystem_hyperedges(infos)
        types_in_order = [e.edge_type for e in edges]
        assert types_in_order == ["parent_vendor", "top_issuer"]

    def test_global_cap_applied(self):
        # Build many shared_slugs pairs to push past MAX_HYPEREDGES.
        # 30 distinct domains → 435 pairs, each with overlap=2.
        infos = {f"d{i}.com": _info(f"d{i}.com", slugs=("s1", "s2")) for i in range(30)}
        edges = build_ecosystem_hyperedges(infos)
        assert len(edges) <= MAX_HYPEREDGES

    def test_returns_hyperedge_dataclass(self):
        infos = {
            "a.com": _info("a.com", top_issuer="LE"),
            "b.com": _info("b.com", top_issuer="LE"),
        }
        edges = build_ecosystem_hyperedges(infos)
        for e in edges:
            assert isinstance(e, Hyperedge)
            assert len(e.members) >= 2
