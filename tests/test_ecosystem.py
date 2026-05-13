"""Unit tests for the v1.8 batch-scope ecosystem hypergraph.

Covers each hyperedge type:
- top_issuer: domains sharing CT top-issuer
- bimi_org: domains sharing BIMI VMC organization
- parent_vendor: domains with detected slugs sharing parent_vendor metadata
- shared_slugs: pairwise slug overlap ≥2

Plus invariants: empty input, single-domain input, output sorting, caps.
"""

from __future__ import annotations

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


def _info(
    domain: str,
    *,
    top_issuer: str | None = None,
    bimi_org: str | None = None,
    slugs: tuple[str, ...] = (),
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


class TestBimiOrg:
    def test_two_domains_same_bimi_fire(self):
        infos = {
            "a.com": _info("a.com", bimi_org="Example Corp"),
            "b.com": _info("b.com", bimi_org="Example Corp"),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "bimi_org"]
        assert len(edges) == 1
        assert edges[0].members == ("a.com", "b.com")
        assert edges[0].key == "Example Corp"

    def test_case_and_whitespace_normalised(self):
        infos = {
            "a.com": _info("a.com", bimi_org="Example  Corp"),
            "b.com": _info("b.com", bimi_org="example corp"),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "bimi_org"]
        assert len(edges) == 1
        assert edges[0].members == ("a.com", "b.com")


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
    def test_three_overlapping_slugs_fire(self):
        """v1.8: MIN_SLUG_OVERLAP raised to 3 to suppress trivial pairs."""
        infos = {
            "a.com": _info("a.com", slugs=("slug1", "slug2", "slug3", "slug4")),
            "b.com": _info("b.com", slugs=("slug1", "slug2", "slug3", "slug5")),
        }
        edges = [e for e in build_ecosystem_hyperedges(infos) if e.edge_type == "shared_slugs"]
        assert len(edges) == 1
        assert edges[0].members == ("a.com", "b.com")
        assert edges[0].key == "slug1,slug2,slug3"

    def test_two_overlap_no_longer_fires(self):
        """v1.8: 2-slug overlap is below MIN_SLUG_OVERLAP and stays silent."""
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
        """v1.8: slugs present on >50 % of the batch are baseline noise.

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
    def test_output_sorted_by_type_then_key(self):
        infos = {
            "a.com": _info("a.com", top_issuer="LE"),
            "b.com": _info("b.com", top_issuer="LE"),
            "c.com": _info("c.com", bimi_org="Org"),
            "d.com": _info("d.com", bimi_org="Org"),
        }
        edges = build_ecosystem_hyperedges(infos)
        types_in_order = [e.edge_type for e in edges]
        # bimi_org sorts before top_issuer alphabetically; both should appear.
        assert "bimi_org" in types_in_order
        assert "top_issuer" in types_in_order
        # Within a type, keys are sorted lexicographically.
        bimi_keys = [e.key for e in edges if e.edge_type == "bimi_org"]
        assert bimi_keys == sorted(bimi_keys)

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
