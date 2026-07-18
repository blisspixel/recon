"""Tests for shared verification token clustering.

Covers the pure clustering API in recon_tool.clustering:
- Token normalization
- Cluster construction
- Symmetric peer relationships
- Multi-peer clusters
- Singleton filtering
- Deterministic ordering
- Empty input handling
- Shape of ClusterEntry
"""

from __future__ import annotations

import pytest

from recon_tool.clustering import (
    ClusterEntry,
    _normalize,
    cluster_tokens,
    compute_shared_tokens,
)

# ── Normalization ───────────────────────────────────────────────────────


class TestNormalization:
    def test_empty_string(self):
        assert _normalize("") == ""

    def test_whitespace_only(self):
        assert _normalize("   ") == ""

    def test_whitespace_stripped(self):
        assert _normalize("  google-site-verification=abc123  ") == "google-site-verification=abc123"

    def test_key_lowercased_value_preserved(self):
        """The key (verification vendor label) is case-insensitive,
        the value (token hash) is case-significant."""
        assert _normalize("MS=ABC123XYZ") == "ms=ABC123XYZ"

    def test_no_equals_sign(self):
        """Tokens without = are returned as-is (just stripped)."""
        assert _normalize("raw-token-value") == "raw-token-value"


# ── cluster_tokens ──────────────────────────────────────────────────────


class TestClusterTokens:
    def test_empty_input(self):
        assert cluster_tokens({}) == {}

    def test_single_domain(self):
        out = cluster_tokens({"alpha.invalid": ("google-site-verification=abc",)})
        assert "google-site-verification=abc" in out
        assert out["google-site-verification=abc"] == {"alpha.invalid"}

    def test_two_domains_one_token(self):
        out = cluster_tokens(
            {
                "alpha.invalid": ("google-site-verification=abc",),
                "beta.invalid": ("google-site-verification=abc",),
            }
        )
        assert out["google-site-verification=abc"] == {"alpha.invalid", "beta.invalid"}

    def test_tokens_deduplicated_within_domain(self):
        """If the same token appears twice on one domain, it's counted once."""
        out = cluster_tokens(
            {
                "alpha.invalid": (
                    "google-site-verification=abc",
                    "google-site-verification=abc",
                ),
            }
        )
        assert out["google-site-verification=abc"] == {"alpha.invalid"}

    def test_empty_tokens_skipped(self):
        out = cluster_tokens({"alpha.invalid": ("",)})
        assert out == {}


# ── compute_shared_tokens ──────────────────────────────────────────────


class TestComputeSharedTokens:
    def test_empty_input(self):
        assert compute_shared_tokens({}) == {}

    def test_singleton_filtered(self):
        """A token on only one domain is not a 'shared' token."""
        out = compute_shared_tokens(
            {
                "alpha.invalid": ("google-site-verification=abc",),
                "beta.invalid": (),
            }
        )
        assert out == {}

    def test_two_domains_one_shared_token(self):
        out = compute_shared_tokens(
            {
                "alpha.invalid": ("google-site-verification=abc",),
                "beta.invalid": ("google-site-verification=abc",),
            }
        )
        assert "alpha.invalid" in out
        assert "beta.invalid" in out
        assert len(out["alpha.invalid"]) == 1
        assert out["alpha.invalid"][0].peer == "beta.invalid"
        assert out["beta.invalid"][0].peer == "alpha.invalid"

    def test_three_domains_one_shared_token(self):
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x",),
                "b.invalid": ("t=x",),
                "c.invalid": ("t=x",),
            }
        )
        # Each domain lists the two others as peers
        assert len(out["a.invalid"]) == 2
        assert {e.peer for e in out["a.invalid"]} == {"b.invalid", "c.invalid"}

    def test_symmetric(self):
        """If A has B as a peer, B must have A as a peer."""
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x",),
                "b.invalid": ("t=x",),
            }
        )
        a_peers = {e.peer for e in out["a.invalid"]}
        b_peers = {e.peer for e in out["b.invalid"]}
        assert "b.invalid" in a_peers
        assert "a.invalid" in b_peers

    def test_no_self_peers(self):
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x", "t=y"),
                "b.invalid": ("t=x",),
            }
        )
        for domain, entries in out.items():
            for e in entries:
                assert e.peer != domain, f"{domain} peers include itself via {e.token}"

    def test_multiple_shared_tokens_same_pair(self):
        """Two domains sharing two tokens produces two ClusterEntry
        per direction."""
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x", "t=y"),
                "b.invalid": ("t=x", "t=y"),
            }
        )
        assert len(out["a.invalid"]) == 2
        tokens = {e.token for e in out["a.invalid"]}
        assert tokens == {"t=x", "t=y"}

    def test_domain_with_no_shared_tokens_omitted(self):
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x",),
                "b.invalid": ("t=x",),
                "c.invalid": ("t=y",),
            }
        )
        assert "c.invalid" not in out

    def test_deterministic_ordering(self):
        out = compute_shared_tokens(
            {
                "a.invalid": ("t=x", "t=y"),
                "b.invalid": ("t=x", "t=y"),
            }
        )
        # Sorted by (token, peer)
        entries_a = out["a.invalid"]
        assert [e.token for e in entries_a] == sorted(e.token for e in entries_a)


# ── ClusterEntry dataclass ──────────────────────────────────────────────


class TestClusterEntry:
    def test_frozen(self):
        e = ClusterEntry(token="t", peer="p")  # noqa: S106
        with pytest.raises(AttributeError):
            e.token = "x"  # pyright: ignore[reportAttributeAccessIssue]  # noqa: S105

    def test_fields(self):
        e = ClusterEntry(token="google-site-verification=abc", peer="beta.invalid")  # noqa: S106
        assert e.token == "google-site-verification=abc"  # noqa: S105
        assert e.peer == "beta.invalid"


# ── v1.3: tenant-ID clustering ─────────────────────────────────────────


class TestTenantClusters:
    def test_clusters_shared_tenant(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.invalid": "tenant-abc",
                "b.invalid": "tenant-abc",
                "c.invalid": "tenant-xyz",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].tenant_id == "tenant-abc"
        assert clusters[0].domains == ("a.invalid", "b.invalid")

    def test_skips_singletons(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.invalid": "tenant-abc",
                "b.invalid": "tenant-xyz",
            }
        )
        assert clusters == ()

    def test_skips_none_tenant(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.invalid": None,
                "b.invalid": None,
                "c.invalid": "tenant-abc",
            }
        )
        assert clusters == ()

    def test_deterministic_ordering(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "b.invalid": "zzz",
                "c.invalid": "aaa",
                "a.invalid": "zzz",
                "d.invalid": "aaa",
            }
        )
        # Sorted by tenant_id; domains within each cluster sorted alphabetically.
        assert [c.tenant_id for c in clusters] == ["aaa", "zzz"]
        assert clusters[0].domains == ("c.invalid", "d.invalid")
        assert clusters[1].domains == ("a.invalid", "b.invalid")


# ── v1.3: display-name clustering ──────────────────────────────────────


class TestDisplayNameClusters:
    def test_clusters_shared_name(self):
        from recon_tool.clustering import compute_display_name_clusters

        clusters = compute_display_name_clusters(
            {
                "a.invalid": "Synthetic Delta Corp",
                "b.invalid": "Synthetic Delta Corp",
                "c.invalid": "Different Org",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].normalized_name == "synthetic delta"
        assert clusters[0].domains == ("a.invalid", "b.invalid")

    def test_corporate_suffix_stripped(self):
        from recon_tool.clustering import compute_display_name_clusters

        # The corporate suffixes strip while the explicit synthetic identity remains.
        clusters = compute_display_name_clusters(
            {
                "a.invalid": "Synthetic Delta Corp",
                "b.invalid": "Synthetic Delta Corp.",
                "c.invalid": "Synthetic Delta Inc",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].normalized_name == "synthetic delta"
        assert set(clusters[0].domains) == {"a.invalid", "b.invalid", "c.invalid"}

    def test_conservative_no_substring(self):
        from recon_tool.clustering import compute_display_name_clusters

        # "Synthetic Delta" vs "Synthetic Delta Holdings" do NOT cluster (exact normalized
        # match required; we don't do substring containment).
        clusters = compute_display_name_clusters(
            {
                "a.invalid": "Synthetic Delta",
                "b.invalid": "Synthetic Delta Holdings",
            }
        )
        assert clusters == ()

    def test_skips_none_name(self):
        from recon_tool.clustering import compute_display_name_clusters

        clusters = compute_display_name_clusters(
            {
                "a.invalid": None,
                "b.invalid": None,
            }
        )
        assert clusters == ()

    def test_preserves_raw_names(self):
        from recon_tool.clustering import compute_display_name_clusters

        # raw_names should preserve the verbatim display names for audit,
        # not the normalized form.
        clusters = compute_display_name_clusters(
            {
                "a.invalid": "Synthetic Delta Corp",
                "b.invalid": "Synthetic Delta Corp.",
            }
        )
        assert len(clusters) == 1
        assert set(clusters[0].raw_names) == {"Synthetic Delta Corp", "Synthetic Delta Corp."}


def test_compute_shared_tokens_skips_high_cardinality_token():
    # A token shared by more than the per-token cap is treated as noise and
    # yields no peer relationships, bounding the O(k^2) cross-product that a
    # large CLI batch would otherwise materialize.
    from recon_tool.clustering import _MAX_CLUSTER_DOMAINS_PER_TOKEN, compute_shared_tokens

    n = _MAX_CLUSTER_DOMAINS_PER_TOKEN + 5
    over_cap = {f"d{i}.example.com": ("shared-token",) for i in range(n)}
    assert compute_shared_tokens(over_cap) == {}

    # A small cluster sharing the same token still clusters normally.
    small = {"a.example.com": ("tok",), "b.example.com": ("tok",)}
    result = compute_shared_tokens(small)
    assert "a.example.com" in result
    assert "b.example.com" in result
