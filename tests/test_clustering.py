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
        out = cluster_tokens({"contoso.com": ("google-site-verification=abc",)})
        assert "google-site-verification=abc" in out
        assert out["google-site-verification=abc"] == {"contoso.com"}

    def test_two_domains_one_token(self):
        out = cluster_tokens(
            {
                "contoso.com": ("google-site-verification=abc",),
                "fabrikam.com": ("google-site-verification=abc",),
            }
        )
        assert out["google-site-verification=abc"] == {"contoso.com", "fabrikam.com"}

    def test_tokens_deduplicated_within_domain(self):
        """If the same token appears twice on one domain, it's counted once."""
        out = cluster_tokens(
            {
                "contoso.com": (
                    "google-site-verification=abc",
                    "google-site-verification=abc",
                ),
            }
        )
        assert out["google-site-verification=abc"] == {"contoso.com"}

    def test_empty_tokens_skipped(self):
        out = cluster_tokens({"contoso.com": ("",)})
        assert out == {}


# ── compute_shared_tokens ──────────────────────────────────────────────


class TestComputeSharedTokens:
    def test_empty_input(self):
        assert compute_shared_tokens({}) == {}

    def test_singleton_filtered(self):
        """A token on only one domain is not a 'shared' token."""
        out = compute_shared_tokens(
            {
                "contoso.com": ("google-site-verification=abc",),
                "fabrikam.com": (),
            }
        )
        assert out == {}

    def test_two_domains_one_shared_token(self):
        out = compute_shared_tokens(
            {
                "contoso.com": ("google-site-verification=abc",),
                "fabrikam.com": ("google-site-verification=abc",),
            }
        )
        assert "contoso.com" in out
        assert "fabrikam.com" in out
        assert len(out["contoso.com"]) == 1
        assert out["contoso.com"][0].peer == "fabrikam.com"
        assert out["fabrikam.com"][0].peer == "contoso.com"

    def test_three_domains_one_shared_token(self):
        out = compute_shared_tokens(
            {
                "a.com": ("t=x",),
                "b.com": ("t=x",),
                "c.com": ("t=x",),
            }
        )
        # Each domain lists the two others as peers
        assert len(out["a.com"]) == 2
        assert {e.peer for e in out["a.com"]} == {"b.com", "c.com"}

    def test_symmetric(self):
        """If A has B as a peer, B must have A as a peer."""
        out = compute_shared_tokens(
            {
                "a.com": ("t=x",),
                "b.com": ("t=x",),
            }
        )
        a_peers = {e.peer for e in out["a.com"]}
        b_peers = {e.peer for e in out["b.com"]}
        assert "b.com" in a_peers
        assert "a.com" in b_peers

    def test_no_self_peers(self):
        out = compute_shared_tokens(
            {
                "a.com": ("t=x", "t=y"),
                "b.com": ("t=x",),
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
                "a.com": ("t=x", "t=y"),
                "b.com": ("t=x", "t=y"),
            }
        )
        assert len(out["a.com"]) == 2
        tokens = {e.token for e in out["a.com"]}
        assert tokens == {"t=x", "t=y"}

    def test_domain_with_no_shared_tokens_omitted(self):
        out = compute_shared_tokens(
            {
                "a.com": ("t=x",),
                "b.com": ("t=x",),
                "c.com": ("t=y",),
            }
        )
        assert "c.com" not in out

    def test_deterministic_ordering(self):
        out = compute_shared_tokens(
            {
                "a.com": ("t=x", "t=y"),
                "b.com": ("t=x", "t=y"),
            }
        )
        # Sorted by (token, peer)
        entries_a = out["a.com"]
        assert [e.token for e in entries_a] == sorted(e.token for e in entries_a)


# ── ClusterEntry dataclass ──────────────────────────────────────────────


class TestClusterEntry:
    def test_frozen(self):
        e = ClusterEntry(token="t", peer="p")  # noqa: S106
        try:
            e.token = "x"  # pyright: ignore[reportAttributeAccessIssue]  # noqa: S105
        except AttributeError:
            pass
        else:
            raise AssertionError("ClusterEntry should be frozen")

    def test_fields(self):
        e = ClusterEntry(token="google-site-verification=abc", peer="fabrikam.com")  # noqa: S106
        assert e.token == "google-site-verification=abc"  # noqa: S105
        assert e.peer == "fabrikam.com"


# ── v1.3: tenant-ID clustering ─────────────────────────────────────────


class TestTenantClusters:
    def test_clusters_shared_tenant(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.com": "tenant-abc",
                "b.com": "tenant-abc",
                "c.com": "tenant-xyz",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].tenant_id == "tenant-abc"
        assert clusters[0].domains == ("a.com", "b.com")

    def test_skips_singletons(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.com": "tenant-abc",
                "b.com": "tenant-xyz",
            }
        )
        assert clusters == ()

    def test_skips_none_tenant(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "a.com": None,
                "b.com": None,
                "c.com": "tenant-abc",
            }
        )
        assert clusters == ()

    def test_deterministic_ordering(self):
        from recon_tool.clustering import compute_tenant_clusters

        clusters = compute_tenant_clusters(
            {
                "b.com": "zzz",
                "c.com": "aaa",
                "a.com": "zzz",
                "d.com": "aaa",
            }
        )
        # Sorted by tenant_id; domains within each cluster sorted alphabetically.
        assert [c.tenant_id for c in clusters] == ["aaa", "zzz"]
        assert clusters[0].domains == ("c.com", "d.com")
        assert clusters[1].domains == ("a.com", "b.com")


# ── v1.3: display-name clustering ──────────────────────────────────────


class TestDisplayNameClusters:
    def test_clusters_shared_name(self):
        from recon_tool.clustering import compute_display_name_clusters

        clusters = compute_display_name_clusters(
            {
                "a.com": "Acme Corp",
                "b.com": "Acme Corp",
                "c.com": "Different Org",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].normalized_name == "acme"
        assert clusters[0].domains == ("a.com", "b.com")

    def test_corporate_suffix_stripped(self):
        from recon_tool.clustering import compute_display_name_clusters

        # "Acme Corp" and "Acme Corp." both strip to "acme".
        # "Acme Inc" also strips to "acme" and joins the cluster.
        clusters = compute_display_name_clusters(
            {
                "a.com": "Acme Corp",
                "b.com": "Acme Corp.",
                "c.com": "Acme Inc",
            }
        )
        assert len(clusters) == 1
        assert clusters[0].normalized_name == "acme"
        assert set(clusters[0].domains) == {"a.com", "b.com", "c.com"}

    def test_conservative_no_substring(self):
        from recon_tool.clustering import compute_display_name_clusters

        # "Acme" vs "Acme Holdings" do NOT cluster (exact normalized
        # match required; we don't do substring containment).
        clusters = compute_display_name_clusters(
            {
                "a.com": "Acme",
                "b.com": "Acme Holdings",
            }
        )
        assert clusters == ()

    def test_skips_none_name(self):
        from recon_tool.clustering import compute_display_name_clusters

        clusters = compute_display_name_clusters(
            {
                "a.com": None,
                "b.com": None,
            }
        )
        assert clusters == ()

    def test_preserves_raw_names(self):
        from recon_tool.clustering import compute_display_name_clusters

        # raw_names should preserve the verbatim display names for audit,
        # not the normalized form.
        clusters = compute_display_name_clusters(
            {
                "a.com": "Acme Corp",
                "b.com": "Acme Corp.",
            }
        )
        assert len(clusters) == 1
        assert set(clusters[0].raw_names) == {"Acme Corp", "Acme Corp."}
