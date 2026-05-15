"""v1.9.9 — Hypothesis property tests on count_cloud_vendors.

The fixture-based tests in ``test_multi_cloud_rollup.py`` pin specific
input → output cases. Property tests pin invariants that should hold
across the full space of possible inputs:

  * Order independence — the function counts vendors, not positions.
  * Non-cloud slug invariance — adding slugs that are not in the
    canonicalization map cannot change the vendor counts.
  * Idempotence under shuffle — running the same multiset through the
    function in any order returns the same dict.
  * Stream union semantics — splitting input across the apex and
    surface streams must produce the same counts as concatenating
    them, since the function merges before counting.

These are invariants worth holding even as the canonicalization map
grows. A future refactor that, say, switches the merge to a generator
or introduces caching must preserve all four properties; the property
tests are the safety net.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from recon_tool.formatter import _CLOUD_VENDOR_BY_SLUG, count_cloud_vendors

# Strategy for known cloud slugs, drawn directly from the canonical map
# so the property tests stay in lockstep with whichever slugs ship.
# Hypothesis will sample with replacement, so a single test can exercise
# multi-mention behaviour without separately listing per-vendor slugs.
_cloud_slugs = st.sampled_from(sorted(_CLOUD_VENDOR_BY_SLUG.keys()))

# A small set of non-cloud slugs from the catalog. Each is a real slug
# that exists in _CATEGORY_BY_SLUG but is not under the Cloud bucket.
# Adding these to a stream must never change the vendor counts because
# they are not in the canonicalization map.
_non_cloud_slugs = st.sampled_from(
    [
        "slack",
        "okta",
        "auth0",
        "atlassian",
        "wiz",
        "proofpoint",
        "mimecast",
        "salesforce",
        "hubspot",
        "openai",
    ]
)


class TestOrderInvariance:
    @given(slugs=st.lists(_cloud_slugs, min_size=1, max_size=12))
    def test_apex_stream_order_does_not_change_counts(self, slugs):
        """A vendor count is a multiset operation. Shuffling the input
        must not change the output. Property holds for arbitrary
        non-empty cloud-slug lists."""
        forward = count_cloud_vendors(slugs)
        reversed_counts = count_cloud_vendors(list(reversed(slugs)))
        assert forward == reversed_counts


class TestNonCloudInvariance:
    @given(
        cloud=st.lists(_cloud_slugs, min_size=0, max_size=8),
        noise=st.lists(_non_cloud_slugs, min_size=0, max_size=8),
    )
    def test_adding_non_cloud_slugs_is_a_noop(self, cloud, noise):
        """Slugs not in ``_CLOUD_VENDOR_BY_SLUG`` are silently dropped.
        Adding any number of them to the apex stream must not change
        the vendor counts. This invariant matters because the panel
        passes ``info.slugs`` directly into the function and that tuple
        carries a mix of cloud and SaaS slugs."""
        baseline = count_cloud_vendors(cloud)
        with_noise = count_cloud_vendors(cloud + noise)
        assert baseline == with_noise


class TestStreamUnionSemantics:
    @given(
        apex=st.lists(_cloud_slugs, min_size=0, max_size=6),
        surface=st.lists(_cloud_slugs, min_size=0, max_size=6),
    )
    def test_split_streams_match_concat(self, apex, surface):
        """The function merges apex and surface streams before
        counting. Splitting the same multiset across the two
        parameters must produce identical results to passing the
        concatenation as a single stream. This pins the merge
        semantics so a future refactor cannot quietly change them."""
        split = count_cloud_vendors(apex, surface)
        concat = count_cloud_vendors(apex + surface)
        assert split == concat


class TestVendorCountBounds:
    @given(slugs=st.lists(_cloud_slugs, min_size=1, max_size=20))
    def test_total_count_equals_input_length(self, slugs):
        """Every input slug is in the canonicalization map (sampled
        from its keys), so the sum of vendor counts must equal the
        input length. A future refactor that adds filtering or
        deduplication inside the function would break this and the
        property test would catch it immediately."""
        counts = count_cloud_vendors(slugs)
        assert sum(counts.values()) == len(slugs)

    @given(slugs=st.lists(_cloud_slugs, min_size=1, max_size=20))
    def test_vendor_count_at_most_unique_input_slugs(self, slugs):
        """Distinct vendor count cannot exceed the distinct input slug
        count, since canonicalization is a many-to-one map (e.g. AWS
        family of slugs collapses to one vendor). This bounds the
        upper end of the count regardless of inputs."""
        counts = count_cloud_vendors(slugs)
        assert len(counts) <= len(set(slugs))
