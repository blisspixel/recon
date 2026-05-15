"""v1.9.9 — cloud-vendor canonicalization coverage gap test.

The multi-cloud rollup relies on ``_CLOUD_VENDOR_BY_SLUG`` to collapse
sibling slugs to a single vendor identity. When the catalog grows a new
cloud-categorized slug, that decision needs to be made deliberately:
either the slug rolls up to an existing vendor (e.g. a new AWS service
joins the AWS family), or it is excluded from the rollup with a stated
reason (SaaS hosting, prototyping platform, specialty CDN).

This test enforces the decision at PR time. Every slug categorized as
``"Cloud"`` in ``_CATEGORY_BY_SLUG`` must appear in either
``_CLOUD_VENDOR_BY_SLUG`` or ``_CLOUD_VENDOR_ROLLUP_EXCLUSIONS``. A slug
that is in neither would silently miss the rollup, producing one of two
failure modes: a multi-cloud apex that the rollup undercounts (slug is
genuinely a cloud vendor but absent from the map), or a single-cloud
apex that gets a misleading Multi-cloud line (rare; would require an
exclusion-set slug to slip into the map). The test catches both.
"""

from __future__ import annotations

from recon_tool.formatter import (
    _CATEGORY_BY_SLUG,
    _CLOUD_VENDOR_BY_SLUG,
    _CLOUD_VENDOR_ROLLUP_EXCLUSIONS,
    _SERVICE_CATEGORIES_ORDER,
)


def _cloud_categorized_slugs() -> set[str]:
    return {slug for slug, cat in _CATEGORY_BY_SLUG.items() if cat == "Cloud"}


class TestCoverageGap:
    def test_every_cloud_slug_has_a_rollup_decision(self):
        """Each ``"Cloud"`` slug in ``_CATEGORY_BY_SLUG`` is either
        mapped to a vendor in ``_CLOUD_VENDOR_BY_SLUG`` or explicitly
        excluded in ``_CLOUD_VENDOR_ROLLUP_EXCLUSIONS``. No silent
        omissions."""
        cloud_slugs = _cloud_categorized_slugs()
        decided = set(_CLOUD_VENDOR_BY_SLUG.keys()) | _CLOUD_VENDOR_ROLLUP_EXCLUSIONS
        undecided = cloud_slugs - decided
        assert not undecided, (
            f"Cloud-categorized slugs without a rollup decision: {sorted(undecided)}. "
            f"Each must either be added to _CLOUD_VENDOR_BY_SLUG (when it represents a "
            f"cloud vendor for rollup purposes) or to _CLOUD_VENDOR_ROLLUP_EXCLUSIONS "
            f"(when it is SaaS hosting, a prototyping platform, or a long-tail specialty "
            f"vendor that does not belong in an at-a-glance multi-cloud summary)."
        )

    def test_map_and_exclusion_set_are_disjoint(self):
        """A slug cannot both map to a vendor AND be excluded — that
        would mean two contradictory decisions in the same file. The
        coverage test would still pass on the union, so we assert
        disjointness separately."""
        overlap = set(_CLOUD_VENDOR_BY_SLUG.keys()) & _CLOUD_VENDOR_ROLLUP_EXCLUSIONS
        assert not overlap, (
            f"Slugs in BOTH the rollup map and the exclusion set (a slug cannot have "
            f"two contradictory rollup decisions): {sorted(overlap)}"
        )

    def test_exclusion_set_entries_are_cloud_categorized(self):
        """An exclusion entry only matters when the slug is actually
        cloud-categorized; otherwise it is dead weight. The exclusion
        set is for resolving the rollup decision for cloud slugs we
        chose not to count, not for arbitrary slugs."""
        cloud_slugs = _cloud_categorized_slugs()
        non_cloud_in_exclusions = _CLOUD_VENDOR_ROLLUP_EXCLUSIONS - cloud_slugs
        assert not non_cloud_in_exclusions, (
            f"Exclusion-set entries that are not Cloud-categorized in _CATEGORY_BY_SLUG: "
            f"{sorted(non_cloud_in_exclusions)}. Remove them — the exclusion set is "
            f"specifically for cloud slugs we chose not to roll up."
        )

    def test_map_entries_are_cloud_categorized(self):
        """A vendor-map entry for a slug that is not cloud-categorized
        would never fire in practice (the rollup pulls from cloud-tier
        slugs only). Dead-weight entries hide intent; assert the map
        stays consistent with ``_CATEGORY_BY_SLUG``."""
        cloud_slugs = _cloud_categorized_slugs()
        non_cloud_in_map = set(_CLOUD_VENDOR_BY_SLUG.keys()) - cloud_slugs
        assert not non_cloud_in_map, (
            f"Vendor-map entries for slugs that are not Cloud-categorized: "
            f"{sorted(non_cloud_in_map)}. Either fix the category in _CATEGORY_BY_SLUG "
            f"or remove the slug from _CLOUD_VENDOR_BY_SLUG."
        )


class TestCategoryOrderCoversAllUsedCategories:
    """A category that appears in ``_CATEGORY_BY_SLUG`` but not in
    ``_SERVICE_CATEGORIES_ORDER`` would crash the panel renderer at
    ``by_cat[cat].append(...)``. The renderer has a defensive guard
    (added v1.9.9) that adds the bucket on the fly so the panel does
    not crash, but the category will not appear in the rendered panel
    in its expected position until added to the order tuple.

    This test exists to catch the drift at PR time so a contributor
    adding a new category-valued slug remembers to extend the order
    tuple. The bug it catches: ``looker-studio`` shipped in v1.9.3.9
    with category ``"Data & Analytics"`` but the category was never
    added to the order tuple, leaving any apex with the slug to crash
    the renderer. v1.9.9 added the missing entry and this test pins
    the invariant going forward."""

    def test_every_used_category_is_in_the_order_tuple(self):
        used = set(_CATEGORY_BY_SLUG.values())
        ordered = set(_SERVICE_CATEGORIES_ORDER)
        missing = used - ordered
        assert not missing, (
            f"Categories used in _CATEGORY_BY_SLUG but missing from "
            f"_SERVICE_CATEGORIES_ORDER: {sorted(missing)}. Add them "
            f"to the order tuple or the renderer will silently drop "
            f"the bucket from the displayed panel order."
        )
