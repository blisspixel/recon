"""Invariant: every new fingerprint slug has an explicit category.

The v1.9.x catalog grew faster than ``recon_tool.formatter._CATEGORY_BY_SLUG``,
so a long tail of legacy slugs falls through to the "Business Apps"
default in ``_categorize_service``. That is correct for many of them
(Salesforce, ServiceNow, Shopify) but it was wrong for the 28 new
slugs the v2.0-prep catalog-growth scan added (datadog, snowflake,
sentry, aws-region-endpoint, etc.) until v1.9.11 mapped them
explicitly.

This test pins the current legacy fall-through set so a future PR
that ships a new slug without an explicit ``_CATEGORY_BY_SLUG``
mapping fails CI rather than silently bucketing under Business Apps.
The frozen set is intentionally large (~75 entries today) and the
expected direction is for it to *shrink* over time as legacy slugs
get explicit categories. New additions to the set require a
deliberate decision: either category the slug, or admit it falls
through and add it to ``EXPECTED_BUSINESS_APPS_FALLBACK`` below.

Update procedure when this test fails:

1. If you added a new slug whose user-facing category is unambiguous
   (CDN, observability, IdP, etc.): add it to
   ``_CATEGORY_BY_SLUG`` in ``recon_tool/formatter.py``. For Cloud-
   categorized slugs, also add a rollup decision (see
   ``tests/test_cloud_vendor_coverage.py``).
2. If you added a new slug whose user-facing category is genuinely
   "Business Apps" (SaaS that doesn't fit any other bucket): add the
   slug to ``EXPECTED_BUSINESS_APPS_FALLBACK`` below with a brief
   reason in the inline comment or the commit message.
3. If you removed or renamed an existing slug: remove the
   corresponding entry from ``EXPECTED_BUSINESS_APPS_FALLBACK``.
"""

from __future__ import annotations

from recon_tool.fingerprints import load_fingerprints
from recon_tool.formatter import _CATEGORY_BY_SLUG

# Slugs that intentionally fall through to "Business Apps" via the
# pass-2 service-name fallback in ``_categorize_service``. Most are
# generic SaaS that don't fit Cloud/Email/Identity/Security/AI/
# Data & Analytics/Collaboration. A few are ambiguous (twilio could
# be Cloud or Business Apps; zendesk could be Collaboration); we
# accept Business Apps as the conservative default and keep the test
# narrow on what we know.
EXPECTED_BUSINESS_APPS_FALLBACK: frozenset[str] = frozenset(
    {
        "6sense",
        "adobe-idp",
        "adobe-sign",
        "apollo",
        "apple",
        "attentive",
        "autodesk",
        "beautifulai",
        "branchio",
        "braze",
        "citrix",
        "clearbit",
        "cloudhealth",
        "coherent-path",
        "contentful",
        "customerio",
        "deel",
        "dell",
        "demandbase",
        "docusign",
        "drift",
        "dyn",
        "freshdesk",
        "ghost",
        "glean",
        "godaddy",
        "gong",
        "google-site",
        "grammarly",
        "hotjar",
        "hubspot",
        "iterable",
        "joopbox",
        "klaviyo",
        "launchdarkly",
        "liveramp",
        "loop-returns",
        "lucidlink",
        "marketo",
        "meta",
        "optimizely",
        "outreach",
        "pantheon",
        "postman",
        "prismic",
        "qualtrics",
        "redfin",
        "rippling",
        "salesforce",
        "salesforce-mc",
        "salesloft",
        "sanity",
        "sap",
        "sendcloud",
        "servicenow",
        "shopify",
        "sina",
        "smartsheet",
        "splitio",
        "squarespace",
        "statsig",
        "stripe",
        "tls-rpt",
        "twilio",
        "ukg",
        "unity",
        "walkme",
        "webex",
        "wix",
        "workday",
        "workplace-meta",
        "workspace-one",
        "wrike",
        "yandex",
        "zendesk",
    }
)


def _catalog_slugs() -> set[str]:
    return {fp.slug for fp in load_fingerprints()}


def test_every_catalog_slug_is_either_mapped_or_an_expected_fallback() -> None:
    """No new slug may ship without an explicit categorization decision.

    Every slug in the catalog must either appear in
    ``_CATEGORY_BY_SLUG`` (explicit user-facing category) or in
    ``EXPECTED_BUSINESS_APPS_FALLBACK`` (deliberate fallback). A slug
    that is in neither would silently bucket under "Business Apps" —
    correct for generic SaaS, wrong for CDNs / observability / IdPs.

    This is the same shape of bug the v2.0-prep 28-slug fix addressed.
    """
    catalog = _catalog_slugs()
    mapped = set(_CATEGORY_BY_SLUG.keys())
    accounted_for = mapped | EXPECTED_BUSINESS_APPS_FALLBACK
    unaccounted = sorted(catalog - accounted_for)
    assert not unaccounted, (
        f"New slugs missing both an explicit _CATEGORY_BY_SLUG entry and an "
        f"EXPECTED_BUSINESS_APPS_FALLBACK entry: {unaccounted}. "
        "These will fall through to the Business Apps default in the panel, "
        "which is wrong for CDN/observability/IdP-shaped slugs. "
        "See the docstring in tests/test_slug_category_invariant.py for the "
        "update procedure."
    )


def test_expected_fallback_entries_are_real_catalog_slugs() -> None:
    """A fallback entry only matters when the slug exists. A stale
    fallback entry (slug was renamed or removed) is dead weight and
    hides intent."""
    catalog = _catalog_slugs()
    stale = sorted(EXPECTED_BUSINESS_APPS_FALLBACK - catalog)
    assert not stale, (
        f"EXPECTED_BUSINESS_APPS_FALLBACK entries that no longer match any catalog slug: "
        f"{stale}. Remove them — the fallback set is specifically for live slugs."
    )


def test_mapped_and_fallback_sets_are_disjoint() -> None:
    """A slug cannot be both 'explicit mapping' and 'expected to fall
    through' — that's two contradictory decisions. Drift between
    ``_CATEGORY_BY_SLUG`` and the fallback set is caught here so the
    two stay in sync."""
    overlap = sorted(set(_CATEGORY_BY_SLUG.keys()) & EXPECTED_BUSINESS_APPS_FALLBACK)
    assert not overlap, (
        f"Slugs in BOTH _CATEGORY_BY_SLUG and EXPECTED_BUSINESS_APPS_FALLBACK "
        f"(contradictory decisions): {overlap}"
    )
