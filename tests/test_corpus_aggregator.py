"""Tests for the corpus-aggregator script.

The aggregator (``validation/corpus_aggregator.py``) mirrors the
trigger logic from ``render_tenant_panel`` so it can compute per-corpus
firing rates without re-running the renderer. Trigger logic that lives
in two places will drift unless the two are pinned to the same
fixtures.

These tests exercise the aggregator's pure-function entry points
(``_multi_cloud_fired``, ``_ceiling_fired``, ``_estimate_categorized_count``,
``aggregate``) against synthetic TenantInfo dicts. A failure here is
either an aggregator drift (the script changed but the renderer
didn't, or vice versa) or a fixture authoring bug.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from recon_tool.cache import tenant_info_from_dict
from validation.corpus_aggregator import (
    _ceiling_fired,
    _estimate_categorized_count,
    _multi_cloud_fired,
    aggregate,
)


def _make_dict(**overrides) -> dict:
    """Build a minimal TenantInfo dict suitable for the aggregator.

    The aggregator deserializes via ``tenant_info_from_dict``, which
    requires the three string fields documented in cache.py. Other
    fields default to the dataclass defaults if absent. Tests override
    only what they care about."""
    base = {
        "tenant_id": "tid",
        "display_name": "Contoso, Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": "high",
        "sources": [],
    }
    base.update(overrides)
    return base


class TestMultiCloudFired:
    def test_single_cloud_apex_does_not_fire(self):
        info = tenant_info_from_dict(_make_dict(slugs=["aws-cloudfront", "aws-route53"]))
        fired, count = _multi_cloud_fired(info)
        assert fired is False
        assert count == 1

    def test_two_distinct_vendors_fires(self):
        info = tenant_info_from_dict(_make_dict(slugs=["aws-cloudfront", "cloudflare"]))
        fired, count = _multi_cloud_fired(info)
        assert fired is True
        assert count == 2

    def test_three_distinct_vendors_fires(self):
        info = tenant_info_from_dict(_make_dict(slugs=["aws-cloudfront", "cloudflare", "gcp-compute"]))
        fired, count = _multi_cloud_fired(info)
        assert fired is True
        assert count == 3

    def test_non_cloud_slugs_do_not_count(self):
        info = tenant_info_from_dict(_make_dict(slugs=["slack", "okta", "auth0"]))
        fired, count = _multi_cloud_fired(info)
        assert fired is False
        assert count == 0

    def test_surface_attribution_slug_counts(self):
        """Surface attributions also contribute to vendor counts; the
        aggregator must merge both streams just like the renderer
        does."""
        info = tenant_info_from_dict(
            _make_dict(
                slugs=["aws-cloudfront"],
                surface_attributions=[
                    {
                        "subdomain": "api.contoso.com",
                        "primary_slug": "fastly",
                        "primary_name": "Fastly",
                        "primary_tier": "infrastructure",
                    }
                ],
            )
        )
        fired, count = _multi_cloud_fired(info)
        assert fired is True
        assert count == 2  # AWS + Fastly


class TestCeilingFired:
    def test_sparse_multi_domain_fires(self):
        info = tenant_info_from_dict(
            _make_dict(
                slugs=["m365"],
                services=["Microsoft 365"],
                domain_count=4,
                tenant_domains=["a.com", "b.com", "c.com", "d.com"],
            )
        )
        cat_count = _estimate_categorized_count(info)
        assert _ceiling_fired(info, cat_count) is True

    def test_single_domain_does_not_fire(self):
        info = tenant_info_from_dict(
            _make_dict(
                slugs=["m365"],
                services=["Microsoft 365"],
                domain_count=1,
                tenant_domains=["a.com"],
            )
        )
        cat_count = _estimate_categorized_count(info)
        assert _ceiling_fired(info, cat_count) is False

    def test_empty_services_does_not_fire(self):
        info = tenant_info_from_dict(_make_dict(domain_count=4))
        cat_count = _estimate_categorized_count(info)
        assert _ceiling_fired(info, cat_count) is False


class TestAggregateOverCorpus:
    def test_aggregate_emits_expected_shape(self):
        results = [
            _make_dict(slugs=["aws-cloudfront", "cloudflare"]),
            _make_dict(slugs=["aws-cloudfront"]),
            _make_dict(
                slugs=["m365"],
                services=["Microsoft 365"],
                domain_count=4,
                tenant_domains=["a.com", "b.com", "c.com", "d.com"],
            ),
        ]
        agg = aggregate(results)

        assert agg["corpus_size"] == 3
        assert agg["counted"] == 3
        assert agg["skipped_load_errors"] == 0

        # Two of three multi-cloud cases fired (the third has only m365)
        assert agg["multi_cloud"]["fired"] == 1
        assert agg["multi_cloud"]["suppressed"] == 2
        # One of three ceiling cases fired (the sparse multi-domain m365)
        assert agg["ceiling"]["fired"] == 1
        assert agg["ceiling"]["suppressed"] == 2

    def test_aggregate_handles_malformed_entries(self):
        results = [
            _make_dict(slugs=["aws-cloudfront", "cloudflare"]),
            {"display_name": None},  # missing required fields
        ]
        agg = aggregate(results)
        assert agg["corpus_size"] == 2
        assert agg["counted"] == 1
        assert agg["skipped_load_errors"] == 1

    def test_aggregate_output_is_json_serializable(self):
        """The output is intended to be written as JSON to a per-run
        artifact. The dict must be fully JSON-serializable; any
        non-serializable types (sets, tuples-as-keys, ...) would break
        the harness."""
        results = [_make_dict(slugs=["aws-cloudfront", "cloudflare"])]
        agg = aggregate(results)
        json.dumps(agg)  # Must not raise
