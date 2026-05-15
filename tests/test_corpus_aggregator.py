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
    _stratum_for_entry,
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


class TestStratumDerivation:
    """The aggregator buckets entries by the ``_stratum`` tag the
    synthetic-corpus generator injects (v1.9.11+). The previous
    tenant_id-substring matcher misbucketed brand-style fixtures like
    ``tailspin-firebase`` (GCP) and ``northwind-oci`` (Oracle), and a
    baseline fixture (``wingtip-azure``) was misbucketed into the
    Azure stratum because its tenant_id happened to contain the
    ``-az`` token. These tests pin the new derivation."""

    def test_explicit_stratum_tag_wins(self):
        entry = _make_dict(tenant_id="tailspin-firebase", _stratum="gcp")
        assert _stratum_for_entry(entry) == "gcp"

    def test_missing_tag_falls_back_to_baseline(self):
        entry = _make_dict(tenant_id="tailspin-firebase")
        assert _stratum_for_entry(entry) == "baseline"

    def test_invalid_tag_falls_back_to_baseline(self):
        entry = _make_dict(tenant_id="tailspin-firebase", _stratum="not-a-stratum")
        assert _stratum_for_entry(entry) == "baseline"

    def test_brand_style_oracle_tenant_id_no_longer_misbucketed(self):
        """``northwind-oci`` has no ``-oracle-`` substring; the
        previous matcher binned it under baseline. The new derivation
        reads the explicit tag emitted by the generator."""
        entry = _make_dict(tenant_id="northwind-oci", _stratum="oracle")
        assert _stratum_for_entry(entry) == "oracle"

    def test_baseline_with_azure_in_tenant_id_no_longer_misbucketed(self):
        """``wingtip-azure`` is a baseline fixture whose tenant_id
        coincidentally contains ``-az``. The previous matcher binned
        it under the Azure stratum; the new derivation reads the
        explicit tag (``baseline``)."""
        entry = _make_dict(tenant_id="wingtip-azure", _stratum="baseline")
        assert _stratum_for_entry(entry) == "baseline"


class TestPerStratumAggregation:
    """End-to-end: the aggregate output's ``per_stratum`` map respects
    the explicit ``_stratum`` tags on each entry."""

    def test_per_stratum_groups_by_explicit_tag(self):
        results = [
            _make_dict(tenant_id="contoso-mid", _stratum="baseline", slugs=["m365"]),
            _make_dict(tenant_id="contoso-gcp-pure", _stratum="gcp", slugs=["gcp-compute"]),
            _make_dict(tenant_id="northwind-oci", _stratum="oracle", slugs=["oracle-cloud"]),
            _make_dict(tenant_id="tailspin-firebase", _stratum="gcp", slugs=["gcp-firebase"]),
        ]
        agg = aggregate(results)
        per = agg["per_stratum"]
        assert per["baseline"]["counted"] == 1
        assert per["gcp"]["counted"] == 2  # both GCP fixtures bucket here, including the brand-style one
        assert per["oracle"]["counted"] == 1
