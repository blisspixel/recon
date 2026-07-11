"""Pin the posture-distribution harness's pure logic.

`validation/posture_distributions.py` reads the engine's per-domain
behaviour as posture-stratified distributions (information recovered;
interval width vs evidence). The orchestration is maintainer-local; the
classification and aggregation are pure functions pinned here with
synthetic records (no network, no apex).
"""

from __future__ import annotations

import asyncio

import pytest

from validation import posture_distributions as posture
from validation.posture_distributions import (
    DomainRecord,
    NodeWidthRecord,
    edge_posture,
    entropy_by_posture,
    evidence_tier,
    neff_bucket,
    quantiles,
    width_by_evidence,
)


class TestEdgePosture:
    def test_threshold(self) -> None:
        assert edge_posture(0.5) == "edge-proxied"
        assert edge_posture(0.9) == "edge-proxied"
        assert edge_posture(0.49) == "direct"
        assert edge_posture(0.0) == "direct"

    def test_missing_is_direct(self) -> None:
        assert edge_posture(None) == "direct"


class TestEvidenceTier:
    @pytest.mark.parametrize(
        ("count", "tier"),
        [(0, "sparse"), (2, "sparse"), (3, "moderate"), (6, "moderate"), (7, "rich"), (20, "rich")],
    )
    def test_tiers(self, count: int, tier: str) -> None:
        assert evidence_tier(count) == tier


class TestNeffBucket:
    @pytest.mark.parametrize(
        ("n_eff", "label"),
        [
            (4.0, "floor (<=4)"),
            (3.0, "floor (<=4)"),
            (5.0, "5-6"),
            (6.0, "5-6"),
            (7.0, "7-9"),
            (9.0, "7-9"),
            (10.0, "10+"),
            (14.0, "10+"),
        ],
    )
    def test_buckets(self, n_eff: float, label: str) -> None:
        assert neff_bucket(n_eff) == label


class TestQuantiles:
    def test_empty_is_zeros(self) -> None:
        assert quantiles([]) == (0.0, 0.0, 0.0)

    def test_single(self) -> None:
        assert quantiles([0.7]) == (0.7, 0.7, 0.7)

    def test_interpolates(self) -> None:
        p25, p50, p75 = quantiles([0.0, 1.0, 2.0, 3.0, 4.0])
        assert (p25, p50, p75) == (1.0, 2.0, 3.0)


class TestEntropyByPosture:
    def test_buckets_and_overall(self) -> None:
        records = [
            DomainRecord(entropy_reduction=1.0, edge="edge-proxied", tier="sparse"),
            DomainRecord(entropy_reduction=2.0, edge="direct", tier="rich"),
            DomainRecord(entropy_reduction=3.0, edge="direct", tier="rich"),
        ]
        out = entropy_by_posture(records)
        assert out["n"] == 3
        assert out["overall_quartiles"][1] == 2.0  # median of {1,2,3}
        assert out["buckets"]["edge-proxied / sparse"]["n"] == 1
        assert out["buckets"]["direct / rich"]["n"] == 2
        # The "(all tiers)" rollup must aggregate both direct records.
        assert out["buckets"]["direct (all tiers)"]["n"] == 2

    def test_empty(self) -> None:
        out = entropy_by_posture([])
        assert out["n"] == 0
        assert out["overall_quartiles"] == (0.0, 0.0, 0.0)


class TestWidthByEvidence:
    def test_separates_grouped_and_bucketed(self) -> None:
        records = [
            NodeWidthRecord(node="m365_tenant", grouped=True, n_eff=4.0, width=0.30),
            NodeWidthRecord(node="m365_tenant", grouped=True, n_eff=8.0, width=0.10),
            NodeWidthRecord(node="cdn_fronting", grouped=False, n_eff=4.0, width=0.40),
        ]
        out = width_by_evidence(records)
        assert out["grouped"]["floor (<=4)"]["mean_width"] == 0.30
        assert out["grouped"]["7-9"]["mean_width"] == 0.10
        assert out["ungrouped"]["floor (<=4)"]["mean_width"] == 0.40
        # No ungrouped observation landed in the 7-9 bucket.
        assert "7-9" not in out["ungrouped"]

    def test_width_falls_with_evidence(self) -> None:
        # A concrete descriptive sample, not a general monotonicity proof.
        records = [
            NodeWidthRecord(node="x", grouped=False, n_eff=4.0, width=0.5),
            NodeWidthRecord(node="x", grouped=False, n_eff=4.0, width=0.5),
            NodeWidthRecord(node="x", grouped=False, n_eff=12.0, width=0.1),
        ]
        out = width_by_evidence(records)
        floor = out["ungrouped"]["floor (<=4)"]["mean_width"]
        rich = out["ungrouped"]["10+"]["mean_width"]
        assert floor > rich

    def test_empty(self) -> None:
        out = width_by_evidence([])
        assert out == {"ungrouped": {}, "grouped": {}}


def test_posture_collector_cannot_load_user_local_priors(monkeypatch) -> None:
    import recon_tool.bayesian as bayesian
    import recon_tool.resolver as resolver
    from recon_tool.merger import merge_results
    from recon_tool.models import SourceResult

    dns = SourceResult(source_name="dns_records")
    info = merge_results([dns], "example.test")

    def _fail_if_loaded():
        raise AssertionError("validation attempted to load user-local priors")

    async def _resolve(_domain: str, *, timeout: float, skip_ct: bool):
        del timeout, skip_ct
        return info, [dns]

    monkeypatch.setattr(bayesian, "load_priors_override", _fail_if_loaded)
    monkeypatch.setattr(resolver, "resolve_tenant", _resolve)
    result = asyncio.run(
        posture._collect_one(
            "example.test",
            timeout=1.0,
            sem=asyncio.Semaphore(1),
        )
    )
    assert result is not None
    domain_record, width_records = result
    assert domain_record.tier == "sparse"
    assert width_records
