"""Tests for v1.9.1 conflict provenance on NodePosterior.

The v1.7 conflict-aware merger captures which sources disagreed on
which fields. Pre-v1.9.1, only the count of conflict-fields fed the
n_eff penalty; the source-pair detail was dropped before reaching the
posterior. v1.9.1 carries the structured detail through to
``NodePosterior.conflict_provenance`` so ``--explain-dag`` and the
``--json`` output can name the disagreeing sources.
"""

from __future__ import annotations

from dataclasses import replace

from recon_tool.bayesian import (
    ConflictProvenance,
    infer,
    infer_from_tenant_info,
    load_network,
)
from recon_tool.bayesian_dag import render_dag_dot, render_dag_text
from recon_tool.cache import _parse_posterior_observations, tenant_info_from_dict, tenant_info_to_dict
from recon_tool.formatter import format_tenant_dict
from recon_tool.models import (
    CandidateValue,
    MergeConflicts,
    NodeConflict,
    PosteriorObservation,
    TenantInfo,
)


def _bare_tenant_info(**overrides: object) -> TenantInfo:
    base = TenantInfo(
        tenant_id=None,
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        services=(),
        slugs=("microsoft365",),
        auth_type="Federated",
        dmarc_policy="reject",
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


class TestConflictProvenanceExtraction:
    def test_no_merge_conflicts_yields_empty_tuple(self) -> None:
        info = _bare_tenant_info()
        result = infer_from_tenant_info(info)
        for p in result.posteriors:
            assert p.conflict_provenance == ()

    def test_populated_when_merge_conflicts_present(self) -> None:
        conflicts = MergeConflicts(
            auth_type=(
                CandidateValue(value="Federated", source="graph", confidence="high"),
                CandidateValue(value="Managed", source="openid_config", confidence="medium"),
            ),
            dmarc_policy=(
                CandidateValue(value="reject", source="dns_txt", confidence="high"),
                CandidateValue(value="quarantine", source="report_uri", confidence="low"),
            ),
        )
        info = _bare_tenant_info(merge_conflicts=conflicts)
        result = infer_from_tenant_info(info)
        # Every node carries the same provenance — global penalty applied uniformly.
        for p in result.posteriors:
            assert len(p.conflict_provenance) == 2
            fields = {c.field for c in p.conflict_provenance}
            assert fields == {"auth_type", "dmarc_policy"}
            for c in p.conflict_provenance:
                assert c.magnitude > 0
                if c.field == "auth_type":
                    assert c.sources == ("graph", "openid_config")
                if c.field == "dmarc_policy":
                    assert c.sources == ("dns_txt", "report_uri")

    def test_dedupes_repeated_sources(self) -> None:
        conflicts = MergeConflicts(
            tenant_id=(
                CandidateValue(value="aaa-bbb", source="graph", confidence="high"),
                CandidateValue(value="ccc-ddd", source="graph", confidence="medium"),
                CandidateValue(value="eee-fff", source="openid_config", confidence="low"),
            ),
        )
        info = _bare_tenant_info(merge_conflicts=conflicts)
        result = infer_from_tenant_info(info)
        first = result.posteriors[0]
        assert len(first.conflict_provenance) == 1
        record = first.conflict_provenance[0]
        assert record.field == "tenant_id"
        assert record.sources == ("graph", "openid_config")


class TestConflictProvenanceInfer:
    def test_explicit_conflicts_overrides_count(self) -> None:
        net = load_network()
        cp = (ConflictProvenance(field="auth_type", sources=("a", "b"), magnitude=1.5),)
        result = infer(
            net,
            observed_slugs={"microsoft365"},
            observed_signals=set(),
            conflict_field_count=99,  # ignored when conflicts is non-empty
            conflicts=cp,
        )
        assert result.conflict_count == 1
        for p in result.posteriors:
            assert p.conflict_provenance == cp

    def test_count_path_yields_empty_provenance(self) -> None:
        net = load_network()
        result = infer(
            net,
            observed_slugs={"microsoft365"},
            observed_signals=set(),
            conflict_field_count=2,
        )
        assert result.conflict_count == 2
        for p in result.posteriors:
            assert p.conflict_provenance == ()


class TestSerialization:
    def _info_with_one_posterior(self) -> TenantInfo:
        po = PosteriorObservation(
            name="m365_tenant",
            description="Microsoft 365 tenant.",
            posterior=0.7,
            interval_low=0.4,
            interval_high=0.9,
            evidence_used=("slug:microsoft365",),
            n_eff=5.0,
            sparse=False,
            conflict_provenance=(
                NodeConflict(
                    field="auth_type",
                    sources=("graph", "openid_config"),
                    magnitude=1.5,
                ),
            ),
        )
        return _bare_tenant_info(posterior_observations=(po,))

    def test_json_shape(self) -> None:
        info = self._info_with_one_posterior()
        d = format_tenant_dict(info)
        po = d["posterior_observations"]
        assert len(po) == 1
        entry = po[0]
        assert "conflict_provenance" in entry
        cp = entry["conflict_provenance"]
        assert cp == [{"field": "auth_type", "sources": ["graph", "openid_config"], "magnitude": 1.5}]

    def test_json_empty_array_when_no_conflicts(self) -> None:
        po = PosteriorObservation(
            name="m365_tenant",
            description="Microsoft 365 tenant.",
            posterior=0.7,
            interval_low=0.4,
            interval_high=0.9,
            evidence_used=("slug:microsoft365",),
            n_eff=5.0,
            sparse=False,
        )
        info = _bare_tenant_info(posterior_observations=(po,))
        d = format_tenant_dict(info)
        assert d["posterior_observations"][0]["conflict_provenance"] == []

    def test_cache_round_trip(self) -> None:
        info = self._info_with_one_posterior()
        d = format_tenant_dict(info)
        parsed = _parse_posterior_observations(d)
        assert len(parsed) == 1
        assert parsed[0].conflict_provenance == (
            NodeConflict(field="auth_type", sources=("graph", "openid_config"), magnitude=1.5),
        )

    def test_cache_serializer_preserves_conflict_provenance(self) -> None:
        info = self._info_with_one_posterior()
        d = tenant_info_to_dict(info)
        assert d["posterior_observations"][0]["conflict_provenance"] == [
            {"field": "auth_type", "sources": ["graph", "openid_config"], "magnitude": 1.5}
        ]

        restored = tenant_info_from_dict(d)
        assert restored.posterior_observations[0].conflict_provenance == (
            NodeConflict(field="auth_type", sources=("graph", "openid_config"), magnitude=1.5),
        )

    def test_cache_round_trip_pre_v191_payload(self) -> None:
        """Old cache entries lack conflict_provenance; parse to empty tuple."""
        legacy = {
            "posterior_observations": [
                {
                    "name": "m365_tenant",
                    "description": "Microsoft 365 tenant.",
                    "posterior": 0.7,
                    "interval_low": 0.4,
                    "interval_high": 0.9,
                    "evidence_used": ["slug:microsoft365"],
                    "n_eff": 5.0,
                    "sparse": False,
                }
            ]
        }
        parsed = _parse_posterior_observations(legacy)
        assert len(parsed) == 1
        assert parsed[0].conflict_provenance == ()


class TestDagRendering:
    def _result_with_conflicts(self):
        net = load_network()
        cp = (ConflictProvenance(field="auth_type", sources=("graph", "openid_config"), magnitude=1.5),)
        result = infer(
            net,
            observed_slugs={"microsoft365"},
            observed_signals=set(),
            conflicts=cp,
        )
        return net, result

    def test_text_renderer_surfaces_conflicts(self) -> None:
        net, result = self._result_with_conflicts()
        out = render_dag_text(net, result, domain="contoso.com")
        assert "**Conflicts:**" in out
        assert "auth_type" in out
        assert "graph vs openid_config" in out

    def test_text_renderer_omits_conflict_line_when_clean(self) -> None:
        net = load_network()
        result = infer(
            net,
            observed_slugs={"microsoft365"},
            observed_signals=set(),
        )
        out = render_dag_text(net, result, domain="contoso.com")
        assert "**Conflicts:**" not in out

    def test_dot_renderer_annotates_conflicts(self) -> None:
        net, result = self._result_with_conflicts()
        out = render_dag_dot(net, result, domain="contoso.com")
        assert "conflicts: auth_type" in out
