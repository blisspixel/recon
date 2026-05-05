"""Integration tests for the v1.9 --fusion + posterior_observations path."""

from __future__ import annotations

from dataclasses import replace

import pytest

from recon_tool.bayesian import infer_from_tenant_info
from recon_tool.bayesian_dag import render_dag_dot, render_dag_text
from recon_tool.formatter import format_tenant_dict
from recon_tool.models import EvidenceRecord, PosteriorObservation, TenantInfo


def _make_tenant_info(
    slugs: tuple[str, ...] = (),
    auth_type: str | None = None,
    dmarc_policy: str | None = None,
    evidence: tuple[EvidenceRecord, ...] = (),
) -> TenantInfo:
    return TenantInfo(
        tenant_id=None,
        display_name="Contoso",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        services=(),
        slugs=slugs,
        auth_type=auth_type,
        dmarc_policy=dmarc_policy,
        evidence=evidence,
    )


class TestPosteriorObservationsInJson:
    def test_field_present_when_populated(self) -> None:
        info = _make_tenant_info(slugs=("microsoft365",))
        result = infer_from_tenant_info(info)
        observations = tuple(
            PosteriorObservation(
                name=p.name,
                description=p.description,
                posterior=p.posterior,
                interval_low=p.interval_low,
                interval_high=p.interval_high,
                evidence_used=p.evidence_used,
                n_eff=p.n_eff,
                sparse=p.sparse,
            )
            for p in result.posteriors
        )
        info = replace(info, posterior_observations=observations)
        d = format_tenant_dict(info)
        assert "posterior_observations" in d
        # Must serialize to a list of dicts with the expected keys.
        po = d["posterior_observations"]
        assert isinstance(po, list)
        assert len(po) == len(result.posteriors)
        for entry in po:
            assert {
                "name",
                "description",
                "posterior",
                "interval_low",
                "interval_high",
                "evidence_used",
                "n_eff",
                "sparse",
            }.issubset(entry.keys())

    def test_empty_when_fusion_off(self) -> None:
        info = _make_tenant_info(slugs=("microsoft365",))
        # No posterior_observations populated → empty list in JSON.
        d = format_tenant_dict(info)
        assert d["posterior_observations"] == []


class TestEndToEndAdapter:
    def test_dense_evidence_collapses_m365(self) -> None:
        info = _make_tenant_info(
            slugs=("microsoft365", "entra-id", "exchange-online"),
            auth_type="Federated",
        )
        result = infer_from_tenant_info(info)
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        assert m365.posterior > 0.95
        assert not m365.sparse

    def test_no_m365_evidence_keeps_prior(self) -> None:
        info = _make_tenant_info()
        result = infer_from_tenant_info(info)
        m365 = next(p for p in result.posteriors if p.name == "m365_tenant")
        # Prior in shipped network is 0.30
        assert abs(m365.posterior - 0.30) < 0.01
        assert m365.sparse

    def test_dag_text_renders_for_real_tenant_info(self) -> None:
        info = _make_tenant_info(
            slugs=("microsoft365", "okta"),
            auth_type="Federated",
            dmarc_policy="reject",
        )
        result = infer_from_tenant_info(info)
        from recon_tool.bayesian import load_network

        out = render_dag_text(load_network(), result, domain="contoso.com")
        assert "## m365_tenant" in out
        assert "## okta_idp" in out
        assert "contoso.com" in out

    def test_dag_dot_renders_for_real_tenant_info(self) -> None:
        info = _make_tenant_info(slugs=("microsoft365",))
        result = infer_from_tenant_info(info)
        from recon_tool.bayesian import load_network

        out = render_dag_dot(load_network(), result, domain="contoso.com")
        assert out.startswith("digraph")
        assert '"m365_tenant"' in out


class TestPosteriorObservationDataclass:
    def test_construction(self) -> None:
        po = PosteriorObservation(
            name="x",
            description="y",
            posterior=0.5,
            interval_low=0.1,
            interval_high=0.9,
            evidence_used=("slug:foo",),
            n_eff=4.0,
            sparse=True,
        )
        assert po.name == "x"
        assert po.posterior == 0.5
        assert po.evidence_used == ("slug:foo",)

    def test_frozen(self) -> None:
        po = PosteriorObservation(
            name="x",
            description="y",
            posterior=0.5,
            interval_low=0.1,
            interval_high=0.9,
            evidence_used=(),
            n_eff=4.0,
            sparse=True,
        )
        with pytest.raises((AttributeError, Exception)):
            po.posterior = 0.7  # type: ignore[misc]
