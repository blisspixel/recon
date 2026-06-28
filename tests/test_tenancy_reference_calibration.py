"""Pin the tenancy-reference-calibration harness's pure logic.

`validation/tenancy_reference_calibration.py` compares the M365 tenancy
posterior (DNS channel only) against the provider's own identity-endpoint
attestation as channel-split corroboration, and reports a one-sided recall check
for GWS. The network
orchestration is maintainer-local; the label derivation, the channel
split, and the aggregation are pure functions pinned here with synthetic
SourceResults (no network, no real apex — fictional brands only).
"""

from __future__ import annotations

import json

import pytest

from recon_tool.models import SourceResult
from validation import tenancy_reference_calibration as tenancy
from validation.tenancy_reference_calibration import (
    CONFLICT,
    NEGATIVE,
    POSITIVE,
    UNLABELED,
    TenancyCounts,
    TenancyRecord,
    dns_only_tenancy_posteriors,
    gws_attested_federated,
    gws_attested_posteriors,
    m365_calibration_records,
    m365_reference_label,
    main,
    one_sided_recall_summary,
    percentile,
)


class TestM365ReferenceLabel:
    def test_oidc_tenant_id_is_positive(self) -> None:
        assert m365_reference_label("a1b2c3d4-e5f6-7890-abcd-ef1234567890", None, None) == POSITIVE

    @pytest.mark.parametrize("namespace", ["Managed", "Federated", "managed", "  FEDERATED  "])
    def test_realm_namespace_is_positive(self, namespace: str) -> None:
        assert m365_reference_label(None, None, namespace) == POSITIVE

    def test_oidc_http_400_is_negative(self) -> None:
        assert m365_reference_label(None, "HTTP 400 from OIDC discovery endpoint", None) == NEGATIVE

    @pytest.mark.parametrize("namespace", ["Unknown", "unknown", " UNKNOWN "])
    def test_realm_unknown_is_negative(self, namespace: str) -> None:
        assert m365_reference_label(None, None, namespace) == NEGATIVE

    def test_transient_oidc_error_carries_no_label(self) -> None:
        # A 5xx or network error is not the tenant-not-found response; it
        # must yield no label rather than a guessed negative.
        assert m365_reference_label(None, "HTTP 503 from OIDC discovery endpoint", None) == UNLABELED
        network_error = "Network error querying OIDC discovery endpoint after retries: x"
        assert m365_reference_label(None, network_error, None) == UNLABELED

    def test_nothing_observed_is_unlabeled(self) -> None:
        assert m365_reference_label(None, None, None) == UNLABELED
        assert m365_reference_label(None, None, "") == UNLABELED

    def test_disagreeing_channels_are_conflict_not_a_guess(self) -> None:
        # OIDC resolved a tenant but GetUserRealm says Unknown (or the
        # reverse): excluded and counted, never silently resolved.
        assert m365_reference_label("a1b2c3d4-e5f6-7890-abcd-ef1234567890", None, "Unknown") == CONFLICT
        assert m365_reference_label(None, "HTTP 400 from OIDC discovery endpoint", "Managed") == CONFLICT


class TestGwsAttestation:
    def test_federated_is_attested(self) -> None:
        assert gws_attested_federated("Federated") is True
        assert gws_attested_federated("  federated ") is True

    def test_anything_else_is_not(self) -> None:
        # The channel has no authoritative negative and no managed
        # detection, so only the federated redirect counts.
        assert gws_attested_federated("Managed") is False
        assert gws_attested_federated(None) is False
        assert gws_attested_federated("") is False


class TestDnsOnlyPosteriors:
    def test_m365_dns_footprint_raises_the_posterior(self) -> None:
        dns = SourceResult(
            source_name="dns_records",
            detected_services=("Microsoft 365", "Exchange Online"),
            detected_slugs=("microsoft365", "exchange-online"),
        )
        pair = dns_only_tenancy_posteriors([dns], "contoso.com", priors_override={})
        assert pair is not None
        m365, gws = pair
        assert m365 > 0.9  # strong DNS evidence
        assert gws < 0.5  # no GWS evidence; stays near its prior

    def test_no_footprint_yields_the_priors(self) -> None:
        # "We looked and found nothing" must stay in the calibration as a
        # near-prior predictor, or the negative stratum is biased away.
        dns = SourceResult(source_name="dns_records")
        pair = dns_only_tenancy_posteriors([dns], "contoso.com", priors_override={})
        assert pair is not None
        m365, gws = pair
        assert m365 == pytest.approx(0.30, abs=1e-2)
        assert gws == pytest.approx(0.25, abs=1e-2)

    def test_endpoint_evidence_is_excluded_from_the_predictor(self) -> None:
        # The channel split is the design: an OIDC result attesting the
        # tenant (and firing the microsoft365 slug) must not move the
        # DNS-only predictor at all.
        dns = SourceResult(source_name="dns_records")
        oidc = SourceResult(
            source_name="oidc_discovery",
            tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            detected_slugs=("microsoft365",),
        )
        realm = SourceResult(source_name="user_realm", auth_type="Managed", m365_detected=True)
        with_endpoints = dns_only_tenancy_posteriors([dns, oidc, realm], "contoso.com", priors_override={})
        without_endpoints = dns_only_tenancy_posteriors([dns], "contoso.com", priors_override={})
        assert with_endpoints == without_endpoints

    def test_no_dns_channel_returns_none(self) -> None:
        oidc = SourceResult(source_name="oidc_discovery", tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert dns_only_tenancy_posteriors([oidc], "contoso.com", priors_override={}) is None

    def test_errored_dns_channel_returns_none(self) -> None:
        dns = SourceResult(source_name="dns_records", error="timeout")
        assert dns_only_tenancy_posteriors([dns], "contoso.com", priors_override={}) is None


class TestPercentile:
    def test_single_value(self) -> None:
        assert percentile([0.4], 0.5) == 0.4

    def test_interpolates(self) -> None:
        assert percentile([0.0, 1.0], 0.5) == pytest.approx(0.5)
        assert percentile([0.3, 0.8, 0.9], 0.25) == pytest.approx(0.55)
        assert percentile([0.3, 0.8, 0.9], 0.75) == pytest.approx(0.85)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            percentile([], 0.5)


class TestOneSidedRecallSummary:
    def test_empty_is_n_zero(self) -> None:
        assert one_sided_recall_summary([]) == {"n": 0}

    def test_recall_and_quartiles(self) -> None:
        s = one_sided_recall_summary([0.9, 0.8, 0.3])
        assert s["n"] == 3
        assert s["recall"] == pytest.approx(0.6667, abs=1e-4)
        assert s["posterior_quartiles"] == (
            pytest.approx(0.55),
            pytest.approx(0.8),
            pytest.approx(0.85),
        )
        lo, hi = s["recall_wilson80"]  # type: ignore[misc]
        assert 0.0 <= lo <= s["recall"] <= hi <= 1.0


def _record(
    disposition: str,
    dns_only: float | None = 0.7,
    full: float | None = 0.9,
    gws_attested: bool = False,
    gws_dns_only: float | None = None,
) -> TenancyRecord:
    return TenancyRecord(
        m365_disposition=disposition,
        m365_dns_only=dns_only,
        m365_full=full,
        gws_attested=gws_attested,
        gws_dns_only=gws_dns_only,
    )


class TestRecordSelection:
    def test_only_labeled_records_calibrate(self) -> None:
        records = [
            _record(POSITIVE),
            _record(NEGATIVE, dns_only=0.2),
            _record(UNLABELED),
            _record(CONFLICT),
        ]
        cal = m365_calibration_records(records, full_pipeline=False)
        assert [(c.posterior, c.label) for c in cal] == [(0.7, 1), (0.2, 0)]

    def test_full_pipeline_switch_selects_the_other_posterior(self) -> None:
        records = [_record(POSITIVE, dns_only=0.6, full=0.95)]
        assert m365_calibration_records(records, full_pipeline=True)[0].posterior == 0.95
        assert m365_calibration_records(records, full_pipeline=False)[0].posterior == 0.6

    def test_missing_dns_posterior_is_skipped(self) -> None:
        records = [_record(POSITIVE, dns_only=None)]
        assert m365_calibration_records(records, full_pipeline=False) == []

    def test_gws_attested_posteriors_filter(self) -> None:
        records = [
            _record(UNLABELED, gws_attested=True, gws_dns_only=0.8),
            _record(UNLABELED, gws_attested=True, gws_dns_only=None),
            _record(UNLABELED, gws_attested=False, gws_dns_only=0.9),
        ]
        assert gws_attested_posteriors(records) == [0.8]


class TestJsonMain:
    """Pin the --json orchestration (the cross-list / PV2-drift surface).

    main()'s glue is otherwise only exercised by a live run; this monkeypatches
    the collector so no network or real apex is touched, and asserts the
    structured output is one valid JSON object carrying the DNS-only
    corroboration, the full-pipeline consistency block, and the one-sided GWS
    check — aggregates only.
    """

    @staticmethod
    def _records() -> list[TenancyRecord]:
        out: list[TenancyRecord] = []
        for i in range(20):
            disp = POSITIVE if i % 2 else NEGATIVE
            out.append(
                _record(
                    disp,
                    dns_only=0.9 if i % 2 else 0.1,
                    full=0.95 if i % 2 else 0.05,
                    gws_attested=(i % 5 == 0),
                    gws_dns_only=0.8 if i % 5 == 0 else None,
                )
            )
        return out

    def _patch_collect(self, monkeypatch) -> None:
        records = self._records()

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency, label="resolving"):
            return records, TenancyCounts(resolved=len(records))

        monkeypatch.setattr(tenancy, "collect", _fake_collect)

    def test_single_json_is_parseable_aggregate(self, tmp_path, monkeypatch, capsys) -> None:
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\nfabrikam.com\n", encoding="utf-8")
        self._patch_collect(monkeypatch)
        rc = main([str(domains_file), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert doc["mode"] == "single"
        assert doc["m365_dns_only"]["n"] == 20
        assert doc["m365_full"]["n"] == 20
        assert doc["gws_one_sided"]["n"] == 4
        assert "counts" in doc
        assert "contoso" not in out
        assert "fabrikam" not in out

    def test_single_json_full_block_independent_of_dns_block(self, tmp_path, monkeypatch, capsys) -> None:
        # Regression: m365_full must be gated on its OWN records, not on the
        # DNS-only list. When the DNS channel failed for every labeled domain
        # (m365_dns_only is None) but the full pipeline produced posteriors, the
        # JSON must still report m365_full, not silently drop it to n=0.
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("contoso.com\n", encoding="utf-8")
        records = [
            _record(POSITIVE if i % 2 else NEGATIVE, dns_only=None, full=0.95 if i % 2 else 0.05)
            for i in range(12)
        ]

        async def _fake_collect(domains, *, timeout, skip_ct, concurrency, label="resolving"):
            return records, TenancyCounts(resolved=len(records))

        monkeypatch.setattr(tenancy, "collect", _fake_collect)
        rc = main([str(domains_file), "--json"])
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["m365_dns_only"] == {"n": 0}  # DNS channel failed for all
        assert doc["m365_full"]["n"] == 12  # full pipeline still calibrated

    def test_stratified_json_carries_dns_and_gws(self, tmp_path, monkeypatch, capsys) -> None:
        (tmp_path / "alpha.txt").write_text("contoso.com\n", encoding="utf-8")
        (tmp_path / "beta.txt").write_text("fabrikam.com\n", encoding="utf-8")
        self._patch_collect(monkeypatch)
        rc = main(["--stratify-dir", str(tmp_path), "--json"])
        assert rc == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["mode"] == "stratified"
        assert doc["m365_dns_only"]["pooled"]["n"] == 40
        assert set(doc["m365_dns_only"]["strata"]) == {"alpha", "beta"}
        assert "gws_one_sided" in doc
