"""Tests for the delta engine."""

import json
from pathlib import Path

import pytest

from recon_tool.cache import tenant_info_to_dict
from recon_tool.constants import SVC_DMARC, SVC_SPF_STRICT
from recon_tool.delta import compute_delta, load_previous
from recon_tool.formatter_serialize import format_tenant_dict
from recon_tool.models import ConfidenceLevel, DeltaReport, EvidenceRecord, TenantInfo


def _make_info(**overrides) -> TenantInfo:
    """Create a minimal TenantInfo with overrides."""
    defaults = {
        "tenant_id": "test-id",
        "display_name": "Test Corp",
        "default_domain": "test.com",
        "queried_domain": "test.com",
        "confidence": ConfidenceLevel.HIGH,
        "services": ("ServiceA", "ServiceB"),
        "slugs": ("slug-a", "slug-b"),
        "insights": ("Signal One: slug-a, slug-b",),
        "auth_type": "Federated",
        "dmarc_policy": "reject",
        "domain_count": 5,
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)


def _make_previous(**overrides) -> dict:
    """Create a minimal previous JSON dict with overrides."""
    defaults = {
        "tenant_id": "test-id",
        "display_name": "Test Corp",
        "default_domain": "test.com",
        "queried_domain": "test.com",
        "confidence": "high",
        "services": ["ServiceA", "ServiceB"],
        "slugs": ["slug-a", "slug-b"],
        "insights": ["Signal One: slug-a, slug-b"],
        "auth_type": "Federated",
        "dmarc_policy": "reject",
        "domain_count": 5,
    }
    defaults.update(overrides)
    return defaults


class TestLoadPrevious:
    def test_load_valid_json(self, tmp_path: Path):
        f = tmp_path / "prev.json"
        f.write_text(json.dumps({"services": ["A"]}))
        result = load_previous(f)
        assert result == {"services": ["A"]}

    def test_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_previous(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path: Path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_previous(f)

    def test_non_object_json(self, tmp_path: Path):
        f = tmp_path / "array.json"
        f.write_text(json.dumps([1, 2, 3]))
        with pytest.raises(ValueError, match="Expected JSON object"):
            load_previous(f)

    def test_deeply_nested_json_is_rejected_cleanly(self, tmp_path: Path) -> None:
        snapshot = tmp_path / "deep.json"
        snapshot.write_text(
            '{"x":' + "[" * 20_000 + "0" + "]" * 20_000 + "}",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="nested"):
            load_previous(snapshot)

    def test_brackets_inside_strings_do_not_count_as_nesting(self, tmp_path: Path) -> None:
        snapshot = tmp_path / "brackets.json"
        snapshot.write_text('{"insights":["[[[{{{\\"quoted\\"}}}]]]"]}', encoding="utf-8")

        assert load_previous(snapshot)["insights"] == ['[[[{{{"quoted"}}}]]]']

    def test_oversized_file_is_rejected_before_parsing(self, tmp_path: Path) -> None:
        from recon_tool.delta import _MAX_PREVIOUS_EXPORT_BYTES

        snapshot = tmp_path / "oversized.json"
        snapshot.write_bytes(b" " * (_MAX_PREVIOUS_EXPORT_BYTES + 1))

        with pytest.raises(ValueError, match="maximum size"):
            load_previous(snapshot)

    def test_oversized_json_integer_is_rejected_cleanly(self, tmp_path: Path) -> None:
        snapshot = tmp_path / "large-integer.json"
        snapshot.write_text('{"x":' + "9" * 5_000 + "}", encoding="utf-8")

        with pytest.raises(ValueError, match="supported limits"):
            load_previous(snapshot)


class TestComputeDelta:
    @pytest.mark.parametrize(
        "snapshot",
        [
            {"services": 1},
            {"services": [{}]},
            {"slugs": "not-a-list"},
            {"insights": ["valid", 1]},
            {"degraded_sources": "dns:dmarc"},
            {"ct_provider_used": 1},
        ],
    )
    def test_invalid_collection_shapes_are_rejected(self, snapshot: dict) -> None:
        with pytest.raises(ValueError, match="snapshot field"):
            compute_delta(snapshot, _make_info())

    def test_no_changes(self):
        info = _make_info()
        prev = _make_previous()
        delta = compute_delta(prev, info)
        assert not delta.has_changes
        assert delta.added_services == ()
        assert delta.removed_services == ()
        assert delta.incomplete_comparison is None

    def test_added_services(self):
        info = _make_info(services=("ServiceA", "ServiceB", "ServiceC"))
        prev = _make_previous(services=["ServiceA", "ServiceB"])
        delta = compute_delta(prev, info)
        assert delta.has_changes
        assert "ServiceC" in delta.added_services

    def test_removed_services(self):
        info = _make_info(services=("ServiceA",))
        prev = _make_previous(services=["ServiceA", "ServiceB"])
        delta = compute_delta(prev, info)
        assert delta.removed_services == ("ServiceB (prior evidence role unavailable)",)

    def test_degraded_collection_withholds_removals_but_keeps_additions(self) -> None:
        info = _make_info(
            services=("ServiceA", "ServiceC"),
            slugs=("slug-a", "slug-c"),
            insights=("Multi-Cloud: Amazon Web Services, Google Cloud",),
            degraded_sources=("source:user_realm",),
        )
        prev = _make_previous(
            services=["ServiceA", "ServiceB"],
            slugs=["slug-a", "slug-b"],
            insights=[],
        )

        delta = compute_delta(prev, info)

        assert delta.added_services == ("ServiceC",)
        assert delta.added_slugs == ("slug-c",)
        assert delta.added_signals == ()
        assert delta.removed_services == ()
        assert delta.removed_slugs == ()
        assert delta.removed_signals == ()
        assert delta.incomplete_comparison is not None
        assert delta.incomplete_comparison.degraded_sources == ("source:user_realm",)
        assert delta.incomplete_comparison.suppressed_fields == (
            "changed_auth_type",
            "changed_confidence",
            "changed_domain_count",
            "removed_services",
            "removed_signals",
            "removed_slugs",
        )

    def test_current_unavailable_channel_cannot_create_additions(self) -> None:
        info = _make_info(
            services=("ServiceA", SVC_DMARC),
            slugs=("slug-a", "dmarc"),
            insights=("DMARC Governance Investment: dmarcian",),
            degraded_sources=("dns:dmarc",),
        )
        prev = _make_previous(
            services=["ServiceA"],
            slugs=["slug-a"],
            insights=[],
        )

        delta = compute_delta(prev, info)

        assert delta.added_services == ()
        assert delta.added_slugs == ()
        assert delta.added_signals == ()

    def test_previous_degradation_withholds_additions_and_names_endpoint(self) -> None:
        info = _make_info(
            services=("ServiceA", "ServiceC"),
            slugs=("slug-a", "slug-c"),
            insights=("Multi-Cloud: Amazon Web Services, Google Cloud",),
        )
        prev = _make_previous(
            services=["ServiceA"],
            slugs=["slug-a"],
            insights=[],
            degraded_sources=["source:user_realm"],
        )

        delta = compute_delta(prev, info)

        assert delta.added_services == ()
        assert delta.added_slugs == ()
        assert delta.added_signals == ()
        assert delta.incomplete_comparison is not None
        assert delta.incomplete_comparison.degraded_sources == ("source:user_realm",)
        assert delta.incomplete_comparison.previous_degraded_sources == ("source:user_realm",)
        assert delta.incomplete_comparison.current_degraded_sources == ()
        assert {"added_services", "added_slugs", "added_signals"} <= set(delta.incomplete_comparison.suppressed_fields)

    @pytest.mark.parametrize(
        ("marker", "service", "slug", "raw_value"),
        [
            ("dns:dmarc", SVC_DMARC, "dmarc", "v=DMARC1; p=reject"),
            ("dns:apex_txt", "Okta", "okta", "_oktaverification=opaque"),
        ],
    )
    def test_previous_unavailable_channel_cannot_create_a_stale_removal(
        self,
        marker: str,
        service: str,
        slug: str,
        raw_value: str,
    ) -> None:
        previous_info = _make_info(
            services=("ServiceA", service),
            slugs=("slug-a", slug),
            insights=(),
            degraded_sources=(marker,),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value=raw_value,
                    rule_name=service,
                    slug=slug,
                ),
            ),
        )
        current = _make_info(services=("ServiceA",), slugs=("slug-a",), insights=())

        delta = compute_delta(tenant_info_to_dict(previous_info), current)

        assert delta.removed_services == ()
        assert delta.removed_slugs == ()

    @pytest.mark.parametrize(
        "legacy_insight",
        [
            "SASE/ZTNA: Zscaler",
            "Email gateway: Proofpoint",
            "Security stack: CrowdStrike",
            "Google Workspace modules: Drive, Meet",
        ],
    )
    def test_retired_cached_insight_cannot_resurface_as_a_removed_signal(self, legacy_insight: str) -> None:
        previous = _make_previous(insights=[legacy_insight])
        current = _make_info(insights=())

        delta = compute_delta(previous, current)

        assert delta.removed_signals == ()

    @pytest.mark.parametrize(
        "observation",
        [
            "MX gateway observed: Proofpoint",
            "DMARC: reject",
            "PKI: DigiCert",
            "Network-security vendor indicator observed: Zscaler",
            "Device-management vendor indicator observed: Intune",
            "Google Workspace module indicators observed: Drive, Meet",
        ],
    )
    def test_non_signal_observation_is_not_promoted_by_colon_syntax(self, observation: str) -> None:
        delta = compute_delta(_make_previous(insights=[]), _make_info(insights=(observation,)))

        assert delta.added_signals == ()

    def test_both_degraded_endpoints_are_distinguished(self) -> None:
        info = _make_info(degraded_sources=("dns:dmarc",))
        prev = _make_previous(degraded_sources=["source:user_realm"])

        delta = compute_delta(prev, info)

        assert delta.incomplete_comparison is not None
        assert delta.incomplete_comparison.degraded_sources == ("dns:dmarc", "source:user_realm")
        assert delta.incomplete_comparison.previous_degraded_sources == ("source:user_realm",)
        assert delta.incomplete_comparison.current_degraded_sources == ("dns:dmarc",)
        assert {"added_services", "removed_services"} <= set(delta.incomplete_comparison.suppressed_fields)

    def test_added_and_removed_slugs(self):
        info = _make_info(slugs=("slug-a", "slug-c"))
        prev = _make_previous(slugs=["slug-a", "slug-b"])
        delta = compute_delta(prev, info)
        assert "slug-c" in delta.added_slugs
        assert "slug-b" in delta.removed_slugs

    def test_changed_auth_type(self):
        info = _make_info(auth_type="Managed")
        prev = _make_previous(auth_type="Federated")
        delta = compute_delta(prev, info)
        assert delta.changed_auth_type == ("Federated", "Managed")

    def test_non_ct_degradation_withholds_identity_scalar_changes(self) -> None:
        info = _make_info(
            auth_type="Managed",
            confidence=ConfidenceLevel.LOW,
            domain_count=2,
            degraded_sources=("source:user_realm",),
        )
        prev = _make_previous(auth_type="Federated", confidence="high", domain_count=5)

        delta = compute_delta(prev, info)

        assert delta.changed_auth_type is None
        assert delta.changed_confidence is None
        assert delta.changed_domain_count is None
        assert delta.incomplete_comparison is not None
        assert {"changed_auth_type", "changed_confidence", "changed_domain_count"} <= set(
            delta.incomplete_comparison.suppressed_fields
        )

    def test_previous_non_ct_degradation_withholds_identity_scalar_changes(self) -> None:
        info = _make_info(
            auth_type="Managed",
            confidence=ConfidenceLevel.LOW,
            domain_count=2,
        )
        prev = _make_previous(
            auth_type="Federated",
            confidence="high",
            domain_count=5,
            degraded_sources=["source:user_realm"],
        )

        delta = compute_delta(prev, info)

        assert delta.changed_auth_type is None
        assert delta.changed_confidence is None
        assert delta.changed_domain_count is None
        assert delta.incomplete_comparison is not None
        assert {"changed_auth_type", "changed_confidence", "changed_domain_count"} <= set(
            delta.incomplete_comparison.suppressed_fields
        )

    @pytest.mark.parametrize("marker", ["crt.sh", "certspotter"])
    def test_ct_only_degradation_without_recovery_withholds_confidence(self, marker: str) -> None:
        info = _make_info(
            auth_type="Managed",
            confidence=ConfidenceLevel.LOW,
            domain_count=2,
            degraded_sources=(marker,),
        )
        prev = _make_previous(auth_type="Federated", confidence="high", domain_count=5)

        delta = compute_delta(prev, info)

        assert delta.changed_auth_type == ("Federated", "Managed")
        assert delta.changed_confidence is None
        assert delta.changed_domain_count == (5, 2)
        assert delta.incomplete_comparison is not None
        assert "changed_auth_type" not in delta.incomplete_comparison.suppressed_fields
        assert "changed_confidence" in delta.incomplete_comparison.suppressed_fields
        assert "changed_domain_count" not in delta.incomplete_comparison.suppressed_fields

    @pytest.mark.parametrize(
        ("marker", "recovered_provider"),
        [("crt.sh", "certspotter"), ("certspotter", "crt.sh")],
    )
    def test_current_ct_recovery_keeps_confidence_comparable(
        self,
        marker: str,
        recovered_provider: str,
    ) -> None:
        info = _make_info(
            confidence=ConfidenceLevel.LOW,
            degraded_sources=(marker,),
            ct_provider_used=recovered_provider,
        )
        prev = _make_previous(confidence="high")

        delta = compute_delta(prev, info)

        assert delta.changed_confidence == ("high", "low")
        assert delta.incomplete_comparison is not None
        assert "changed_confidence" not in delta.incomplete_comparison.suppressed_fields

    @pytest.mark.parametrize("marker", ["crt.sh", "certspotter"])
    def test_previous_ct_degradation_without_recovery_withholds_confidence(self, marker: str) -> None:
        info = _make_info(
            auth_type="Managed",
            confidence=ConfidenceLevel.HIGH,
            domain_count=2,
        )
        prev = _make_previous(
            auth_type="Federated",
            confidence="low",
            domain_count=5,
            degraded_sources=[marker],
        )

        delta = compute_delta(prev, info)

        assert delta.changed_auth_type == ("Federated", "Managed")
        assert delta.changed_confidence is None
        assert delta.changed_domain_count == (5, 2)
        assert delta.incomplete_comparison is not None
        assert "changed_auth_type" not in delta.incomplete_comparison.suppressed_fields
        assert "changed_confidence" in delta.incomplete_comparison.suppressed_fields
        assert "changed_domain_count" not in delta.incomplete_comparison.suppressed_fields

    @pytest.mark.parametrize(
        ("marker", "recovered_provider"),
        [("crt.sh", "certspotter"), ("certspotter", "crt.sh")],
    )
    def test_previous_ct_recovery_keeps_confidence_comparable(
        self,
        marker: str,
        recovered_provider: str,
    ) -> None:
        info = _make_info(confidence=ConfidenceLevel.HIGH)
        prev = _make_previous(
            confidence="low",
            degraded_sources=[marker],
            ct_provider_used=recovered_provider,
        )

        delta = compute_delta(prev, info)

        assert delta.changed_confidence == ("low", "high")
        assert delta.incomplete_comparison is not None
        assert "changed_confidence" not in delta.incomplete_comparison.suppressed_fields

    def test_every_degraded_ct_endpoint_requires_explicit_recovery(self) -> None:
        info = _make_info(
            confidence=ConfidenceLevel.HIGH,
            degraded_sources=("certspotter",),
            ct_provider_used="crt.sh",
        )
        prev = _make_previous(
            confidence="low",
            degraded_sources=["crt.sh"],
        )

        delta = compute_delta(prev, info)

        assert delta.changed_confidence is None
        assert delta.incomplete_comparison is not None
        assert "changed_confidence" in delta.incomplete_comparison.suppressed_fields

    def test_changed_dmarc_policy(self):
        info = _make_info(dmarc_policy="none")
        prev = _make_previous(dmarc_policy="reject")
        delta = compute_delta(prev, info)
        assert delta.changed_dmarc_policy == ("reject", "none")

    def test_unavailable_dmarc_withholds_policy_and_score_changes(self) -> None:
        info = _make_info(
            dmarc_policy=None,
            services=(SVC_SPF_STRICT,),
            degraded_sources=("dns:dmarc",),
        )
        prev = _make_previous(dmarc_policy="reject", email_security_score=2)

        delta = compute_delta(prev, info)

        assert delta.changed_dmarc_policy is None
        assert delta.changed_email_security_score is None
        assert delta.incomplete_comparison is not None
        assert "changed_dmarc_policy" in delta.incomplete_comparison.suppressed_fields
        assert "changed_email_security_score" in delta.incomplete_comparison.suppressed_fields

    def test_previous_unavailable_dmarc_withholds_policy_and_score_changes(self) -> None:
        info = _make_info(dmarc_policy="reject", services=(SVC_DMARC, SVC_SPF_STRICT))
        prev = _make_previous(
            dmarc_policy=None,
            email_security_score=1,
            degraded_sources=["dns:dmarc"],
        )

        delta = compute_delta(prev, info)

        assert delta.changed_dmarc_policy is None
        assert delta.changed_email_security_score is None
        assert delta.incomplete_comparison is not None
        assert "changed_dmarc_policy" in delta.incomplete_comparison.suppressed_fields
        assert "changed_email_security_score" in delta.incomplete_comparison.suppressed_fields

    @pytest.mark.parametrize(
        "marker",
        [
            "dns:dmarc",
            "dns:dkim",
            "dns:apex_txt",
            "http:mta_sts_policy",
            "dns:bimi",
        ],
    )
    def test_unavailable_email_control_withholds_score_change(self, marker: str) -> None:
        info = _make_info(degraded_sources=(marker,))
        prev = _make_previous(email_security_score=5)

        delta = compute_delta(prev, info)

        assert delta.changed_email_security_score is None
        assert delta.incomplete_comparison is not None
        assert "changed_email_security_score" in delta.incomplete_comparison.suppressed_fields

    def test_changed_confidence(self):
        info = _make_info(confidence=ConfidenceLevel.LOW)
        prev = _make_previous(confidence="high")
        delta = compute_delta(prev, info)
        assert delta.changed_confidence == ("high", "low")

    def test_no_phantom_email_score_change_for_p_none_dmarc(self):
        """Re-running an unchanged p=none DMARC domain shows no score delta.

        Regression: delta scored DMARC by service presence (counting any DMARC
        record) while the exported ``email_security_score`` scores DMARC only
        when the policy is enforcing. A p=none domain therefore reported a
        spurious email-security-score change against its own prior export.
        The previous snapshot here is built by the real exporter so the two
        code paths must agree.
        """
        info = _make_info(dmarc_policy="none", services=(SVC_DMARC, SVC_SPF_STRICT))
        prev = format_tenant_dict(info)
        delta = compute_delta(prev, info)
        assert delta.changed_email_security_score is None

    def test_email_score_change_reported_when_policy_strengthens(self):
        """An enforcing DMARC policy raises the score and the delta reports it."""
        evidence = (
            EvidenceRecord(
                source_type="SPF",
                raw_value="v=spf1 -all",
                rule_name="SPF strict",
                slug="spf-strict",
            ),
        )
        prev_info = _make_info(dmarc_policy="none", services=(SVC_DMARC, SVC_SPF_STRICT), evidence=evidence)
        curr_info = _make_info(dmarc_policy="reject", services=(SVC_DMARC, SVC_SPF_STRICT), evidence=evidence)
        delta = compute_delta(format_tenant_dict(prev_info), curr_info)
        assert delta.changed_email_security_score == (1, 2)

    def test_changed_domain_count(self):
        info = _make_info(domain_count=10)
        prev = _make_previous(domain_count=5)
        delta = compute_delta(prev, info)
        assert delta.changed_domain_count == (5, 10)

    def test_missing_fields_in_old_json(self):
        """Older JSON missing newer fields should not error."""
        info = _make_info()
        prev = {"services": ["ServiceA", "ServiceB"]}  # minimal old format
        delta = compute_delta(prev, info)
        # Should not raise, missing fields treated as absent
        assert isinstance(delta, DeltaReport)

    def test_signal_extraction(self):
        info = _make_info(
            slugs=("aws-route53", "gcp-dns"),
            insights=("Multi-Cloud: Amazon Web Services, Google Cloud",),
        )
        prev = _make_previous(insights=[])
        delta = compute_delta(prev, info)
        assert (
            "Multiple cloud-vendor catalog indicators co-observed; provider roles and diversity are unresolved"
            in delta.added_signals
        )
        assert "Multi-Cloud" not in delta.added_signals

    def test_signal_extraction_with_humanized_values(self):
        # Real signal insights render their matched products humanized (spaces,
        # qualifiers), e.g. "Multi-Cloud: Amazon Web Services, Google Cloud".
        # These must still be recognized as signals by name, not dropped because
        # the value is no longer a bare slug list.
        info = _make_info(
            slugs=("aws-route53", "gcp-dns"),
            insights=("Multi-Cloud: Amazon Web Services, Google Cloud",),
        )
        prev = _make_previous(insights=[])
        delta = compute_delta(prev, info)
        assert (
            "Multiple cloud-vendor catalog indicators co-observed; provider roles and diversity are unresolved"
            in delta.added_signals
        )

    def test_nonreportable_signal_identifier_is_never_emitted(self):
        delta = compute_delta(
            _make_previous(insights=["Incomplete Identity Migration: Okta"]),
            _make_info(insights=()),
        )

        assert delta.removed_signals == ()

    def test_service_addition_uses_retained_evidence_role(self):
        info = _make_info(
            services=("ServiceA", "Okta"),
            slugs=("slug-a", "okta"),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value="oktaverification=opaque",
                    rule_name="Okta",
                    slug="okta",
                ),
            ),
        )

        delta = compute_delta(_make_previous(services=["ServiceA"], slugs=["slug-a"]), info)

        assert delta.added_services == ("Okta (public TXT account indicator)",)

    def test_service_removal_uses_retained_prior_evidence_role(self):
        previous = _make_info(
            services=("ServiceA", "Okta"),
            slugs=("slug-a", "okta"),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value="oktaverification=opaque",
                    rule_name="Okta",
                    slug="okta",
                ),
            ),
        )
        current = _make_info(services=("ServiceA",), slugs=("slug-a",), evidence=())

        delta = compute_delta(format_tenant_dict(previous), current)

        assert delta.removed_services == ("Okta (public TXT account indicator)",)

    def test_prose_insight_not_treated_as_signal(self):
        # A non-signal insight whose value happens to contain commas must not be
        # mistaken for a signal (its prefix is not a known signal name).
        info = _make_info(insights=("Email security 4/5: DMARC reject, DKIM, SPF strict, BIMI",))
        prev = _make_previous(insights=[])
        delta = compute_delta(prev, info)
        assert not delta.added_signals

    def test_ordering_independent(self):
        """Services in different order should not show as changes."""
        info = _make_info(services=("B", "A", "C"))
        prev = _make_previous(services=["C", "A", "B"])
        delta = compute_delta(prev, info)
        assert not delta.added_services
        assert not delta.removed_services
