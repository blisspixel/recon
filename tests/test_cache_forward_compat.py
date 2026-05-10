"""Forward-compatibility tests for the on-disk cache format.

Backward compatibility (today's reader on a yesterday's cache file) is
already exercised by ``tests/test_backward_compat.py``. This file covers
the *forward* direction: today's reader on a hypothetical tomorrow's
cache file that has an extra field the reader doesn't know about.

The implicit contract — established by the ``data.get(...)`` access
pattern in ``recon_tool.cache.tenant_info_from_dict`` — is that unknown
top-level fields and unknown nested-dict keys are silently ignored, and
the rest of the object loads cleanly. This test pins that behaviour so
a future refactor (e.g. switching to a strict pydantic model) cannot
silently break forward-compat.

The contract matters because a v1.10 cache writer that adds a new
top-level field must not require a v1.9 reader to crash on the file.
Operators upgrading and downgrading recon between machines, or rolling
back a deploy, hit this case routinely.
"""

from __future__ import annotations

import json

import pytest

from recon_tool.cache import _CACHE_VERSION, tenant_info_from_dict, tenant_info_to_dict
from recon_tool.models import ConfidenceLevel, TenantInfo


def _make_minimal_dict() -> dict:
    """Round-trip a minimal valid TenantInfo through the serializer.

    Using the project's own serializer guarantees the base shape stays
    in sync with the model; we then mutate the dict to inject unknown
    fields.
    """
    info = TenantInfo(
        tenant_id=None,
        display_name="Contoso, Ltd",
        default_domain="contoso.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
    )
    return tenant_info_to_dict(info)


class TestUnknownTopLevelFields:
    """Unknown top-level keys must not break the reader."""

    def test_extra_top_level_string_field_ignored(self) -> None:
        data = _make_minimal_dict()
        data["future_field_v1_10"] = "future-value"
        info = tenant_info_from_dict(data)
        # Reader returns a TenantInfo; the unknown field is simply not
        # carried into the dataclass (no public attribute appears).
        assert info.display_name == "Contoso, Ltd"
        assert not hasattr(info, "future_field_v1_10")

    def test_extra_top_level_dict_field_ignored(self) -> None:
        data = _make_minimal_dict()
        data["future_nested_v2"] = {"new_key": "new_value", "another": 42}
        info = tenant_info_from_dict(data)
        assert info.display_name == "Contoso, Ltd"

    def test_extra_top_level_list_field_ignored(self) -> None:
        data = _make_minimal_dict()
        data["future_list_v2"] = ["alpha", "beta", "gamma"]
        info = tenant_info_from_dict(data)
        assert info.display_name == "Contoso, Ltd"

    def test_higher_cache_version_loads_with_known_fields(self) -> None:
        """A future cache writer that bumps _cache_version but keeps
        the existing field shapes still loads on this reader. The
        contract is "ignore unknowns and load knowns cleanly," not
        "refuse anything with a higher version."
        """
        data = _make_minimal_dict()
        data["_cache_version"] = _CACHE_VERSION + 99
        info = tenant_info_from_dict(data)
        assert info.display_name == "Contoso, Ltd"


class TestUnknownNestedFields:
    """Unknown keys inside a nested dict (cert_summary, posteriors, etc.)
    must not break the reader."""

    def test_extra_field_in_cert_summary_ignored(self) -> None:
        data = _make_minimal_dict()
        data["cert_summary"] = {
            "cert_count": 5,
            "issuer_diversity": 2,
            "issuance_velocity": 3,
            "newest_cert_age_days": 10,
            "oldest_cert_age_days": 30,
            "top_issuers": ["Let's Encrypt"],
            # Future-only field a v1.10 cert engine might add:
            "hawkes_kernel_class": "automated_renewal",
        }
        info = tenant_info_from_dict(data)
        assert info.cert_summary is not None
        assert info.cert_summary.cert_count == 5

    def test_extra_field_in_posterior_observations_ignored(self) -> None:
        data = _make_minimal_dict()
        data["posterior_observations"] = [
            {
                "name": "m365_tenant",
                "description": "Domain has a Microsoft 365 / Entra tenant.",
                "posterior": 0.95,
                "interval_low": 0.85,
                "interval_high": 1.0,
                "evidence_used": ["slug:microsoft365"],
                "n_eff": 5.0,
                "sparse": False,
                # Future-only field a v1.10 fusion layer might add:
                "ignorance_mass": 0.05,
                "future_calibration_id": "abc-123",
            },
        ]
        info = tenant_info_from_dict(data)
        assert len(info.posterior_observations) == 1
        assert info.posterior_observations[0].name == "m365_tenant"
        assert info.posterior_observations[0].posterior == pytest.approx(0.95)

    def test_extra_field_in_evidence_record_ignored(self) -> None:
        data = _make_minimal_dict()
        data["evidence"] = [
            {
                "source_type": "TXT",
                "raw_value": "v=spf1 -all",
                "rule_name": "SPF strict",
                "slug": "spf-strict",
                # Future-only:
                "captured_at_iso": "2026-05-09T00:00:00Z",
                "future_provenance_id": "uuid-here",
            },
        ]
        info = tenant_info_from_dict(data)
        assert len(info.evidence) == 1
        assert info.evidence[0].source_type == "TXT"


class TestRoundTripSafety:
    """A future cache file that's a superset of today's must round-trip
    on the v1.9 reader without losing the known fields, even if the
    v1.9 writer can't reproduce the unknowns."""

    def test_dense_record_with_unknowns_round_trips(self) -> None:
        data = _make_minimal_dict()
        # Sprinkle unknowns at every layer.
        data["future_top"] = "x"
        if "cert_summary" not in data or data["cert_summary"] is None:
            data["cert_summary"] = {
                "cert_count": 0,
                "issuer_diversity": 0,
                "issuance_velocity": 0,
                "newest_cert_age_days": 0,
                "oldest_cert_age_days": 0,
                "top_issuers": [],
            }
        data["cert_summary"]["future_nested"] = "y"

        info = tenant_info_from_dict(data)
        # Re-serialize; the v1.9 writer drops the unknowns. That's
        # expected — the contract is "v1.9 reader survives v1.10 writer
        # output," not "v1.9 reader preserves v1.10 fields it doesn't
        # understand."
        re_serialized = tenant_info_to_dict(info)
        assert re_serialized["display_name"] == "Contoso, Ltd"
        assert "future_top" not in re_serialized
        assert "future_nested" not in re_serialized.get("cert_summary", {})


class TestMalformedCacheStillRejected:
    """Forward-compat must not weaken the malformed-input contract.
    Missing required fields still raise; unknown extras are ignored."""

    def test_missing_required_field_still_raises(self) -> None:
        data = _make_minimal_dict()
        del data["display_name"]
        with pytest.raises(ValueError, match="Missing required fields"):
            tenant_info_from_dict(data)

    def test_non_dict_input_still_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dict"):
            tenant_info_from_dict(json.loads("[1, 2, 3]"))
