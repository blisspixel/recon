"""Data model extension tests (TenantInfo, SignalContext, Signal, SourceResult).

Validates:
- New TenantInfo fields (primary_email_provider, email_gateway, dmarc_pct) (2.1)
- New SignalContext fields (dmarc_pct, primary_email_provider) (2.2)
- expected_counterparts parsing on Signal (2.3)
- dmarc_rua detection type in fingerprints.py (2.4)
- New SourceResult fields (dmarc_pct, raw_dns_records) (2.5)
- Requirements: 1.4, 2.2, 5.1–5.5, 10.2, 14.5, 17.1, 17.2, 18.1–18.3, 19.5
"""

from __future__ import annotations

import dataclasses
import logging

import pytest

from recon_tool.fingerprints import (
    get_dmarc_rua_patterns,
    reload_fingerprints,
)
from recon_tool.models import (
    ConfidenceLevel,
    SignalContext,
    SourceResult,
    TenantInfo,
)
from recon_tool.signals import (
    Signal,
    _evaluate_metadata_condition,  # pyright: ignore[reportPrivateUsage]
    _validate_and_build_signal,  # pyright: ignore[reportPrivateUsage]
)

# ── Helper ────────────────────────────────────────────────────────────


def _make_tenant_info(**overrides: object) -> TenantInfo:
    """Create a TenantInfo with Contoso defaults, overriding specific fields."""
    defaults: dict[str, object] = {
        "tenant_id": "contoso-tenant-id",
        "display_name": "Contoso Ltd",
        "default_domain": "contoso.com",
        "queried_domain": "contoso.com",
        "confidence": ConfidenceLevel.MEDIUM,
    }
    defaults.update(overrides)
    return TenantInfo(**defaults)  # type: ignore[arg-type]


def _ctx(
    slugs: set[str],
    *,
    dmarc_policy: str | None = None,
    dmarc_pct: int | None = None,
    primary_email_provider: str | None = None,
) -> SignalContext:
    return SignalContext(
        detected_slugs=frozenset(slugs),
        dmarc_policy=dmarc_policy,
        dmarc_pct=dmarc_pct,
        primary_email_provider=primary_email_provider,
    )


# ── 2.1: TenantInfo new fields ───────────────────────────────────────


class TestTenantInfoNewFields:
    """Verify new TenantInfo fields: primary_email_provider, email_gateway, dmarc_pct."""

    def test_primary_email_provider_defaults_to_none(self) -> None:
        info = _make_tenant_info()
        assert info.primary_email_provider is None

    def test_email_gateway_defaults_to_none(self) -> None:
        info = _make_tenant_info()
        assert info.email_gateway is None

    def test_dmarc_pct_defaults_to_none(self) -> None:
        info = _make_tenant_info()
        assert info.dmarc_pct is None

    def test_primary_email_provider_set_explicitly(self) -> None:
        info = _make_tenant_info(primary_email_provider="Microsoft 365")
        assert info.primary_email_provider == "Microsoft 365"

    def test_email_gateway_set_explicitly(self) -> None:
        info = _make_tenant_info(email_gateway="Proofpoint")
        assert info.email_gateway == "Proofpoint"

    def test_dmarc_pct_set_explicitly(self) -> None:
        info = _make_tenant_info(dmarc_pct=50)
        assert info.dmarc_pct == 50

    def test_frozen_immutability_primary_email_provider(self) -> None:
        info = _make_tenant_info(primary_email_provider="Microsoft 365")
        with pytest.raises(dataclasses.FrozenInstanceError):
            info.primary_email_provider = "Google Workspace"  # type: ignore[misc]

    def test_frozen_immutability_email_gateway(self) -> None:
        info = _make_tenant_info(email_gateway="Mimecast")
        with pytest.raises(dataclasses.FrozenInstanceError):
            info.email_gateway = "Proofpoint"  # type: ignore[misc]

    def test_frozen_immutability_dmarc_pct(self) -> None:
        info = _make_tenant_info(dmarc_pct=75)
        with pytest.raises(dataclasses.FrozenInstanceError):
            info.dmarc_pct = 100  # type: ignore[misc]

    def test_all_three_fields_set_together(self) -> None:
        """Northwind Traders with full email topology."""
        info = _make_tenant_info(
            display_name="Northwind Traders",
            primary_email_provider="Microsoft 365",
            email_gateway="Proofpoint",
            dmarc_pct=25,
        )
        assert info.primary_email_provider == "Microsoft 365"
        assert info.email_gateway == "Proofpoint"
        assert info.dmarc_pct == 25


# ── 2.2: SignalContext new fields ─────────────────────────────────────


class TestSignalContextNewFields:
    """Verify new SignalContext fields: dmarc_pct, primary_email_provider."""

    def test_dmarc_pct_defaults_to_none(self) -> None:
        ctx = SignalContext(detected_slugs=frozenset())
        assert ctx.dmarc_pct is None

    def test_primary_email_provider_defaults_to_none(self) -> None:
        ctx = SignalContext(detected_slugs=frozenset())
        assert ctx.primary_email_provider is None

    def test_dmarc_pct_set_explicitly(self) -> None:
        ctx = SignalContext(detected_slugs=frozenset(), dmarc_pct=50)
        assert ctx.dmarc_pct == 50

    def test_primary_email_provider_set_explicitly(self) -> None:
        ctx = SignalContext(
            detected_slugs=frozenset(),
            primary_email_provider="Google Workspace",
        )
        assert ctx.primary_email_provider == "Google Workspace"

    def test_metadata_evaluator_accepts_dmarc_pct(self) -> None:
        """Metadata condition on dmarc_pct should evaluate correctly."""
        from recon_tool.models import MetadataCondition

        cond = MetadataCondition(field="dmarc_pct", operator="lte", value=99)
        ctx = _ctx(set(), dmarc_pct=50)
        assert _evaluate_metadata_condition(cond, ctx) is True

    def test_metadata_evaluator_accepts_primary_email_provider(self) -> None:
        """Metadata condition on primary_email_provider should evaluate correctly."""
        from recon_tool.models import MetadataCondition

        cond = MetadataCondition(field="primary_email_provider", operator="neq", value="")
        ctx = _ctx(set(), primary_email_provider="Microsoft 365")
        assert _evaluate_metadata_condition(cond, ctx) is True

    def test_metadata_evaluator_dmarc_pct_none_neq_returns_true(self) -> None:
        """When dmarc_pct is None, neq should return True (field doesn't exist)."""
        from recon_tool.models import MetadataCondition

        cond = MetadataCondition(field="dmarc_pct", operator="neq", value=100)
        ctx = _ctx(set())
        assert _evaluate_metadata_condition(cond, ctx) is True

    def test_metadata_evaluator_primary_email_provider_none_eq_returns_false(self) -> None:
        """When primary_email_provider is None, eq should return False."""
        from recon_tool.models import MetadataCondition

        cond = MetadataCondition(field="primary_email_provider", operator="eq", value="Microsoft 365")
        ctx = _ctx(set())
        assert _evaluate_metadata_condition(cond, ctx) is False

    def test_dmarc_pct_in_valid_metadata_fields(self) -> None:
        """dmarc_pct should be in _VALID_METADATA_FIELDS in signals.py."""
        from recon_tool.signals import _VALID_METADATA_FIELDS  # pyright: ignore[reportPrivateUsage]

        assert "dmarc_pct" in _VALID_METADATA_FIELDS

    def test_primary_email_provider_in_valid_metadata_fields(self) -> None:
        """primary_email_provider should be in _VALID_METADATA_FIELDS in signals.py."""
        from recon_tool.signals import _VALID_METADATA_FIELDS  # pyright: ignore[reportPrivateUsage]

        assert "primary_email_provider" in _VALID_METADATA_FIELDS


# ── 2.3: expected_counterparts parsing on Signal ──────────────────────


class TestExpectedCounterpartsParsing:
    """Verify expected_counterparts parsing in _validate_and_build_signal()."""

    def _build_signal_dict(self, **overrides: object) -> dict[str, object]:
        """Minimal valid signal dict for Fabrikam test signals."""
        base: dict[str, object] = {
            "name": "Fabrikam Test Signal",
            "category": "Test",
            "confidence": "medium",
            "description": "Test signal for Fabrikam Corp",
            "requires": {"any": ["openai"]},
            "min_matches": 1,
        }
        base.update(overrides)
        return base

    def test_valid_list_stored_as_tuple(self) -> None:
        """Valid list of strings → stored as tuple on Signal."""
        d = self._build_signal_dict(expected_counterparts=["proofpoint", "mimecast"])
        sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ("proofpoint", "mimecast")

    def test_single_entry_list(self) -> None:
        d = self._build_signal_dict(expected_counterparts=["crowdstrike"])
        sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ("crowdstrike",)

    def test_invalid_entry_non_string(self, caplog: pytest.LogCaptureFixture) -> None:
        """Non-string entry → warning logged, defaults to empty tuple."""
        d = self._build_signal_dict(expected_counterparts=["proofpoint", 42])
        with caplog.at_level(logging.WARNING, logger="recon"):
            sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()
        assert any("invalid entry" in r.message.lower() for r in caplog.records)

    def test_invalid_entry_empty_string(self, caplog: pytest.LogCaptureFixture) -> None:
        """Empty string entry → warning logged, defaults to empty tuple."""
        d = self._build_signal_dict(expected_counterparts=["proofpoint", ""])
        with caplog.at_level(logging.WARNING, logger="recon"):
            sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()
        assert any("invalid entry" in r.message.lower() for r in caplog.records)

    def test_invalid_entry_whitespace_only(self, caplog: pytest.LogCaptureFixture) -> None:
        """Whitespace-only string → warning logged, defaults to empty tuple."""
        d = self._build_signal_dict(expected_counterparts=["proofpoint", "   "])
        with caplog.at_level(logging.WARNING, logger="recon"):
            sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()

    def test_non_list_value(self, caplog: pytest.LogCaptureFixture) -> None:
        """Non-list value → warning logged, defaults to empty tuple."""
        d = self._build_signal_dict(expected_counterparts="proofpoint")
        with caplog.at_level(logging.WARNING, logger="recon"):
            sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()
        assert any("not a list" in r.message.lower() for r in caplog.records)

    def test_omitted_field_defaults_to_empty_tuple(self) -> None:
        """Omitted expected_counterparts → defaults to empty tuple."""
        d = self._build_signal_dict()
        assert "expected_counterparts" not in d
        sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()

    def test_empty_list_stored_as_empty_tuple(self) -> None:
        """Empty list → stored as empty tuple (no counterparts)."""
        d = self._build_signal_dict(expected_counterparts=[])
        sig = _validate_and_build_signal(d, 0)
        assert sig is not None
        assert sig.expected_counterparts == ()

    def test_field_exists_on_signal_dataclass(self) -> None:
        """Signal dataclass has expected_counterparts field."""
        sig = Signal(
            name="Test",
            category="Test",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
            expected_counterparts=("proofpoint", "mimecast"),
        )
        assert sig.expected_counterparts == ("proofpoint", "mimecast")

    def test_signal_dataclass_default_empty_tuple(self) -> None:
        """Signal dataclass defaults expected_counterparts to empty tuple."""
        sig = Signal(
            name="Test",
            category="Test",
            confidence="medium",
            description="",
            candidates=(),
            min_matches=0,
        )
        assert sig.expected_counterparts == ()


# ── 2.4: dmarc_rua detection type in fingerprints.py ─────────────────


class TestDmarcRuaDetectionType:
    """Verify dmarc_rua detection type support in fingerprints.py."""

    def setup_method(self) -> None:
        reload_fingerprints()

    def test_dmarc_rua_is_valid_detection_type(self) -> None:
        """dmarc_rua should be in _VALID_DETECTION_TYPES."""
        from recon_tool.fingerprints import _VALID_DETECTION_TYPES  # pyright: ignore[reportPrivateUsage]

        assert "dmarc_rua" in _VALID_DETECTION_TYPES

    def test_get_dmarc_rua_patterns_returns_tuple(self) -> None:
        """get_dmarc_rua_patterns() should return a tuple of Detection."""
        patterns = get_dmarc_rua_patterns()
        assert isinstance(patterns, tuple)

    def test_get_dmarc_rua_patterns_detection_fields(self) -> None:
        """Each Detection from get_dmarc_rua_patterns() has expected fields."""
        patterns = get_dmarc_rua_patterns()
        for det in patterns:
            assert det.pattern, f"Detection for {det.name} has empty pattern"
            assert det.slug, f"Detection for {det.name} has empty slug"
            assert det.name, "Detection has empty name"
            assert det.category, f"Detection for {det.name} has empty category"
            assert det.confidence in {"high", "medium", "low"}

    def test_dmarc_rua_fingerprint_accepted_during_validation(self) -> None:
        """A fingerprint with dmarc_rua detection type should pass validation."""
        from recon_tool.fingerprints import _validate_fingerprint  # pyright: ignore[reportPrivateUsage]

        fp_dict = {
            "name": "Contoso DMARC Vendor",
            "slug": "contoso-dmarc",
            "category": "Email Governance",
            "confidence": "high",
            "detections": [{"type": "dmarc_rua", "pattern": "contoso.com"}],
        }
        result = _validate_fingerprint(fp_dict, "test")
        assert result is not None
        assert result.slug == "contoso-dmarc"
        assert result.detections[0].type == "dmarc_rua"


# ── 2.5: SourceResult new fields ─────────────────────────────────────


class TestSourceResultNewFields:
    """Verify new SourceResult fields: dmarc_pct, raw_dns_records."""

    def test_dmarc_pct_defaults_to_none(self) -> None:
        result = SourceResult(source_name="DNS")
        assert result.dmarc_pct is None

    def test_raw_dns_records_defaults_to_empty_tuple(self) -> None:
        result = SourceResult(source_name="DNS")
        assert result.raw_dns_records == ()

    def test_dmarc_pct_set_explicitly(self) -> None:
        result = SourceResult(source_name="DNS", dmarc_pct=75)
        assert result.dmarc_pct == 75

    def test_raw_dns_records_set_explicitly(self) -> None:
        records = (("TXT", "v=spf1 include:_spf.google.com ~all"), ("MX", "10 mail.contoso.com"))
        result = SourceResult(source_name="DNS", raw_dns_records=records)
        assert result.raw_dns_records == records
        assert len(result.raw_dns_records) == 2

    def test_frozen_immutability_dmarc_pct(self) -> None:
        result = SourceResult(source_name="DNS", dmarc_pct=50)
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.dmarc_pct = 100  # type: ignore[misc]

    def test_frozen_immutability_raw_dns_records(self) -> None:
        result = SourceResult(source_name="DNS")
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.raw_dns_records = (("TXT", "test"),)  # type: ignore[misc]
