"""Round-trip tests for the disk cache's TenantInfo serialization.

Covers every field that lives on TenantInfo as of v0.9.2 — including the
v0.9.1 topology fields (primary_email_provider, email_gateway, dmarc_pct,
likely_primary_email_provider) and the v0.9.2 CT provider attribution
fields (ct_provider_used, ct_subdomain_count). Raises coverage on
cache.py from 60% toward 90%.

All fixtures use fabricated data only — no real company names.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from recon_tool.cache import (
    DEFAULT_TTL,
    cache_dir,
    cache_get,
    cache_put,
    tenant_info_from_dict,
    tenant_info_to_dict,
)
from recon_tool.models import (
    BIMIIdentity,
    CertSummary,
    ConfidenceLevel,
    EvidenceRecord,
    MergeConflicts,
    TenantInfo,
)


def _complete_info() -> TenantInfo:
    """Build a TenantInfo with every field populated."""
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Contoso Ltd",
        default_domain="contoso.onmicrosoft.com",
        queried_domain="contoso.com",
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("oidc_discovery", "user_realm", "dns_records", "google_identity"),
        services=("Microsoft 365", "Google Workspace", "Cloudflare"),
        slugs=("microsoft365", "google-workspace", "cloudflare"),
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=5,
        tenant_domains=("contoso.com", "contoso.onmicrosoft.com"),
        related_domains=("api.contoso.com", "dev.contoso.com"),
        insights=("Federated auth", "Dual provider"),
        degraded_sources=("crt.sh",),
        cert_summary=CertSummary(
            cert_count=42,
            issuer_diversity=3,
            issuance_velocity=5,
            newest_cert_age_days=2,
            oldest_cert_age_days=365,
            top_issuers=("DigiCert", "Let's Encrypt", "Sectigo"),
        ),
        evidence=(
            EvidenceRecord(
                source_type="TXT",
                raw_value="MS=ms12345",
                rule_name="Microsoft 365",
                slug="microsoft365",
            ),
            EvidenceRecord(
                source_type="MX",
                raw_value="10 aspmx.l.google.com",
                rule_name="Google Workspace",
                slug="google-workspace",
            ),
        ),
        evidence_confidence=ConfidenceLevel.HIGH,
        inference_confidence=ConfidenceLevel.MEDIUM,
        detection_scores=(("microsoft365", "high"), ("cloudflare", "medium")),
        bimi_identity=BIMIIdentity(
            organization="Contoso Ltd",
            country="US",
            state="WA",
            locality="Redmond",
        ),
        site_verification_tokens=("google-verify-token-xyz",),
        mta_sts_mode="enforce",
        google_auth_type="Managed",
        google_idp_name="Google",
        primary_email_provider="Microsoft 365",
        email_gateway="Proofpoint",
        dmarc_pct=100,
        likely_primary_email_provider=None,
        ct_provider_used="certspotter",
        ct_subdomain_count=87,
        merge_conflicts=MergeConflicts(
            tenant_id=(),
            display_name=(),
        ),
    )


class TestRoundTripAllFields:
    """Every field survives a round-trip through tenant_info_to_dict and
    tenant_info_from_dict without loss."""

    def test_basic_fields(self) -> None:
        info = _complete_info()
        d = tenant_info_to_dict(info)
        restored = tenant_info_from_dict(d)
        assert restored.tenant_id == info.tenant_id
        assert restored.display_name == info.display_name
        assert restored.default_domain == info.default_domain
        assert restored.queried_domain == info.queried_domain
        assert restored.region == info.region
        assert restored.auth_type == info.auth_type
        assert restored.dmarc_policy == info.dmarc_policy
        assert restored.domain_count == info.domain_count

    def test_confidence_roundtrip(self) -> None:
        info = _complete_info()
        d = tenant_info_to_dict(info)
        restored = tenant_info_from_dict(d)
        assert restored.confidence == ConfidenceLevel.HIGH
        assert restored.evidence_confidence == ConfidenceLevel.HIGH
        assert restored.inference_confidence == ConfidenceLevel.MEDIUM

    def test_tuple_fields_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.sources == info.sources
        assert restored.services == info.services
        assert restored.slugs == info.slugs
        assert restored.tenant_domains == info.tenant_domains
        assert restored.related_domains == info.related_domains
        assert restored.insights == info.insights
        assert restored.degraded_sources == info.degraded_sources
        assert restored.site_verification_tokens == info.site_verification_tokens

    def test_cert_summary_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.cert_summary is not None
        assert restored.cert_summary.cert_count == 42
        assert restored.cert_summary.issuer_diversity == 3
        assert restored.cert_summary.issuance_velocity == 5
        assert restored.cert_summary.top_issuers == ("DigiCert", "Let's Encrypt", "Sectigo")

    def test_bimi_identity_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.bimi_identity is not None
        assert restored.bimi_identity.organization == "Contoso Ltd"
        assert restored.bimi_identity.country == "US"
        assert restored.bimi_identity.state == "WA"
        assert restored.bimi_identity.locality == "Redmond"

    def test_evidence_records_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert len(restored.evidence) == 2
        first = restored.evidence[0]
        assert first.source_type == "TXT"
        assert first.slug == "microsoft365"
        assert first.raw_value == "MS=ms12345"
        assert first.rule_name == "Microsoft 365"

    def test_detection_scores_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        # Order may not be preserved (dict → tuple), so compare as sets
        assert set(restored.detection_scores) == set(info.detection_scores)

    def test_v091_topology_fields_roundtrip(self) -> None:
        """v0.9.1 topology fields must persist through the cache."""
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.primary_email_provider == "Microsoft 365"
        assert restored.email_gateway == "Proofpoint"
        assert restored.dmarc_pct == 100
        assert restored.likely_primary_email_provider is None

    def test_v092_ct_provenance_roundtrip(self) -> None:
        """v0.9.2 CT provider attribution must persist through the cache."""
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.ct_provider_used == "certspotter"
        assert restored.ct_subdomain_count == 87

    def test_google_workspace_fields_roundtrip(self) -> None:
        info = _complete_info()
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.google_auth_type == "Managed"
        assert restored.google_idp_name == "Google"
        assert restored.mta_sts_mode == "enforce"

    def test_likely_primary_roundtrip_when_set(self) -> None:
        """Symmetric check: when likely_primary is populated and primary
        is None (gateway-fronted domain), round-trip preserves both."""
        from dataclasses import replace

        base = _complete_info()
        info = replace(
            base,
            primary_email_provider=None,
            likely_primary_email_provider="Google Workspace",
            email_gateway="Proofpoint",
        )
        restored = tenant_info_from_dict(tenant_info_to_dict(info))
        assert restored.primary_email_provider is None
        assert restored.likely_primary_email_provider == "Google Workspace"
        assert restored.email_gateway == "Proofpoint"


class TestCacheDiskOperations:
    """Exercise the cache_put / cache_get disk I/O paths in isolated temp dirs."""

    @pytest.fixture(autouse=True)
    def _isolated_cache(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("RECON_CONFIG_DIR", tmp)
            yield

    def test_put_then_get_roundtrip(self) -> None:
        info = _complete_info()
        cache_put("contoso.com", info)
        restored = cache_get("contoso.com")
        assert restored is not None
        assert restored.tenant_id == info.tenant_id
        assert restored.display_name == info.display_name

    def test_get_missing_returns_none(self) -> None:
        assert cache_get("does-not-exist.com") is None

    def test_get_corrupt_json_returns_none(self) -> None:
        cache_dir().mkdir(parents=True, exist_ok=True)
        (cache_dir() / "bad.com.json").write_text("not valid json{{{", encoding="utf-8")
        assert cache_get("bad.com") is None

    def test_get_stale_returns_none(self) -> None:
        """Files older than TTL are evicted lazily by cache_get."""
        info = _complete_info()
        cache_put("contoso.com", info)
        # Age the file past the TTL
        path = cache_dir() / "contoso.com.json"
        old = time.time() - (DEFAULT_TTL + 10)
        os.utime(path, (old, old))
        assert cache_get("contoso.com", ttl=DEFAULT_TTL) is None

    def test_get_fresh_survives_zero_ttl_query_with_larger_ttl(self) -> None:
        """A fresh file is returned as long as the caller's TTL covers it."""
        info = _complete_info()
        cache_put("contoso.com", info)
        # Fresh file, caller uses default TTL → hit
        assert cache_get("contoso.com") is not None

    def test_put_creates_cache_directory_if_missing(self) -> None:
        """cache_put should create the cache directory on first write."""
        # Remove the cache dir if it already exists from an earlier call
        import shutil

        if cache_dir().exists():
            shutil.rmtree(cache_dir())
        assert not cache_dir().exists()
        cache_put("contoso.com", _complete_info())
        assert cache_dir().exists()
        assert (cache_dir() / "contoso.com.json").exists()


class TestCacheDirRespectsEnvVar:
    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
        assert cache_dir() == tmp_path / "cache"

    def test_default_when_env_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RECON_CONFIG_DIR", raising=False)
        d = cache_dir()
        assert d.name == "cache"
        assert d.parent.name == ".recon"


class TestDictShape:
    """The serialized dict shape matches what callers expect."""

    def test_dict_has_cache_metadata(self) -> None:
        d = tenant_info_to_dict(_complete_info())
        assert "_cache_version" in d
        assert "_cached_at" in d
        # _cached_at is an ISO 8601 string with timezone info
        parsed = datetime.fromisoformat(d["_cached_at"])
        assert parsed.tzinfo is not None

    def test_dict_is_json_serializable(self) -> None:
        d = tenant_info_to_dict(_complete_info())
        # Should serialize cleanly — no sets, datetimes, etc.
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        assert parsed["tenant_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_from_dict_handles_missing_new_fields(self) -> None:
        """A dict from an older cache version (no v0.9.2 fields) still
        restores into a valid TenantInfo — the new fields default to None
        / 0 instead of raising KeyError."""
        d = tenant_info_to_dict(_complete_info())
        # Strip out the v0.9.2 fields to simulate an older cache entry
        d.pop("ct_provider_used", None)
        d.pop("ct_subdomain_count", None)
        restored = tenant_info_from_dict(d)
        assert restored.ct_provider_used is None
        assert restored.ct_subdomain_count == 0

    def test_from_dict_handles_missing_v091_fields(self) -> None:
        """Even older cache dicts (pre-v0.9.1) without topology fields
        should still deserialize — the fields default to None."""
        d = tenant_info_to_dict(_complete_info())
        d.pop("primary_email_provider", None)
        d.pop("email_gateway", None)
        d.pop("dmarc_pct", None)
        d.pop("likely_primary_email_provider", None)
        restored = tenant_info_from_dict(d)
        assert restored.primary_email_provider is None
        assert restored.email_gateway is None
        assert restored.dmarc_pct is None
        assert restored.likely_primary_email_provider is None


# Needed for os.utime in test_get_stale_returns_none
import time
