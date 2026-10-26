"""Offline reproductions for canonical evidence, cache states and literal hosts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from itertools import permutations
from pathlib import Path
from unittest.mock import patch

import dns.resolver
import pytest
from typer.testing import CliRunner

from recon_tool import resolver as resolver_module
from recon_tool.cache import cache_dir, cache_get, cache_put
from recon_tool.cache_inspection import inspect_result_cache
from recon_tool.capsule import (
    CollectionContext,
    build_capsule,
    compare_capsules,
    content_digest,
    replay_capsule,
    validate_capsule,
)
from recon_tool.cli import app
from recon_tool.ct_cache import ct_cache_dir, ct_cache_get, ct_cache_put
from recon_tool.formatter.serialize import format_tenant_dict
from recon_tool.merger import merge_results
from recon_tool.models import (
    CertSummary,
    EvidenceRecord,
    InfrastructureClusterReport,
    ReconLookupError,
    SourceResult,
    TenantInfo,
)
from recon_tool.network_policy import OPERATOR_POLICY, CollectionPolicy, collection_scope
from recon_tool.resolver import SourcePool, resolve_tenant
from recon_tool.sources import dns as dns_source
from recon_tool.sources import dns_base, dns_infra
from recon_tool.sources.cert_issuer import issuer_display_name
from recon_tool.sources.cert_providers import CertSpotterProvider, CrtshProvider, build_cert_summary
from recon_tool.sources.dns_tables import parse_rdata
from recon_tool.validator import validate_domain

_NOW = datetime(2026, 10, 23, tzinfo=UTC)
_EVIDENCE = (
    EvidenceRecord("TXT", "synthetic-a", "Synthetic A", "synthetic-a"),
    EvidenceRecord("TXT", "synthetic-b", "Synthetic B", "synthetic-b"),
    EvidenceRecord("CAA", '0 issue "ca.example"', "CAA record", "caa"),
)


@pytest.mark.parametrize("ordered", tuple(permutations(_EVIDENCE)))
def test_same_facts_have_identical_renderings_and_capsule_interpretations(ordered: tuple[EvidenceRecord, ...]) -> None:
    before = SourceResult(
        source_name="dns_records",
        evidence=_EVIDENCE,
        raw_dns_records=tuple((record.source_type, record.raw_value) for record in _EVIDENCE),
    )
    after = replace(before, evidence=ordered, raw_dns_records=tuple(reversed(before.raw_dns_records)))
    a, b = merge_results([before], "example.com"), merge_results([after], "example.com")
    assert format_tenant_dict(a) == format_tenant_dict(b)
    assert sorted(a.evidence, key=repr) == sorted(_EVIDENCE, key=repr)
    context = CollectionContext(_NOW, _NOW, False, False, 10)
    delta = compare_capsules(build_capsule(a, [before], context), build_capsule(b, [after], context))
    assert not delta["observation"]["changed"]
    assert not delta["collection_regime"]["changed"]
    assert not delta["interpretation"]["changed"]


def test_canonical_evidence_preserves_duplicates_and_actual_fact_changes() -> None:
    duplicated = SourceResult(source_name="dns_records", evidence=(_EVIDENCE[0], _EVIDENCE[0]))
    info = merge_results([duplicated], "example.com")
    assert info.evidence == (_EVIDENCE[0], _EVIDENCE[0])
    a = SourceResult(source_name="dns_records", evidence=(_EVIDENCE[0],), raw_dns_records=(("TXT", "synthetic-a"),))
    b = replace(a, evidence=(_EVIDENCE[1],), raw_dns_records=(("TXT", "synthetic-b"),))
    context = CollectionContext(_NOW, _NOW, False, False, 10)
    delta = compare_capsules(
        build_capsule(merge_results([a], "example.com"), [a], context),
        build_capsule(merge_results([b], "example.com"), [b], context),
    )
    assert delta["observation"]["changed"]


def test_older_normalizer_capsules_remain_valid_and_report_the_context_change() -> None:
    source = SourceResult(source_name="dns_records", evidence=_EVIDENCE)
    capsule = build_capsule(
        merge_results([source], "example.com"), [source], CollectionContext(_NOW, _NOW, False, False, 10)
    )
    assert capsule["interpretation_context"]["normalizer_version"] == "2"
    capsule["interpretation_context"]["normalizer_version"] = "1"
    del capsule["content_digest"]
    capsule["content_digest"] = content_digest(capsule)
    validate_capsule(capsule)
    replayed = replay_capsule(capsule)
    assert not replayed["interpretation_context_match"]
    assert capsule["interpretation_context"]["normalizer_version"] == "1"


@pytest.mark.asyncio
async def test_captures_of_shuffled_resolver_answers_have_no_interpretation_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = ["10 mx1.improvmx.com", "20 mx2.forwardemail.net"]

    async def resolve(name: str, kind: str, **_kwargs: object) -> list[str]:
        return answers.copy() if (name, kind) == ("example.com", "MX") else []

    monkeypatch.setattr(dns_base, "safe_resolve", resolve)
    before = await dns_source.DNSSource().lookup("example.com", skip_ct=True)
    answers.reverse()
    after = await dns_source.DNSSource().lookup("example.com", skip_ct=True)
    assert before.evidence != after.evidence
    context = CollectionContext(_NOW, _NOW, False, False, 10)
    delta = compare_capsules(
        build_capsule(merge_results([before], "example.com"), [before], context),
        build_capsule(merge_results([after], "example.com"), [after], context),
    )
    assert not delta["observation"]["changed"]
    assert not delta["interpretation"]["changed"]


@pytest.mark.parametrize(
    "raw",
    [
        "www.example.com",
        "WWW.example.com.",
        "https://www.example.com/path",
        "www.www.example.com",
        "www.example.org",
        "www.example.net",
    ],
)
def test_exact_www_is_literal_and_normalization_is_idempotent(raw: str) -> None:
    host = validate_domain(raw, apex=False)
    expected = (
        "www.www.example.com"
        if raw == "www.www.example.com"
        else (
            "www.example.org"
            if raw.endswith(".org")
            else "www.example.net"
            if raw.endswith(".net")
            else "www.example.com"
        )
    )
    assert host == expected
    assert validate_domain(host, apex=False) == host
    assert validate_domain(raw) == expected.removeprefix("www.").removeprefix("www.")


@pytest.mark.parametrize("tag", ["issue", "issuewild", "issuemail", "iodef"])
def test_caa_evidence_preserves_balanced_record_quotes(tag: str) -> None:
    raw = f'0 {tag} "ca.example"'
    assert parse_rdata(raw) == raw
    assert parse_rdata('"v=spf1 " "-all"') == "v=spf1 -all"
    assert parse_rdata("ns.example.com.") == "ns.example.com"


@pytest.fixture
def isolated_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    with collection_scope(OPERATOR_POLICY):
        yield tmp_path


@pytest.mark.parametrize("single", [False, True])
def test_other_policy_cache_is_labeled_without_admitting_or_rendering_its_payload(
    isolated_cache: Path, single: bool
) -> None:
    other = CollectionPolicy("caller-safe", ("1.1.1.1",), "cloudflare-dns.com")
    info = TenantInfo(
        tenant_id=None, display_name="private-sentinel", default_domain="example.com", queried_domain="example.com"
    )
    with collection_scope(other):
        ct_cache_put("example.com", ["private-sentinel.example.com"], None, "private-provider-sentinel")
        cache_put("example.com", info)
    assert isolated_cache.is_dir()
    assert ct_cache_get("example.com") is None
    assert cache_get("example.com") is None
    inspection = inspect_result_cache("example.com")
    assert inspection.other_policy
    assert not inspection.failed
    assert inspection.entry is None
    command = ["cache", "show", "example.com"] if single else ["cache", "show"]
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 0, result.output
    assert "other collection policy" in result.output.lower()
    assert "not reusable here" in result.output
    assert "Inspection failures" not in result.output
    assert "private-sentinel" not in result.output
    assert "private-provider-sentinel" not in result.output


def test_www_literal_cache_entries_do_not_alias_the_apex(isolated_cache: Path) -> None:
    for domain in ("example.com", "www.example.com"):
        cache_put(domain, TenantInfo(tenant_id=None, display_name="", default_domain=domain, queried_domain=domain))
        ct_cache_put(domain, [f"app.{domain}"], None, "synthetic")
        result = cache_get(domain)
        assert result is not None
        assert result.queried_domain == domain
    literal = CliRunner().invoke(app, ["cache", "show", "www.example.com", "--exact"])
    ordinary = CliRunner().invoke(app, ["cache", "show", "www.example.com"])
    assert literal.exit_code == ordinary.exit_code == 0
    assert next(line.strip() for line in literal.output.splitlines() if line.strip()) == "www.example.com"
    assert next(line.strip() for line in ordinary.output.splitlines() if line.strip()) == "example.com"
    assert isolated_cache.is_dir()


def test_exact_www_cli_forwards_and_serializes_the_literal_host(
    monkeypatch: pytest.MonkeyPatch, isolated_cache: Path
) -> None:
    calls: list[str] = []

    async def resolve(domain: str, **_kwargs: object) -> tuple[TenantInfo, list[SourceResult]]:
        calls.append(domain)
        return TenantInfo(tenant_id=None, display_name="", default_domain=domain, queried_domain=domain), []

    monkeypatch.setattr(resolver_module, "resolve_tenant", resolve)
    result = CliRunner().invoke(app, ["WWW.example.com", "--exact", "--no-cache", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["queried_domain"] == "www.example.com"
    assert calls == ["www.example.com"]
    assert isolated_cache.is_dir()


@pytest.mark.parametrize("layer", ["ct", "result"])
@pytest.mark.parametrize("corruption", ["version", "domain", "policy", "json"])
def test_invalid_other_policy_envelopes_still_fail_inspection(
    isolated_cache: Path, layer: str, corruption: str
) -> None:
    other = CollectionPolicy("caller-safe", ("1.1.1.1",), "cloudflare-dns.com")
    with collection_scope(other):
        if layer == "ct":
            ct_cache_put("example.com", [], None, "synthetic")
        else:
            cache_put(
                "example.com",
                TenantInfo(tenant_id=None, display_name="", default_domain="example.com", queried_domain="example.com"),
            )
    path = (ct_cache_dir() if layer == "ct" else cache_dir()) / "example.com.json"
    data = json.loads(path.read_text())
    if corruption == "json":
        path.write_text("not JSON")
    else:
        if corruption == "version":
            data["_cache_version"] = -1
        elif corruption == "domain":
            data["domain" if layer == "ct" else "queried_domain"] = "other.invalid"
        else:
            data["_resolution_policy_id"] = "invalid"
        path.write_text(json.dumps(data))
    assert isolated_cache.is_dir()
    result = CliRunner().invoke(app, ["cache", "show", "example.com"])
    assert result.exit_code == 4
    assert "could not inspect" in result.output


class _OfflineResolver:
    async def resolve(self, _name: str, _kind: str, **_kwargs: object) -> None:
        raise dns.resolver.NoNameservers()


@pytest.fixture
def _real_cert_intel(_mock_crtsh: object) -> Iterator[None]:
    with patch.object(dns_source, "_detect_cert_intel", dns_infra.detect_cert_intel):
        yield


def _install_offline_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(
        _self: object, _domain: str
    ) -> tuple[list[str], CertSummary | None, InfrastructureClusterReport | None]:
        raise RuntimeError("synthetic offline CT transport")

    monkeypatch.setattr(dns_base, "get_resolver", _OfflineResolver)
    monkeypatch.setattr(CrtshProvider, "query", refuse)
    monkeypatch.setattr(CertSpotterProvider, "query", refuse)
    monkeypatch.setattr(resolver_module, "default_pool", lambda: SourcePool([dns_source.DNSSource()]))


@pytest.mark.asyncio
@pytest.mark.usefixtures("_real_cert_intel")
@pytest.mark.parametrize("payload", ["empty", "empty_graph", "empty_summary", "names", "summary"])
async def test_only_real_cached_ct_observations_can_recover_an_offline_dns_source(
    monkeypatch: pytest.MonkeyPatch, isolated_cache: Path, payload: str
) -> None:
    names = ["www.example.com"] if payload == "names" else []
    summary = (
        CertSummary(1 if payload == "summary" else 0, 1, 0, 0, 0, ("Synthetic CA",)) if "summary" in payload else None
    )
    graph = InfrastructureClusterReport((), 0, "skipped", 0, 0) if payload == "empty_graph" else None
    ct_cache_put("example.com", names, summary, "synthetic", infrastructure_clusters=graph)
    assert isolated_cache.is_dir()

    _install_offline_dns(monkeypatch)
    result = await dns_source.DNSSource().lookup("example.com", skip_ct=False)
    real_data = payload == "names"
    assert result.source_unavailable is not real_data
    assert (result.error is None) is real_data
    if real_data:
        assert result.ct_attempt_outcome == "cache_hit"
        assert result.ct_cache_age_days == 0
    else:
        with pytest.raises(ReconLookupError, match="DNS resolution unavailable") as caught:
            await resolve_tenant("example.com", pool=SourcePool([dns_source.DNSSource()]))
        assert caught.value.error_type == "all_sources_failed"


@pytest.mark.parametrize("command", [["example.com", "--no-cache"], ["review", "example.com", "--json"]])
@pytest.mark.usefixtures("_real_cert_intel")
def test_empty_ct_cache_cannot_turn_offline_cli_or_review_into_success(
    monkeypatch: pytest.MonkeyPatch, isolated_cache: Path, command: list[str]
) -> None:
    _install_offline_dns(monkeypatch)
    ct_cache_put(
        "example.com",
        [],
        None,
        "synthetic",
        infrastructure_clusters=InfrastructureClusterReport((), 0, "skipped", 0, 0),
    )
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 4, result.output
    assert "1 matched" not in result.output
    if command[0] == "review":
        assert json.loads(result.stdout)["workflow"]["status"] == "failed"
    assert isolated_cache.is_dir()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C=US, O=SSL Corporation, CN=Synthetic CA 1", "SSL.com"),
        ("C=US, O=SSL Corporation, CN=Synthetic CA 2", "SSL.com"),
        ("SSL.com", "SSL.com"),
        ("O=Sectigo Limited,CN=Synthetic CA", "Sectigo"),
        (r"C=US,O=Synthetic CA\, Inc.,CN=Intermediate", "Synthetic CA, Inc."),
        ('C=US,O="Synthetic CA, Inc.",CN=Intermediate', "Synthetic CA, Inc."),
        (r"O=Synthetic\2C CA,CN=Intermediate", "Synthetic, CA"),
        ("OU=Section+O=Synthetic CA,CN=Intermediate", "Synthetic CA"),
        ("2.5.4.10=Synthetic CA", "Synthetic CA"),
        ("CN=Synthetic CA", "Synthetic CA"),
        ("O=Second CA+O=First CA", "First CA / Second CA"),
        ('O="unfinished', "Unknown issuer"),
        ("O=unfinished\\", "Unknown issuer"),
        ("O=#010203,CN=Synthetic CA", "Synthetic CA"),
        ("O=,C=US", "Unknown issuer"),
        ("Evil\x00 CA\n", "Evil CA"),
    ],
)
def test_issuer_labels_are_bounded_and_do_not_depend_on_dn_layout(raw: str, expected: str) -> None:
    assert issuer_display_name(raw) == expected
    assert len(issuer_display_name("x" * 10000)) <= 200


def test_provider_summary_aggregates_equivalent_issuer_labels() -> None:
    entries = [
        {
            "issuer_id": index,
            "issuer_name": name,
            "not_before": "2026-10-01T00:00:00Z",
            "not_after": "2026-12-01T00:00:00Z",
        }
        for index, name in enumerate(
            ["C=US, O=SSL Corporation, CN=Synthetic CA 1", "SSL.com", "O=Sectigo Limited,CN=Synthetic CA"], start=1
        )
    ]
    summary = build_cert_summary(entries, _NOW)
    assert summary is not None
    assert summary.top_issuers == ("SSL.com", "Sectigo")
    assert summary.cert_count == summary.issuer_diversity == 3


def test_old_cache_labels_are_projected_without_rewriting_stored_artifacts(isolated_cache: Path) -> None:
    raw_label = "C=US, O=SSL Corporation, CN=Synthetic CA"
    summary = CertSummary(2, 1, 0, 1, 2, (raw_label, "SSL.com"))
    info = TenantInfo(
        tenant_id=None,
        display_name="",
        default_domain="example.com",
        queried_domain="example.com",
        cert_summary=summary,
    )
    ct_cache_put("example.com", [], summary, "synthetic")
    cache_put("example.com", info)
    ct_path = ct_cache_dir() / "example.com.json"
    result_path = cache_dir() / "example.com.json"
    before = ct_path.read_bytes(), result_path.read_bytes()
    ct = ct_cache_get("example.com")
    cached = cache_get("example.com")
    assert ct is not None
    assert ct.cert_summary is not None
    assert cached is not None
    assert cached.cert_summary is not None
    assert ct.cert_summary.top_issuers == cached.cert_summary.top_issuers == ("SSL.com",)
    assert ct.cert_summary.cert_count == cached.cert_summary.cert_count == 2
    assert (ct_path.read_bytes(), result_path.read_bytes()) == before
    assert isolated_cache.is_dir()


@pytest.mark.parametrize("command", [["example.com", "--no-cache"], ["review", "example.com", "--json"]])
@pytest.mark.usefixtures("_real_cert_intel")
def test_cached_cert_summary_with_zero_subdomains_cannot_turn_offline_cli_into_success(
    monkeypatch: pytest.MonkeyPatch, isolated_cache: Path, command: list[str]
) -> None:
    _install_offline_dns(monkeypatch)
    ct_cache_put(
        "example.com",
        [],
        CertSummary(9, 9, 0, 0, 0, ("Synthetic CA",)),
        "certspotter",
    )
    result = CliRunner().invoke(app, command)
    assert result.exit_code == 4, result.output
    assert "1 matched" not in result.output
    if command[0] == "review":
        assert json.loads(result.stdout)["workflow"]["status"] == "failed"
    assert isolated_cache.is_dir()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_real_cert_intel")
async def test_soft_empty_ct_with_no_cache_does_not_set_provider_used_or_report_recovered(
    monkeypatch: pytest.MonkeyPatch, isolated_cache: Path
) -> None:
    async def empty_query(
        _self: object, _domain: str
    ) -> tuple[list[str], CertSummary | None, InfrastructureClusterReport | None]:
        return [], None, None

    monkeypatch.setattr(CrtshProvider, "query", empty_query)
    monkeypatch.setattr(CertSpotterProvider, "query", empty_query)
    result = await dns_source.DNSSource().lookup("example.com", skip_ct=False)
    assert result.ct_provider_used is None
    assert result.ct_attempt_outcome == "cache_miss"
    assert "certspotter" in result.degraded_sources
    assert "crt.sh" in result.degraded_sources
    assert isolated_cache.is_dir()
