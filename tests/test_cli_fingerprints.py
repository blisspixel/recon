"""Characterization tests for the `recon fingerprints` CLI surface."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from recon_tool.cli import app
from recon_tool.exit_codes import EXIT_VALIDATION
from recon_tool.fingerprints import Fingerprint, load_fingerprints
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo

runner = CliRunner()
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _plain(text: str) -> str:
    return ANSI_RE.sub("", text)


def _sample_fingerprint() -> Fingerprint:
    return load_fingerprints()[0]


def _unique_prefix_slug() -> Fingerprint:
    for fp in load_fingerprints():
        if len(fp.slug) > 5:
            return fp
    pytest.fail("expected at least one fingerprint slug long enough for suggestion coverage")


def _name_only_search_token() -> str:
    for fp in load_fingerprints():
        excluded = " ".join(
            [fp.slug, fp.category, *(d.pattern for d in fp.detections), *(d.description for d in fp.detections)]
        ).lower()
        for token in re.findall(r"[a-z0-9]+", fp.name.lower()):
            if len(token) >= 4 and token not in excluded:
                return token
    pytest.fail("expected a fingerprint with a searchable name-only token")


def test_list_without_filters_prints_compact_category_summary() -> None:
    result = runner.invoke(app, ["fingerprints", "list"])

    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert "fingerprints across" in plain_output
    assert "recon fingerprints" in plain_output
    assert "search" in plain_output
    assert "<query>" in plain_output


def test_list_json_emits_fingerprint_summaries() -> None:
    result = runner.invoke(app, ["fingerprints", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload
    assert {
        "slug",
        "name",
        "category",
        "confidence",
        "detection_types",
        "detection_count",
    } <= payload[0].keys()


def test_list_category_short_name_matches_word_prefix_not_raw_substring() -> None:
    expected_categories = {
        fp.category
        for fp in load_fingerprints()
        if any(word.startswith("ai") for word in re.findall(r"[a-z0-9]+", fp.category.lower()))
    }
    if not expected_categories:
        pytest.skip("catalog currently has no AI-prefixed category")

    result = runner.invoke(app, ["fingerprints", "list", "--category", "ai", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    categories = {entry["category"] for entry in payload}
    assert categories == expected_categories
    assert "Email" not in categories


def test_list_filter_with_no_matches_exits_cleanly() -> None:
    result = runner.invoke(app, ["fingerprints", "list", "--category", "zzz-no-such-category"])

    assert result.exit_code == 0
    assert "No fingerprints match those filters" in result.output


def test_list_filtered_text_prints_full_rows() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(app, ["fingerprints", "list", "--category", fp.category])

    assert result.exit_code == 0
    assert "fingerprint" in result.output
    assert fp.slug in result.output
    assert fp.name in result.output


def test_list_detection_type_filter_limits_json_results() -> None:
    detection_type = _sample_fingerprint().detections[0].type

    result = runner.invoke(app, ["fingerprints", "list", "--type", detection_type, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload
    assert all(detection_type in entry["detection_types"] for entry in payload)


def test_search_json_returns_matching_slug() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(app, ["fingerprints", "search", fp.slug, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert any(entry["slug"] == fp.slug for entry in payload)


def test_search_empty_query_exits_validation() -> None:
    result = runner.invoke(app, ["fingerprints", "search", "   "])

    assert result.exit_code == EXIT_VALIDATION
    assert "Empty search query" in result.output


def test_search_no_matches_prints_discovery_hint() -> None:
    result = runner.invoke(app, ["fingerprints", "search", "zzz-no-such-fingerprint"])

    assert result.exit_code == 0
    assert "No fingerprints match" in result.output
    assert "recon fingerprints list" in result.output


def test_search_text_prints_table_and_next_hint() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(app, ["fingerprints", "search", fp.slug])

    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert fp.slug in plain_output
    assert "recon fingerprints show" in plain_output
    assert "<slug>" in plain_output


def test_search_ranking_covers_name_category_and_detection_pattern_matches() -> None:
    name_token = _name_only_search_token()
    category_query = "infrastructure"
    pattern_query = "verification"

    for query in (name_token, category_query, pattern_query):
        result = runner.invoke(app, ["fingerprints", "search", query, "--json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout), query


def test_show_json_payload_matches_fingerprint_object() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(app, ["fingerprints", "show", fp.slug, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["slug"] == fp.slug
    assert payload["name"] == fp.name
    assert payload["category"] == fp.category
    assert payload["confidence"] == fp.confidence
    assert len(payload["detections"]) == len(fp.detections)


def test_show_synthetic_slug_json_documents_probe_origin() -> None:
    result = runner.invoke(app, ["fingerprints", "show", "self-hosted-mail", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["slug"] == "self-hosted-mail"
    assert payload["synthetic"] is True
    assert "MX records" in payload["note"]


def test_show_text_mode_prints_detection_rules() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(app, ["fingerprints", "show", fp.slug])

    assert result.exit_code == 0
    plain_output = _plain(result.output)
    assert fp.name in plain_output
    assert "Detection rules" in plain_output
    assert fp.detections[0].pattern in plain_output


def test_show_synthetic_slug_text_mode_documents_probe_origin() -> None:
    result = runner.invoke(app, ["fingerprints", "show", "exchange-onprem"])

    assert result.exit_code == 0
    assert "Exchange Server" in result.output
    assert "synthetic slug" in result.output


def test_show_unknown_slug_exits_validation_with_suggestion() -> None:
    fp = _unique_prefix_slug()
    needle = fp.slug[: max(3, len(fp.slug) - 2)]

    result = runner.invoke(app, ["fingerprints", "show", needle])

    assert result.exit_code == EXIT_VALIDATION
    assert "No fingerprint with slug" in result.output
    assert "Did you mean" in result.output


def test_show_unknown_slug_without_suggestion_exits_validation() -> None:
    result = runner.invoke(app, ["fingerprints", "show", "zzz-no-such-fingerprint"])

    assert result.exit_code == EXIT_VALIDATION
    assert "No fingerprint with slug" in result.output
    assert "Did you mean" not in result.output


def test_new_duplicate_slug_exits_validation() -> None:
    fp = _sample_fingerprint()

    result = runner.invoke(
        app,
        [
            "fingerprints",
            "new",
            fp.slug,
            "--name",
            fp.name,
            "--pattern",
            "^duplicate-verification=",
        ],
    )

    assert result.exit_code == EXIT_VALIDATION
    assert "already exists" in result.output


def test_new_invalid_detection_type_exits_validation() -> None:
    result = runner.invoke(
        app,
        [
            "fingerprints",
            "new",
            "cycle31-invalid-detection",
            "--name",
            "Cycle 31 Invalid Detection",
            "--type",
            "not-a-type",
            "--pattern",
            "^cycle31-invalid=",
        ],
    )

    assert result.exit_code == EXIT_VALIDATION
    assert "Schema validation failed" in result.output


def test_new_broad_pattern_exits_validation() -> None:
    result = runner.invoke(
        app,
        [
            "fingerprints",
            "new",
            "cycle31-broad-pattern",
            "--name",
            "Cycle 31 Broad Pattern",
            "--pattern",
            ".*",
        ],
    )

    assert result.exit_code == EXIT_VALIDATION
    assert "Pattern too broad" in result.output


def test_new_valid_fingerprint_writes_candidate_yaml(tmp_path: Path) -> None:
    output = tmp_path / "candidate.yaml"
    category = _sample_fingerprint().category

    result = runner.invoke(
        app,
        [
            "fingerprints",
            "new",
            "cycle31-example-service",
            "--name",
            "Cycle 31 Example Service",
            "--category",
            category,
            "--pattern",
            "^cycle31-example-verification=",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Wrote" in result.output
    text = output.read_text(encoding="utf-8")
    assert "cycle31-example-service" in text
    assert "^cycle31-example-verification=" in text


def test_new_valid_fingerprint_prints_candidate_yaml() -> None:
    result = runner.invoke(
        app,
        [
            "fingerprints",
            "new",
            "cycle31-stdout-service",
            "--name",
            "Cycle 31 Stdout Service",
            "--pattern",
            "^cycle31-stdout-verification=",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Slug, schema, and specificity all pass" in result.output
    assert "cycle31-stdout-service" in result.output


def test_fingerprints_test_unknown_slug_exits_validation() -> None:
    result = runner.invoke(app, ["fingerprints", "test", "zzz-no-such-fingerprint"])

    assert result.exit_code == EXIT_VALIDATION
    assert "No fingerprint with slug" in result.output


def test_fingerprints_test_missing_corpus_exits_validation(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["fingerprints", "test", _sample_fingerprint().slug, "--corpus", str(tmp_path / "missing.txt")],
    )

    assert result.exit_code == EXIT_VALIDATION
    assert "Corpus file not found" in result.output


def test_fingerprints_test_default_example_corpus_runs_without_user_corpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slug = _sample_fingerprint().slug

    async def fake_resolve_tenant(domain: str, timeout: float):
        return (
            TenantInfo(
                tenant_id=None,
                display_name=domain,
                default_domain=domain,
                queried_domain=domain,
                confidence=ConfidenceLevel.LOW,
            ),
            None,
        )

    import recon_tool.resolver as resolver

    monkeypatch.setattr(resolver, "resolve_tenant", fake_resolve_tenant)

    result = runner.invoke(app, ["fingerprints", "test", slug])

    assert result.exit_code == 0, result.output
    plain_output = _plain(result.output)
    assert "fictional-company example corpus" in plain_output
    assert "0 of" in plain_output


def test_fingerprints_test_json_is_machine_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slug = _sample_fingerprint().slug
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("# comment\nhit.example\nmiss.example\nerror.example\n", encoding="utf-8")

    async def fake_resolve_tenant(domain: str, timeout: float):
        assert timeout == 60.0
        if domain == "error.example":
            raise RuntimeError("resolver failure")
        matched = domain == "hit.example"
        info = TenantInfo(
            tenant_id=None,
            display_name=domain,
            default_domain=domain,
            queried_domain=domain,
            confidence=ConfidenceLevel.LOW,
            sources=("test",),
            services=(),
            slugs=(slug,) if matched else (),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value="[bold]cycle31\x1b[31m",
                    rule_name="cycle31",
                    slug=slug,
                ),
            )
            if matched
            else (),
        )
        return info, None

    import recon_tool.resolver as resolver

    monkeypatch.setattr(resolver, "resolve_tenant", fake_resolve_tenant)

    result = runner.invoke(app, ["fingerprints", "test", slug, "--corpus", str(corpus), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload == [
        {"domain": "hit.example", "matched": True, "detail": "TXT:[bold]cycle31\x1b[31m"},
        {"domain": "miss.example", "matched": False, "detail": ""},
        {"domain": "error.example", "matched": False, "detail": "error: resolver failure"},
    ]


def test_fingerprints_test_text_mode_escapes_match_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slug = _sample_fingerprint().slug
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("hit.example\nmiss.example\n", encoding="utf-8")

    async def fake_resolve_tenant(domain: str, timeout: float):
        matched = domain == "hit.example"
        info = TenantInfo(
            tenant_id=None,
            display_name=domain,
            default_domain=domain,
            queried_domain=domain,
            confidence=ConfidenceLevel.LOW,
            slugs=(slug,) if matched else (),
            evidence=(
                EvidenceRecord(
                    source_type="TXT",
                    raw_value="[bold]cycle31\x1b[31m",
                    rule_name="cycle31",
                    slug=slug,
                ),
            )
            if matched
            else (),
        )
        return info, None

    import recon_tool.resolver as resolver

    monkeypatch.setattr(resolver, "resolve_tenant", fake_resolve_tenant)

    result = runner.invoke(app, ["fingerprints", "test", slug, "--corpus", str(corpus)])

    assert result.exit_code == 0, result.output
    plain_output = _plain(result.output)
    assert "MATCH" in plain_output
    assert "1 of 2 matched" in plain_output
    assert "\x1b[31m" not in result.output
    assert "recon fingerprints show" in plain_output


def test_fingerprints_check_missing_path_exits_validation(tmp_path: Path) -> None:
    result = runner.invoke(app, ["fingerprints", "check", str(tmp_path / "missing.yaml")])

    assert result.exit_code == EXIT_VALIDATION
    assert "Path not found" in result.output


def test_fingerprints_check_default_catalog_passes_quietly() -> None:
    result = runner.invoke(app, ["fingerprints", "check", "--quiet"])

    assert result.exit_code == 0
    assert "Validated" in result.output
