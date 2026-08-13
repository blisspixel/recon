"""Pure contract tests for the aggregate-only live characterization harness."""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest

import validation.characterize_live_quality as live_quality
from recon_tool.models import SourceResult, TenantInfo
from validation.characterize_live_quality import (
    MeasurementConfig,
    RunObservation,
    SelectionOptions,
    _ct_value_summary,
    _identifier_safe_logging,
    _load_canonical_corpus,
    _measure_one,
    _measure_warm_mcp,
    _mode_summary,
    _nearest_rank,
    main,
)


def _observation(
    *,
    ct_enabled: bool,
    slugs: frozenset[str] = frozenset(),
    services: frozenset[str] = frozenset(),
    evidence_count: int = 0,
) -> RunObservation:
    return RunObservation(
        ct_enabled=ct_enabled,
        success=True,
        failure_kind=None,
        resolver_seconds=2.0 if ct_enabled else 1.0,
        peak_allocation_bytes=2048,
        maximum_event_loop_lag_seconds=0.002,
        slow_callback_count=0,
        stage_seconds=(("dns_records", 0.5), ("json_render", 0.01)),
        degraded_markers=("crt.sh",) if ct_enabled else (),
        unavailable_source_count=0,
        partial=False,
        slugs=slugs,
        services=services,
        evidence_count=evidence_count,
        related_domain_count=1 if ct_enabled else 0,
        surface_attribution_count=1 if ct_enabled else 0,
        insight_count=1 if ct_enabled else 0,
        ct_subdomain_count=3 if ct_enabled else 0,
        ct_attempt_outcome="live_success" if ct_enabled else None,
        json_result_bytes=1500,
        disk_cache_write_seconds=0.01,
        warm_disk_read_render_seconds=0.02,
        mcp_warm_call_seconds=0.03,
        mcp_result_wire_bytes=1600,
    )


def test_corpus_loader_binds_raw_digest_and_canonical_rows(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    raw = b"# frozen frame\nalpha.invalid\nbeta.invalid\n"
    corpus.write_bytes(raw)

    selection = _load_canonical_corpus(corpus, options=SelectionOptions(maximum_rows=2))

    assert selection.domains == ("alpha.invalid", "beta.invalid")
    assert len(selection.source_sha256) == 64
    assert len(selection.selection_sha256) == 64
    assert selection.source_input_count == 2
    assert selection.source_eligible_count == 2
    assert selection.normalized_row_count == 0
    assert selection.duplicate_rows_removed == 0
    assert selection.invalid_rows_excluded == 0
    assert selection.invalid_row_policy == "reject-v1"
    assert selection.source_normalization == "strict-canonical-v1"
    assert selection.sampling_method == "all-canonical-rows-v1"


@pytest.mark.parametrize("row", ["ALPHA.invalid", "www.alpha.invalid", "https://alpha.invalid"])
def test_corpus_loader_rejects_noncanonical_rows(tmp_path: Path, row: str) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text(row + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="lowercase canonical apexes"):
        _load_canonical_corpus(corpus, options=SelectionOptions(maximum_rows=1))


def test_corpus_loader_rejects_duplicates_and_oversized_frames(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("alpha.invalid\nbeta.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="declared cap"):
        _load_canonical_corpus(corpus, options=SelectionOptions(maximum_rows=1))

    corpus.write_text("alpha.invalid\nalpha.invalid\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        _load_canonical_corpus(corpus, options=SelectionOptions(maximum_rows=2))


def test_seeded_sampling_is_deterministic_and_binds_selected_membership(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("alpha.invalid\nbeta.invalid\ngamma.invalid\ndelta.invalid\n", encoding="utf-8")

    first = _load_canonical_corpus(
        corpus,
        options=SelectionOptions(
            maximum_rows=2,
            sample_size=2,
            sampling_seed="stable-v1-20260812",
        ),
    )
    second = _load_canonical_corpus(
        corpus,
        options=SelectionOptions(
            maximum_rows=2,
            sample_size=2,
            sampling_seed="stable-v1-20260812",
        ),
    )

    assert first == second
    assert len(first.domains) == 2
    assert first.source_eligible_count == 4
    assert first.sampling_method == "sha256-rank-without-replacement-v1"
    assert first.sampling_seed == "stable-v1-20260812"


def test_explicit_source_normalization_records_changes_and_canonical_deduplication(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("WWW.Alpha.invalid\nalpha.invalid\nbeta.invalid\n", encoding="utf-8")

    selection = _load_canonical_corpus(
        corpus,
        options=SelectionOptions(maximum_rows=2, normalize_source=True),
    )

    assert selection.domains == ("alpha.invalid", "beta.invalid")
    assert selection.source_input_count == 3
    assert selection.source_eligible_count == 2
    assert selection.normalized_row_count == 1
    assert selection.duplicate_rows_removed == 1
    assert selection.source_normalization == "recon-apex-v1"


def test_invalid_source_rows_require_explicit_counted_exclusion(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("alpha.invalid\nnot a domain\nbeta.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed row"):
        _load_canonical_corpus(
            corpus,
            options=SelectionOptions(maximum_rows=2, normalize_source=True),
        )

    selection = _load_canonical_corpus(
        corpus,
        options=SelectionOptions(
            maximum_rows=2,
            normalize_source=True,
            exclude_invalid_source=True,
        ),
    )

    assert selection.domains == ("alpha.invalid", "beta.invalid")
    assert selection.source_input_count == 3
    assert selection.source_eligible_count == 2
    assert selection.invalid_rows_excluded == 1
    assert selection.invalid_row_policy == "exclude-and-count-v1"


def test_invalid_source_exclusion_requires_normalization(tmp_path: Path) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("alpha.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="requires explicit source normalization"):
        _load_canonical_corpus(
            corpus,
            options=SelectionOptions(maximum_rows=1, exclude_invalid_source=True),
        )


@pytest.mark.parametrize(
    ("sample_size", "seed", "message"),
    [(2, None, "provided together"), (None, "seed", "provided together"), (3, "seed", "declared maximum")],
)
def test_seeded_sampling_rejects_incomplete_or_oversized_declarations(
    tmp_path: Path,
    sample_size: int | None,
    seed: str | None,
    message: str,
) -> None:
    corpus = tmp_path / "frame.txt"
    corpus.write_text("alpha.invalid\nbeta.invalid\ngamma.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        _load_canonical_corpus(
            corpus,
            options=SelectionOptions(
                maximum_rows=2,
                sample_size=sample_size,
                sampling_seed=seed,
            ),
        )


def test_nearest_rank_uses_only_observed_values() -> None:
    assert _nearest_rank([5.0, 1.0, 4.0, 2.0, 3.0], 0.50) == 3.0
    assert _nearest_rank([5.0, 1.0, 4.0, 2.0, 3.0], 0.95) == 5.0


@pytest.mark.parametrize("logger_name", ["httpx.characterization-test", "asyncio"])
def test_identifier_safe_logging_suppresses_and_restores_existing_handlers(logger_name: str) -> None:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger(logger_name)
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        with _identifier_safe_logging():
            logger.info("private-target.invalid")
        logger.info("restored-safe-marker")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    assert stream.getvalue().strip() == "restored-safe-marker"


def test_mode_summary_contains_aggregates_only() -> None:
    summary = _mode_summary([_observation(ct_enabled=True, slugs=frozenset({"synthetic-vendor"}))])

    serialized = json.dumps(summary, sort_keys=True)
    assert summary["succeeded"] == 1
    assert summary["degraded_markers"] == {"crt.sh": 1}
    assert "synthetic-vendor" not in serialized
    assert "domain" not in serialized


def test_ct_value_summary_reports_paired_gain_without_signal_names() -> None:
    without = _observation(ct_enabled=False, slugs=frozenset({"base"}), services=frozenset({"Base"}))
    with_ct = _observation(
        ct_enabled=True,
        slugs=frozenset({"base", "ct-added"}),
        services=frozenset({"Base", "CT Added"}),
        evidence_count=2,
    )

    summary = _ct_value_summary([(without, with_ct)])

    assert summary["eligible_success_pairs"] == 1
    assert summary["pairs_with_any_observable_gain"] == 1
    assert summary["added_slug_count"]["p50"] == 1
    assert "ct-added" not in json.dumps(summary)


@pytest.mark.asyncio
async def test_warm_mcp_measurement_uses_seeded_cache_without_network() -> None:
    info = TenantInfo(
        tenant_id=None,
        display_name="Synthetic MCP Fixture",
        default_domain="alpha.invalid",
        queried_domain="alpha.invalid",
    )
    result = SourceResult(source_name="synthetic_fixture", display_name=info.display_name)

    elapsed, wire_bytes = await _measure_warm_mcp("alpha.invalid", info, [result])

    assert elapsed >= 0
    assert wire_bytes > 0


@pytest.mark.asyncio
async def test_measure_one_retains_safe_expected_failure_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail_pipeline(*_args: object, **_kwargs: object) -> None:
        raise live_quality._CharacterizationFailure("cache_roundtrip_miss")

    monkeypatch.setattr(live_quality, "default_pool", list)
    monkeypatch.setattr(live_quality, "_run_pipeline", _fail_pipeline)

    observation = await _measure_one(
        "alpha.invalid",
        ct_enabled=False,
        config=MeasurementConfig(timeout=1.0, slow_callback_seconds=0.05),
    )

    assert not observation.success
    assert observation.failure_kind == "cache_roundtrip_miss"


def test_preflight_validates_selection_without_network_or_writes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus = tmp_path / "frame.txt"
    output = tmp_path / "run" / "characterization.json"
    corpus.write_text("alpha.invalid\nbeta.invalid\ngamma.invalid\n", encoding="utf-8")

    result = main(
        [
            "--corpus",
            str(corpus),
            "--output",
            str(output),
            "--network-class",
            "wifi",
            "--maximum-rows",
            "2",
            "--sample-size",
            "2",
            "--sampling-seed",
            "preflight-test",
            "--normalize-source",
            "--exclude-invalid-source",
            "--preflight",
        ]
    )

    report = json.loads(capsys.readouterr().out)
    assert result == 0
    assert report["network"] == "not used"
    assert report["writes"] == 0
    assert report["eligible_domain_count"] == 2
    assert report["source_normalization"] == "recon-apex-v1"
    assert report["invalid_rows_excluded"] == 0
    assert report["invalid_row_policy"] == "exclude-and-count-v1"
    assert not output.exists()
