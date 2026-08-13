"""Contracts for the private v2.11 evaluation-frame preparer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from validation.prepare_quality_evaluation_frame import (
    FramePreparationConfig,
    generate_private_sampling_key,
    main,
    prepare_frame,
    public_summary,
)

SAMPLING_KEY = bytes(range(32))
ROOT = Path(__file__).resolve().parents[1]


def _ranked_source(path: Path) -> None:
    path.write_text(
        "rank,domain\n1,alpha.invalid\n2,beta.invalid\n3,gamma.invalid\n4,delta.invalid\n5,epsilon.invalid\n",
        encoding="utf-8",
    )


def test_prepare_frame_is_deterministic_and_excludes_development_corpus(tmp_path: Path) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    _ranked_source(ranked)
    excluded.write_text("WWW.Alpha.invalid\nbeta.invalid\nbeta.invalid\nnot a domain\n", encoding="utf-8")

    first = prepare_frame(
        ranked,
        excluded,
        config=FramePreparationConfig(5, 2, SAMPLING_KEY, "frozen-context"),
    )
    second = prepare_frame(
        ranked,
        excluded,
        config=FramePreparationConfig(5, 2, SAMPLING_KEY, "frozen-context"),
    )

    assert first == second
    assert len(first.selected) == 2
    assert {row.domain for row in first.selected}.isdisjoint({"alpha.invalid", "beta.invalid"})
    assert first.development_overlap_excluded == 2
    assert first.eligible_universe_rows == 3
    assert first.exclusion_normalized_rows == 1
    assert first.exclusion_duplicate_rows_removed == 1
    assert first.exclusion_invalid_rows_excluded == 1
    assert first.frame_sha256 == hashlib.sha256(first.frame_bytes).hexdigest()


def test_public_summary_has_no_frame_membership(tmp_path: Path) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    _ranked_source(ranked)
    excluded.write_text("alpha.invalid\n", encoding="utf-8")
    frame = prepare_frame(
        ranked,
        excluded,
        config=FramePreparationConfig(5, 2, SAMPLING_KEY, "frozen-context"),
    )

    summary = public_summary(frame, list_id="A1B2C", context="frozen-context", written=False)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["privacy"] == {
        "frame_written": False,
        "identifiers_printed": 0,
        "per_domain_rows_printed": 0,
        "network_requests": 0,
    }
    assert summary["sampling"]["first_stage_inclusion_probability"] == "2/4"
    assert summary["sampling"]["private_key_sha256"] == hashlib.sha256(SAMPLING_KEY).hexdigest()
    assert "00010203" not in serialized
    assert all(row.domain not in serialized for row in frame.selected)


def test_frozen_reference_label_requires_concordant_identity_endpoints() -> None:
    preregistration = (ROOT / "docs" / "quality-baseline-preregistration.md").read_text(encoding="utf-8")
    declaration = (ROOT / "docs" / "quality-evaluation-frame-declaration.md").read_text(encoding="utf-8")

    assert "{`Federated`, `Managed`} **and** OIDC discovery resolves a tenant" in preregistration
    assert "returns `Federated` or `Managed`, and OIDC" in declaration
    assert "`Managed`}, or OIDC discovery resolves a tenant" not in preregistration
    assert "returns `Federated` or `Managed`, or OIDC" not in declaration


def test_ranked_source_contract_fails_closed_without_identifier_echo(tmp_path: Path) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    ranked.write_text("rank,domain\n1,alpha.invalid\n3,private-target.invalid\n", encoding="utf-8")
    excluded.write_text("beta.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="breaks contiguous rank order") as captured:
        prepare_frame(
            ranked,
            excluded,
            config=FramePreparationConfig(2, 1, SAMPLING_KEY, "frozen-context"),
        )

    assert "private-target" not in str(captured.value)


def test_invalid_ranked_source_rows_are_excluded_without_identifier_echo(tmp_path: Path) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    ranked.write_text(
        "rank,domain\n1,alpha.invalid\n2,_private-target.invalid\n3,beta.invalid\n",
        encoding="utf-8",
    )
    excluded.write_text("gamma.invalid\n", encoding="utf-8")

    frame = prepare_frame(
        ranked,
        excluded,
        config=FramePreparationConfig(3, 2, SAMPLING_KEY, "frozen-context"),
    )
    serialized = json.dumps(public_summary(frame, list_id="A1B2C", context="frozen-context", written=False))

    assert frame.source_invalid_rows_excluded == 1
    assert "private-target" not in serialized


def test_preflight_writes_nothing_and_write_mode_is_exclusive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    output = tmp_path / "private" / "frame.csv"
    key_file = tmp_path / "private" / "sampling-key.hex"
    _ranked_source(ranked)
    excluded.write_text("alpha.invalid\n", encoding="utf-8")
    key_file.parent.mkdir(parents=True)
    key_file.write_bytes(SAMPLING_KEY.hex().encode("ascii") + b"\n")
    common = [
        "prepare",
        "--ranked-source",
        str(ranked),
        "--exclude-corpus",
        str(excluded),
        "--output",
        str(output),
        "--sampling-key-file",
        str(key_file),
        "--tranco-list-id",
        "A1B2C",
        "--expected-source-rows",
        "5",
        "--sample-size",
        "2",
        "--sampling-context",
        "frozen-context",
    ]

    assert main([*common, "--preflight"]) == 0
    preflight = json.loads(capsys.readouterr().out)
    assert preflight["privacy"]["frame_written"] is False
    assert not output.exists()

    assert main([*common, "--write-private-frame"]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["privacy"]["frame_written"] is True
    assert output.read_bytes().startswith(b"rank,domain\n")
    assert written["sampling"]["frame_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="refusing to replace"):
        main([*common, "--write-private-frame"])


def test_invalid_public_parameters_are_rejected(tmp_path: Path) -> None:
    ranked = tmp_path / "ranked.csv"
    excluded = tmp_path / "excluded.txt"
    _ranked_source(ranked)
    excluded.write_text("alpha.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="sampling context"):
        prepare_frame(
            ranked,
            excluded,
            config=FramePreparationConfig(5, 2, SAMPLING_KEY, "unsafe context"),
        )

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        prepare_frame(
            ranked,
            excluded,
            config=FramePreparationConfig(5, 2, b"short", "safe-context"),
        )

    with pytest.raises(ValueError, match="expected exactly 4"):
        prepare_frame(
            ranked,
            excluded,
            config=FramePreparationConfig(4, 2, SAMPLING_KEY, "safe-context"),
        )


def test_private_key_generation_is_secret_and_exclusive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_file = tmp_path / "private" / "sampling-key.hex"

    assert main(["generate-key", "--output", str(key_file)]) == 0
    report = json.loads(capsys.readouterr().out)
    raw = key_file.read_bytes()

    assert len(raw) == 65
    assert report["private_key_sha256"] == hashlib.sha256(bytes.fromhex(raw.decode().strip())).hexdigest()
    assert report["key_printed"] is False
    assert raw.decode().strip() not in json.dumps(report)
    with pytest.raises(ValueError, match="refusing to replace"):
        generate_private_sampling_key(key_file)
