"""Tests for the private catalog rank-strata preparer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from validation import prepare_catalog_rank_frame as rank_preparer

TEST_KEY = bytes(range(32))
TEST_BANDS = (
    ("rank-1-1k", 1, 3),
    ("rank-1k-10k", 4, 6),
    ("rank-10k-100k", 7, 9),
    ("rank-100k-1m", 10, 12),
)


def _configure_small_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rank_preparer, "EXPECTED_SOURCE_ROWS", 12)
    monkeypatch.setattr(rank_preparer, "CANONICAL_BANDS", TEST_BANDS)


def _fixture(tmp_path: Path, *, sample_size: int = 2) -> tuple[Path, Path, Path, list[str]]:
    source = tmp_path / "private" / "ranked.csv"
    exclusion = tmp_path / "private" / "development.txt"
    key = tmp_path / "private" / "sampling-key.hex"
    plan = tmp_path / "private" / "rank-plan.json"
    source.parent.mkdir(parents=True)
    domains = [f"private-row-{index}.invalid" for index in range(1, 13)]
    source.write_text(
        "rank,domain\n" + "".join(f"{rank},{domain}\n" for rank, domain in enumerate(domains, start=1)),
        encoding="utf-8",
    )
    exclusion.write_text(f"{domains[0]}\n", encoding="utf-8")
    key.write_bytes(TEST_KEY.hex().encode("ascii") + b"\n")
    payload = {
        "schema_version": 1,
        "private": True,
        "source": {
            "path": str(source),
            "name": "Tranco fixture source",
            "revision": "A1B2C",
            "expected_rows": 12,
        },
        "development_exclusion": {
            "path": str(exclusion),
            "rule": "Exclude every namespace used during prior catalog development.",
        },
        "sampling": {
            "key_path": str(key),
            "context": "catalog-rank-test-01",
            "method": rank_preparer.SAMPLING_METHOD,
        },
        "bands": [
            {
                "id": band_id,
                "label": f"Private fixture band {minimum}-{maximum}",
                "minimum_rank": minimum,
                "maximum_rank": maximum,
                "sample_size": sample_size,
            }
            for band_id, minimum, maximum in TEST_BANDS
        ],
    }
    plan.write_text(json.dumps(payload), encoding="utf-8")
    return plan, source, exclusion, domains


def test_rank_strata_are_deterministic_disjoint_and_development_excluded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, domains = _fixture(tmp_path)
    output = tmp_path / "private" / "rank-output"

    first_payloads, first_manifest = rank_preparer.prepare_rank_strata(
        plan,
        output,
        prepared_at="2026-08-13T12:00:00Z",
    )
    second_payloads, second_manifest = rank_preparer.prepare_rank_strata(
        plan,
        output,
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert first_payloads == second_payloads
    assert first_manifest == second_manifest
    selected = [domain for payload in first_payloads.values() for domain in payload.decode("ascii").splitlines()]
    assert len(selected) == 8
    assert len(set(selected)) == 8
    assert domains[0] not in selected
    assert first_manifest["bands"][0]["development_overlap_excluded"] == 1
    assert all(band["selected_rows"] == 2 for band in first_manifest["bands"])


def test_public_summary_omits_membership_paths_labels_rules_and_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, source, exclusion, domains = _fixture(tmp_path)
    _, manifest = rank_preparer.prepare_rank_strata(
        plan,
        tmp_path / "private" / "rank-output",
        prepared_at="2026-08-13T12:00:00Z",
    )

    summary = rank_preparer.public_summary(manifest, written=False)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["privacy"] == {
        "private_artifacts_written": False,
        "identifiers_printed": 0,
        "per_domain_rows_printed": 0,
        "network_requests": 0,
    }
    assert str(source) not in serialized
    assert str(exclusion) not in serialized
    assert "Exclude every namespace" not in serialized
    assert "Private fixture band" not in serialized
    assert TEST_KEY.hex() not in serialized
    assert all(domain not in serialized for domain in domains)


def test_bom_exclusion_remains_disjoint_in_rank_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_small_source(monkeypatch)
    plan, _, exclusion, domains = _fixture(tmp_path)
    exclusion.write_bytes(b"\xef\xbb\xbf" + f"{domains[0]}\nnot-in-source.invalid\n".encode("ascii"))

    payloads, manifest = rank_preparer.prepare_rank_strata(
        plan, tmp_path / "private" / "rank-output", prepared_at="2026-08-13T12:00:00Z"
    )

    assert domains[0] not in {domain for raw in payloads.values() for domain in raw.decode("ascii").splitlines()}
    assert manifest["development_exclusion"]["canonical_rows"] == 2
    assert manifest["development_exclusion"]["invalid_rows_excluded"] == 0
    assert manifest["bands"][0]["development_overlap_excluded"] == 1
    assert manifest["development_exclusion"]["sha256"] == hashlib.sha256(exclusion.read_bytes()).hexdigest()


def test_manifest_commits_to_plan_source_exclusions_key_and_each_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, source, exclusion, _ = _fixture(tmp_path)
    payloads, manifest = rank_preparer.prepare_rank_strata(
        plan,
        tmp_path / "private" / "rank-output",
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert manifest["plan_digest_sha256"] == hashlib.sha256(plan.read_bytes()).hexdigest()
    assert manifest["source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["development_exclusion"]["sha256"] == hashlib.sha256(exclusion.read_bytes()).hexdigest()
    assert manifest["sampling"]["private_key_sha256"] == hashlib.sha256(TEST_KEY).hexdigest()
    for band in manifest["bands"]:
        filename = f"{band['id']}.txt"
        assert band["frame_sha256"] == hashlib.sha256(payloads[filename]).hexdigest()
    digest_payload = dict(manifest)
    supplied = digest_payload.pop("manifest_digest_sha256")
    assert supplied == hashlib.sha256(rank_preparer._canonical_json(digest_payload)).hexdigest()


def test_write_is_exclusive_and_cleans_only_new_reservations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, _ = _fixture(tmp_path)
    output = tmp_path / "private" / "rank-output"
    output.mkdir()
    existing = output / "rank-1k-10k.txt"
    existing.write_text("operator-owned.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to replace"):
        rank_preparer.write_rank_strata(plan, output)

    assert existing.read_text(encoding="utf-8") == "operator-owned.invalid\n"
    assert not (output / "rank-1-1k.txt").exists()
    assert not (output / "rank-selection-manifest.json").exists()


def test_cli_preflight_writes_nothing_then_write_emits_only_aggregate_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, domains = _fixture(tmp_path)
    output = tmp_path / "private" / "rank-output"
    common = ["prepare", "--plan", str(plan), "--output-directory", str(output)]

    assert rank_preparer.main([*common, "--preflight"]) == 0
    preflight = capsys.readouterr().out
    assert not output.exists()
    assert all(domain not in preflight for domain in domains)

    assert rank_preparer.main([*common, "--write-private-strata"]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["privacy"]["private_artifacts_written"] is True
    assert (output / "rank-selection-manifest.json").is_file()
    assert {path.name for path in output.glob("*.txt")} == {f"{band[0]}.txt" for band in TEST_BANDS}


def test_generate_key_is_secret_and_exclusive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "private" / "rank-key.hex"

    assert rank_preparer.main(["generate-key", "--output", str(output)]) == 0
    summary = json.loads(capsys.readouterr().out)
    raw = output.read_bytes()

    assert len(raw) == 65
    assert summary["private_key_sha256"] == hashlib.sha256(bytes.fromhex(raw.decode().strip())).hexdigest()
    assert raw.decode().strip() not in json.dumps(summary)
    with pytest.raises(ValueError, match="refusing to replace"):
        rank_preparer.generate_private_sampling_key(output)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("range", "canonical rank-1-1k range"),
        ("quota", "same discovery quota"),
        ("rows", "must be 12"),
        ("method", "sampling.method"),
        ("field", "unexpected unexpected"),
    ],
)
def test_plan_fails_closed_on_design_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, _ = _fixture(tmp_path)
    value = cast(dict[str, Any], json.loads(plan.read_text(encoding="utf-8")))
    if case == "range":
        value["bands"][0]["maximum_rank"] = 2
    elif case == "quota":
        value["bands"][1]["sample_size"] = 1
    elif case == "rows":
        value["source"]["expected_rows"] = 11
    elif case == "method":
        value["sampling"]["method"] = "public-seed"
    else:
        value["unexpected"] = True
    plan.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        rank_preparer.load_selection_plan(plan)


def test_duplicate_plan_field_and_malformed_key_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, _ = _fixture(tmp_path)
    raw = plan.read_text(encoding="utf-8")
    plan.write_text(raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate field: schema_version"):
        rank_preparer.load_selection_plan(plan)

    plan, _, _, _ = _fixture(tmp_path / "second")
    value = json.loads(plan.read_text(encoding="utf-8"))
    key = Path(value["sampling"]["key_path"])
    key.write_text("not-a-secret-key\n", encoding="utf-8")
    with pytest.raises(ValueError, match="64-character hexadecimal"):
        rank_preparer.prepare_rank_strata(plan, tmp_path / "second" / "private" / "output")


def test_ranked_source_error_does_not_echo_private_identifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_small_source(monkeypatch)
    plan, source, _, _ = _fixture(tmp_path)
    rows = source.read_text(encoding="utf-8").splitlines()
    rows[2] = "99,sensitive-customer-name.invalid"
    source.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="breaks contiguous rank order") as captured:
        rank_preparer.prepare_rank_strata(plan, tmp_path / "private" / "output")

    assert "sensitive-customer-name" not in str(captured.value)


def test_naive_timestamp_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_small_source(monkeypatch)
    plan, _, _, _ = _fixture(tmp_path)

    with pytest.raises(ValueError, match="UTC timezone"):
        rank_preparer.prepare_rank_strata(
            plan,
            tmp_path / "private" / "output",
            prepared_at="2026-08-13T12:00:00",
        )
