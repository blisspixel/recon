"""Tests for the private catalog ccTLD-delegation frame preparer."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any, cast

import pytest

from validation import prepare_catalog_region_frame as region_preparer

TEST_KEY = bytes(range(32))
TEST_TLDS = (
    ("africa", "002", "Africa", "za", "ng"),
    ("americas", "019", "Americas", "br", "mx"),
    ("asia", "142", "Asia", "jp", "in"),
    ("europe", "150", "Europe", "de", "fr"),
    ("oceania", "009", "Oceania", "au", "nz"),
)


def _domain(index: int, tld: str) -> str:
    return f"private-fixture-{index}.{tld}"


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, list[str]]:
    private = tmp_path / "private"
    private.mkdir(parents=True)
    source = private / "ranked.csv"
    mapping = private / "mapping.csv"
    exclusion_a = private / "development.txt"
    exclusion_b = private / "prior-round.txt"
    key = private / "sampling-key.hex"
    plan = private / "region-plan.json"

    domains: list[str] = []
    mapping_rows: list[str] = []
    index = 1
    for _, code, name, primary_tld, secondary_tld in TEST_TLDS:
        for tld, count in ((primary_tld, 4), (secondary_tld, 2)):
            mapping_rows.append(f"{tld},country-code,{tld.upper()},{code},{name}")
            for _ in range(count):
                domains.append(_domain(index, tld))
                index += 1
    source.write_text(
        "rank,domain\n" + "".join(f"{rank},{domain}\n" for rank, domain in enumerate(domains, start=1)),
        encoding="utf-8",
    )
    mapping.write_text(
        ",".join(region_preparer.MAPPING_COLUMNS) + "\n" + "\n".join(mapping_rows) + "\n",
        encoding="utf-8",
    )
    exclusion_a.write_text(f"{domains[0]}\n", encoding="utf-8")
    exclusion_b.write_text(f"{domains[0]}\n{domains[6]}\n", encoding="utf-8")
    key.write_bytes(TEST_KEY.hex().encode("ascii") + b"\n")
    payload = {
        "schema_version": 1,
        "private": True,
        "question": "Do ccTLD namespace groups expose different recurrent catalog gaps by bounded record type?",
        "interpretation_boundary": (
            "The ccTLD grouping describes a delegated namespace only and does not identify registrant location."
        ),
        "source": {
            "path": str(source),
            "name": "Private ranked fixture source",
            "revision": "fixture-revision-1",
            "expected_rows": len(domains),
        },
        "geography": {
            "path": str(mapping),
            "name": "IANA and UN M49 fixture intersection",
            "revision": "fixture-iana-un-20260813",
            "expected_rows": len(mapping_rows),
        },
        "prior_exclusions": [
            {
                "path": str(exclusion_a),
                "rule": "Exclude every prior catalog development namespace before selection.",
            },
            {
                "path": str(exclusion_b),
                "rule": "Exclude every namespace from the completed prior catalog round.",
            },
        ],
        "sampling": {
            "key_path": str(key),
            "context": "catalog-region-test-01",
            "method": region_preparer.SAMPLING_METHOD,
        },
        "design": {
            "regions": [
                {"id": region_id, "code": code, "name": name}
                for region_id, code, name in region_preparer.CANONICAL_REGIONS
            ],
            "tlds_per_region": 1,
            "sample_size_per_tld": 2,
        },
    }
    plan.write_text(json.dumps(payload), encoding="utf-8")
    return plan, source, mapping, exclusion_a, exclusion_b, domains


def test_region_strata_are_deterministic_disjoint_and_prior_excluded(tmp_path: Path) -> None:
    plan, _, _, _, _, domains = _fixture(tmp_path)
    output = tmp_path / "private" / "region-output"

    first_payloads, first_manifest = region_preparer.prepare_region_strata(
        plan,
        output,
        prepared_at="2026-08-13T12:00:00Z",
    )
    second_payloads, second_manifest = region_preparer.prepare_region_strata(
        plan,
        output,
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert first_payloads == second_payloads
    assert first_manifest == second_manifest
    selected = [domain for payload in first_payloads.values() for domain in payload.decode("ascii").splitlines()]
    assert len(selected) == 10
    assert len(set(selected)) == 10
    assert domains[0] not in selected
    assert domains[6] not in selected
    selected_tlds = [region["selected_ccTLDs"][0]["tld"] for region in first_manifest["regions"]]
    assert selected_tlds == [row[3] for row in TEST_TLDS]
    assert all(region["selected_rows"] == 2 for region in first_manifest["regions"])


def test_public_summary_omits_membership_paths_rules_key_and_domains(tmp_path: Path) -> None:
    plan, source, mapping, exclusion_a, exclusion_b, domains = _fixture(tmp_path)
    _, manifest = region_preparer.prepare_region_strata(
        plan,
        tmp_path / "private" / "region-output",
        prepared_at="2026-08-13T12:00:00Z",
    )

    summary = region_preparer.public_summary(manifest, written=False)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["privacy"] == {
        "private_artifacts_written": False,
        "identifiers_printed": 0,
        "per_domain_rows_printed": 0,
        "network_requests": 0,
    }
    assert str(source) not in serialized
    assert str(mapping) not in serialized
    assert str(exclusion_a) not in serialized
    assert str(exclusion_b) not in serialized
    assert "Exclude every namespace" not in serialized
    assert TEST_KEY.hex() not in serialized
    assert all(domain not in serialized for domain in domains)


def test_manifest_commits_to_plan_sources_exclusions_key_and_frames(tmp_path: Path) -> None:
    plan, source, mapping, exclusion_a, exclusion_b, _ = _fixture(tmp_path)
    payloads, manifest = region_preparer.prepare_region_strata(
        plan,
        tmp_path / "private" / "region-output",
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert manifest["plan_digest_sha256"] == hashlib.sha256(plan.read_bytes()).hexdigest()
    assert manifest["source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["geography"]["sha256"] == hashlib.sha256(mapping.read_bytes()).hexdigest()
    assert [row["sha256"] for row in manifest["prior_exclusions"]] == [
        hashlib.sha256(exclusion_a.read_bytes()).hexdigest(),
        hashlib.sha256(exclusion_b.read_bytes()).hexdigest(),
    ]
    assert manifest["prior_exclusion_union_rows"] == 2
    assert manifest["sampling"]["private_key_sha256"] == hashlib.sha256(TEST_KEY).hexdigest()
    assert len(manifest["implementation"]["execution_sha256"]) == 64
    for region in manifest["regions"]:
        filename = f"{region['id']}.txt"
        assert region["frame_sha256"] == hashlib.sha256(payloads[filename]).hexdigest()
    digest_payload = dict(manifest)
    supplied = digest_payload.pop("manifest_digest_sha256")
    assert supplied == hashlib.sha256(region_preparer._canonical_json(digest_payload)).hexdigest()


def test_write_is_exclusive_and_cleans_only_new_reservations(tmp_path: Path) -> None:
    plan, _, _, _, _, _ = _fixture(tmp_path)
    output = tmp_path / "private" / "region-output"
    output.mkdir()
    existing = output / "americas.txt"
    existing.write_text("operator-owned.invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to replace"):
        region_preparer.write_region_strata(plan, output)

    assert existing.read_text(encoding="utf-8") == "operator-owned.invalid\n"
    assert not (output / "africa.txt").exists()
    assert not (output / "region-selection-manifest.json").exists()


def test_cli_preflight_writes_nothing_then_write_emits_safe_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan, _, _, _, _, domains = _fixture(tmp_path)
    output = tmp_path / "private" / "region-output"
    common = ["--plan", str(plan), "--output-directory", str(output)]

    assert region_preparer.main([*common, "--preflight"]) == 0
    preflight = capsys.readouterr().out
    assert not output.exists()
    assert all(domain not in preflight for domain in domains)

    assert region_preparer.main([*common, "--write-private-strata"]) == 0
    written = json.loads(capsys.readouterr().out)
    assert written["privacy"]["private_artifacts_written"] is True
    assert (output / "region-selection-manifest.json").is_file()
    assert {path.name for path in output.glob("*.txt")} == {f"{region[0]}.txt" for region in TEST_TLDS}


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("region", "canonical region africa"),
        ("quota", "positive integer"),
        ("method", "sampling.method"),
        ("duplicate-exclusion", "paths must be unique"),
        ("field", "unexpected unexpected"),
    ],
)
def test_plan_fails_closed_on_design_drift(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    plan, _, _, _, _, _ = _fixture(tmp_path)
    value = cast(dict[str, Any], json.loads(plan.read_text(encoding="utf-8")))
    if case == "region":
        value["design"]["regions"][0]["code"] = "999"
    elif case == "quota":
        value["design"]["sample_size_per_tld"] = 0
    elif case == "method":
        value["sampling"]["method"] = "public-seed"
    elif case == "duplicate-exclusion":
        value["prior_exclusions"][1]["path"] = value["prior_exclusions"][0]["path"]
    else:
        value["unexpected"] = True
    plan.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        region_preparer.load_selection_plan(plan)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("header", "invalid header"),
        ("tld", "invalid code"),
        ("alpha2", "not an exact ISO alpha-2 match"),
        ("type", "not IANA country-code"),
        ("region", "unsupported UN M49 region"),
        ("duplicate", "duplicates a TLD"),
        ("rows", "expected exactly"),
    ],
)
def test_mapping_fails_closed_on_semantic_drift(tmp_path: Path, case: str, message: str) -> None:
    plan, _, mapping, _, _, _ = _fixture(tmp_path)
    rows = list(csv.reader(io.StringIO(mapping.read_text(encoding="utf-8"))))
    if case == "header":
        rows[0][0] = "suffix"
    elif case == "tld":
        rows[1][0] = "toolong"
    elif case == "alpha2":
        rows[1][2] = "NG"
    elif case == "type":
        rows[1][1] = "generic"
    elif case == "region":
        rows[1][3] = "999"
    elif case == "duplicate":
        rows[2][0] = rows[1][0]
        rows[2][2] = rows[1][2]
    else:
        value = json.loads(plan.read_text(encoding="utf-8"))
        value["geography"]["expected_rows"] += 1
        plan.write_text(json.dumps(value), encoding="utf-8")
    if case != "rows":
        mapping.write_text("\n".join(",".join(row) for row in rows) + "\n", encoding="utf-8")

    loaded = region_preparer.load_selection_plan(plan)
    with pytest.raises(ValueError, match=message):
        region_preparer._read_mapping(loaded)


def test_duplicate_plan_field_malformed_key_and_naive_time_are_rejected(tmp_path: Path) -> None:
    plan, _, _, _, _, _ = _fixture(tmp_path)
    raw = plan.read_text(encoding="utf-8")
    plan.write_text(raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate field: schema_version"):
        region_preparer.load_selection_plan(plan)

    plan, _, _, _, _, _ = _fixture(tmp_path / "second")
    value = json.loads(plan.read_text(encoding="utf-8"))
    Path(value["sampling"]["key_path"]).write_text("not-a-secret-key\n", encoding="utf-8")
    with pytest.raises(ValueError, match="64-character hexadecimal"):
        region_preparer.prepare_region_strata(plan, tmp_path / "second" / "private" / "output")

    plan, _, _, _, _, _ = _fixture(tmp_path / "third")
    with pytest.raises(ValueError, match="UTC timezone"):
        region_preparer.prepare_region_strata(
            plan,
            tmp_path / "third" / "private" / "output",
            prepared_at="2026-08-13T12:00:00",
        )
