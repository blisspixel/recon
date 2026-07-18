"""Determinism and privacy contracts for tracked validation fixtures."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts import check_validation_hygiene
from validation import corpus_aggregator, threshold_sensitivity
from validation.aggregate import make_synthetic_cohort
from validation.synthetic_corpus import generator

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def test_synthetic_corpus_source_emits_only_public_safe_identities(tmp_path: Path) -> None:
    paths: list[str] = []
    for name, builder in generator.REGISTRY.items():
        relative = f"validation/synthetic_corpus/fixtures/{name}.json"
        _write_json(tmp_path / relative, generator._tag(name, builder()))
        paths.append(relative)

    assert check_validation_hygiene.find_violations(tmp_path, paths) == []


def test_synthetic_corpus_artifacts_match_generator() -> None:
    fixture_dir = ROOT / "validation" / "synthetic_corpus" / "fixtures"
    expected = {name: generator._tag(name, builder()) for name, builder in generator.REGISTRY.items()}
    fixture_paths = list(fixture_dir.glob("*.json"))
    actual = {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in fixture_paths}

    assert actual == expected
    for path in fixture_paths:
        assert path.read_text(encoding="utf-8") == json.dumps(expected[path.stem], indent=2) + "\n"
    results_path = ROOT / "validation" / "synthetic_corpus" / "results.json"
    results_text = results_path.read_text(encoding="utf-8")
    combined = json.loads(results_text)
    assert combined == list(expected.values())
    assert results_text == json.dumps(list(expected.values()), indent=2) + "\n"


def test_synthetic_scenario_identifiers_are_stable_and_unique() -> None:
    identifiers = generator._SCENARIO_ID_BY_KEY

    assert set(identifiers) == set(generator.REGISTRY)
    assert len(set(identifiers.values())) == len(identifiers)
    assert all(len(identifier) == 12 and identifier.isdecimal() for identifier in identifiers.values())


def test_current_aggregate_and_threshold_artifacts_match_generators() -> None:
    corpus_dir = ROOT / "validation" / "synthetic_corpus"
    results = json.loads((corpus_dir / "results.json").read_text(encoding="utf-8"))
    aggregate = json.loads((corpus_dir / "aggregate.json").read_text(encoding="utf-8"))
    threshold = (ROOT / "validation" / "threshold_sensitivity.md").read_text(encoding="utf-8")

    assert aggregate == corpus_aggregator.aggregate(results)
    assert (corpus_dir / "aggregate.json").read_text(encoding="utf-8") == json.dumps(
        corpus_aggregator.aggregate(results),
        indent=2,
    ) + "\n"
    assert threshold == threshold_sensitivity._format_markdown(threshold_sensitivity.sweep_thresholds(results))


def test_tracked_render_review_matches_current_aggregate_counts() -> None:
    corpus_dir = ROOT / "validation" / "synthetic_corpus"
    aggregate = json.loads((corpus_dir / "aggregate.json").read_text(encoding="utf-8"))
    review = (corpus_dir / "render_snapshots.md").read_text(encoding="utf-8")
    corpus_size = aggregate["corpus_size"]

    assert f"discovered {corpus_size + 2} fixture paths" in review
    assert f"{corpus_size} generated synthetic corpus fixtures rendered successfully" in review
    assert f"Multi-cloud rollup rendered on {aggregate['multi_cloud']['rendered_fired']} of the {corpus_size}" in review
    assert f"Passive-DNS ceiling rendered on {aggregate['ceiling']['rendered_fired']} of the {corpus_size}" in review


def test_aggregate_source_emits_only_public_safe_identities(tmp_path: Path) -> None:
    records, grouping = make_synthetic_cohort.build_cohort()
    ndjson_path = tmp_path / "validation" / "aggregate" / "synthetic_cohort.ndjson"
    ndjson_path.parent.mkdir(parents=True, exist_ok=True)
    ndjson_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    csv_path = ndjson_path.with_name("synthetic_groups.csv")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("domain", "label"))
        writer.writerows(grouping)

    paths = [
        "validation/aggregate/synthetic_cohort.ndjson",
        "validation/aggregate/synthetic_groups.csv",
    ]
    assert check_validation_hygiene.find_violations(tmp_path, paths) == []


def test_aggregate_artifacts_match_generator() -> None:
    aggregate_dir = ROOT / "validation" / "aggregate"
    expected_records, expected_grouping = make_synthetic_cohort.build_cohort()
    ndjson_path = aggregate_dir / "synthetic_cohort.ndjson"
    csv_path = aggregate_dir / "synthetic_groups.csv"
    actual_records = [json.loads(line) for line in ndjson_path.read_text(encoding="utf-8").splitlines() if line]
    with csv_path.open(
        encoding="utf-8",
        newline="",
    ) as handle:
        rows = list(csv.DictReader(handle))
    actual_grouping = [(row["domain"], row["label"]) for row in rows]

    assert actual_records == expected_records
    assert actual_grouping == expected_grouping
    assert ndjson_path.read_bytes() == make_synthetic_cohort.render_records(expected_records).encode()
    assert csv_path.read_bytes() == make_synthetic_cohort.render_grouping(expected_grouping).encode()
