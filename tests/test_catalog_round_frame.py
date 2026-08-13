"""Tests for the fail-closed private catalog-round frame preparer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from validation import prepare_catalog_round as round_preparer
from validation.prepare_catalog_round import prepare_catalog_round, write_catalog_round


def _plan(tmp_path: Path, *, overlap: str = "reject", round_kind: str = "rank") -> Path:
    first = tmp_path / "head.txt"
    second = tmp_path / "tail.txt"
    first.write_text("WWW.BETA.CO.UK\nhttps://mail.alpha.example/path\nalpha.example\n", encoding="utf-8")
    second.write_text("zeta.example\nsub.gamma.example\n", encoding="utf-8")
    plan = {
        "schema_version": 1,
        "private": True,
        "round_id": "rank-2026-08",
        "round_kind": round_kind,
        "question": "Do head and tail namespaces expose different recurrent catalog gaps?",
        "source": {"name": "Example ranked source", "revision": "2026-08-13"},
        "strata": [
            {"id": "head", "label": "Ranks 1 through 1000", "input": first.name},
            {"id": "tail", "label": "Ranks 100001 through 1000000", "input": second.name},
        ],
        "policies": {
            "exclusions": "Exclude malformed rows and previously used development namespaces.",
            "overlap": overlap,
        },
        "collection": {"ct_enabled": False, "direct_probes_enabled": False},
        "thresholds": {"minimum_occurrences": 3, "minimum_distinct_namespaces": 2},
        "promotion_budget": {
            "metric": "classified share by record type",
            "minimum_improvement": 0.01,
            "maximum_regression": 0.0,
            "decision_rule": "Promote only documented recurrent rules with no observed regression.",
        },
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_preparer_normalizes_sorts_deduplicates_and_emits_exact_manifest(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    frame_path = tmp_path / "frame.txt"

    frame, manifest = prepare_catalog_round(
        plan,
        frame_path,
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert frame == b"alpha.example\nbeta.co.uk\ngamma.example\nzeta.example\n"
    assert list(manifest) == [
        "schema_version",
        "private",
        "round_id",
        "round_kind",
        "question",
        "prepared_at",
        "source",
        "frame",
        "strata",
        "policies",
        "collection",
        "thresholds",
        "promotion_budget",
        "plan_digest_sha256",
        "manifest_digest_sha256",
    ]
    assert manifest["strata"] == [
        {"id": "head", "label": "Ranks 1 through 1000", "count": 2},
        {"id": "tail", "label": "Ranks 100001 through 1000000", "count": 2},
    ]
    frame_meta = manifest["frame"]
    assert isinstance(frame_meta, dict)
    assert frame_meta["path"] == str(frame_path.resolve())
    assert frame_meta["count"] == 4
    assert frame_meta["digest_sha256"] == hashlib.sha256(frame).hexdigest()
    digest = manifest.pop("manifest_digest_sha256")
    canonical = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    assert digest == hashlib.sha256(canonical).hexdigest()


@pytest.mark.parametrize("round_kind", ["baseline", "rank", "region", "vertical", "vendor-seed", "drift"])
def test_every_declared_round_kind_is_accepted(tmp_path: Path, round_kind: str) -> None:
    frame, manifest = prepare_catalog_round(
        _plan(tmp_path, round_kind=round_kind),
        tmp_path / "frame.txt",
        prepared_at="2026-08-13T12:00:00Z",
    )

    assert frame
    assert manifest["round_kind"] == round_kind


def test_malformed_source_row_fails_without_echoing_identifier(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    (tmp_path / "tail.txt").write_text("safe.example\nbad target with spaces\n", encoding="utf-8")

    with pytest.raises(ValueError, match="stratum tail row 2 is malformed") as captured:
        prepare_catalog_round(plan, tmp_path / "frame.txt")

    assert "bad target" not in str(captured.value)


def test_cross_stratum_overlap_rejects_or_assigns_to_first_stratum(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    (tmp_path / "tail.txt").write_text("sub.alpha.example\nzeta.example\n", encoding="utf-8")

    with pytest.raises(ValueError, match="registrable apex appears in multiple strata"):
        prepare_catalog_round(plan, tmp_path / "reject.txt")

    data = json.loads(plan.read_text(encoding="utf-8"))
    data["policies"]["overlap"] = "first-stratum-wins"
    plan.write_text(json.dumps(data), encoding="utf-8")
    frame, manifest = prepare_catalog_round(plan, tmp_path / "accepted.txt", prepared_at="2026-08-13T12:00:00Z")
    assert frame.count(b"alpha.example\n") == 1
    assert manifest["strata"] == [
        {"id": "head", "label": "Ranks 1 through 1000", "count": 2},
        {"id": "tail", "label": "Ranks 100001 through 1000000", "count": 1},
    ]


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("unexpected",), True, "unexpected unexpected"),
        (("question",), "TBD", "question must be meaningful"),
        (("source", "revision"), "latest", "source.revision must be meaningful"),
        (("policies", "exclusions"), "none", "policies.exclusions must be meaningful"),
        (
            ("collection", "direct_probes_enabled"),
            True,
            "direct_probes_enabled must be false",
        ),
        (
            ("promotion_budget", "minimum_improvement"),
            0,
            "minimum_improvement must be in",
        ),
    ],
)
def test_strict_plan_rejects_missing_or_nonmeaningful_contracts(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    plan_path = _plan(tmp_path)
    plan = cast(dict[str, Any], json.loads(plan_path.read_text(encoding="utf-8")))
    target = plan
    for segment in path[:-1]:
        target = cast(dict[str, Any], target[segment])
    target[path[-1]] = value
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        prepare_catalog_round(plan_path, tmp_path / "frame.txt")


def test_write_is_private_exclusive_and_does_not_print_identifiers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = _plan(tmp_path)
    frame = tmp_path / "frame.txt"
    manifest_path = tmp_path / "manifest.json"

    manifest = write_catalog_round(plan, frame, manifest_path)

    assert frame.read_bytes().startswith(b"alpha.example\n")
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest
    assert capsys.readouterr().out == ""
    with pytest.raises(ValueError, match="already exists; refusing to replace"):
        write_catalog_round(plan, frame, manifest_path)


def test_existing_manifest_blocks_both_outputs_before_any_write(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    frame = tmp_path / "new-frame.txt"
    manifest = tmp_path / "manifest.json"
    manifest.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="manifest already exists"):
        write_catalog_round(plan, frame, manifest)

    assert not frame.exists()
    assert manifest.read_text(encoding="utf-8") == "keep"


def test_reservation_race_never_removes_an_output_the_preparer_did_not_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(tmp_path)
    frame = tmp_path / "frame.txt"
    manifest = tmp_path / "manifest.json"
    original = round_preparer._reserve_exclusive
    calls = 0

    def race(path: Path, *, kind: str) -> int:
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_text("other writer", encoding="utf-8")
            raise ValueError(f"{kind} already exists; refusing to replace it")
        return original(path, kind=kind)

    monkeypatch.setattr(round_preparer, "_reserve_exclusive", race)

    with pytest.raises(ValueError, match="manifest already exists"):
        write_catalog_round(plan, frame, manifest)

    assert not frame.exists()
    assert manifest.read_text(encoding="utf-8") == "other writer"
