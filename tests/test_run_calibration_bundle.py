from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from validation.run_calibration_bundle import preflight_corpus_inputs, run_bundle


def _summary(n: int) -> dict[str, object]:
    return {
        "n": n,
        "base_rate_enforcing": 0.6,
        "brier": 0.12,
        "log_score": 0.31,
        "ece": 0.05,
        "agreement_rate": 0.86,
    }


REFERENCE_STRATIFIED = {
    "mode": "stratified",
    "full": {
        "min_cell": 10,
        "pooled": _summary(23),
        "strata": {
            "saas": _summary(10),
            "security": _summary(10),
            "tiny": {"n": 3, "suppressed": True},
        },
    },
    "held_out": {
        "min_cell": 10,
        "pooled": _summary(23),
        "strata": {
            "saas": _summary(10),
            "security": _summary(10),
            "tiny": {"n": 3, "suppressed": True},
        },
    },
}

TENANCY_STRATIFIED = {
    "mode": "stratified",
    "m365_dns_only": {
        "min_cell": 10,
        "pooled": _summary(20),
        "strata": {
            "saas": _summary(10),
            "security": _summary(10),
        },
    },
    "gws_one_sided": {
        "n": 4,
        "threshold": 0.5,
        "recall": 0.75,
        "recall_wilson80": [0.41, 0.93],
        "posterior_quartiles": [0.51, 0.63, 0.81],
    },
}

CONFORMAL = {
    "mode": "single",
    "node": "email_security_policy_enforcing",
    "construction": "split_conformal",
    "summary": {
        "n": 23.0,
        "trials": 20.0,
        "target_coverage": 0.9,
        "mean_coverage": 0.92,
        "min_coverage": 0.86,
        "mean_set_size": 1.18,
    },
}


def _write_private_inputs(root: Path) -> tuple[Path, Path]:
    stratify_dir = root / "corpus-private" / "by-vertical"
    stratify_dir.mkdir(parents=True)
    (stratify_dir / "saas.txt").write_text(
        "\n".join(f"saas-{index}.example" for index in range(10)) + "\n",
        encoding="utf-8",
    )
    (stratify_dir / "security.txt").write_text(
        "\n".join(f"security-{index}.example" for index in range(10)) + "\n",
        encoding="utf-8",
    )
    (stratify_dir / "tiny.txt").write_text("tiny-1.example\ntiny-2.example\ntiny-3.example\n", encoding="utf-8")
    consolidated = root / "corpus-private" / "consolidated.txt"
    consolidated.write_text(
        "\n".join(f"domain-{index}.example" for index in range(23)) + "\n",
        encoding="utf-8",
    )
    return stratify_dir, consolidated


def test_preflight_reports_eligible_and_suppressed_strata(tmp_path) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)

    preflight = preflight_corpus_inputs(stratify_dir=stratify_dir, consolidated=consolidated, min_cell=10)

    assert preflight.consolidated_domain_count == 23
    assert preflight.stratum_count == 3
    assert preflight.eligible_strata_count == 2
    assert preflight.suppressed_strata_count == 1
    assert [(stratum.name, stratum.domain_count, stratum.eligible) for stratum in preflight.strata] == [
        ("saas", 10, True),
        ("security", 10, True),
        ("tiny", 3, False),
    ]


def test_preflight_rejects_all_small_strata(tmp_path) -> None:
    stratify_dir = tmp_path / "corpus-private" / "by-vertical"
    stratify_dir.mkdir(parents=True)
    (stratify_dir / "tiny.txt").write_text("tiny-1.example\n", encoding="utf-8")
    consolidated = tmp_path / "corpus-private" / "consolidated.txt"
    consolidated.write_text("\n".join(f"domain-{index}.example" for index in range(10)) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no stratum has at least min-cell 10"):
        preflight_corpus_inputs(stratify_dir=stratify_dir, consolidated=consolidated, min_cell=10)


def test_preflight_rejects_small_consolidated_corpus(tmp_path) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)
    consolidated.write_text("only-one.example\n", encoding="utf-8")

    with pytest.raises(ValueError, match="consolidated corpus has 1 domain"):
        preflight_corpus_inputs(stratify_dir=stratify_dir, consolidated=consolidated, min_cell=10)


def test_run_bundle_writes_json_memo_and_meta(tmp_path) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)
    calls: list[list[str]] = []

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        module = cmd[2]
        if module == "validation.reference_calibration":
            payload = REFERENCE_STRATIFIED
        elif module == "validation.tenancy_reference_calibration":
            payload = TENANCY_STRATIFIED
        elif module == "validation.conformal_coverage":
            payload = CONFORMAL
        else:
            raise AssertionError(module)
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

    outputs = run_bundle(
        stratify_dir=stratify_dir,
        consolidated=consolidated,
        output_root=tmp_path / "runs-private",
        label="Aggregate Calibration Validation Memo",
        stamp="20260619-000000Z",
        runner=runner,
    )

    assert [cmd[2] for cmd in calls] == [
        "validation.reference_calibration",
        "validation.tenancy_reference_calibration",
        "validation.conformal_coverage",
    ]
    assert all(">" not in cmd for cmd in calls)
    assert json.loads(outputs.reference_json.read_text(encoding="utf-8"))["mode"] == "stratified"
    assert json.loads(outputs.tenancy_json.read_text(encoding="utf-8"))["mode"] == "stratified"
    assert json.loads(outputs.conformal_json.read_text(encoding="utf-8"))["construction"] == "split_conformal"
    memo = outputs.memo_md.read_text(encoding="utf-8")
    assert "Disclosure Controls" in memo
    assert "M365 DNS-only Stratified Corroboration" in memo
    assert "Conformal Coverage" in memo
    meta = json.loads(outputs.meta_json.read_text(encoding="utf-8"))
    assert meta["strata_count"] == 3
    assert meta["eligible_strata_count"] == 2
    assert meta["suppressed_strata_count"] == 1
    assert meta["consolidated_domain_count"] == 23
    assert meta["disclosure"]["memo_rendered_with_disclosure_checks"] is True


def test_dry_run_prints_commands_without_calling_runner(tmp_path, capsys) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)

    def runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError(cmd)

    outputs = run_bundle(
        stratify_dir=stratify_dir,
        consolidated=consolidated,
        output_root=tmp_path / "runs-private",
        label="",
        stamp="20260619-000000Z",
        dry_run=True,
        runner=runner,
    )

    assert not outputs.run_dir.exists()
    out = capsys.readouterr().out
    assert "Corpus preflight: 23 consolidated domain(s), 2/3 eligible stratum file(s)" in out
    assert "validation.reference_calibration" in out
    assert "validation.tenancy_reference_calibration" in out
    assert "validation.conformal_coverage" in out


def test_run_bundle_rejects_missing_private_inputs(tmp_path) -> None:
    stratify_dir = tmp_path / "missing-dir"
    consolidated = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError, match="stratify directory not found"):
        run_bundle(
            stratify_dir=stratify_dir,
            consolidated=consolidated,
            output_root=tmp_path / "runs-private",
            label="",
            stamp="20260619-000000Z",
        )


@pytest.mark.parametrize(
    "stamp",
    [
        "",
        "../outside",
        "..\\outside",
        "/absolute/path",
        "C:\\absolute\\path",
        "-leading-dash",
        "with space",
        "a" * 81,
    ],
)
def test_run_bundle_rejects_unsafe_stamp(tmp_path, stamp) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)

    with pytest.raises(ValueError, match="run stamp"):
        run_bundle(
            stratify_dir=stratify_dir,
            consolidated=consolidated,
            output_root=tmp_path / "runs-private",
            label="",
            stamp=stamp,
            dry_run=True,
        )


def test_run_bundle_resolves_safe_stamp_under_output_root(tmp_path) -> None:
    stratify_dir, consolidated = _write_private_inputs(tmp_path)
    output_root = tmp_path / "runs-private"

    outputs = run_bundle(
        stratify_dir=stratify_dir,
        consolidated=consolidated,
        output_root=output_root,
        label="",
        stamp="safe-run_20260619.1",
        dry_run=True,
    )

    assert outputs.run_dir == (output_root / "safe-run_20260619.1").resolve(strict=False)
