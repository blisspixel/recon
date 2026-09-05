"""Canonical audit artifacts must not contain operator-local catalog data."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from recon_tool import fingerprints
from recon_tool.fingerprint_audit import summarize_fingerprint_freshness
from validation import audit_fingerprints


@pytest.fixture
def local_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("RECON_CONFIG_DIR", str(tmp_path))
    custom = {
        "name": "Private Synthetic Local",
        "slug": "private-synthetic-local",
        "category": "Cloud",
        "confidence": "medium",
        "detections": [
            {"type": "txt", "pattern": "^private-synthetic=", "verified": "2026-09-01"},
            {"type": "cname", "pattern": "private.synthetic.invalid", "verified": "2026-09-01"},
        ],
    }
    (tmp_path / "fingerprints.yaml").write_text(yaml.safe_dump({"fingerprints": [custom]}), encoding="utf-8")
    fingerprints.reload_fingerprints()
    fingerprints.inject_ephemeral(
        fingerprints.Fingerprint(
            name="Private Synthetic Ephemeral",
            slug="private-synthetic-ephemeral",
            category="Cloud",
            confidence="medium",
            m365=False,
            detections=(
                fingerprints.DetectionRule(type="txt", pattern="^private-ephemeral="),
                fingerprints.DetectionRule(type="cname", pattern="ephemeral.synthetic.invalid"),
            ),
        )
    )
    try:
        assert any(fp.slug == "private-synthetic-local" for fp in fingerprints.load_fingerprints())
        yield
    finally:
        fingerprints.clear_ephemeral()
        fingerprints.reload_fingerprints()


def test_default_freshness_is_builtin_only(
    local_catalog: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["audit_fingerprints", "--freshness"])
    audit_fingerprints.main()
    payload = json.loads(capsys.readouterr().out)
    builtin = fingerprints.load_builtin_fingerprints()
    assert payload["catalog_scope"] == "builtin"
    assert payload["total_detections"] == sum(len(fp.detections) for fp in builtin)
    assert summarize_fingerprint_freshness(today="2026-09-05")["total_detections"] == payload["total_detections"] + 4


@pytest.mark.parametrize("effective", [False, True])
def test_audit_artifacts_label_scope_and_isolate_local_data(
    local_catalog: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, effective: bool
) -> None:
    json_path = tmp_path / "audit.json"
    markdown_path = tmp_path / "audit.md"
    args = ["audit_fingerprints", "--json-output", str(json_path), "--markdown-output", str(markdown_path)]
    if effective:
        args.append("--effective-catalog")
    monkeypatch.setattr(sys, "argv", args)
    audit_fingerprints.main()
    raw = json_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    assert json.loads(raw)["catalog_scope"] == ("effective" if effective else "builtin")
    assert ("private-synthetic-local" in raw) == effective
    assert ("private-synthetic-ephemeral" in raw) == effective
    assert ("Private Synthetic Local" in markdown) == effective
    assert ("Private Synthetic Ephemeral" in markdown) == effective
    assert markdown.startswith("Catalog scope: ")


def test_explicit_effective_freshness_is_labeled(
    local_catalog: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["audit_fingerprints", "--freshness", "--effective-catalog"])
    audit_fingerprints.main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["catalog_scope"] == "effective"
    assert payload["total_detections"] == sum(len(fp.detections) for fp in fingerprints.load_fingerprints())


def test_default_audit_never_calls_effective_loader(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(audit_fingerprints, "load_fingerprints", lambda: pytest.fail("operator data accessed"))
    monkeypatch.setattr(sys, "argv", ["audit_fingerprints"])
    audit_fingerprints.main()
    assert capsys.readouterr().out.startswith("Catalog scope: builtin")
