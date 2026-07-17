"""Contracts for the deterministic built-in fingerprint artifact."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from recon_tool.fingerprint_artifact import (
    ArtifactSource,
    FingerprintArtifactError,
    load_artifact_sources,
    serialize_artifact_sources,
)
from recon_tool.fingerprints import (
    CnameTargetDetection,
    Detection,
    Fingerprint,
    _load_builtin_artifact,
    _load_from_dir,
    clear_ephemeral,
    get_caa_patterns,
    get_cname_patterns,
    get_cname_target_patterns,
    get_cname_target_rules,
    get_dmarc_rua_patterns,
    get_m365_names,
    get_m365_slugs,
    get_mx_patterns,
    get_ns_patterns,
    get_spf_patterns,
    get_srv_patterns,
    get_subdomain_txt_patterns,
    get_txt_patterns,
    load_fingerprints,
    match_txt,
    match_txt_all,
    reload_fingerprints,
)
from scripts.generate_fingerprint_catalog import build_artifact
from scripts.generate_fingerprint_catalog import main as generate_main

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_DIR = _ROOT / "src" / "recon_tool" / "data" / "fingerprints"
_ARTIFACT = _ROOT / "src" / "recon_tool" / "data" / "fingerprints.generated.json"


def _detections(catalog: tuple[Fingerprint, ...], detection_type: str) -> tuple[Detection, ...]:
    return tuple(
        Detection(rule.pattern, fingerprint.name, fingerprint.slug, fingerprint.category, fingerprint.confidence)
        for fingerprint in catalog
        for rule in fingerprint.detections
        if rule.type == detection_type and rule.pattern
    )


def test_generated_builtins_equal_canonical_yaml_exactly() -> None:
    canonical = tuple(_load_from_dir(_SOURCE_DIR))
    generated = tuple(_load_builtin_artifact(_ARTIFACT))

    assert len(canonical) == 855
    assert sum(len(fingerprint.detections) for fingerprint in canonical) == 1062
    assert generated == canonical
    repeated_slugs = [fingerprint.slug for fingerprint in generated]
    assert len(repeated_slugs) > len(set(repeated_slugs))


def test_generated_artifact_public_views_equal_canonical_yaml() -> None:
    canonical = tuple(_load_from_dir(_SOURCE_DIR))
    clear_ephemeral()
    reload_fingerprints()
    try:
        assert load_fingerprints() == canonical
        accessors = {
            "txt": get_txt_patterns,
            "spf": get_spf_patterns,
            "mx": get_mx_patterns,
            "ns": get_ns_patterns,
            "cname": get_cname_patterns,
            "cname_target": get_cname_target_patterns,
            "subdomain_txt": get_subdomain_txt_patterns,
            "caa": get_caa_patterns,
            "srv": get_srv_patterns,
            "dmarc_rua": get_dmarc_rua_patterns,
        }
        for detection_type, accessor in accessors.items():
            assert accessor() == _detections(canonical, detection_type)
        expected_cname_rules = tuple(
            CnameTargetDetection(
                pattern=rule.pattern,
                name=fingerprint.name,
                slug=fingerprint.slug,
                category=fingerprint.category,
                confidence=fingerprint.confidence,
                tier=rule.tier,
            )
            for fingerprint in canonical
            for rule in fingerprint.detections
            if rule.type == "cname_target" and rule.pattern
        )
        assert get_cname_target_rules() == expected_cname_rules
        assert get_m365_names() == frozenset(fingerprint.name for fingerprint in canonical if fingerprint.m365)
        assert get_m365_slugs() == frozenset(fingerprint.slug for fingerprint in canonical if fingerprint.m365)
        txt_patterns = _detections(canonical, "txt")
        value = "crowdstrike-falcon-site-verification=fictional"
        assert match_txt(value, get_txt_patterns()) == match_txt(value, txt_patterns)
        assert match_txt_all(value, get_txt_patterns()) == match_txt_all(value, txt_patterns)
    finally:
        clear_ephemeral()
        reload_fingerprints()


def test_committed_artifact_is_byte_deterministic_and_current() -> None:
    first = build_artifact(_SOURCE_DIR)
    second = build_artifact(_SOURCE_DIR)

    assert first == second
    assert first.endswith("\n")
    assert "\r" not in first
    assert _ARTIFACT.read_bytes() == first.encode("utf-8")


def test_generator_normalizes_native_yaml_verification_dates(tmp_path: Path) -> None:
    source_dir = tmp_path / "fingerprints"
    source_dir.mkdir()
    (source_dir / "example.yaml").write_text(
        "fingerprints:\n"
        "  - name: Fictional Date Example\n"
        "    slug: fictional-date-example\n"
        "    category: Misc\n"
        "    confidence: high\n"
        "    detections:\n"
        "      - type: txt\n"
        "        pattern: '^fictional-date-example='\n"
        "        description: Synthetic verification-date fixture.\n"
        "        verified: 2026-07-17\n",
        encoding="utf-8",
    )

    document = json.loads(build_artifact(source_dir))

    detection = document["sources"][0]["fingerprints"][0]["detections"][0]
    assert detection["verified"] == "2026-07-17"


def test_generator_check_detects_semantic_source_drift(tmp_path: Path) -> None:
    source_dir = tmp_path / "fingerprints"
    shutil.copytree(_SOURCE_DIR, source_dir)
    output = tmp_path / "fingerprints.generated.json"
    args = ["--source-dir", str(source_dir), "--output", str(output)]
    assert generate_main([*args, "--write"]) == 0
    assert generate_main([*args, "--check"]) == 0

    source_path = source_dir / "ai.yaml"
    document = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    document["fingerprints"].append(
        {
            "name": "Fictional Cycle 65 Proof",
            "slug": "fictional-cycle-65-proof",
            "category": "AI & Generative",
            "confidence": "high",
            "detections": [
                {
                    "type": "txt",
                    "pattern": "^cycle65-generated-proof=",
                    "description": "Synthetic drift-check fixture.",
                }
            ],
        }
    )
    source_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    assert generate_main([*args, "--check"]) == 1


def test_artifact_round_trip_preserves_source_and_entry_order(tmp_path: Path) -> None:
    sources = (
        ArtifactSource(path="a.yaml", fingerprints=({"name": "First", "detections": []},)),
        ArtifactSource(path="b.yaml", fingerprints=({"name": "Second", "detections": []},)),
    )
    path = tmp_path / "artifact.json"
    path.write_text(serialize_artifact_sources(sources), encoding="utf-8", newline="\n")

    assert load_artifact_sources(path) == sources


def test_artifact_rejects_missing_or_invalid_json(tmp_path: Path) -> None:
    with pytest.raises(FingerprintArtifactError, match="unavailable"):
        load_artifact_sources(tmp_path / "missing.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(FingerprintArtifactError, match="not valid JSON"):
        load_artifact_sources(invalid)
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(FingerprintArtifactError, match="not valid UTF-8"):
        load_artifact_sources(invalid_utf8)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "root must be an object"),
        ({"format_version": 1}, "missing keys"),
        (
            {
                "format_version": 1,
                "fingerprint_count": 0,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": [],
                "extra": 1,
            },
            "unexpected keys",
        ),
        (
            {
                "format_version": 1,
                "fingerprint_count": 0,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": [],
            },
            "non-empty array",
        ),
        (
            {
                "format_version": 1,
                "fingerprint_count": 0,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": ["invalid"],
            },
            "must be an object",
        ),
        (
            {
                "format_version": 1,
                "fingerprint_count": 0,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": [{"path": "a.yaml"}],
            },
            "missing keys",
        ),
        (
            {
                "format_version": 1,
                "fingerprint_count": 0,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": [{"path": "a.yaml", "fingerprints": {}}],
            },
            "must be an array",
        ),
        (
            {
                "format_version": 1,
                "fingerprint_count": 1,
                "detection_count": 0,
                "semantic_sha256": "invalid",
                "sources": [{"path": "a.yaml", "fingerprints": ["invalid"]}],
            },
            "only objects",
        ),
    ],
)
def test_artifact_rejects_invalid_container_shapes(tmp_path: Path, document: object, message: str) -> None:
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(FingerprintArtifactError, match=message):
        load_artifact_sources(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("format_version", 2, "unsupported artifact format"),
        ("format_version", True, "unsupported artifact format"),
        ("format_version", 1.0, "unsupported artifact format"),
        ("fingerprint_count", -1, "non-negative integer"),
        ("fingerprint_count", 0, "fingerprint_count does not match"),
        ("detection_count", 0, "detection_count does not match"),
    ],
)
def test_artifact_rejects_inconsistent_envelope(tmp_path: Path, field: str, value: object, message: str) -> None:
    document = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    document[field] = value
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(FingerprintArtifactError, match=message):
        load_artifact_sources(path)


def test_artifact_rejects_unsafe_or_unsorted_source_paths(tmp_path: Path) -> None:
    document = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    document["sources"][0]["path"] = "../ai.yaml"
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FingerprintArtifactError, match="YAML base name"):
        load_artifact_sources(path)

    document = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    document["sources"][0], document["sources"][1] = document["sources"][1], document["sources"][0]
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FingerprintArtifactError, match="sorted and unique"):
        load_artifact_sources(path)


def test_artifact_rejects_semantic_digest_mismatch(tmp_path: Path) -> None:
    document = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    document["sources"][0]["fingerprints"][0]["confidence"] = "low"
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(FingerprintArtifactError, match="semantic_sha256"):
        load_artifact_sources(path)


def test_artifact_size_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import recon_tool.fingerprint_artifact as artifact_module

    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(artifact_module, "MAX_ARTIFACT_BYTES", 1)

    with pytest.raises(FingerprintArtifactError, match="byte limit"):
        load_artifact_sources(path)


def test_artifact_fingerprint_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import recon_tool.fingerprint_artifact as artifact_module

    monkeypatch.setattr(artifact_module, "MAX_ARTIFACT_FINGERPRINTS", 0)

    with pytest.raises(FingerprintArtifactError, match="fingerprint limit"):
        load_artifact_sources(_ARTIFACT)


@pytest.mark.parametrize(
    "sources",
    [
        (),
        (
            ArtifactSource(path="b.yaml", fingerprints=()),
            ArtifactSource(path="a.yaml", fingerprints=()),
        ),
    ],
)
def test_serializer_rejects_empty_or_unsorted_sources(sources: tuple[ArtifactSource, ...]) -> None:
    with pytest.raises(ValueError, match="sorted, unique, and non-empty"):
        serialize_artifact_sources(sources)


def test_serializer_enforces_runtime_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    import recon_tool.fingerprint_artifact as artifact_module

    sources = (ArtifactSource(path="a.yaml", fingerprints=({"detections": []},)),)
    monkeypatch.setattr(artifact_module, "MAX_ARTIFACT_FINGERPRINTS", 0)
    with pytest.raises(ValueError, match="fingerprint limit"):
        serialize_artifact_sources(sources)

    monkeypatch.setattr(artifact_module, "MAX_ARTIFACT_FINGERPRINTS", 2000)
    monkeypatch.setattr(artifact_module, "MAX_ARTIFACT_BYTES", 1)
    with pytest.raises(ValueError, match="byte limit"):
        serialize_artifact_sources(sources)


def test_runtime_rejects_domain_invalid_generated_entries(tmp_path: Path) -> None:
    document = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    document["sources"][0]["fingerprints"][0]["confidence"] = ["high"]
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(FingerprintArtifactError, match="semantic_sha256"):
        _load_builtin_artifact(path)
