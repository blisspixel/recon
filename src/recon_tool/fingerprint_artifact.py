"""Bounded JSON envelope for the generated built-in fingerprint catalog.

This module validates only the artifact container. Fingerprint domain rules
remain owned by :mod:`recon_tool.fingerprints` and are applied after decoding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

ARTIFACT_FORMAT_VERSION = 1
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_FINGERPRINTS = 2000

_ROOT_KEYS = frozenset({"format_version", "fingerprint_count", "detection_count", "semantic_sha256", "sources"})
_SOURCE_KEYS = frozenset({"path", "fingerprints"})


class FingerprintArtifactError(ValueError):
    """Raised when a generated catalog artifact violates its envelope."""


@dataclass(frozen=True)
class ArtifactSource:
    """One canonical source file and its ordered raw fingerprint mappings."""

    path: str
    fingerprints: tuple[dict[str, Any], ...]


def _require_exact_keys(value: dict[str, Any], expected: frozenset[str], context: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing keys: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected keys: {', '.join(extra)}")
        raise FingerprintArtifactError(f"{context} has an invalid shape ({'; '.join(details)})")


def _require_count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FingerprintArtifactError(f"{context} must be a non-negative integer")
    return value


def _decode_source(value: Any, index: int) -> ArtifactSource:
    context = f"sources[{index}]"
    if not isinstance(value, dict):
        raise FingerprintArtifactError(f"{context} must be an object")
    _require_exact_keys(value, _SOURCE_KEYS, context)
    path = value["path"]
    if not isinstance(path, str) or not path or PurePosixPath(path).name != path or not path.endswith(".yaml"):
        raise FingerprintArtifactError(f"{context}.path must be a YAML base name")
    fingerprints = value["fingerprints"]
    if not isinstance(fingerprints, list):
        raise FingerprintArtifactError(f"{context}.fingerprints must be an array")
    if not all(isinstance(fingerprint, dict) for fingerprint in fingerprints):
        raise FingerprintArtifactError(f"{context}.fingerprints must contain only objects")
    return ArtifactSource(path=path, fingerprints=tuple(fingerprints))


def _sources_payload(sources: tuple[ArtifactSource, ...]) -> list[dict[str, object]]:
    return [{"path": source.path, "fingerprints": list(source.fingerprints)} for source in sources]


def _semantic_digest(sources: tuple[ArtifactSource, ...]) -> str:
    payload = json.dumps(
        _sources_payload(sources), ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def load_artifact_sources(path: Path) -> tuple[ArtifactSource, ...]:
    """Decode one size-bounded, versioned generated catalog artifact."""
    try:
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise FingerprintArtifactError(f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FingerprintArtifactError(f"artifact is unavailable: {exc}") from exc
    except UnicodeError as exc:
        raise FingerprintArtifactError(f"artifact is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FingerprintArtifactError(f"artifact is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise FingerprintArtifactError("artifact root must be an object")
    _require_exact_keys(raw, _ROOT_KEYS, "artifact")
    format_version = raw["format_version"]
    if (
        not isinstance(format_version, int)
        or isinstance(format_version, bool)
        or format_version != ARTIFACT_FORMAT_VERSION
    ):
        raise FingerprintArtifactError(f"unsupported artifact format version: {raw['format_version']!r}")
    sources_raw = raw["sources"]
    if not isinstance(sources_raw, list) or not sources_raw:
        raise FingerprintArtifactError("artifact.sources must be a non-empty array")
    sources = tuple(_decode_source(value, index) for index, value in enumerate(sources_raw))
    paths = [source.path for source in sources]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise FingerprintArtifactError("artifact source paths must be sorted and unique")
    semantic_sha256 = raw["semantic_sha256"]
    if not isinstance(semantic_sha256, str) or semantic_sha256 != _semantic_digest(sources):
        raise FingerprintArtifactError("artifact.semantic_sha256 does not match its sources")
    fingerprint_count = sum(len(source.fingerprints) for source in sources)
    if fingerprint_count > MAX_ARTIFACT_FINGERPRINTS:
        raise FingerprintArtifactError(
            f"artifact exceeds the {MAX_ARTIFACT_FINGERPRINTS}-fingerprint limit"
        )
    if _require_count(raw["fingerprint_count"], "artifact.fingerprint_count") != fingerprint_count:
        raise FingerprintArtifactError("artifact.fingerprint_count does not match its sources")
    detection_count = sum(
        len(fingerprint.get("detections", ()))
        for source in sources
        for fingerprint in source.fingerprints
        if isinstance(fingerprint.get("detections"), list)
    )
    if _require_count(raw["detection_count"], "artifact.detection_count") != detection_count:
        raise FingerprintArtifactError("artifact.detection_count does not match its sources")
    return sources


def serialize_artifact_sources(sources: tuple[ArtifactSource, ...]) -> str:
    """Return canonical JSON text for already ordered source mappings."""
    paths = tuple(source.path for source in sources)
    if not paths or paths != tuple(sorted(set(paths))):
        raise ValueError("artifact source paths must be sorted, unique, and non-empty")
    fingerprint_count = sum(len(source.fingerprints) for source in sources)
    if fingerprint_count > MAX_ARTIFACT_FINGERPRINTS:
        raise ValueError(f"artifact exceeds the {MAX_ARTIFACT_FINGERPRINTS}-fingerprint limit")
    detection_count = sum(
        len(fingerprint.get("detections", ()))
        for source in sources
        for fingerprint in source.fingerprints
        if isinstance(fingerprint.get("detections"), list)
    )
    document = {
        "format_version": ARTIFACT_FORMAT_VERSION,
        "fingerprint_count": fingerprint_count,
        "detection_count": detection_count,
        "semantic_sha256": _semantic_digest(sources),
        "sources": _sources_payload(sources),
    }
    text = json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n"
    if len(text.encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte limit")
    return text
