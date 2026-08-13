"""Freeze one private catalog-quality round before any target collection.

The plan and source rows remain maintainer-local.  This preparer validates the
round contract, reduces every supplied host to its registrable apex, and writes
an immutable newline-delimited corpus plus a canonical private manifest.  It
performs no network requests.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast

from recon_tool.validator import validate_domain
from validation.run_path_safety import validate_private_output_root

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = 2
ROUND_KINDS = frozenset({"baseline", "rank", "region", "vertical", "vendor-seed", "drift"})
OVERLAP_POLICIES = frozenset({"reject", "first-stratum-wins"})
_SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$")
_MAX_PLAN_BYTES = 256 * 1024
_MAX_SOURCE_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_FRAME_ROWS = 1_000_000
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_FRAME_BYTES = 256 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "private",
        "round_id",
        "round_kind",
        "question",
        "source",
        "strata",
        "policies",
        "collection",
        "thresholds",
        "promotion_budget",
    }
)
ROUND_MANIFEST_KEYS = frozenset(
    {
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
        "implementation",
        "plan_digest_sha256",
        "manifest_digest_sha256",
    }
)


@dataclass(frozen=True)
class RoundExecutionOptions:
    """Executable settings that must match a frozen round contract."""

    round_kind: str
    ct_enabled: bool
    min_count: int
    min_distinct_namespaces: int = 2


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _strict_object(value: object, *, name: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{name} must be an object")
    actual = frozenset(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        _fail(f"{name} has invalid fields: {'; '.join(details)}")
    return value


def _meaningful_text(value: object, *, name: str, minimum: int) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    normalized = " ".join(value.split())
    if len(normalized) < minimum or normalized.casefold() in {"n/a", "na", "none", "tbd", "unknown", "latest"}:
        _fail(f"{name} must be meaningful and at least {minimum} characters")
    return normalized


def _identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        _fail(f"{name} must be 1-80 lowercase letters, digits, dots, underscores, or hyphens")
    return value


def _positive_int(value: object, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(f"{name} must be a positive integer")
    return value


def _bounded_number(value: object, *, name: str, positive: bool) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        _fail(f"{name} must be a number")
    result = float(value)
    lower_ok = result > 0 if positive else result >= 0
    if not lower_ok or result > 1:
        interval = "(0, 1]" if positive else "[0, 1]"
        _fail(f"{name} must be in {interval}")
    return result


def _private_file(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


def _bounded_read(path: Path, *, maximum_bytes: int, name: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot read {name}: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail(f"{name} must be a regular file, not a symbolic link")
    size = before.st_size
    if size <= 0:
        _fail(f"{name} is empty")
    if size > maximum_bytes:
        _fail(f"{name} exceeds the {maximum_bytes}-byte limit")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {name}: {path}") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"{name} changed while it was read") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(payload) != size
    ):
        _fail(f"{name} changed while it was read")
    return payload


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 digest used by round contracts."""
    return _digest(value)


def canonical_json_digest(value: object) -> str:
    """Digest one value using the round contract's canonical JSON form."""
    return _digest(_canonical_json(value))


def _digest_paths(paths: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(REPO_ROOT).as_posix()):
        relative = path.relative_to(REPO_ROOT).as_posix().encode("utf-8")
        raw = _bounded_read(path, maximum_bytes=32 * 1024 * 1024, name="implementation input")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def catalog_digest_sha256() -> str:
    """Digest the canonical source fingerprint catalog."""
    catalog = REPO_ROOT / "src" / "recon_tool" / "data" / "fingerprints"
    files = sorted(catalog.glob("*.yaml"))
    if not files:
        _fail("fingerprint catalog has no source files")
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_bounded_read(path, maximum_bytes=32 * 1024 * 1024, name="fingerprint catalog input"))
        digest.update(b"\0")
    return digest.hexdigest()


def execution_digest_sha256() -> str:
    """Digest the code, data, and dependency lock used by a catalog scan."""
    package_root = REPO_ROOT / "src" / "recon_tool"
    package_files = [
        path for path in package_root.rglob("*") if path.is_file() and path.suffix in {".json", ".py", ".yaml"}
    ]
    validation_files = [
        REPO_ROOT / "validation" / name
        for name in (
            "catalog_baseline.py",
            "diff_runs.py",
            "find_gaps.py",
            "prepare_catalog_round.py",
            "run_path_safety.py",
            "scan.py",
            "triage_candidates.py",
        )
    ]
    root_files = [REPO_ROOT / "pyproject.toml", REPO_ROOT / "uv.lock"]
    return _digest_paths([*package_files, *validation_files, *root_files])


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            _fail(f"catalog round JSON contains duplicate field: {key}")
        value[key] = child
    return value


def _nonempty_text(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"round manifest {name} must be a non-empty string")
    return value


def _sha256(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"round manifest {name} must be a lowercase SHA-256 digest")
    return value


def load_round_manifest(manifest_path: Path) -> dict[str, object]:
    """Load one bounded, stable, private round manifest with exact fields."""
    resolved = _private_file(manifest_path)
    raw = _bounded_read(resolved, maximum_bytes=_MAX_MANIFEST_BYTES, name="round manifest")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("round manifest must be valid UTF-8 JSON") from exc
    return _strict_object(value, name="round manifest", keys=ROUND_MANIFEST_KEYS)


def validate_round_manifest_identity(manifest: dict[str, object], *, round_kind: str) -> None:
    """Validate immutable identity and source commitments."""
    if manifest["schema_version"] != SCHEMA_VERSION or manifest["private"] is not True:
        _fail(f"round manifest must use private schema version {SCHEMA_VERSION}")
    supplied = _sha256(manifest["manifest_digest_sha256"], name="manifest_digest_sha256")
    digest_payload = dict(manifest)
    del digest_payload["manifest_digest_sha256"]
    if canonical_json_digest(digest_payload) != supplied:
        _fail("round manifest digest mismatch")
    _sha256(manifest["plan_digest_sha256"], name="plan_digest_sha256")
    _identifier(manifest["round_id"], name="round manifest round_id")
    _meaningful_text(manifest["question"], name="round manifest question", minimum=12)
    prepared_at = _nonempty_text(manifest["prepared_at"], name="prepared_at")
    try:
        timestamp = datetime.fromisoformat(prepared_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("round manifest prepared_at must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
        _fail("round manifest prepared_at must carry the UTC timezone")
    manifest_round_kind = manifest["round_kind"]
    if (
        not isinstance(manifest_round_kind, str)
        or manifest_round_kind not in ROUND_KINDS
        or manifest_round_kind != round_kind
    ):
        _fail(f"round manifest kind {manifest_round_kind!r} does not match --round-kind {round_kind!r}")
    source = _strict_object(
        manifest["source"],
        name="round manifest source",
        keys=frozenset({"name", "revision", "digest_sha256"}),
    )
    _meaningful_text(source["name"], name="round manifest source.name", minimum=3)
    _meaningful_text(source["revision"], name="round manifest source.revision", minimum=2)
    _sha256(source["digest_sha256"], name="source.digest_sha256")
    implementation = _strict_object(
        manifest["implementation"],
        name="round manifest implementation",
        keys=frozenset({"catalog_digest_sha256", "execution_digest_sha256"}),
    )
    expected_catalog = _sha256(
        implementation["catalog_digest_sha256"],
        name="implementation.catalog_digest_sha256",
    )
    expected_execution = _sha256(
        implementation["execution_digest_sha256"],
        name="implementation.execution_digest_sha256",
    )
    if catalog_digest_sha256() != expected_catalog:
        _fail("round manifest catalog digest does not match the current catalog")
    if execution_digest_sha256() != expected_execution:
        _fail("round manifest execution digest does not match the current code or lockfile")


def canonical_frame_rows(frame_bytes: bytes) -> tuple[str, ...]:
    """Decode the exact normalized frame form emitted by the preparer."""
    try:
        text = frame_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("frozen round frame must be ASCII") from exc
    if not text.endswith("\n") or text.startswith("\n") or "\n\n" in text:
        _fail("frozen round frame must be non-empty newline-delimited canonical apexes")
    rows = tuple(text.splitlines())
    if not rows or tuple(sorted(set(rows))) != rows:
        _fail("frozen round frame must be sorted and contain unique canonical apexes")
    for row in rows:
        try:
            canonical = validate_domain(row)
        except ValueError as exc:
            raise ValueError("frozen round frame contains a malformed apex") from exc
        if canonical != row:
            _fail("frozen round frame must contain exact canonical registrable apexes")
    return rows


def load_round_frame_rows(manifest: dict[str, object]) -> tuple[str, ...]:
    """Read and verify the stable normalized frame named by a manifest."""
    frame = _strict_object(
        manifest["frame"],
        name="round manifest frame",
        keys=frozenset({"path", "digest_sha256", "count"}),
    )
    frame_path = _private_file(Path(_nonempty_text(frame["path"], name="frame.path")))
    frame_digest = _sha256(frame["digest_sha256"], name="frame.digest_sha256")
    frame_bytes = _bounded_read(frame_path, maximum_bytes=_MAX_FRAME_BYTES, name="frozen round frame")
    if digest_bytes(frame_bytes) != frame_digest:
        _fail("frozen round frame digest mismatch")
    rows = canonical_frame_rows(frame_bytes)
    frame_count = _positive_int(frame["count"], name="round manifest frame.count")
    if len(rows) != frame_count:
        _fail("frozen round frame row count does not match frame.count")
    return rows


def validate_round_manifest_frame(manifest: dict[str, object], *, corpus: Path) -> int:
    """Bind a stable normalized frame to its declared path, digest, and count."""
    frame = _strict_object(
        manifest["frame"],
        name="round manifest frame",
        keys=frozenset({"path", "digest_sha256", "count"}),
    )
    frame_path = _private_file(Path(_nonempty_text(frame["path"], name="frame.path")))
    corpus_path = _private_file(corpus)
    if frame_path != corpus_path:
        _fail("round manifest frame path does not match --corpus")
    return len(load_round_frame_rows(manifest))


def validate_round_manifest_strata(manifest: dict[str, object], *, frame_count: int) -> None:
    """Validate unique stratum identities and complete count accounting."""
    strata = manifest["strata"]
    if not isinstance(strata, list) or not strata:
        _fail("round manifest strata must be a non-empty array")
    if len(strata) > 100:
        _fail("round manifest strata exceeds the 100-stratum limit")
    stratum_count = 0
    stratum_ids: set[str] = set()
    for index, raw_stratum in enumerate(strata):
        stratum = _strict_object(
            raw_stratum,
            name=f"round manifest strata[{index}]",
            keys=frozenset({"id", "label", "count"}),
        )
        stratum_id = _identifier(stratum["id"], name=f"round manifest strata[{index}].id")
        _meaningful_text(stratum["label"], name=f"round manifest strata[{index}].label", minimum=3)
        count = _positive_int(stratum["count"], name=f"round manifest strata[{index}].count")
        if stratum_id in stratum_ids:
            _fail("round manifest stratum ids must be unique")
        stratum_ids.add(stratum_id)
        stratum_count += count
    if stratum_count != frame_count:
        _fail("round manifest stratum counts must sum to frame.count")


def validate_round_manifest_options(
    manifest: dict[str, object],
    *,
    ct_enabled: bool,
    min_count: int,
    min_distinct_namespaces: int = 2,
) -> None:
    """Bind collection and recurrence options and reject direct probes."""
    policies = _strict_object(
        manifest["policies"],
        name="round manifest policies",
        keys=frozenset({"exclusions", "overlap"}),
    )
    _meaningful_text(policies["exclusions"], name="round manifest policies.exclusions", minimum=12)
    if not isinstance(policies["overlap"], str) or policies["overlap"] not in OVERLAP_POLICIES:
        _fail(f"round manifest policies.overlap must be one of: {', '.join(sorted(OVERLAP_POLICIES))}")
    collection = _strict_object(
        manifest["collection"],
        name="round manifest collection",
        keys=frozenset({"ct_enabled", "direct_probes_enabled"}),
    )
    if not isinstance(collection["ct_enabled"], bool):
        _fail("round manifest collection.ct_enabled must be a boolean")
    if collection["ct_enabled"] is not ct_enabled:
        _fail("round manifest CT setting does not match the scan options")
    if collection["direct_probes_enabled"] is not False:
        _fail("catalog rounds do not permit direct probes")
    thresholds = _strict_object(
        manifest["thresholds"],
        name="round manifest thresholds",
        keys=frozenset({"minimum_occurrences", "minimum_distinct_namespaces"}),
    )
    _positive_int(thresholds["minimum_occurrences"], name="round manifest thresholds.minimum_occurrences")
    _positive_int(
        thresholds["minimum_distinct_namespaces"],
        name="round manifest thresholds.minimum_distinct_namespaces",
    )
    if (
        thresholds["minimum_occurrences"] != min_count
        or thresholds["minimum_distinct_namespaces"] != min_distinct_namespaces
    ):
        _fail("round manifest recurrence thresholds do not match the scan options")
    budget = _strict_object(
        manifest["promotion_budget"],
        name="round manifest promotion_budget",
        keys=frozenset({"metric", "minimum_improvement", "maximum_regression", "decision_rule"}),
    )
    _meaningful_text(budget["metric"], name="round manifest promotion_budget.metric", minimum=5)
    _bounded_number(
        budget["minimum_improvement"],
        name="round manifest promotion_budget.minimum_improvement",
        positive=True,
    )
    _bounded_number(
        budget["maximum_regression"],
        name="round manifest promotion_budget.maximum_regression",
        positive=False,
    )
    _meaningful_text(
        budget["decision_rule"],
        name="round manifest promotion_budget.decision_rule",
        minimum=15,
    )


def validate_round_contract(
    manifest: dict[str, object],
    *,
    corpus: Path,
    options: RoundExecutionOptions,
) -> None:
    """Validate every frozen-round commitment against executable options."""
    validate_round_manifest_identity(manifest, round_kind=options.round_kind)
    frame_count = validate_round_manifest_frame(manifest, corpus=corpus)
    validate_round_manifest_strata(manifest, frame_count=frame_count)
    validate_round_manifest_options(
        manifest,
        ct_enabled=options.ct_enabled,
        min_count=options.min_count,
        min_distinct_namespaces=options.min_distinct_namespaces,
    )


def load_round_contract(
    manifest_path: Path,
    *,
    corpus: Path,
    options: RoundExecutionOptions,
) -> dict[str, object]:
    """Load and verify a frozen private catalog-round contract."""
    manifest = load_round_manifest(manifest_path)
    validate_round_contract(
        manifest,
        corpus=corpus,
        options=options,
    )
    return manifest


def _load_plan(plan_path: Path) -> tuple[dict[str, object], bytes]:
    raw = _bounded_read(plan_path, maximum_bytes=_MAX_PLAN_BYTES, name="round plan")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("round plan must be valid UTF-8 JSON") from exc
    return _strict_object(value, name="round plan", keys=_PLAN_KEYS), raw


def _input_path(plan_path: Path, value: object, *, stratum_id: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        _fail(f"stratum {stratum_id} input must be a non-empty path")
    supplied = Path(value)
    path = supplied if supplied.is_absolute() else plan_path.parent / supplied
    return _private_file(path)


def _read_stratum(path: Path, *, stratum_id: str) -> tuple[tuple[str, ...], bytes]:
    raw = _bounded_read(path, maximum_bytes=_MAX_SOURCE_BYTES, name=f"stratum {stratum_id} input")
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"stratum {stratum_id} input must be UTF-8") from exc
    domains: set[str] = set()
    for row_number, raw_line in enumerate(lines, start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            domains.add(validate_domain(value))
        except ValueError as exc:
            raise ValueError(f"stratum {stratum_id} row {row_number} is malformed") from exc
    if not domains:
        _fail(f"stratum {stratum_id} has no valid domains")
    return tuple(sorted(domains)), raw


def _source_digest(parts: Sequence[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for stratum_id, raw in parts:
        identifier = stratum_id.encode("ascii")
        digest.update(len(identifier).to_bytes(2, "big"))
        digest.update(identifier)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _validate_plan(
    plan: Mapping[str, object],
    *,
    plan_path: Path,
) -> tuple[dict[str, object], list[tuple[str, str, Path]]]:
    if plan["schema_version"] != SCHEMA_VERSION:
        _fail(f"round plan schema_version must be {SCHEMA_VERSION}")
    if plan["private"] is not True:
        _fail("round plan private must be true")
    round_id = _identifier(plan["round_id"], name="round_id")
    round_kind = plan["round_kind"]
    if not isinstance(round_kind, str) or round_kind not in ROUND_KINDS:
        _fail(f"round_kind must be one of: {', '.join(sorted(ROUND_KINDS))}")
    question = _meaningful_text(plan["question"], name="question", minimum=12)

    source = _strict_object(plan["source"], name="source", keys=frozenset({"name", "revision"}))
    source_name = _meaningful_text(source["name"], name="source.name", minimum=3)
    source_revision = _meaningful_text(source["revision"], name="source.revision", minimum=2)

    raw_strata = plan["strata"]
    if not isinstance(raw_strata, list) or not raw_strata:
        _fail("strata must be a non-empty list")
    if len(raw_strata) > 100:
        _fail("strata exceeds the 100-stratum limit")
    strata: list[tuple[str, str, Path]] = []
    seen_ids: set[str] = set()
    for index, raw_stratum in enumerate(raw_strata):
        stratum = _strict_object(
            raw_stratum,
            name=f"strata[{index}]",
            keys=frozenset({"id", "label", "input"}),
        )
        stratum_id = _identifier(stratum["id"], name=f"strata[{index}].id")
        if stratum_id in seen_ids:
            _fail(f"duplicate stratum id: {stratum_id}")
        seen_ids.add(stratum_id)
        label = _meaningful_text(stratum["label"], name=f"strata[{index}].label", minimum=3)
        strata.append((stratum_id, label, _input_path(plan_path, stratum["input"], stratum_id=stratum_id)))

    policies = _strict_object(plan["policies"], name="policies", keys=frozenset({"exclusions", "overlap"}))
    exclusions = _meaningful_text(policies["exclusions"], name="policies.exclusions", minimum=12)
    overlap = policies["overlap"]
    if not isinstance(overlap, str) or overlap not in OVERLAP_POLICIES:
        _fail(f"policies.overlap must be one of: {', '.join(sorted(OVERLAP_POLICIES))}")

    collection = _strict_object(
        plan["collection"],
        name="collection",
        keys=frozenset({"ct_enabled", "direct_probes_enabled"}),
    )
    if not isinstance(collection["ct_enabled"], bool):
        _fail("collection.ct_enabled must be a boolean")
    if collection["direct_probes_enabled"] is not False:
        _fail("collection.direct_probes_enabled must be false")

    thresholds = _strict_object(
        plan["thresholds"],
        name="thresholds",
        keys=frozenset({"minimum_occurrences", "minimum_distinct_namespaces"}),
    )
    minimum_occurrences = _positive_int(thresholds["minimum_occurrences"], name="thresholds.minimum_occurrences")
    minimum_namespaces = _positive_int(
        thresholds["minimum_distinct_namespaces"],
        name="thresholds.minimum_distinct_namespaces",
    )

    budget = _strict_object(
        plan["promotion_budget"],
        name="promotion_budget",
        keys=frozenset({"metric", "minimum_improvement", "maximum_regression", "decision_rule"}),
    )
    metric = _meaningful_text(budget["metric"], name="promotion_budget.metric", minimum=5)
    minimum_improvement = _bounded_number(
        budget["minimum_improvement"],
        name="promotion_budget.minimum_improvement",
        positive=True,
    )
    maximum_regression = _bounded_number(
        budget["maximum_regression"],
        name="promotion_budget.maximum_regression",
        positive=False,
    )
    decision_rule = _meaningful_text(
        budget["decision_rule"],
        name="promotion_budget.decision_rule",
        minimum=15,
    )

    normalized: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "round_id": round_id,
        "round_kind": round_kind,
        "question": question,
        "source": {"name": source_name, "revision": source_revision},
        "policies": {"exclusions": exclusions, "overlap": overlap},
        "collection": {
            "ct_enabled": collection["ct_enabled"],
            "direct_probes_enabled": False,
        },
        "thresholds": {
            "minimum_occurrences": minimum_occurrences,
            "minimum_distinct_namespaces": minimum_namespaces,
        },
        "promotion_budget": {
            "metric": metric,
            "minimum_improvement": minimum_improvement,
            "maximum_regression": maximum_regression,
            "decision_rule": decision_rule,
        },
    }
    return normalized, strata


def prepare_catalog_round(
    plan_path: Path,
    frame_path: Path,
    *,
    prepared_at: str | None = None,
) -> tuple[bytes, dict[str, object]]:
    """Return normalized frame bytes and its canonical private manifest."""
    resolved_plan = _private_file(plan_path)
    plan, plan_raw = _load_plan(resolved_plan)
    normalized, strata_spec = _validate_plan(plan, plan_path=resolved_plan)

    normalized_policies = cast(dict[str, object], normalized["policies"])
    overlap_policy = str(normalized_policies["overlap"])
    assigned: dict[str, str] = {}
    source_parts: list[tuple[str, bytes]] = []
    strata_rows: list[dict[str, object]] = []
    all_domains: set[str] = set()
    total_source_bytes = 0
    for stratum_id, label, input_path in strata_spec:
        domains, raw = _read_stratum(input_path, stratum_id=stratum_id)
        total_source_bytes += len(raw)
        if total_source_bytes > _MAX_TOTAL_SOURCE_BYTES:
            _fail(f"round sources exceed the {_MAX_TOTAL_SOURCE_BYTES}-byte aggregate limit")
        source_parts.append((stratum_id, raw))
        accepted: list[str] = []
        for domain in domains:
            prior = assigned.get(domain)
            if prior is not None:
                if overlap_policy == "reject":
                    _fail(f"registrable apex appears in multiple strata: {prior}, {stratum_id}")
                continue
            assigned[domain] = stratum_id
            accepted.append(domain)
            all_domains.add(domain)
            if len(all_domains) > _MAX_FRAME_ROWS:
                _fail(f"round frame exceeds the {_MAX_FRAME_ROWS}-domain limit")
        if not accepted:
            _fail(f"stratum {stratum_id} is empty after overlap policy")
        strata_rows.append({"id": stratum_id, "label": label, "count": len(accepted)})

    rendered = ("\n".join(sorted(all_domains)) + "\n").encode("ascii")
    timestamp = prepared_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("prepared_at must be an ISO-8601 timestamp") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() != UTC.utcoffset(parsed_timestamp):
        _fail("prepared_at must carry the UTC timezone")

    source = cast(dict[str, object], normalized["source"])
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "round_id": normalized["round_id"],
        "round_kind": normalized["round_kind"],
        "question": normalized["question"],
        "prepared_at": timestamp,
        "source": {
            "name": source["name"],
            "revision": source["revision"],
            "digest_sha256": _source_digest(source_parts),
        },
        "frame": {
            "path": str(_private_file(frame_path)),
            "digest_sha256": _digest(rendered),
            "count": len(all_domains),
        },
        "strata": strata_rows,
        "policies": normalized["policies"],
        "collection": normalized["collection"],
        "thresholds": normalized["thresholds"],
        "promotion_budget": normalized["promotion_budget"],
        "implementation": {
            "catalog_digest_sha256": catalog_digest_sha256(),
            "execution_digest_sha256": execution_digest_sha256(),
        },
        "plan_digest_sha256": _digest(plan_raw),
    }
    manifest["manifest_digest_sha256"] = _digest(_canonical_json(manifest))
    return rendered, manifest


def _reserve_exclusive(path: Path, *, kind: str) -> int:
    resolved = _private_file(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    try:
        return os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"{kind} already exists; refusing to replace it") from exc


def write_catalog_round(plan_path: Path, frame_path: Path, manifest_path: Path) -> dict[str, object]:
    """Prepare and exclusively write both private round artifacts."""
    resolved_frame = _private_file(frame_path)
    resolved_manifest = _private_file(manifest_path)
    if resolved_frame.exists():
        _fail("private normalized corpus already exists; refusing to replace it")
    if resolved_manifest.exists():
        _fail("private round manifest already exists; refusing to replace it")
    frame, manifest = prepare_catalog_round(plan_path, resolved_frame)
    frame_descriptor: int | None = None
    manifest_descriptor: int | None = None
    frame_owned = False
    manifest_owned = False
    try:
        frame_descriptor = _reserve_exclusive(resolved_frame, kind="private normalized corpus")
        frame_owned = True
        manifest_descriptor = _reserve_exclusive(resolved_manifest, kind="private round manifest")
        manifest_owned = True
        with os.fdopen(frame_descriptor, "wb") as handle:
            frame_descriptor = None
            handle.write(frame)
        with os.fdopen(manifest_descriptor, "wb") as handle:
            manifest_descriptor = None
            handle.write(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    except Exception:
        if frame_descriptor is not None:
            os.close(frame_descriptor)
        if manifest_descriptor is not None:
            os.close(manifest_descriptor)
        if frame_owned:
            with contextlib.suppress(OSError):
                resolved_frame.unlink()
        if manifest_owned:
            with contextlib.suppress(OSError):
                resolved_manifest.unlink()
        raise
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path, help="Strict private round-plan JSON.")
    parser.add_argument("--output-corpus", required=True, type=Path, help="Private normalized apex corpus to create.")
    parser.add_argument("--output-manifest", required=True, type=Path, help="Private canonical manifest to create.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifest = write_catalog_round(args.plan, args.output_corpus, args.output_manifest)
    source = cast(dict[str, object], manifest["source"])
    frame = cast(dict[str, object], manifest["frame"])
    print(
        json.dumps(
            {
                "schema_version": manifest["schema_version"],
                "round_id": manifest["round_id"],
                "round_kind": manifest["round_kind"],
                "source_digest_sha256": source["digest_sha256"],
                "frame_digest_sha256": frame["digest_sha256"],
                "frame_count": frame["count"],
                "manifest_digest_sha256": manifest["manifest_digest_sha256"],
                "identifiers_printed": 0,
                "network_requests": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
