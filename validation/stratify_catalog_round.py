"""Reduce frozen catalog results by private stratum without leaking members.

The original scan result, round plan, and detailed candidate queues remain in
ignored private workspaces. Public review is limited to ordered stratum indexes,
counts, typed aggregate measures, and cryptographic commitments. This tool
performs no network requests.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from validation import catalog_baseline  # noqa: E402
from validation.prepare_catalog_round import (  # noqa: E402
    RoundStratumMembership,
    execution_digest_sha256,
    load_round_manifest,
    load_round_membership,
)
from validation.ranked_sampling import bounded_stable_read, digest_bytes  # noqa: E402
from validation.run_path_safety import validate_private_output_root  # noqa: E402

PRIVATE_OUTPUT_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = "1.0"
_MAX_AGGREGATE_BYTES = 32 * 1024 * 1024
_MIN_PUBLIC_STRATUM_ROWS = 20


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _private_output(path: Path) -> Path:
    return validate_private_output_root(path, repo_root=REPO_ROOT, allowed_roots=PRIVATE_OUTPUT_ROOTS)


def _read_json_object(path: Path, *, kind: str) -> tuple[dict[str, Any], bytes]:
    raw = bounded_stable_read(path.resolve(strict=False), maximum_bytes=_MAX_AGGREGATE_BYTES, kind=kind)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{kind} must contain one JSON object")
    return value, raw


def _result_domain(record: Mapping[str, Any]) -> str | None:
    value = record.get("domain") if record.get("record_type") == "error" else record.get("queried_domain")
    return value if isinstance(value, str) else None


def _membership_index(
    memberships: Sequence[RoundStratumMembership],
) -> tuple[dict[str, int], list[list[dict[str, Any]]]]:
    index: dict[str, int] = {}
    records: list[list[dict[str, Any]]] = [[] for _ in memberships]
    for stratum_index, stratum in enumerate(memberships):
        for domain in stratum.domains:
            if domain in index:
                _fail("frozen round membership assigns one namespace to multiple strata")
            index[domain] = stratum_index
    return index, records


def _partition_records(
    results_path: Path,
    memberships: Sequence[RoundStratumMembership],
) -> tuple[list[list[dict[str, Any]]], list[Path]]:
    membership_by_domain, records_by_stratum = _membership_index(memberships)
    seen: set[str] = set()
    for record in catalog_baseline.iter_result_records(results_path):
        domain = _result_domain(record)
        if domain is None or domain not in membership_by_domain:
            _fail("result record does not belong to the frozen stratum membership")
        if domain in seen:
            _fail("result records contain a duplicate frozen-frame namespace")
        seen.add(domain)
        records_by_stratum[membership_by_domain[domain]].append(record)
    expected = set(membership_by_domain)
    if seen != expected:
        _fail(f"stratified reduction requires the complete frozen frame; observed {len(seen)} of {len(expected)} rows")
    files = catalog_baseline.result_files(results_path)
    if not files:
        _fail("no result files were found for stratified reduction")
    return records_by_stratum, files


def _validate_pooled_aggregate(
    pooled: Mapping[str, Any],
    *,
    manifest: Mapping[str, object],
    results_digest: str,
    records_total: int,
) -> None:
    catalog_baseline.assert_aggregate_safe(pooled)
    if pooled.get("aggregate_only") is not True:
        _fail("pooled catalog baseline is not marked aggregate-only")
    if pooled.get("results_digest_sha256") != results_digest:
        _fail("pooled catalog baseline results digest does not match the frozen results")
    if pooled.get("records_total") != records_total:
        _fail("pooled catalog baseline record count does not match the frozen results")
    contract = pooled.get("round_contract")
    if not isinstance(contract, dict):
        _fail("pooled catalog baseline has no round contract")
    if contract.get("manifest_digest_sha256") != manifest.get("manifest_digest_sha256"):
        _fail("pooled catalog baseline does not reference the frozen round manifest")
    if contract.get("implementation") != manifest.get("implementation"):
        _fail("pooled catalog baseline implementation commitment does not match the frozen round manifest")


def _stratum_digest(stratum: RoundStratumMembership) -> str:
    raw = ("\n".join(sorted(stratum.domains)) + "\n").encode("ascii")
    return digest_bytes(raw)


def _reducer_digest() -> str:
    files = [
        REPO_ROOT / "validation" / "catalog_baseline.py",
        REPO_ROOT / "validation" / "prepare_catalog_round.py",
        REPO_ROOT / "validation" / "stratify_catalog_round.py",
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / "uv.lock",
    ]
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(REPO_ROOT).as_posix().encode("utf-8")
        raw = bounded_stable_read(path, maximum_bytes=32 * 1024 * 1024, kind="stratified reducer input")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def reduce_strata(
    *,
    results_path: Path,
    round_plan_path: Path,
    round_manifest_path: Path,
    pooled_aggregate_path: Path,
    max_samples: int = 3,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return public aggregate, private candidates, and private manifest."""
    if max_samples < 0:
        _fail("max_samples must be non-negative")
    manifest = load_round_manifest(round_manifest_path)
    memberships = load_round_membership(round_plan_path, manifest)
    if any(len(membership.domains) < _MIN_PUBLIC_STRATUM_ROWS for membership in memberships):
        _fail(f"public stratified output requires at least {_MIN_PUBLIC_STRATUM_ROWS} rows in every stratum")
    records_by_stratum, result_files = _partition_records(results_path, memberships)
    results_digest = catalog_baseline.digest_result_files(result_files)
    records_total = sum(len(records) for records in records_by_stratum)
    pooled, pooled_raw = _read_json_object(pooled_aggregate_path, kind="pooled catalog baseline")
    _validate_pooled_aggregate(
        pooled,
        manifest=manifest,
        results_digest=results_digest,
        records_total=records_total,
    )

    thresholds = cast(dict[str, object], manifest["thresholds"])
    min_count = int(cast(int, thresholds["minimum_occurrences"]))
    min_namespaces = int(cast(int, thresholds["minimum_distinct_namespaces"]))
    strata: list[dict[str, Any]] = []
    private_candidates: list[dict[str, Any]] = []
    for stratum_index, (membership, records) in enumerate(zip(memberships, records_by_stratum, strict=True)):
        aggregate, candidates = catalog_baseline.aggregate_records(
            records,
            min_count=min_count,
            min_distinct_namespaces=min_namespaces,
            max_samples=max_samples,
        )
        strata.append(
            {
                "stratum_index": stratum_index,
                "frame_count": len(membership.domains),
                "frame_digest_sha256": _stratum_digest(membership),
                "complete": len(records) == len(membership.domains),
                "aggregate": aggregate,
            }
        )
        private_candidates.append(
            {
                "stratum_id": membership.id,
                "stratum_label": membership.label,
                "candidates": candidates,
            }
        )

    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    revision, dirty = catalog_baseline.repository_revision()
    public: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "aggregate_only": True,
        "generated_at": generated_at,
        "round_kind": manifest["round_kind"],
        "records_total": records_total,
        "results_digest_sha256": results_digest,
        "pooled_aggregate_sha256": digest_bytes(pooled_raw),
        "observation_contract": catalog_baseline.public_round_contract(cast(dict[str, Any], manifest)),
        "reducer": {
            "code_revision": revision,
            "working_tree_dirty": dirty,
            "digest_sha256": _reducer_digest(),
            "network_requests": 0,
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "strata": strata,
    }
    catalog_baseline.assert_aggregate_safe(public)
    private_payload = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "generated_at": generated_at,
        "round_manifest": manifest,
        "strata": private_candidates,
    }
    private_manifest = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "generated_at": generated_at,
        "results_path": str(results_path.resolve(strict=False)),
        "round_plan_path": str(round_plan_path.resolve(strict=False)),
        "round_manifest_path": str(round_manifest_path.resolve(strict=False)),
        "pooled_aggregate_path": str(pooled_aggregate_path.resolve(strict=False)),
        "results_digest_sha256": results_digest,
        "pooled_aggregate_sha256": digest_bytes(pooled_raw),
        "observation_execution_digest_sha256": cast(dict[str, object], manifest["implementation"])[
            "execution_digest_sha256"
        ],
        "current_execution_digest_sha256": execution_digest_sha256(),
        "stratified_reducer_digest_sha256": public["reducer"]["digest_sha256"],
        "records_total": records_total,
        "stratum_counts": [len(records) for records in records_by_stratum],
    }
    return public, private_payload, private_manifest


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("stratified catalog output already exists; refusing to replace it") from exc


def write_stratified_outputs(
    output_dir: Path,
    public: Mapping[str, Any],
    private_payload: Mapping[str, Any],
    private_manifest: Mapping[str, Any],
) -> None:
    """Exclusively write all three stratified reduction artifacts."""
    root = _private_output(output_dir.resolve(strict=False))
    root.mkdir(parents=True, exist_ok=True)
    outputs = {
        root / "catalog-stratified-aggregate.json": public,
        root / "catalog-stratified-gaps.json": private_payload,
        root / "catalog-stratified-manifest.json": private_manifest,
    }
    descriptors: dict[Path, int] = {}
    owned: list[Path] = []
    try:
        for path in outputs:
            descriptors[path] = _reserve(path)
            owned.append(path)
        for path, value in outputs.items():
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in owned:
            with contextlib.suppress(OSError):
                path.unlink()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Private result file or run directory.")
    parser.add_argument("--round-plan", required=True, type=Path, help="Original frozen private round plan.")
    parser.add_argument("--round-manifest", required=True, type=Path, help="Original frozen private round manifest.")
    parser.add_argument("--pooled-aggregate", required=True, type=Path, help="Completed pooled aggregate for the run.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Ignored private output directory.")
    parser.add_argument("--max-samples", type=int, default=3)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        public, private_payload, private_manifest = reduce_strata(
            results_path=args.input,
            round_plan_path=args.round_plan,
            round_manifest_path=args.round_manifest,
            pooled_aggregate_path=args.pooled_aggregate,
            max_samples=args.max_samples,
        )
        write_stratified_outputs(args.output_dir, public, private_payload, private_manifest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "records_total": public["records_total"],
                "strata": [
                    {
                        "stratum_index": row["stratum_index"],
                        "frame_count": row["frame_count"],
                        "complete": row["complete"],
                    }
                    for row in public["strata"]
                ],
                "results_digest_sha256": public["results_digest_sha256"],
                "reducer_digest_sha256": public["reducer"]["digest_sha256"],
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
