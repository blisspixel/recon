"""Aggregate typed catalog coverage from private recon batch results.

The input and detailed gap queue remain in an ignored private workspace. The
separate aggregate output contains counts, digests, and environment metadata
only, so a maintainer can review it before copying results into a public memo.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from recon_tool.fingerprint_artifact import load_artifact_sources
from recon_tool.validator import host_has_suffix

REPO_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "live_runs",
    REPO_ROOT / "validation" / "local",
)
RECORD_TYPES = (
    "cname_target",
    "cname",
    "txt",
    "spf",
    "mx",
    "ns",
    "caa",
    "dmarc_rua",
    "subdomain_txt",
    "srv",
)
HOST_RECORD_TYPES = frozenset({"cname_target", "cname", "spf", "mx", "ns", "dmarc_rua", "srv"})
_SAFE_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,63}$", re.IGNORECASE)
_CAA_ISSUER_RE = re.compile(r"\bissue(?:wild)?\s+\"?([^\";\s]+)", re.IGNORECASE)
_FORBIDDEN_AGGREGATE_KEYS = frozenset(
    {
        "apex",
        "candidates",
        "domain",
        "domains",
        "owner",
        "queried_domain",
        "samples",
        "tenant_id",
        "value",
    }
)


@dataclass
class CandidateBucket:
    """Private recurrence bucket with no retained namespace list in output."""

    count: int = 0
    namespaces: set[str] = field(default_factory=set)
    samples: list[dict[str, str]] = field(default_factory=list)


def _validate_private_path(path: Path) -> Path:
    from validation.run_path_safety import validate_private_output_root

    return validate_private_output_root(path, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)


def _result_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = sorted(path.glob("results*.ndjson")) + sorted(path.glob("results*.json"))
    if not files:
        files = sorted(path.glob("*.ndjson"))
    return files


def _iter_records(path: Path) -> Iterator[dict[str, Any]]:
    for result_file in _result_files(path):
        try:
            text = result_file.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"warning: cannot read {result_file}: {exc}", file=sys.stderr)
            continue
        stripped = text.lstrip()
        if not stripped:
            continue
        if stripped.startswith("["):
            with contextlib.suppress(json.JSONDecodeError):
                payload = json.loads(text)
                if isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict):
                            yield item
                continue
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"warning: skipping malformed line {line_number} in {result_file}: {exc}",
                    file=sys.stderr,
                )
                continue
            if isinstance(item, dict):
                yield item


def _digest_files(files: list[Path], *, relative_to: Path | None = None) -> str:
    digest = hashlib.sha256()
    for path in files:
        name = path.relative_to(relative_to).as_posix() if relative_to is not None else path.name
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _catalog_metadata(catalog_dir: Path) -> dict[str, Any]:
    source_files = sorted(catalog_dir.glob("*.yaml"))
    artifact = catalog_dir.parent / "fingerprints.generated.json"
    sources = load_artifact_sources(artifact)
    fingerprints = [fingerprint for source in sources for fingerprint in source.fingerprints]
    detections = [
        detection
        for fingerprint in fingerprints
        for detection in fingerprint.get("detections", [])
        if isinstance(detection, dict)
    ]
    dated = sum(isinstance(detection.get("verified"), str) for detection in detections)
    return {
        "digest_sha256": _digest_files(source_files, relative_to=catalog_dir),
        "entries": len(fingerprints),
        "detections": len(detections),
        "dated_detections": dated,
        "undated_detections": len(detections) - dated,
    }


def _git_revision() -> tuple[str, bool]:
    git = shutil.which("git")
    if git is None:
        return "unknown", True
    revision = subprocess.run(  # noqa: S603 - executable resolved locally; arguments are fixed
        [git, "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    status = subprocess.run(  # noqa: S603 - executable resolved locally; arguments are fixed
        [git, "status", "--porcelain"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    sha = revision.stdout.strip() if revision.returncode == 0 else "unknown"
    return sha, bool(status.stdout.strip())


def _host_bucket(value: str) -> str | None:
    host = value.strip().lower().rstrip(".")
    if not host or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789.-_" for char in host):
        return None
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return None
    return ".".join(labels[-3:]) if len(labels) >= 3 else ".".join(labels)


def _candidate_key(record_type: str, owner: str, value: str, apex: str) -> str | None:
    normalized_value = value.strip().lower()
    key: str | None = None
    if record_type in HOST_RECORD_TYPES:
        host = normalized_value.split()[-1].rstrip(".") if normalized_value else ""
        if host and host != "." and not (apex and host_has_suffix(host, apex)):
            key = _host_bucket(host)
    elif record_type == "caa":
        match = _CAA_ISSUER_RE.search(normalized_value)
        key = _host_bucket(match.group(1)) if match is not None else None
    elif record_type == "subdomain_txt":
        key = owner.strip().lower() or None
    elif record_type == "txt":
        prefix = normalized_value.split("=", 1)[0].strip()
        if prefix == "v" and "=" in normalized_value:
            version = re.split(r"[;\s]", normalized_value.split("=", 1)[1], maxsplit=1)[0]
            key = f"v={version[:32]}" if version else None
        elif _SAFE_PREFIX_RE.fullmatch(prefix) is not None:
            key = prefix
        else:
            value_digest = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()[:16]
            key = f"opaque:{value_digest}"
    return key


def _availability_counts() -> dict[str, int]:
    return dict.fromkeys(("available", "partial", "unavailable", "unmeasured"), 0)


def _new_type_totals() -> dict[str, dict[str, Any]]:
    return {
        record_type: {
            "availability": _availability_counts(),
            "measured_namespaces": 0,
            "opportunity_count": 0,
            "observed_count": 0,
            "classified_count": 0,
            "unclassified_count": 0,
            "truncated_namespaces": 0,
        }
        for record_type in RECORD_TYPES
    }


def _accumulate_summary_rows(record: dict[str, Any], type_totals: dict[str, dict[str, Any]]) -> None:
    summaries = record.get("dns_catalog_summary")
    summary_by_type = (
        {
            str(item.get("record_type")): item
            for item in summaries
            if isinstance(item, dict) and isinstance(item.get("record_type"), str)
        }
        if isinstance(summaries, list)
        else {}
    )
    for record_type in RECORD_TYPES:
        row = summary_by_type.get(record_type)
        if row is None:
            type_totals[record_type]["availability"]["unmeasured"] += 1
            continue
        availability = str(row.get("availability", "unmeasured"))
        if availability not in type_totals[record_type]["availability"]:
            availability = "unmeasured"
        type_totals[record_type]["availability"][availability] += 1
        if availability in {"available", "partial"}:
            type_totals[record_type]["measured_namespaces"] += 1
        for key in ("opportunity_count", "observed_count", "classified_count", "unclassified_count"):
            value = row.get(key, 0)
            if isinstance(value, int) and value >= 0:
                type_totals[record_type][key] += value
        if bool(row.get("truncated")):
            type_totals[record_type]["truncated_namespaces"] += 1


def _accumulate_candidate_rows(
    record: dict[str, Any],
    buckets: dict[str, dict[str, CandidateBucket]],
    *,
    max_samples: int,
) -> None:
    observations = record.get("unclassified_dns_observations")
    if not isinstance(observations, list):
        return
    apex = str(record.get("queried_domain", "")).strip().lower()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        record_type = str(observation.get("record_type", ""))
        if record_type not in buckets:
            continue
        owner = str(observation.get("owner", ""))
        value = str(observation.get("value", ""))
        key = _candidate_key(record_type, owner, value, apex)
        if key is None:
            continue
        bucket = buckets[record_type][key]
        bucket.count += 1
        if apex:
            bucket.namespaces.add(apex)
        if len(bucket.samples) < max_samples:
            bucket.samples.append({"owner": owner, "value": value})


def _finalize_candidates(
    buckets: dict[str, dict[str, CandidateBucket]],
    type_totals: dict[str, dict[str, Any]],
    *,
    min_count: int,
    min_distinct_namespaces: int,
) -> dict[str, list[dict[str, Any]]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    for record_type in RECORD_TYPES:
        rows = [
            {
                "key": key,
                "count": bucket.count,
                "distinct_namespace_count": len(bucket.namespaces),
                "samples": bucket.samples,
            }
            for key, bucket in buckets[record_type].items()
            if bucket.count >= min_count and len(bucket.namespaces) >= min_distinct_namespaces
        ]
        candidates[record_type] = sorted(rows, key=lambda row: (-int(row["count"]), str(row["key"])))
        total = type_totals[record_type]
        observed = int(total["observed_count"])
        classified = int(total["classified_count"])
        total["classified_rate"] = round(classified / observed, 6) if observed else None
        total["recurrent_candidate_buckets"] = len(candidates[record_type])
    return candidates


def aggregate_records(
    records: list[dict[str, Any]],
    *,
    min_count: int,
    min_distinct_namespaces: int,
    max_samples: int,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Return a public-safe aggregate and a private typed candidate queue."""
    type_totals = _new_type_totals()
    buckets: dict[str, dict[str, CandidateBucket]] = {
        record_type: defaultdict(CandidateBucket) for record_type in RECORD_TYPES
    }
    degraded_counts: Counter[str] = Counter()
    partial_records = 0

    for record in records:
        if bool(record.get("partial")):
            partial_records += 1
        degraded = record.get("degraded_sources")
        if isinstance(degraded, list):
            degraded_counts.update(str(item) for item in degraded if isinstance(item, str))
        _accumulate_summary_rows(record, type_totals)
        _accumulate_candidate_rows(record, buckets, max_samples=max_samples)

    candidates = _finalize_candidates(
        buckets,
        type_totals,
        min_count=min_count,
        min_distinct_namespaces=min_distinct_namespaces,
    )

    aggregate = {
        "schema_version": "1.0",
        "aggregate_only": True,
        "records_total": len(records),
        "partial_records": partial_records,
        "record_types": type_totals,
        "degraded_source_counts": dict(sorted(degraded_counts.items())),
        "candidate_thresholds": {
            "minimum_occurrences": min_count,
            "minimum_distinct_namespaces": min_distinct_namespaces,
        },
    }
    return aggregate, candidates


def _assert_aggregate_safe(value: Any, *, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in _FORBIDDEN_AGGREGATE_KEYS:
                raise ValueError(f"aggregate output contains forbidden key at {path}.{key}")
            _assert_aggregate_safe(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_aggregate_safe(child, path=f"{path}[{index}]")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Private result file or run directory.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Private output directory; defaults beside input.",
    )
    parser.add_argument(
        "--round-kind",
        choices=("baseline", "rank", "region", "vertical", "vendor-seed", "drift"),
        default="baseline",
    )
    parser.add_argument("--min-count", type=int, default=2)
    parser.add_argument("--min-distinct-namespaces", type=int, default=2)
    parser.add_argument("--max-samples", type=int, default=3)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.min_count < 1 or args.min_distinct_namespaces < 1 or args.max_samples < 0:
        print("error: count thresholds must be positive and max samples must be non-negative", file=sys.stderr)
        return 2
    input_path = _validate_private_path(args.input)
    output_dir = _validate_private_path(args.output_dir or (input_path if input_path.is_dir() else input_path.parent))
    files = _result_files(input_path)
    if not files:
        print(f"error: no result files found under {input_path}", file=sys.stderr)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)

    records = list(_iter_records(input_path))
    aggregate, candidates = aggregate_records(
        records,
        min_count=args.min_count,
        min_distinct_namespaces=args.min_distinct_namespaces,
        max_samples=args.max_samples,
    )
    revision, dirty = _git_revision()
    catalog = _catalog_metadata(REPO_ROOT / "src" / "recon_tool" / "data" / "fingerprints")
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    results_digest = _digest_files(files)
    aggregate.update(
        {
            "generated_at": generated_at,
            "round_kind": args.round_kind,
            "code_revision": revision,
            "working_tree_dirty": dirty,
            "results_digest_sha256": results_digest,
            "catalog": catalog,
            "environment": {
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
        }
    )
    _assert_aggregate_safe(aggregate)

    manifest = {
        "schema_version": "1.0",
        "private": True,
        "generated_at": generated_at,
        "round_kind": args.round_kind,
        "input_path": str(input_path),
        "source_files": [str(path) for path in files],
        "results_digest_sha256": results_digest,
        "code_revision": revision,
        "working_tree_dirty": dirty,
        "catalog": catalog,
        "records_total": len(records),
        "thresholds": aggregate["candidate_thresholds"],
    }
    private_payload = {
        "schema_version": "1.0",
        "private": True,
        "aggregate": aggregate,
        "candidates": candidates,
    }

    manifest_path = output_dir / "catalog-manifest.json"
    aggregate_path = output_dir / "catalog-aggregate.json"
    gaps_path = output_dir / "catalog-gaps.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    aggregate_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gaps_path.write_text(json.dumps(private_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote private manifest: {manifest_path}")
    print(f"wrote aggregate-only baseline: {aggregate_path}")
    print(f"wrote private typed gap queue: {gaps_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
