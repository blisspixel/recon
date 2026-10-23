"""Private admission and explicit collection around the canonical round helpers."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from recon_tool.validator import validate_domain
from validation.catalog_freshness import validated_json
from validation.catalog_receipts import read_frozen_frame, read_json, write_private_blob, write_private_event
from validation.prepare_catalog_round import (
    REPO_ROOT,
    _bounded_read,
    _private_file,
    canonical_json_digest,
    catalog_digest_sha256,
    digest_bytes,
    execution_digest_sha256,
    prepare_catalog_round,
)

PLAN_SCHEMA = REPO_ROOT / "docs/catalog-maintenance-plan.schema.json"
ATTRIBUTE_FIELDS = (
    "geography",
    "language",
    "scale",
    "sector",
    "ownership",
    "website_role",
    "provider_mix",
    "footprint",
)


def runtime_context() -> dict[str, object]:
    """Bind effective local overlays without changing DNS, config or rate limits."""
    from recon_tool.bayesian_loader import load_priors_override
    from recon_tool.fingerprints import load_builtin_fingerprints, load_fingerprints, reload_fingerprints
    from recon_tool.motifs import load_motifs
    from recon_tool.signals import load_signals, reload_signals

    reload_fingerprints()
    reload_signals()
    fingerprints = [asdict(item) for item in load_fingerprints()]
    return {
        "fingerprints": canonical_json_digest(fingerprints),
        "builtin_catalog": fingerprints == [asdict(item) for item in load_builtin_fingerprints()],
        "motifs": canonical_json_digest([asdict(item) for item in load_motifs(reload=True)]),
        "signals": canonical_json_digest([asdict(item) for item in load_signals()]),
        "priors": canonical_json_digest(load_priors_override()),
    }


def _input_path(base: Path, value: str) -> Path:
    path = Path(value)
    return _private_file(path if path.is_absolute() else base / path)


def _archive(path: Path, destination: Path) -> dict[str, object]:
    raw = _bounded_read(path, maximum_bytes=32 * 1024 * 1024, name="private maintenance source")
    write_private_blob(destination, raw)
    return {
        "original": str(path),
        "frozen": str(destination),
        "sha256": digest_bytes(raw),
        "bytes": len(raw),
        "nonempty_rows": sum(bool(line.strip()) and not line.lstrip().startswith(b"#") for line in raw.splitlines()),
    }


def _freeze_sources(plan_path: Path, campaign: Path) -> tuple[Path, list[dict[str, object]]]:
    original = read_json(plan_path)
    strata = original.get("strata")
    if not isinstance(strata, list) or not 1 <= len(strata) <= 50:
        raise ValueError("maintenance round needs 1-50 supplied strata")
    archives = [_archive(plan_path, campaign / "inputs/original-round-plan.json")]
    for index, row in enumerate(strata):
        if not isinstance(row, dict) or not isinstance(row.get("input"), str):
            raise ValueError("maintenance stratum needs an input path")
        source = _input_path(plan_path.parent, row["input"])
        archive = _archive(source, campaign / f"inputs/stratum-{index:03d}.txt")
        archives.append(archive)
        if sum(item["bytes"] for item in archives) > 64 * 1024 * 1024:
            raise ValueError("maintenance source bytes exceed the shared 64 MiB bound")
        row["input"] = archive["frozen"]
    frozen = campaign / "inputs/round-plan.json"
    write_private_event(frozen, original)
    return frozen, archives


def sampling_summary(plan: dict[str, Any], frame: frozenset[str], manifest: dict[str, Any]) -> dict[str, object]:
    """Summarize declared attributes privately; infer no population or independence."""
    rows = []
    if plan["attributes_file"] is not None:
        rows = validated_json(Path(plan["attributes_file"]), PLAN_SCHEMA, definition="attributes")["rows"]
    identities = [row["domain"] for row in rows]
    if len(set(identities)) != len(identities) or any(
        domain not in frame or validate_domain(domain) != domain for domain in identities
    ):
        raise ValueError("attribute rows must be unique canonical members of the frozen frame")
    groups = {row["dependency_group"] for row in rows if row.get("dependency_group") not in (None, "", "unknown")}
    present = {row["id"] for row in manifest["strata"]}
    return {
        "namespaces": len(frame),
        "declared_dependency_groups": len(groups),
        "unknown_dependency_namespaces": len(frame)
        - sum(row.get("dependency_group") not in (None, "", "unknown") for row in rows),
        "independent_sample_size": None,
        "missing_strata": sorted(set(plan["expected_strata"]) - present),
        "unknown_attributes": {
            field: len(frame) - sum(row.get(field) not in (None, "", "unknown") for row in rows)
            for field in ATTRIBUTE_FIELDS
        },
        "sampling_notes": plan["sampling_notes"],
        "publication": "withheld_private_membership_and_small_cells",
    }


def _check_exclusions(plan: dict[str, Any], frame: frozenset[str], campaign: Path) -> list[dict[str, object]]:
    paths = list(plan["exclusions"])
    if plan["development_frame"] is not None:
        paths.append(plan["development_frame"])
    archives = []
    for index, name in enumerate(paths):
        source = Path(name)
        excluded, _ = read_frozen_frame(source, 10000)
        if frame & excluded:
            raise ValueError("frozen frame overlaps exclusions or development data; revise the plan before admission")
        archives.append(_archive(source, campaign / f"inputs/exclusion-{index:03d}.txt"))
    return archives


def _holdout_check(root: Path, frame: frozenset[str]) -> None:
    if any((root / "holdouts" / f"{digest_bytes(domain.encode())}.json").exists() for domain in frame):
        raise ValueError("frame includes a consumed holdout namespace; select a fresh disjoint frame")


def _prepare_frame(plan: dict[str, Any], campaign: Path, root: Path) -> dict[str, object]:
    if plan["round_plan"] is None or min(plan["budgets"]["max_namespaces"], plan["budgets"]["max_dns_queries"]) <= 0:
        raise ValueError("collection admission needs a round plan and positive namespace/query budgets")
    frozen, archives = _freeze_sources(Path(plan["round_plan"]), campaign)
    raw, manifest = prepare_catalog_round(frozen, campaign / "frame.txt")
    supplied_rows = sum(item["nonempty_rows"] for item in archives[1:])
    collection = manifest["collection"]
    if collection["ct_enabled"] != plan["layers"]["ct"]:
        raise ValueError("round and maintenance CT choices differ")
    if manifest["round_kind"] == "drift":
        raise ValueError("drift collection must use its separate prior-comparison contract")
    if manifest["thresholds"]["minimum_distinct_namespaces"] != 2:
        raise ValueError("maintenance scan uses the existing two-distinct-namespace recurrence contract")
    frame = frozenset(raw.decode("ascii").splitlines())
    if len(frame) > plan["budgets"]["max_namespaces"]:
        raise ValueError("normalized frame exceeds its frozen namespace budget")
    archives.extend(_check_exclusions(plan, frame, campaign))
    _holdout_check(root, frame)
    if plan["role"] == "holdout" and (
        plan["development_frame"] is None or plan["candidate_catalog_digest"] != catalog_digest_sha256()
    ):
        raise ValueError("holdout admission needs a development frame and exact frozen candidate catalog")
    write_private_blob(campaign / "frame.txt", raw)
    write_private_event(campaign / "round-manifest.json", manifest)
    sampling = sampling_summary(plan, frame, manifest)
    sampling.update(supplied_namespace_rows=supplied_rows, normalized_duplicates_removed=supplied_rows - len(frame))
    return {
        "frame": manifest["frame"],
        "manifest": str(campaign / "round-manifest.json"),
        "round_plan": str(frozen),
        "archives": archives,
        "sampling": sampling,
        "round_kind": manifest["round_kind"],
        "min_count": manifest["thresholds"]["minimum_occurrences"],
    }


def prepare_admission(plan_path: Path, root: Path) -> dict[str, Any]:
    """Freeze a private operator plan without collecting or expanding membership."""
    root = _private_file(root / "path-check").parent
    plan_path = _private_file(plan_path)
    plan = validated_json(plan_path, PLAN_SCHEMA)
    for field, value in plan["budgets"].items():
        integer_cap = field not in {"namespace_timeout_seconds", "max_runtime_seconds"}
        if isinstance(value, bool) or (integer_cap and type(value) is not int):
            raise ValueError("maintenance budgets need exact integer caps and finite numeric time bounds")
    for field in ("round_plan", "development_frame", "attributes_file"):
        if plan[field] is not None:
            plan[field] = str(_input_path(plan_path.parent, plan[field]))
    plan["exclusions"] = [str(_input_path(plan_path.parent, item)) for item in plan["exclusions"]]
    digest = canonical_json_digest(plan)
    campaign = root / "rounds" / plan["id"]
    admission_path = campaign / "admission.json"
    if admission_path.exists():
        admission = read_json(admission_path)
        if admission["plan_digest"] != digest:
            raise ValueError("admitted plan changed; preserve the original and use a new round ID")
        return admission
    write_private_event(campaign / "preparing.json", {"schema_version": 1, "plan_digest": digest})
    write_private_event(campaign / "maintenance-plan.json", plan)
    archived = None
    if plan["attributes_file"] is not None:
        archived = _archive(Path(plan["attributes_file"]), campaign / "inputs/attributes.json")
        plan["attributes_file"] = archived["frozen"]
    prepared = {} if plan["role"] == "documentation" else _prepare_frame(plan, campaign, root)
    admission = {
        "schema_version": 1,
        "plan_digest": digest,
        "plan": plan,
        "prepared": prepared,
        "catalog_digest": catalog_digest_sha256(),
        "execution_digest": execution_digest_sha256(),
        "runtime_context": runtime_context(),
        "attribute_archive": archived,
        "promotion": "none",
    }
    write_private_event(admission_path, admission)
    return admission


def verify_admission_inputs(admission_path: Path, admission: dict[str, Any]) -> None:
    """Check frozen plan and source commitments before contract-bound use."""
    original = read_json(admission_path.parent / "maintenance-plan.json")
    if canonical_json_digest(original) != admission["plan_digest"]:
        raise ValueError("frozen maintenance plan changed")
    archives = list(admission["prepared"].get("archives", []))
    if admission.get("attribute_archive") is not None:
        archives.append(admission["attribute_archive"])
    for archive in archives:
        raw = _bounded_read(Path(archive["frozen"]), maximum_bytes=32 * 1024 * 1024, name="frozen source")
        if digest_bytes(raw) != archive["sha256"]:
            raise ValueError("frozen maintenance source changed")


def _collection_command(admission: dict[str, Any], output: Path) -> list[str]:
    plan, prepared = admission["plan"], admission["prepared"]
    budget = plan["budgets"]
    command = [
        sys.executable,
        "-m",
        "validation.scan",
        "--corpus",
        prepared["frame"]["path"],
        "--round-manifest",
        prepared["manifest"],
        "--round-kind",
        prepared["round_kind"],
        "--output-root",
        str(output),
        "--no-compare",
        "--concurrency",
        str(budget["concurrency"]),
        "--timeout",
        str(budget["namespace_timeout_seconds"]),
        "--max-runtime",
        str(budget["max_runtime_seconds"]),
        "--max-dns-queries",
        str(budget["max_dns_queries"]),
        "--min-count",
        str(prepared["min_count"]),
    ]
    if plan["layers"]["ct"]:
        command.append("--ct")
    return command


def collect_admission(admission_path: Path, *, attempt: int, allow_network: bool = False) -> dict[str, object]:
    """Start one explicitly authorized attempt, preserving every earlier attempt."""
    if not allow_network:
        raise ValueError("bounded maintenance collection needs explicit --allow-network authorization")
    admission = read_json(admission_path)
    verify_admission_inputs(admission_path, admission)
    plan = admission["plan"]
    valid_attempt = type(attempt) is int and 1 <= attempt <= plan["budgets"]["max_attempts"]
    if plan["role"] == "documentation" or not valid_attempt:
        raise ValueError("collection attempt is outside the frozen admission")
    campaign = admission_path.parent
    previous = campaign / f"attempt-{attempt - 1:02d}-started.json"
    if attempt > 1 and (not previous.exists() or plan["role"] == "holdout"):
        raise ValueError("retry needs an original attempt; consumed holdouts cannot be retried")
    if attempt > 1 and not any(
        (campaign / f"attempt-{attempt - 1:02d}-{state}.json").exists() for state in ("returned", "finalized")
    ):
        raise ValueError("previous attempt is still running or interrupted; finalize it before retrying")
    if (
        admission["catalog_digest"] != catalog_digest_sha256()
        or admission["execution_digest"] != execution_digest_sha256()
        or admission["runtime_context"] != runtime_context()
    ):
        raise ValueError("frozen catalog, execution or local runtime context changed; collection refused")
    frame, digest = read_frozen_frame(Path(admission["prepared"]["frame"]["path"]), plan["budgets"]["max_namespaces"])
    if digest != admission["prepared"]["frame"]["digest_sha256"]:
        raise ValueError("admitted frame changed")
    _holdout_check(campaign.parents[1], frame)
    output = campaign / f"attempt-{attempt:02d}"
    write_private_event(
        campaign / f"attempt-{attempt:02d}-started.json",
        {
            "schema_version": 1,
            "attempt": attempt,
            "retry_of": attempt - 1 if attempt > 1 else None,
            "plan_digest": admission["plan_digest"],
            "output": str(output),
        },
    )
    if plan["role"] == "holdout":
        for domain in sorted(frame):
            write_private_event(
                campaign.parents[1] / "holdouts" / f"{digest_bytes(domain.encode())}.json",
                {
                    "campaign": plan["id"],
                    "candidate_catalog_digest": admission["catalog_digest"],
                    "frame_digest": digest,
                },
            )
    result = subprocess.run(_collection_command(admission, output), cwd=REPO_ROOT, check=False)  # noqa: S603
    context_current = admission["runtime_context"] == runtime_context()
    receipt = {
        "schema_version": 1,
        "attempt": attempt,
        "returncode": result.returncode,
        "runtime_context_current": context_current,
        "status": "finalization_required",
        "classification_comparison": "withheld_until_typed_evaluation",
        "promotion": "none",
    }
    write_private_event(campaign / f"attempt-{attempt:02d}-returned.json", receipt)
    return receipt


def finalize_admission(admission_path: Path, *, attempt: int, run_dir: Path) -> dict[str, object]:
    """Resume existing offline finalization without recollecting or rewriting starts."""
    admission = read_json(admission_path)
    if type(attempt) is not int or not 1 <= attempt <= admission["plan"]["budgets"]["max_attempts"]:
        raise ValueError("finalization attempt is outside the frozen admission")
    campaign = admission_path.parent
    started = read_json(campaign / f"attempt-{attempt:02d}-started.json")
    output = Path(started["output"]).resolve()
    run_dir = _private_file(run_dir / "path-check").parent
    if output not in run_dir.parents:
        raise ValueError("finalization run is outside the original attempt output")
    command = [*_collection_command(admission, output), "--finalize-existing", str(run_dir)]
    result = subprocess.run(command, cwd=REPO_ROOT, check=False)  # noqa: S603 - explicit offline scan mode
    if result.returncode != 0:
        raise ValueError("offline finalization failed; original attempt remains unresolved")
    metadata = read_json(run_dir / "meta.json")
    manifest = read_json(Path(admission["prepared"]["manifest"]))
    if (
        metadata.get("corpus_path") != admission["prepared"]["frame"]["path"]
        or metadata.get("round_manifest_digest_sha256") != manifest["manifest_digest_sha256"]
        or not metadata.get("scan_finalized_utc")
    ):
        raise ValueError("offline finalization metadata differs from the admitted round")
    receipt = {
        "schema_version": 1,
        "attempt": attempt,
        "run_dir": str(run_dir),
        "status": "offline_finalization_recorded",
        "collection_returncode": None,
        "finalization_returncode": result.returncode,
        "batch_completed": metadata["batch_completed"],
        "collection_completion": metadata.get("collection_completion"),
        "promotion": "none",
    }
    write_private_event(campaign / f"attempt-{attempt:02d}-finalized.json", receipt, idempotent=True)
    return receipt
