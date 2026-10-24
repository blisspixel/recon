"""Source-checkout maintenance commands; all modes are offline except collect."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

from scripts.check_validation_hygiene import PRIVATE_PREFIXES, find_violations
from validation import catalog_freshness as freshness
from validation.catalog_baseline import aggregate_records
from validation.catalog_maintenance_round import (
    collect_admission,
    finalize_admission,
    prepare_admission,
    runtime_context,
    verify_admission_inputs,
)
from validation.catalog_receipts import (
    completion_summary,
    read_frozen_frame,
    read_json,
    write_private_blob,
    write_private_event,
)
from validation.catalog_result_input import load_evaluation_results
from validation.prepare_catalog_round import REPO_ROOT, _private_file, canonical_json_digest, digest_bytes

DEFAULT_ROOT = REPO_ROOT / "validation/runs-private/catalog-maintenance"


def check_publication_paths(paths: list[str]) -> dict[str, object]:
    """Require explicit tracked public files, never upload globs or private roots."""
    if not paths or any(any(character in item for character in "*?[]!\n\r") for item in paths):
        raise ValueError("publication needs an explicit reviewed file list; broad globs are refused")
    inventory = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 - fixed read-only repository inventory
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split("\0")
    normalized = []
    for value in paths:
        path = Path(value)
        resolved = (REPO_ROOT / path).resolve()
        if path.is_absolute() or path.is_symlink() or REPO_ROOT not in resolved.parents:
            raise ValueError("publication paths must be regular tracked public repository files")
        relative = resolved.relative_to(REPO_ROOT).as_posix()
        if relative.startswith((*PRIVATE_PREFIXES, ".agent/", ".grok/")) or relative not in inventory:
            raise ValueError("publication includes private or untracked data")
        normalized.append(relative)
    violations = find_violations(paths=normalized)
    if violations:
        raise ValueError("publication files fail the canonical validation-hygiene gate")
    return {"status": "paths_checked", "files": normalized, "content_review": "still_required"}


def evaluate(admission_path: Path, results_path: Path) -> dict[str, Any]:
    """Reduce existing private results once; this never collects or promotes."""
    admission = read_json(admission_path)
    verify_admission_inputs(admission_path, admission)
    if admission["plan"]["role"] == "documentation":
        raise ValueError("documentation admission has no measured cohort")
    if admission["plan"]["role"] == "holdout":
        from validation.prepare_catalog_round import catalog_digest_sha256, execution_digest_sha256

        if (
            admission["catalog_digest"] != catalog_digest_sha256()
            or admission["execution_digest"] != execution_digest_sha256()
            or admission["runtime_context"] != runtime_context()
        ):
            raise ValueError("holdout candidate or runtime context changed before evaluation")
    prepared = admission["prepared"]
    maximum = admission["plan"]["budgets"]["max_namespaces"]
    frame, frame_digest = read_frozen_frame(Path(prepared["frame"]["path"]), maximum)
    if frame_digest != prepared["frame"]["digest_sha256"]:
        raise ValueError("evaluation frame changed")
    identity, records = load_evaluation_results(_private_file(results_path), maximum_records=maximum, frame=frame)
    location = canonical_json_digest(str(results_path.resolve()))
    receipt_path = admission_path.parent / "evaluations" / location / "receipt.json"
    if receipt_path.exists():
        previous = read_json(receipt_path)
        if previous["results_digest"] != identity:
            raise ValueError("evaluation already consumed different results; preserve the original")
        return previous
    if admission["plan"]["role"] == "holdout":
        _consume_evaluation_holdout(admission_path, frame, identity)
    completion = completion_summary(
        results_path if results_path.is_dir() else results_path.parent, admitted=len(frame), records=records
    )
    aggregate, queue = aggregate_records(
        records, min_count=prepared["min_count"], min_distinct_namespaces=2, max_samples=3
    )
    state = "blocked" if not aggregate["measured_input_records"] else "completed"
    if completion["unfinished"] and state != "blocked":
        state = "partial"
    context_current = admission["runtime_context"] == runtime_context()
    receipt = {
        "schema_version": 1,
        "results_digest": identity,
        "status": state,
        "completion": completion,
        "aggregate": aggregate,
        "private_candidate_queue": queue,
        "runtime_context_current": context_current,
        "classification_comparison": (
            "fixed_observations_only"
            if context_current and admission["runtime_context"]["builtin_catalog"]
            else "withheld_local_overlay_or_context_drift"
        ),
        "layers": {
            "atomic": "typed_record_reduction",
            "composite": "requires_separate_contract_fixtures",
            "ct": "enabled_requires_status_review" if admission["plan"]["layers"]["ct"] else "disabled",
        },
        "publication": "withheld_private_membership_and_small_cells",
        "promotion": "none",
    }
    write_private_event(receipt_path, receipt)
    return receipt


def _consume_evaluation_holdout(admission_path: Path, frame: frozenset[str], results_digest: str) -> None:
    campaign = admission_path.parent
    admission = read_json(admission_path)
    root = campaign.parents[1]
    write_private_event(campaign / "holdout-evaluation-started.json", {"results_digest": results_digest})
    for domain in sorted(frame):
        path = root / "holdouts" / f"{digest_bytes(domain.encode())}.json"
        if path.exists():
            if read_json(path)["campaign"] != admission["plan"]["id"]:
                raise ValueError("holdout already consumed by another round")
        else:
            write_private_event(path, {"campaign": admission["plan"]["id"], "results_digest": results_digest})


def demo(root: Path) -> dict[str, object]:
    """Run fictional preparation, finite match controls and a failed-run lesson."""
    from recon_tool.fingerprints import get_txt_patterns, match_txt_all
    from recon_tool.motifs import _BUILTIN_PATH, _load_from_path, match_chain_motifs

    inputs = root / "demo-inputs"
    for name in ("plan", "round", "attributes"):
        source = REPO_ROOT / f"docs/examples/catalog-maintenance-{name}.json"
        write_private_blob(inputs / source.name, source.read_bytes(), idempotent=True)
    write_private_blob(inputs / "community.txt", b"alpha.test\nwww.alpha.test\nbeta.test\n", idempotent=True)
    write_private_blob(inputs / "institution.txt", b"gamma.test\n", idempotent=True)
    admission = prepare_admission(inputs / "catalog-maintenance-plan.json", root)
    motif = next(item for item in _load_from_path(_BUILTIN_PATH) if item.name == "cloudflare_to_aws")
    positive = ["edge.cloudflare.net", "origin.amazonaws.com"]
    observed = match_chain_motifs(positive, (motif,), subdomain="api.alpha.test")
    atomic = match_txt_all("forward-email-site-verification=synthetic-token-001", get_txt_patterns())
    controls = {
        "atomic_positive": any(item.slug == "forward-email" for item in atomic),
        "atomic_lookalike": not match_txt_all(
            "note=forward-email-site-verification=synthetic-token-001", get_txt_patterns()
        ),
        "sequence_positive_provenance": len(observed) == 1 and observed[0].subdomain == "api.alpha.test",
        "sequence_deceptive": not match_chain_motifs([hop + ".attacker.invalid" for hop in positive], (motif,)),
        "sequence_order_counterexample": not match_chain_motifs(list(reversed(positive)), (motif,)),
        "sequence_missing": not match_chain_motifs(positive[:1], (motif,)),
        "duplicate_hops_one_observation": len(match_chain_motifs([*positive[:1], *positive], (motif,))) == 1,
    }
    if not all(controls.values()):
        raise ValueError("offline synthetic maintenance controls failed")
    failures = [{"record_type": "error", "domain": "alpha.test", "error_kind": "timeout"}]
    aggregate, queue = aggregate_records(failures, min_count=3, min_distinct_namespaces=2, max_samples=3)
    completion = completion_summary(root / "legacy-unrecorded-run", admitted=3, records=failures)
    receipt = {
        "schema_version": 1,
        "status": "completed_offline_example",
        "network_calls": 0,
        "plan_digest": admission["plan_digest"],
        "catalog_digest": admission["catalog_digest"],
        "sampling": admission["prepared"]["sampling"],
        "controls": controls,
        "failure_lesson": {
            "completion": completion,
            "typed_aggregate": aggregate,
            "queue": queue,
            "catalog_completeness": "not_established",
        },
        "layers": {
            "atomic": "finite_synthetic_controls",
            "composite": "finite_ordered_sequence_controls",
            "ct": "disabled",
            "cross_namespace_graph": "not_evaluated",
        },
        "stratified_publication": "withheld_below_existing_20_row_minimum",
        "promotion": "none",
    }
    write_private_event(root / "offline-demo.json", receipt, idempotent=True)
    return receipt


def review_template(admission_path: Path, output: Path) -> dict[str, object]:
    """Create a schema-valid unknown-status template, never a claimed review."""
    admission = read_json(admission_path)
    rows = [
        {
            "rule_id": row["rule_id"],
            "source_status": "unreviewed",
            "source_checked_on": None,
            "reviewed_on": None,
            "next_review": None,
            "prior_reference": row["reference"],
            "new_reference": row["reference"],
            "disposition": "deferred",
            "basis": "Not reviewed yet. Replace with the actual supporting basis after source review.",
        }
        for row in admission["rules"]
    ]
    receipt = {"schema_version": 1, "reviews": rows}
    write_private_event(output, receipt, idempotent=True)
    return {"status": "unreviewed_template_created", "path": str(output), "rules": len(rows)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in (
        "demo",
        "plan",
        "collect",
        "resume",
        "evaluate",
        "due",
        "review",
        "review-template",
        "status",
        "skip",
        "check-publication",
    ):
        command = sub.add_parser(name)
        command.add_argument("--root", type=Path, default=DEFAULT_ROOT)
        if name == "plan":
            command.add_argument("--plan", type=Path, required=True)
        if name in {"collect", "resume", "evaluate", "review", "review-template", "status", "skip"}:
            command.add_argument("--admission", type=Path, required=True)
        if name in {"evaluate", "resume", "review"}:
            command.add_argument("--input", type=Path, required=True)
        if name == "review-template":
            command.add_argument("--output", type=Path, required=True)
        if name in {"due", "review", "status"}:
            command.add_argument("--as-of", type=date.fromisoformat, default=date.today())
        if name == "due":
            command.add_argument("--period", required=True)
            command.add_argument("--review-limit", type=int, default=8)
            command.add_argument("--proposal-limit", type=int, default=8)
        if name in {"collect", "resume"}:
            command.add_argument("--attempt", type=int, default=1)
        if name == "collect":
            command.add_argument("--allow-network", action="store_true")
        if name == "skip":
            command.add_argument("--reason", required=True)
        if name == "check-publication":
            command.add_argument("paths", nargs="+")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {
        "demo": lambda: demo(args.root),
        "plan": lambda: prepare_admission(args.plan, args.root),
        "collect": lambda: collect_admission(args.admission, attempt=args.attempt, allow_network=args.allow_network),
        "resume": lambda: finalize_admission(args.admission, attempt=args.attempt, run_dir=args.input),
        "evaluate": lambda: evaluate(args.admission, args.input),
        "due": lambda: freshness.due_work(
            args.root, args.period, as_of=args.as_of, review_limit=args.review_limit, proposal_limit=args.proposal_limit
        ),
        "review": lambda: freshness.review_cycle(args.admission, args.input, as_of=args.as_of),
        "review-template": lambda: review_template(args.admission, args.output),
        "status": lambda: freshness.cycle_status(args.admission, as_of=args.as_of),
        "skip": lambda: freshness.skip_cycle(args.admission, args.reason),
        "check-publication": lambda: check_publication_paths(args.paths),
    }
    try:
        receipt = handlers[args.mode]()
    except (OSError, ValueError) as exc:
        parser = _parser()
        parser.error(str(exc))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
