"""Launch the existing batch collector under a frozen maintenance budget."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from recon_tool.collection_limits import CollectionBudget, CollectionBudgetExceeded, collection_budget
from validation.catalog_receipts import read_frozen_frame, start_recorder, write_private_event
from validation.prepare_catalog_round import PRIVATE_ROOTS, REPO_ROOT
from validation.run_path_safety import validate_private_output_root

BUDGET_STOP = 75


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--max-namespaces", type=int, required=True)
    parser.add_argument("--max-dns-queries", type=int, required=True)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--ct", action="store_true")
    parser.add_argument(
        "--allow-network", action="store_true", help="Explicit collection invocation, never a due-work wake."
    )
    args = parser.parse_args(argv)
    if not args.allow_network:
        parser.error("collection requires an explicit --allow-network invocation")
    if not 1 <= args.max_namespaces <= 10_000 or not 1 <= args.concurrency <= 20:
        parser.error("namespace/concurrency budget is outside the supported bounds")
    if args.max_dns_queries < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("query and timeout budgets must be positive and finite")
    run_dir = validate_private_output_root(args.run_dir, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    validate_private_output_root(args.corpus.resolve().parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    frame, digest = read_frozen_frame(args.corpus, args.max_namespaces)
    descriptor = {
        "schema_version": 1,
        "corpus": str(args.corpus.resolve()),
        "namespace_count": len(frame),
        "frame_sha256": digest,
        "max_dns_queries": args.max_dns_queries,
        "concurrency": args.concurrency,
        "namespace_timeout_seconds": args.timeout,
        "ct_enabled": args.ct,
        "direct_probes_enabled": False,
    }
    budget = CollectionBudget(frame, args.max_dns_queries, on_start=start_recorder(run_dir, descriptor))
    command = [
        "recon",
        "batch",
        str(args.corpus),
        "--ndjson",
        "--include-unclassified",
        "--concurrency",
        str(args.concurrency),
        "--timeout",
        str(args.timeout),
    ]
    if not args.ct:
        command.append("--no-ct")
    original = sys.argv
    status = 1
    try:
        from recon_tool.cli import run

        sys.argv = command
        with collection_budget(budget):
            run()
        status = 0
    except CollectionBudgetExceeded:
        status = BUDGET_STOP
    except SystemExit as exc:
        status = exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.argv = original
        write_private_event(
            run_dir / "collection-budget.json",
            {
                **descriptor,
                "dns_queries_reserved": budget.dns_queries,
                "stopped_reason": budget.stopped_reason,
                "exit_code": status,
            },
        )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
