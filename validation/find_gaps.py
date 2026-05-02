"""Surface unclassified CNAME terminals from a recon validation run.

Reads ``--json --include-unclassified`` output (single file or a directory of
files) and produces a ``gaps.json`` report listing the most common terminal
hostname suffixes that no ``cname_target`` fingerprint matched. Each entry is
a candidate for a new fingerprint or an extension of an existing one.

Usage:
    # Aggregate across a run directory of *.json files:
    python validation/find_gaps.py --input runs-private/20260502/ --output gaps.json

    # Single file (e.g. one ``recon <domain> --json --include-unclassified`` invocation):
    python validation/find_gaps.py --input my-domain.json --output gaps.json

The output schema matches the ``/recon-fingerprint-triage`` skill's input
contract: ``[{suffix, count, samples: [{subdomain, terminal, chain}]}]``,
sorted by count desc.

Self-referential chains (target ends with the queried apex) are filtered
out because they are intra-org infrastructure, not third-party SaaS.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def _suffix_for(terminal: str) -> str:
    """Bucket a terminal hostname by its rightmost three labels.

    ``edge.fastly.net`` and ``app.fastly.net`` both bucket as ``fastly.net``.
    ``deep.cdn.fastly.net`` becomes ``cdn.fastly.net``. The 3-label window
    keeps the bucket specific enough to reveal real services while wide
    enough to merge per-customer subdomains.
    """
    parts = terminal.split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 else terminal


def _is_intra_org(apex: str, terminal: str) -> bool:
    """Drop chains where the terminal is in the queried domain's own zone."""
    apex = apex.lower().lstrip(".")
    terminal = terminal.lower().lstrip(".")
    return terminal == apex or terminal.endswith("." + apex)


def _load_inputs(path: Path) -> list[tuple[str, list[Any]]]:
    """Return ``[(apex, unclassified_list), ...]`` from a file or directory."""
    files: list[Path] = (
        [Path(p) for p in sorted(glob.glob(str(path / "*.json")))]
        if path.is_dir()
        else [path]
    )
    out: list[tuple[str, list[Any]]] = []
    for fp in files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"warning: skipping {fp}: {exc}", file=sys.stderr)
            continue
        if isinstance(data, dict):
            apex = str(data.get("queried_domain", fp.stem))
            unclass = data.get("unclassified_cname_chains", [])
            if not isinstance(unclass, list):
                unclass = []
            out.append((apex, unclass))
        elif isinstance(data, list):
            # Batch output shape: a list of per-domain dicts.
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                apex = str(entry.get("queried_domain", ""))
                unclass = entry.get("unclassified_cname_chains", [])
                if isinstance(unclass, list):
                    out.append((apex, unclass))
    return out


def find_gaps(input_path: Path, *, max_samples_per_suffix: int = 5) -> list[dict[str, Any]]:
    """Build the suffix-frequency report.

    Each returned entry: ``{suffix, count, samples: [{subdomain, terminal, chain}]}``.
    Results are ranked by count desc.
    """
    suffix_count: dict[str, int] = defaultdict(int)
    suffix_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for apex, unclassified in _load_inputs(input_path):
        for entry in unclassified:
            if not isinstance(entry, dict):
                continue
            subdomain = str(entry.get("subdomain", ""))
            chain = entry.get("chain") or []
            if not isinstance(chain, list) or not chain:
                continue
            terminal = str(chain[-1])
            if not terminal or _is_intra_org(apex, terminal):
                continue
            suffix = _suffix_for(terminal)
            suffix_count[suffix] += 1
            if len(suffix_samples[suffix]) < max_samples_per_suffix:
                suffix_samples[suffix].append(
                    {
                        "subdomain": subdomain,
                        "terminal": terminal,
                        "chain": [str(h) for h in chain],
                    }
                )

    # Sort first as (count, suffix) tuples, then materialize the dicts in
    # ranked order. Avoids running a sort key over heterogeneous dict values.
    ranked = sorted(suffix_count.items(), key=lambda pair: (-pair[1], pair[0]))
    rows: list[dict[str, Any]] = [
        {"suffix": suffix, "count": count, "samples": suffix_samples[suffix]}
        for suffix, count in ranked
    ]
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to a JSON file or a directory of JSON files (one per domain).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to write gaps.json. Defaults to <input>/gaps.json or stdout.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=5,
        help="Maximum sample chains stored per suffix (default 5).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        help="If >0, only emit the top N suffixes by count.",
    )
    args = parser.parse_args()

    rows = find_gaps(args.input, max_samples_per_suffix=args.samples)
    if args.top > 0:
        rows = rows[: args.top]

    payload = json.dumps(rows, indent=2)

    if args.output is None and args.input.is_dir():
        args.output = args.input / "gaps.json"

    if args.output is None:
        print(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote {args.output} ({len(rows)} suffixes)")


if __name__ == "__main__":
    main()
