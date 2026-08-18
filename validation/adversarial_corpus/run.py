"""End-to-end runner for the adversarial DNS-record corpus.

For each fixture the runner takes a baseline record set and a planted record set
through the shipped path, records-first and offline:

    build_source_result            (validation.adversarial_corpus.dns_mock)
      -> replay_cached_dns_fingerprints   (recon_tool.sources.dns_replay)
      -> merge_results                    (recon_tool.merger)
      -> infer_from_tenant_info           (recon_tool.bayesian; this call applies
                                           the record-role gate in
                                           bayesian_observations.signals_from_tenant_info
                                           before inference)
      -> posterior_dot_fill               (recon_tool.formatter.roles; threshold 0.5)

A node is "supported" when the shipped ``posterior_dot_fill`` returns 2 or 3, i.e.
the posterior is on the yes-side of the 0.5 model threshold. The gate lives inside
``infer_from_tenant_info``, so the round measures the engine including its
provenance gate, which an abstract ``infer()`` harness would skip.

Every step is a shipped public function taking exactly the type the previous step
returns; the only new code is the ``build_source_result`` helper and this loop.

Run it from the repository root:

    python validation/adversarial_corpus/run.py
    python validation/adversarial_corpus/run.py --write   # refresh results.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypedDict

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
# Bind to the checked-out source tree, matching the editable install CI uses,
# not any stale wheel that might sit in site-packages.
for _path in (str(_ROOT / "src"), str(_HERE)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from dns_mock import IDENTITY_SCALARS, INJECTABLE_SCALARS, build_source_result  # noqa: E402

import recon_tool  # noqa: E402
from recon_tool.bayesian import infer_from_tenant_info  # noqa: E402
from recon_tool.formatter.roles import POSTERIOR_DECISION_THRESHOLD, posterior_dot_fill  # noqa: E402
from recon_tool.merger import merge_results  # noqa: E402
from recon_tool.sources.dns_replay import replay_cached_dns_fingerprints  # noqa: E402

FIXTURES_PATH = _HERE / "fixtures.json"
RESULTS_PATH = _HERE / "results.json"
ROUND_DATE = "2026-08-17"
# Reported posteriors are rounded to six places; equality checks allow half a
# unit in the last place.
_TOL = 6e-7


class FixtureError(RuntimeError):
    """A fixture violates the schema invariants; the run stops rather than scores."""


class NodeRow(TypedDict):
    """Per-target-node measurement for one fixture, baseline versus planted."""

    node: str
    baseline_posterior: float
    planted_posterior: float
    baseline_supported: bool
    planted_supported: bool
    baseline_band_width: float
    planted_band_width: float
    conflict_provenance_count: int


class InferOut(TypedDict):
    """One end-to-end inference: the merged info and its per-node posteriors."""

    info: object
    posteriors: dict[str, Any]


def _infer(queried_domain: str, sources: list[dict[str, Any]]) -> InferOut:
    results = [
        replay_cached_dns_fingerprints(
            build_source_result(
                queried_domain,
                [tuple(record) for record in spec["records"]],
                spec.get("scalar_override"),
                spec.get("source_name", "dns-replay-fixture"),
            )
        )
        for spec in sources
    ]
    info = merge_results(results, queried_domain)
    posteriors = {p.name: p for p in infer_from_tenant_info(info).posteriors}
    return {"info": info, "posteriors": posteriors}


def _assert_gate_invariants(fixture: dict[str, Any], planted_info: object) -> None:
    gate_class = fixture["gate_class"]
    overrides = [spec.get("scalar_override") for spec in (*fixture["baseline"], *fixture["planted"])]
    set_scalars = {name for name in INJECTABLE_SCALARS if getattr(planted_info, name, None) is not None}
    if gate_class == "gate_path":
        if any(overrides):
            raise FixtureError(f"{fixture['id']}: gate_path fixture carries a scalar_override")
        stray = [name for name in IDENTITY_SCALARS if getattr(planted_info, name, None) is not None]
        if stray:
            raise FixtureError(f"{fixture['id']}: gate_path identity scalars are not all None: {stray}")
    elif gate_class == "bypass_path":
        declared = set(fixture.get("declared_scalars", ()))
        if set_scalars != declared:
            raise FixtureError(f"{fixture['id']}: bypass scalars {sorted(set_scalars)} != declared {sorted(declared)}")
    else:  # pragma: no cover - schema is authored, not parsed from input
        raise FixtureError(f"{fixture['id']}: unknown gate_class {gate_class!r}")


def _node_row(node: str, baseline: InferOut, planted: InferOut) -> NodeRow:
    base = baseline["posteriors"][node]
    plant = planted["posteriors"][node]
    return {
        "node": node,
        "baseline_posterior": round(base.posterior, 6),
        "planted_posterior": round(plant.posterior, 6),
        "baseline_supported": posterior_dot_fill(base) >= 2,
        "planted_supported": posterior_dot_fill(plant) >= 2,
        "baseline_band_width": round(base.interval_high - base.interval_low, 6),
        "planted_band_width": round(plant.interval_high - plant.interval_low, 6),
        "conflict_provenance_count": len(plant.conflict_provenance),
    }


def _unchanged(row: NodeRow) -> bool:
    return abs(row["planted_posterior"] - row["baseline_posterior"]) <= _TOL


# One predicate per pre-registered property, applied to every target node.
_PROPERTY_PREDICATES: dict[str, Callable[[NodeRow], bool]] = {
    "no_flip": lambda row: not row["planted_supported"],
    "flip": lambda row: row["planted_supported"] and not row["baseline_supported"],
    "inert_token": lambda row: row["planted_supported"] and _unchanged(row),
    "unchanged": _unchanged,
    "lifts": lambda row: row["planted_posterior"] > row["baseline_posterior"] + _TOL,
    "conflict_provenance_populated": lambda row: row["conflict_provenance_count"] > 0,
    "band_widens": lambda row: (
        row["conflict_provenance_count"] > 0 and row["planted_band_width"] > row["baseline_band_width"] + _TOL
    ),
}


def _property_pass(prop: str, rows: list[NodeRow]) -> bool:
    predicate = _PROPERTY_PREDICATES.get(prop)
    if predicate is None:
        raise FixtureError(f"unknown property {prop!r}")
    return all(predicate(row) for row in rows)


def evaluate(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    fixture_rows: list[dict[str, Any]] = []
    for fixture in fixtures:
        queried_domain = fixture["queried_domain"]
        baseline = _infer(queried_domain, fixture["baseline"])
        planted = _infer(queried_domain, fixture["planted"])
        _assert_gate_invariants(fixture, planted["info"])
        rows = [_node_row(node, baseline, planted) for node in fixture["target_nodes"]]
        fixture_rows.append(
            {
                "id": fixture["id"],
                "pattern": fixture["pattern"],
                "gate_class": fixture["gate_class"],
                "expect": fixture["expect"],
                "property": fixture["property"],
                "property_pass": _property_pass(fixture["property"], rows),
                "target_nodes": rows,
            }
        )

    ia_rows = [row for fixture, row in zip(fixtures, fixture_rows, strict=True) if fixture["pattern"] == "Ia"]
    ia_node_flips = sum(1 for row in ia_rows for node in row["target_nodes"] if node["planted_supported"])
    patterns = sorted({fixture["pattern"] for fixture in fixtures})
    pattern_summary = {
        pattern: {
            "fixtures": sum(1 for row in fixture_rows if row["pattern"] == pattern),
            "properties_pass": sum(1 for row in fixture_rows if row["pattern"] == pattern and row["property_pass"]),
        }
        for pattern in patterns
    }
    return {
        "round": "adversarial-corpus",
        "date": ROUND_DATE,
        "recon_version": recon_tool.__version__,
        "posterior_decision_threshold": POSTERIOR_DECISION_THRESHOLD,
        # Canonical-JSON digest so the frozen fixture identity is invariant to
        # whitespace and platform line-ending normalization.
        "fixtures_sha256": hashlib.sha256(
            json.dumps(fixtures, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "fixture_count": len(fixtures),
        "headline_ia": {
            "m_fixtures": len(ia_rows),
            "n_target_nodes_moved_to_supported": ia_node_flips,
        },
        "all_properties_pass": all(row["property_pass"] for row in fixture_rows),
        "pattern_summary": pattern_summary,
        "fixtures": fixture_rows,
    }


def _print_report(report: dict[str, Any]) -> None:
    ia = report["headline_ia"]
    print("Adversarial DNS-record corpus round")
    print(f"  recon {report['recon_version']}, threshold {report['posterior_decision_threshold']}, {report['date']}")
    print(f"  fixtures: {report['fixture_count']}  digest: {report['fixtures_sha256'][:16]}...")
    print()
    print(
        f"  Pattern Ia: over {ia['m_fixtures']} gate-path administrative-token fixtures "
        f"(clean baseline unresolved plus one administrative-only plant), the shipped engine "
        f"moved {ia['n_target_nodes_moved_to_supported']} of {ia['m_fixtures']} target nodes to "
        f"supported at the {report['posterior_decision_threshold']} threshold."
    )
    print()
    for pattern in sorted(report["pattern_summary"]):
        summary = report["pattern_summary"][pattern]
        print(f"  pattern {pattern}: {summary['properties_pass']}/{summary['fixtures']} properties hold")
    print()
    failures = [row for row in report["fixtures"] if not row["property_pass"]]
    if failures:
        print("  PROPERTY FAILURES:")
        for row in failures:
            print(f"    {row['id']} ({row['property']})")
        print()
    print(f"  all properties pass: {report['all_properties_pass']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write results.json alongside the fixtures.")
    args = parser.parse_args(argv)

    fixtures: list[dict[str, Any]] = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    report = evaluate(fixtures)
    _print_report(report)
    if args.write:
        RESULTS_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\n  wrote {RESULTS_PATH.relative_to(_ROOT)}")
    return 0 if report["all_properties_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
