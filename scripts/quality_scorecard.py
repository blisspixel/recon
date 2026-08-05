"""Aggregate-safe product-quality baseline scorecard.

Phase 1 of the
[Quality Proof execution plan](../docs/strategic-gap-audit.md) asks for one
dated, revision-bound artifact that records what the product measurably costs
and covers, plus an explicit ledger of what it does not measure. This script
emits that artifact.

It is deliberately not a gate. Nothing here fails a build, because a scorecard
that blocks a merge becomes a number people tune rather than a number people
read.

Scope discipline matters more than metric count. Most Phase 1 quantities
already have an owner: component latency and allocation belong to
``characterize_performance.py``, claim lineage to ``check_default_claim_audit.py``,
and corpus-derived catalog coverage to ``validation/catalog_baseline.py``. This
script measures only what nothing else measures, names the owner for what is
covered elsewhere, and records the rest as unmeasured with the reason. Several
Phase 1 metrics cannot be produced without either network access or the private
corpus, and inventing them from synthetic fixtures would measure the fixtures
rather than the product.

Network-free and corpus-free by construction. No target rows, no apex domains,
no organization names, no tenant identifiers.

Run with::

    uv run python scripts/quality_scorecard.py
    uv run python scripts/quality_scorecard.py --markdown
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from collections import Counter
from importlib import import_module
from pathlib import Path
from typing import Any

from recon_tool.fingerprints import load_fingerprints
from recon_tool.mcp_client.sdk_compat import model_wire_dict

_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_DIR = _ROOT / "src" / "recon_tool" / "data" / "fingerprints"

# Byte counts are exact; token counts depend on the client's tokenizer, which
# this project does not control and must not pretend to know. Four bytes per
# token is a coarse English-plus-JSON rule of thumb, reported only to make the
# order of magnitude legible. It is not a measurement.
_BYTES_PER_TOKEN_ESTIMATE = 4


def _compact(value: object) -> str:
    """Serialize the way a protocol client receives it: compact and stable."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _byte_length(value: object) -> int:
    """Return the UTF-8 wire size of one JSON-serializable value."""
    return len(_compact(value).encode("utf-8"))


def _approx_tokens(byte_count: int) -> int:
    """Return the coarse token-order estimate for a byte count."""
    return round(byte_count / _BYTES_PER_TOKEN_ESTIMATE)


async def _tool_wire_dicts() -> list[dict[str, Any]]:
    """Return every registered MCP tool exactly as a client receives it."""
    import_module("recon_tool.server")
    from recon_tool.server.app import mcp

    return [model_wire_dict(tool) for tool in await mcp.list_tools()]


def _server_instructions() -> str:
    """Return the MCP instruction preamble, which every session also pays for."""
    import_module("recon_tool.server")
    from recon_tool.server.app import mcp

    instructions = getattr(mcp, "instructions", None)
    return instructions if isinstance(instructions, str) else ""


def _duplicate_definition_bytes(tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Measure bytes spent re-sending byte-identical schema definitions.

    Each tool schema is standalone on the wire, so a definition shared by
    several tools is transmitted once per tool. This quantifies how much of the
    payload a cross-tool ``$defs`` scheme could recover, which bounds one
    otherwise-plausible optimization before anyone builds it.
    """
    occurrences: Counter[tuple[str, str]] = Counter()
    sizes: dict[tuple[str, str], int] = {}
    carrying = 0
    for tool in tools:
        output_schema = tool.get("outputSchema") or {}
        definitions = output_schema.get("$defs") or output_schema.get("definitions") or {}
        if definitions:
            carrying += 1
        for name, body in definitions.items():
            canonical = _compact(body)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
            key = (str(name), digest)
            occurrences[key] += 1
            sizes[key] = len(canonical.encode("utf-8"))

    repeated = {key: count for key, count in occurrences.items() if count > 1}
    redundant_bytes = sum(sizes[key] * (count - 1) for key, count in repeated.items())
    ranked = sorted(repeated.items(), key=lambda item: -sizes[item[0]] * (item[1] - 1))
    return {
        "tools_carrying_definitions": carrying,
        "distinct_definition_bodies": len(occurrences),
        "bodies_shared_by_multiple_tools": len(repeated),
        "redundant_bytes": redundant_bytes,
        "most_redundant": [
            {
                "definition": name,
                "tools": count,
                "bytes_each": sizes[(name, digest)],
                "redundant_bytes": sizes[(name, digest)] * (count - 1),
            }
            for (name, digest), count in ranked[:5]
        ],
    }


def _mcp_context_cost() -> dict[str, Any]:
    """Measure what an agent pays in context before it does any work.

    This is the one Phase 1 metric with no existing owner, and it is the
    evidence the deferred core-versus-advanced profile decision depends on.
    """
    tools = asyncio.run(_tool_wire_dicts())
    instructions = _server_instructions()

    discovery_bytes = _byte_length({"tools": tools})
    instruction_bytes = len(instructions.encode("utf-8"))
    session_bytes = discovery_bytes + instruction_bytes

    components: Counter[str] = Counter()
    for tool in tools:
        for field in ("name", "description", "inputSchema", "outputSchema", "annotations"):
            if field in tool:
                components[field] += _byte_length(tool[field])

    per_tool = sorted(
        (
            {
                "name": str(tool.get("name", "")),
                "total_bytes": _byte_length(tool),
                "output_schema_bytes": _byte_length(tool.get("outputSchema") or {}),
                "input_schema_bytes": _byte_length(tool.get("inputSchema") or {}),
                "description_bytes": len(str(tool.get("description") or "").encode("utf-8")),
            }
            for tool in tools
        ),
        key=lambda entry: -int(entry["total_bytes"]),
    )

    without_output_schema = _byte_length(
        {"tools": [{key: value for key, value in tool.items() if key != "outputSchema"} for tool in tools]}
    )
    field_total = sum(components.values())
    top_five = sum(int(entry["total_bytes"]) for entry in per_tool[:5])

    return {
        "tool_count": len(tools),
        "discovery_bytes": discovery_bytes,
        "instruction_preamble_bytes": instruction_bytes,
        "session_context_bytes": session_bytes,
        "session_context_approx_tokens": _approx_tokens(session_bytes),
        "component_bytes": dict(components.most_common()),
        "component_share": {
            field: round(value / field_total, 4) for field, value in components.most_common() if field_total
        },
        "concentration": {
            "top_5_tool_bytes": top_five,
            "top_5_share_of_discovery": round(top_five / discovery_bytes, 4) if discovery_bytes else 0.0,
            "largest_tool": per_tool[0]["name"] if per_tool else None,
            "largest_tool_bytes": per_tool[0]["total_bytes"] if per_tool else 0,
            "smallest_tool": per_tool[-1]["name"] if per_tool else None,
            "smallest_tool_bytes": per_tool[-1]["total_bytes"] if per_tool else 0,
        },
        "headroom": {
            "discovery_without_output_schema_bytes": without_output_schema,
            "output_schema_share_of_discovery": (
                round((discovery_bytes - without_output_schema) / discovery_bytes, 4) if discovery_bytes else 0.0
            ),
            "cross_tool_definition_duplication": _duplicate_definition_bytes(tools),
            "interpretation": (
                "Output schemas dominate the payload, so tool-count reduction is not the "
                "lever it appears to be. The without-output-schema figure is an upper "
                "bound on available headroom, not a recommendation: structured output is "
                "part of the protocol contract clients validate against. Cross-tool "
                "definition duplication bounds what a shared-definition scheme could "
                "recover on its own."
            ),
        },
        "per_tool": per_tool,
    }


def _catalog_surface() -> dict[str, Any]:
    """Record the static shape of the shipped detection catalog.

    Static shape only. What share of a real bounded observation surface the
    catalog actually classifies is a corpus question, and it is recorded as
    unmeasured rather than approximated here.
    """
    fingerprints = load_fingerprints()
    rule_types: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    confidences: Counter[str] = Counter()
    match_modes: Counter[str] = Counter()
    dated = 0
    total_rules = 0
    verified_dates: list[str] = []

    for fingerprint in fingerprints:
        categories[fingerprint.category] += 1
        confidences[fingerprint.confidence] += 1
        match_modes[fingerprint.match_mode] += 1
        for rule in fingerprint.detections:
            total_rules += 1
            rule_types[rule.type] += 1
            if rule.verified:
                dated += 1
                verified_dates.append(rule.verified)

    return {
        "entries": len(fingerprints),
        "detection_rules": total_rules,
        "m365_entries": sum(1 for fingerprint in fingerprints if fingerprint.m365),
        "rules_by_type": dict(rule_types.most_common()),
        "entries_by_category": dict(categories.most_common()),
        "entries_by_confidence": dict(confidences.most_common()),
        "entries_by_match_mode": dict(match_modes.most_common()),
        "verification_dates": {
            "dated_rules": dated,
            "undated_rules": total_rules - dated,
            "dated_share": round(dated / total_rules, 4) if total_rules else 0.0,
            "earliest": min(verified_dates) if verified_dates else None,
            "latest": max(verified_dates) if verified_dates else None,
        },
    }


def _directory_digest(directory: Path) -> str | None:
    """Return a stable digest over a directory's file contents."""
    if not directory.is_dir():
        return None
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _git(*arguments: str) -> str | None:
    """Run one read-only git command, returning None when git is unavailable."""
    git = shutil.which("git")
    if git is None:
        return None
    completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [git, *arguments],
        check=False,
        capture_output=True,
        cwd=os.fspath(_ROOT),
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _revisions() -> dict[str, Any]:
    """Bind every number above to the exact code and catalog it measured."""
    status = _git("status", "--porcelain")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(status) if status is not None else None,
        "catalog_digest_sha256": _directory_digest(_CATALOG_DIR),
    }


def _environment() -> dict[str, Any]:
    """Record enough of the host to make a later comparison honest."""
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor(),
    }


def _measured_elsewhere() -> list[dict[str, str]]:
    """Name the owner for Phase 1 quantities this script deliberately skips."""
    return [
        {
            "metric": "component latency and peak allocation",
            "owner": "scripts/characterize_performance.py",
            "reason": (
                "Already a reproducible network-free harness. Duplicating it would create a "
                "second set of numbers to keep consistent."
            ),
        },
        {
            "metric": "claim lineage and provenance completeness",
            "owner": "scripts/check_default_claim_audit.py",
            "reason": (
                "The fail-closed audit already covers all 27 families and blocks the gate on "
                "any uncovered surface, so a recomputed share would report a constant."
            ),
        },
        {
            "metric": "typed catalog coverage from real results",
            "owner": "validation/catalog_baseline.py",
            "reason": "Requires the private corpus and emits its own aggregate-only artifact.",
        },
        {
            "metric": "claim-family precision, benefit, and safety",
            "owner": "docs/quality-baseline-preregistration.md",
            "reason": "Governed by the frozen decision rule and requires independently labeled units.",
        },
    ]


def _unmeasured() -> list[dict[str, str]]:
    """Record what Phase 1 asks for and this artifact cannot honestly supply.

    Phase 1 requires unmeasured channels to be named rather than omitted. An
    absent metric otherwise reads as a passing one.
    """
    return [
        {
            "metric": "classified versus unclassified observable surface",
            "blocker": "private corpus",
            "reason": (
                "Requires real bounded observations. Computing it over synthetic fixtures "
                "would measure the fixtures, not the catalog, because the unclassified share "
                "would be whatever the fixture author chose to include."
            ),
        },
        {
            "metric": "CT marginal signal gain relative to latency cost",
            "blocker": "network and private corpus",
            "reason": (
                "Needs live certificate-transparency responses across a real domain sample. "
                "Synthetic CT entries would predetermine the marginal gain."
            ),
        },
        {
            "metric": "end-to-end cold and warm p50/p95 for single, batch, graph, and MCP workflows",
            "blocker": "network",
            "reason": (
                "Dominated by external DNS and CT providers. A network-free number would "
                "characterize the fixture layer rather than the workflow an operator runs."
            ),
        },
        {
            "metric": "degraded-source rate and partial-result rate",
            "blocker": "network and private corpus",
            "reason": (
                "Degradation behavior is covered by the test suite, but its rate is a property "
                "of live provider availability over a real sample and cannot be synthesized."
            ),
        },
        {
            "metric": "MCP result payload bytes under real lookups",
            "blocker": "network",
            "reason": (
                "Discovery cost is fully determined by the registered surface and is measured "
                "above. Result size depends on how much a real domain actually resolves."
            ),
        },
    ]


def build_scorecard() -> dict[str, Any]:
    """Return the complete JSON-serializable scorecard."""
    return {
        "schema_version": 1,
        "purpose": (
            "Phase 1 product-quality baseline. Aggregate-safe, network-free, corpus-free. "
            "Diagnostic artifact, not a gate."
        ),
        "revisions": _revisions(),
        "environment": _environment(),
        "reproduction": {
            "command": "uv run python scripts/quality_scorecard.py",
            "network": "not used",
            "private_corpus": "not used",
            "token_estimate_divisor_bytes": _BYTES_PER_TOKEN_ESTIMATE,
        },
        "measurements": {
            "mcp_context_cost": _mcp_context_cost(),
            "catalog_surface": _catalog_surface(),
        },
        "measured_elsewhere": _measured_elsewhere(),
        "unmeasured": _unmeasured(),
    }


def _render_markdown(scorecard: dict[str, Any]) -> str:
    """Render the maintainer-readable memo form of the scorecard."""
    revisions = scorecard["revisions"]
    mcp = scorecard["measurements"]["mcp_context_cost"]
    catalog = scorecard["measurements"]["catalog_surface"]
    headroom = mcp["headroom"]
    commit = revisions["commit"] or "unknown"

    lines = [
        "# Product-quality baseline scorecard",
        "",
        f"Commit `{commit[:12]}`, catalog `{(revisions['catalog_digest_sha256'] or 'unknown')[:12]}`, "
        f"Python {scorecard['environment']['python']}.",
        "",
        "Network-free, corpus-free, aggregate-safe. Diagnostic artifact, not a gate.",
        "",
        "## MCP context cost",
        "",
        "What an agent pays before it does any work.",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Registered tools | {mcp['tool_count']} |",
        f"| Discovery payload | {mcp['discovery_bytes']:,} bytes |",
        f"| Instruction preamble | {mcp['instruction_preamble_bytes']:,} bytes |",
        f"| **Session context before first call** | **{mcp['session_context_bytes']:,} bytes** |",
        f"| Order-of-magnitude tokens | ~{mcp['session_context_approx_tokens']:,} |",
        "",
        "Where the discovery payload goes:",
        "",
        "| Component | Bytes | Share |",
        "|---|---:|---:|",
    ]
    for field, value in mcp["component_bytes"].items():
        share = mcp["component_share"].get(field, 0.0)
        lines.append(f"| `{field}` | {value:,} | {share * 100:.1f}% |")

    duplication = headroom["cross_tool_definition_duplication"]
    lines += [
        "",
        f"Output schemas are {headroom['output_schema_share_of_discovery'] * 100:.1f}% of discovery. "
        f"Removing them entirely would leave {headroom['discovery_without_output_schema_bytes']:,} bytes, "
        "which is an upper bound on headroom rather than a proposal: structured output is part of the "
        "contract clients validate against.",
        "",
        f"Cross-tool definition duplication accounts for only {duplication['redundant_bytes']:,} bytes across "
        f"{duplication['bodies_shared_by_multiple_tools']} shared definition bodies, so a shared-definition "
        "scheme is not the lever either.",
        "",
        "Largest and smallest registered tools:",
        "",
        f"- `{mcp['concentration']['largest_tool']}` at {mcp['concentration']['largest_tool_bytes']:,} bytes",
        f"- `{mcp['concentration']['smallest_tool']}` at {mcp['concentration']['smallest_tool_bytes']:,} bytes",
        f"- top 5 tools carry {mcp['concentration']['top_5_share_of_discovery'] * 100:.1f}% of discovery",
        "",
        "## Catalog surface",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Entries | {catalog['entries']:,} |",
        f"| Detection rules | {catalog['detection_rules']:,} |",
        f"| Rules carrying a verification date | {catalog['verification_dates']['dated_rules']:,} "
        f"({catalog['verification_dates']['dated_share'] * 100:.1f}%) |",
        f"| Undated rules | {catalog['verification_dates']['undated_rules']:,} |",
        "",
        "## Measured elsewhere",
        "",
        "| Metric | Owner |",
        "|---|---|",
    ]
    lines += [f"| {entry['metric']} | `{entry['owner']}` |" for entry in scorecard["measured_elsewhere"]]
    lines += [
        "",
        "## Unmeasured",
        "",
        "Named rather than omitted, because an absent metric reads as a passing one.",
        "",
        "| Metric | Blocked by |",
        "|---|---|",
    ]
    lines += [f"| {entry['metric']} | {entry['blocker']} |" for entry in scorecard["unmeasured"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Emit the scorecard as JSON, or as a maintainer-readable memo."""
    parser = argparse.ArgumentParser(description="Emit the aggregate-safe product-quality baseline scorecard.")
    parser.add_argument("--markdown", action="store_true", help="Render the memo form instead of JSON.")
    arguments = parser.parse_args(argv)

    scorecard = build_scorecard()
    if arguments.markdown:
        sys.stdout.write(_render_markdown(scorecard))
        return 0
    json.dump(scorecard, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
