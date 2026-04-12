"""Accuracy report generator for the validation corpus.

Resolves all fixture domains from tests/validation/fixtures/ (gitignored),
computes per-category recall, and writes docs/accuracy.md (also gitignored).

Usage:
    python -m tests.validation.generate_report
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from recon_tool.models import ReconLookupError  # noqa: E402
from recon_tool.resolver import resolve_tenant  # noqa: E402

_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_OUTPUT_PATH = _PROJECT_ROOT / "docs" / "accuracy.md"


@dataclass
class FixtureResult:
    domain: str
    passed: bool
    missing_services: list[str] = field(default_factory=list)
    missing_slugs: list[str] = field(default_factory=list)
    missing_signals: list[str] = field(default_factory=list)
    confidence_ok: bool = True
    degraded_sources: list[str] = field(default_factory=list)
    error: str | None = None
    actual_confidence: str = ""


async def _validate_fixture(path: Path) -> FixtureResult:
    with open(path) as f:
        fix = json.load(f)

    domain = fix["domain"]
    result = FixtureResult(domain=domain, passed=True)

    try:
        info, _ = await resolve_tenant(domain)
    except (ReconLookupError, Exception) as exc:
        result.passed = False
        result.error = str(exc)
        return result

    result.actual_confidence = info.confidence.value
    result.degraded_sources = list(info.degraded_sources)

    for s in fix["expected_services"]:
        if not any(s.lower() in svc.lower() for svc in info.services):
            result.missing_services.append(s)
            result.passed = False

    for s in fix["expected_slugs"]:
        if s not in set(info.slugs):
            result.missing_slugs.append(s)
            result.passed = False

    for s in fix["expected_signals"]:
        if not any(s.lower() in i.lower() for i in info.insights):
            result.missing_signals.append(s)
            result.passed = False

    order = {"low": 0, "medium": 1, "high": 2}
    lo, hi = fix["expected_confidence_range"]
    if not (order[lo] <= order[info.confidence.value] <= order[hi]):
        result.confidence_ok = False
        result.passed = False

    return result


def _build_report(results: list[FixtureResult]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    degraded = sum(1 for r in results if r.degraded_sources)

    lines = [
        "# Accuracy Report",
        "",
        "Auto-generated. Fixture files are local-only (gitignored).",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Fixtures | {total} |",
        f"| Passed | {passed} |",
        f"| Failed | {total - passed} |",
        f"| Pass rate | {passed / total * 100:.0f}% |" if total else "| Pass rate | N/A |",
        f"| Degraded | {degraded} |",
        "",
        "## Results",
        "",
        "| Domain | Status | Confidence | Degraded | Notes |",
        "|--------|--------|------------|----------|-------|",
    ]

    for r in sorted(results, key=lambda x: x.domain):
        status = "pass" if r.passed else "FAIL"
        notes = []
        if r.error:
            notes.append(f"Error: {r.error}")
        if r.missing_services:
            notes.append(f"Missing svc: {', '.join(r.missing_services)}")
        if r.missing_slugs:
            notes.append(f"Missing slug: {', '.join(r.missing_slugs)}")
        if not r.confidence_ok:
            notes.append(f"Confidence: {r.actual_confidence}")
        deg = ", ".join(r.degraded_sources) if r.degraded_sources else "—"
        lines.append(f"| {r.domain} | {status} | {r.actual_confidence or 'N/A'} | {deg} | {'; '.join(notes) or '—'} |")

    lines.extend(["", "---", ""])
    return "\n".join(lines)


async def main() -> None:
    if not _FIXTURE_DIR.is_dir():
        print(f"No fixtures directory at {_FIXTURE_DIR}")
        print("Create it and add JSON fixture files. See tests/validation/README.md.")
        sys.exit(1)

    fixtures = sorted(_FIXTURE_DIR.glob("*.json"))
    if not fixtures:
        print(f"No fixture files in {_FIXTURE_DIR}")
        sys.exit(1)

    print(f"Running {len(fixtures)} fixtures...")
    results = []
    for fp in fixtures:
        with open(fp) as f:
            domain = json.load(f)["domain"]
        print(f"  {domain}...", end=" ", flush=True)
        r = await _validate_fixture(fp)
        print("pass" if r.passed else "FAIL")
        results.append(r)

    report = _build_report(results)
    _OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUTPUT_PATH.write_text(report, encoding="utf-8")

    passed = sum(1 for r in results if r.passed)
    print(f"\n{passed}/{len(results)} passed. Report: {_OUTPUT_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
