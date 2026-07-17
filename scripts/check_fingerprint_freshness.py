#!/usr/bin/env python3
"""Require valid verification dates on newly added fingerprint detections.

The existing undated catalog is a migration backlog, so this gate compares the
working catalog with a Git baseline instead of requiring an all-at-once
backfill. A detection is new when its source file, fingerprint slug, record
type, or pattern is absent from the baseline. New detections must carry a real
``YYYY-MM-DD`` date that is not in the future.

The check performs no network requests. It validates when a basis was checked,
not whether a reference URL is currently reachable.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG_RELATIVE = Path("src/recon_tool/data/fingerprints")
CATALOG_ROOT = ROOT / CATALOG_RELATIVE
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True, order=True)
class DetectionKey:
    source: str
    slug: str
    detection_type: str
    pattern: str


@dataclass(frozen=True)
class DetectionMetadata:
    key: DetectionKey
    verified: object


@dataclass(frozen=True)
class FreshnessViolation:
    key: DetectionKey
    reason: str

    def render(self) -> str:
        return (
            f"{self.key.source}: {self.key.slug} "
            f"[{self.key.detection_type}] {self.key.pattern!r}: {self.reason}"
        )


def _catalog_entries(raw: Any, source: str) -> list[Any]:
    entries = raw.get("fingerprints") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError(f"{source}: expected a fingerprint list")
    return entries


def parse_catalog_text(text: str, *, source: str) -> dict[DetectionKey, DetectionMetadata]:
    """Parse the detection identities and verification metadata from one YAML file."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{source}: invalid YAML: {exc}") from exc

    detections: dict[DetectionKey, DetectionMetadata] = {}
    for entry in _catalog_entries(raw, source):
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        rules = entry.get("detections")
        if not isinstance(slug, str) or not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            detection_type = rule.get("type")
            pattern = rule.get("pattern")
            if not isinstance(detection_type, str) or not isinstance(pattern, str):
                continue
            key = DetectionKey(source, slug, detection_type, pattern)
            detections[key] = DetectionMetadata(key=key, verified=rule.get("verified"))
    return detections


def audit_new_detections(
    baseline: dict[DetectionKey, DetectionMetadata],
    current: dict[DetectionKey, DetectionMetadata],
    *,
    today: date,
) -> list[FreshnessViolation]:
    """Return verification-date violations for identities absent from ``baseline``."""
    violations: list[FreshnessViolation] = []
    for key in sorted(current.keys() - baseline.keys()):
        value = current[key].verified
        normalized = value.isoformat() if isinstance(value, date) else value
        if not isinstance(normalized, str) or not normalized:
            violations.append(FreshnessViolation(key, "missing verified date"))
            continue
        if ISO_DATE_RE.fullmatch(normalized) is None:
            violations.append(FreshnessViolation(key, "verified must use YYYY-MM-DD"))
            continue
        try:
            parsed = date.fromisoformat(normalized)
        except ValueError:
            violations.append(FreshnessViolation(key, "verified is not a real calendar date"))
            continue
        if parsed > today:
            violations.append(FreshnessViolation(key, f"verified date {normalized} is in the future"))
    return violations


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed git executable and argument vector
        ["git", *args],  # noqa: S607 - maintainer tool resolved from PATH
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _git_output(args: list[str]) -> str:
    result = _run_git(args)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"git {' '.join(args)} failed"
        raise RuntimeError(detail)
    return result.stdout


def resolve_base_ref(explicit: str | None) -> str | None:
    """Resolve an explicit, CI-provided, or local main-branch comparison base."""
    candidate = explicit or os.environ.get("FINGERPRINT_BASE_SHA")
    if candidate:
        return candidate

    origin_main = _run_git(["rev-parse", "--verify", "origin/main^{commit}"])
    if origin_main.returncode == 0:
        merge_base = _run_git(["merge-base", "HEAD", "origin/main"])
        if merge_base.returncode == 0 and merge_base.stdout.strip():
            return merge_base.stdout.strip()

    head = _run_git(["rev-parse", "--verify", "HEAD^{commit}"])
    return head.stdout.strip() if head.returncode == 0 and head.stdout.strip() else None


def load_working_catalog() -> dict[DetectionKey, DetectionMetadata]:
    combined: dict[DetectionKey, DetectionMetadata] = {}
    for path in sorted(CATALOG_ROOT.glob("*.yaml")):
        combined.update(parse_catalog_text(path.read_text(encoding="utf-8"), source=path.name))
    return combined


def load_catalog_at_ref(base_ref: str) -> dict[DetectionKey, DetectionMetadata]:
    """Load catalog YAML directly from a Git tree without touching the worktree."""
    tree_check = _run_git(["rev-parse", "--verify", f"{base_ref}^{{tree}}"])
    if tree_check.returncode != 0:
        detail = (tree_check.stderr or tree_check.stdout).strip() or f"unknown Git ref {base_ref!r}"
        raise RuntimeError(detail)

    prefix = CATALOG_RELATIVE.as_posix()
    listed = _git_output(["ls-tree", "-r", "--name-only", base_ref, "--", prefix])
    combined: dict[DetectionKey, DetectionMetadata] = {}
    for relative in sorted(line for line in listed.splitlines() if line.endswith(".yaml")):
        text = _git_output(["show", f"{base_ref}:{relative}"])
        combined.update(parse_catalog_text(text, source=Path(relative).name))
    return combined


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Require verified dates on new fingerprint detection rules.")
    parser.add_argument("--base-ref", help="Git commit or tree to compare with the working catalog.")
    parser.add_argument("--today", help="Override today's date for deterministic tests (YYYY-MM-DD).")
    args = parser.parse_args(argv)

    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
    except ValueError:
        print("Fingerprint freshness check failed: --today must be a real YYYY-MM-DD date.", file=sys.stderr)
        return 1

    base_ref = resolve_base_ref(args.base_ref)
    if base_ref is None:
        print("SKIP: no Git baseline is available for the fingerprint freshness check.")
        return 0

    try:
        baseline = load_catalog_at_ref(base_ref)
        current = load_working_catalog()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Fingerprint freshness check failed: {exc}", file=sys.stderr)
        return 1

    new_count = len(current.keys() - baseline.keys())
    violations = audit_new_detections(baseline, current, today=today)
    if violations:
        print("Fingerprint freshness check failed on new detection rules:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation.render()}", file=sys.stderr)
        return 1

    print(f"OK: {new_count} new fingerprint detection rule(s) carry valid verification dates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
