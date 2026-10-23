#!/usr/bin/env python3
"""Require verification dates and explicit catalog claim-review dispositions.

The existing undated catalog is a migration backlog, so this gate compares the
working catalog with a Git baseline instead of requiring an all-at-once
backfill. A detection is new when its source file, fingerprint slug, record
type, or pattern is absent from the baseline. New detections must carry a real
``YYYY-MM-DD`` date that is not in the future.

Additions, removals and existing-key semantic or verification edits also need
an exact before/after disposition. Description layout alone is normalized;
spelling corrections can retain the source date under an editorial review.

The check performs no network requests. It validates when a basis was checked,
not whether a reference URL is currently reachable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
REVIEWS = ROOT / "docs/catalog-rule-reviews.json"
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
    claim_digest: str = ""
    structural_digest: str = ""
    review_digest: str = ""
    reference: str = ""


@dataclass(frozen=True)
class ClaimReview:
    key: DetectionKey
    before: str | None
    after: str | None
    disposition: str
    reviewed_on: str
    source_checked_on: str | None
    reason: str


@dataclass(frozen=True)
class FreshnessViolation:
    key: DetectionKey
    reason: str

    def render(self) -> str:
        return f"{self.key.source}: {self.key.slug} [{self.key.detection_type}] {self.key.pattern!r}: {self.reason}"


def _catalog_entries(raw: Any, source: str) -> list[Any]:
    entries = raw.get("fingerprints") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError(f"{source}: expected a fingerprint list")
    return entries


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _metadata(entry: dict[str, Any], rule: dict[str, Any], key: DetectionKey) -> DetectionMetadata:
    context = {name: value for name, value in entry.items() if name != "detections"}
    claim = {name: value for name, value in rule.items() if name != "verified"}
    if isinstance(claim.get("description"), str):
        claim["description"] = " ".join(claim["description"].split())
    structural = {name: value for name, value in claim.items() if name != "description"}
    return DetectionMetadata(
        key=key,
        verified=rule.get("verified"),
        claim_digest=_digest((context, claim)),
        structural_digest=_digest((context, structural)),
        review_digest=_digest((context, claim, rule.get("verified"))),
        reference=rule.get("reference") if isinstance(rule.get("reference"), str) else "",
    )


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
            detections[key] = _metadata(entry, rule, key)
    return detections


def _review_date(value: object, today: date) -> bool:
    if not isinstance(value, str) or ISO_DATE_RE.fullmatch(value) is None:
        return False
    try:
        return date.fromisoformat(value) <= today
    except ValueError:
        return False


def load_claim_reviews(path: Path, *, today: date) -> tuple[ClaimReview, ...]:
    """Load explicit dispositions bound to exact before/after metadata."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"version", "reviews"} or raw["version"] != 1:
        raise ValueError("catalog review ledger must have version 1 and reviews")
    if not isinstance(raw["reviews"], list):
        raise ValueError("catalog reviews must be an array")
    reviews = []
    fields = {"rule", "before", "after", "disposition", "reviewed_on", "source_checked_on", "reason"}
    for row in raw["reviews"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("catalog review has missing or unknown fields")
        rule = row["rule"]
        if not isinstance(rule, dict) or set(rule) != {"source", "slug", "detection_type", "pattern"}:
            raise ValueError("catalog review rule needs source, slug, detection_type and pattern")
        if not all(isinstance(value, str) and value.strip() for value in rule.values()):
            raise ValueError("catalog review rule fields must be nonempty strings")
        if not isinstance(row["disposition"], str) or row["disposition"] not in {"semantic", "editorial"}:
            raise ValueError("catalog review disposition must be semantic or editorial")
        if not isinstance(row["reason"], str) or not row["reason"].strip():
            raise ValueError("catalog review needs a reason and supporting basis")
        if (
            not all(
                row[key] is None or (isinstance(row[key], str) and re.fullmatch(r"[0-9a-f]{64}", row[key]))
                for key in ("before", "after")
            )
            or row["before"] == row["after"]
        ):
            raise ValueError("catalog review digests must differ; use null for an absent rule")
        if not _review_date(row["reviewed_on"], today):
            raise ValueError("catalog review date must be real and not in the future")
        checked = row["source_checked_on"]
        if checked is not None and (not _review_date(checked, today) or checked > row["reviewed_on"]):
            raise ValueError("source check date must be real and no later than review")
        review = ClaimReview(DetectionKey(**rule), **{key: value for key, value in row.items() if key != "rule"})
        if any((old.key, old.before, old.after) == (review.key, review.before, review.after) for old in reviews):
            raise ValueError("duplicate catalog review disposition")
        reviews.append(review)
    return tuple(reviews)


def audit_changed_detections(
    baseline: dict[DetectionKey, DetectionMetadata],
    current: dict[DetectionKey, DetectionMetadata],
    reviews: tuple[ClaimReview, ...],
) -> list[FreshnessViolation]:
    """Require a disposition for additions, removals and claim/date changes."""
    indexed = {(row.key, row.before, row.after): row for row in reviews}
    violations = []
    for key in sorted(current.keys() | baseline.keys()):
        before, after = baseline.get(key), current.get(key)
        before_digest = before.review_digest if before else None
        after_digest = after.review_digest if after else None
        if before_digest == after_digest:
            continue
        review = indexed.get((key, before_digest, after_digest))
        detail = f"before={before_digest} after={after_digest}"
        if review is None:
            violations.append(FreshnessViolation(key, f"claim/provenance or verification edit needs review: {detail}"))
        elif review.disposition == "editorial" and (
            before is None or after is None or before.structural_digest != after.structural_digest
        ):
            violations.append(FreshnessViolation(key, "role, reference or matching semantics require semantic review"))
        elif (
            after is not None
            and after.verified
            and (before is None or str(before.verified) != str(after.verified))
            and review.source_checked_on != str(after.verified)
        ):
            violations.append(FreshnessViolation(key, "verified edit requires its actual source_checked_on date"))
    return violations


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
    parser = argparse.ArgumentParser(description="Require fingerprint dates and explicit claim-review dispositions.")
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
        reviews = load_claim_reviews(REVIEWS, today=today)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Fingerprint freshness check failed: {exc}", file=sys.stderr)
        return 1

    new_count = len(current.keys() - baseline.keys())
    violations = audit_new_detections(baseline, current, today=today)
    violations.extend(audit_changed_detections(baseline, current, reviews))
    if violations:
        print("Fingerprint freshness/claim review check failed:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation.render()}", file=sys.stderr)
        return 1

    print(f"OK: {new_count} new fingerprint detection rule(s) carry valid verification dates.")
    print("OK: catalog additions, removals, claim and verification edits have explicit review dispositions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
