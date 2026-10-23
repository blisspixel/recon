"""Bounded monthly reference work, separate from smoke tests and promotion."""

from __future__ import annotations

import re
from calendar import monthrange
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from scripts.check_fingerprint_freshness import DetectionKey, load_working_catalog
from validation.catalog_receipts import read_json, write_private_event
from validation.prepare_catalog_round import REPO_ROOT, canonical_json_digest, catalog_digest_sha256

HISTORY = REPO_ROOT / "docs/catalog-freshness-ledger.json"
REVIEW_SCHEMA = REPO_ROOT / "docs/catalog-reference-review.schema.json"


def validated_json(path: Path, schema: Path, *, definition: str | None = None) -> dict[str, object]:
    value = read_json(path)
    contract = read_json(schema)
    if definition is not None:
        contract = contract["$defs"][definition]
    try:
        Draft202012Validator(contract, format_checker=FormatChecker()).validate(value)
    except ValidationError as exc:
        raise ValueError(f"invalid maintenance document at {exc.json_path}") from exc
    return value


def rule_id(key: DetectionKey) -> str:
    return f"{key.source}/{key.slug}/{key.detection_type}/{key.pattern}"


def _resolved(row: dict[str, object]) -> bool:
    return row["source_status"] == "checked" and row["disposition"] != "deferred"


def _review_rows(cycle: Path) -> dict[str, dict[str, object]]:
    """Combine immutable submissions; a checked decision cannot be rewritten."""
    result = {}
    paths = sorted((cycle / "reviews").glob("*.json"))
    if len(paths) > 50:
        raise ValueError("freshness submission budget exhausted")
    for path in paths:
        for row in validated_json(path, REVIEW_SCHEMA)["reviews"]:
            previous = result.get(row["rule_id"])
            if previous is not None and _resolved(previous):
                if _resolved(row) and row != previous:
                    raise ValueError("conflicting checked review receipts")
                continue
            if previous is None or _resolved(row) or (row["reviewed_on"] or "") >= (previous["reviewed_on"] or ""):
                result[row["rule_id"]] = row
    return result


def _history(path: Path, root: Path) -> dict[str, dict[str, object]]:
    data = read_json(path)
    if data.get("schema_version") != 1 or not isinstance(data.get("reviews"), list):
        raise ValueError("freshness history needs schema version 1 and review rows")
    result = {}
    row_schema = read_json(REVIEW_SCHEMA)["properties"]["reviews"]["items"]
    validator = Draft202012Validator(row_schema, format_checker=FormatChecker())
    for row in data["reviews"]:
        if not isinstance(row, dict) or not isinstance(row.get("rule_id"), str):
            raise ValueError("invalid freshness history row")
        clean = {key: value for key, value in row.items() if key != "review_digest"}
        if not validator.is_valid(clean):
            raise ValueError("invalid freshness history review fields")
        for field in ("reviewed_on", "source_checked_on", "next_review"):
            if row.get(field) is not None:
                date.fromisoformat(row[field])
        _validate_review(row, {"reference": row["prior_reference"]}, date.today())
        result[row["rule_id"]] = row
    for cycle in sorted((root / "freshness").glob("*")):
        admission_path = cycle / "admission.json"
        if not admission_path.is_file():
            continue
        frozen = {row["rule_id"]: row["review_digest"] for row in read_json(admission_path)["rules"]}
        for identity, row in _review_rows(cycle).items():
            previous = result.get(identity, {})
            if (row["reviewed_on"] or "") >= (previous.get("reviewed_on") or ""):
                result[identity] = {**row, "review_digest": frozen[identity]}
    return result


def _outstanding(root: Path, period: str) -> set[str]:
    owned = set()
    for path in sorted((root / "freshness").glob("*/admission.json")):
        if path.parent.name == period:
            continue
        if (path.parent / "skip.json").is_file():
            continue
        admission = read_json(path)
        checked = {identity for identity, row in _review_rows(path.parent).items() if _resolved(row)}
        owned.update(row["rule_id"] for row in admission["rules"] if row["rule_id"] not in checked)
    return owned


def due_work(
    root: Path,
    period: str,
    *,
    as_of: date,
    review_limit: int = 8,
    proposal_limit: int = 8,
) -> dict[str, object]:
    """One immutable cycle admission; repeated wakes never duplicate work."""
    if not re.fullmatch(r"\d{4}-\d{2}(?:-[a-z0-9][a-z0-9_.-]{0,59})?", period):
        raise ValueError("freshness cycle must be YYYY-MM with an optional explicit recheck name")
    date.fromisoformat(f"{period[:7]}-01")
    if not 1 <= review_limit <= 50 or not 0 <= proposal_limit <= 50:
        raise ValueError("freshness review/proposal budget is outside bounds")
    path = root / "freshness" / period / "admission.json"
    digest = catalog_digest_sha256()
    if path.is_file():
        existing = read_json(path)
        if (
            existing["catalog_digest"] != digest
            or existing["review_limit"] != review_limit
            or existing["proposal_limit"] != proposal_limit
        ):
            raise ValueError("existing freshness admission differs; resume it without expanding scope")
        return existing
    history = _history(HISTORY, root)
    outstanding = _outstanding(root, period)
    due = []
    for key, metadata in load_working_catalog().items():
        identity = rule_id(key)
        previous = history.get(identity, {})
        next_review = previous.get("next_review")
        unchanged = previous.get("review_digest") == metadata.review_digest
        if identity in outstanding or (
            unchanged and next_review is not None and date.fromisoformat(next_review) > as_of
        ):
            continue
        due.append(
            {
                "rule_id": identity,
                "reference": metadata.reference or None,
                "verified": str(metadata.verified) if metadata.verified else None,
                "review_digest": metadata.review_digest,
            }
        )
    due.sort(key=lambda row: (row["verified"] or "0000-00-00", row["rule_id"]))
    admission = {
        "schema_version": 1,
        "period": period,
        "as_of": as_of.isoformat(),
        "catalog_digest": digest,
        "review_limit": review_limit,
        "proposal_limit": proposal_limit,
        "rules": due[:review_limit],
        "due_total": len(due),
        "deferred_by_budget": max(0, len(due) - review_limit),
        "owned_by_other_cycle": len(outstanding),
        "status": "planned" if due else "blocked" if outstanding else "no_change",
    }
    write_private_event(path, admission, idempotent=True)
    return admission


def _validate_review(row: dict[str, object], frozen: dict[str, object], as_of: date) -> None:
    if row["prior_reference"] != frozen["reference"]:
        raise ValueError("review prior reference differs from admission")
    for name in ("reviewed_on", "source_checked_on"):
        if row[name] is not None and date.fromisoformat(row[name]) > min(as_of, date.today()):
            raise ValueError("review/source date cannot be in the future")
    if row["source_status"] == "checked":
        if row["source_checked_on"] is None or row["reviewed_on"] is None or row["next_review"] is None:
            raise ValueError("checked source needs actual check/review dates and next review")
        if row["source_checked_on"] > row["reviewed_on"] or row["next_review"] <= row["reviewed_on"]:
            raise ValueError("source/review/next-review date order is invalid")
    elif row["source_checked_on"] is not None or row["disposition"] != "deferred":
        raise ValueError("unreachable/unreviewed sources must remain deferred with no source-check date")
    if row["source_status"] == "unreviewed" and row["next_review"] is not None:
        raise ValueError("unreviewed basis cannot advance its next-review schedule")
    if row["source_status"] == "unreachable" and row["reviewed_on"] is None:
        raise ValueError("unreachable reference needs its actual attempted-review date")
    reference = row["new_reference"]
    if reference is not None:
        parsed = urlsplit(reference)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("review reference must be an unauthenticated HTTPS documentation URL")


def _proposals(rows: list[dict[str, object]], frozen: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    result = []
    for row in rows:
        if not _resolved(row):
            continue
        identity = row["rule_id"]
        verified_update = (
            frozen[identity]["verified"] is None or row["source_checked_on"] > frozen[identity]["verified"]
        )
        if row["disposition"] != "unchanged" or row["new_reference"] != row["prior_reference"] or verified_update:
            proposal = {
                "rule_id": identity,
                "disposition": row["disposition"],
                "reference_changed": row["new_reference"] != row["prior_reference"],
                "verified_update_proposed": verified_update,
                "source_checked_on": row["source_checked_on"],
                "new_reference": row["new_reference"],
                "status": "pending",
                "basis_revision": frozen[identity]["review_digest"],
            }
            proposal["proposal_id"] = canonical_json_digest(proposal)
            result.append(proposal)
    return result


def _review_result(admission: dict[str, object], combined: list[dict[str, object]]) -> dict[str, object]:
    frozen = {row["rule_id"]: row for row in admission["rules"]}
    proposals = _proposals(combined, frozen)
    checked = sum(row["source_status"] == "checked" for row in combined)
    unknown = len(frozen) - checked
    unresolved = len(frozen) - sum(_resolved(row) for row in combined)
    status = ("partial" if checked else "blocked") if unresolved else "completed" if proposals else "no_change"
    return {
        "schema_version": 1,
        "period": admission["period"],
        "catalog_digest": admission["catalog_digest"],
        "status": status,
        "scope_count": len(frozen),
        "checked_count": checked,
        "unknown_count": unknown,
        "unresolved_count": unresolved,
        "reviews": combined,
        "proposal_queue": proposals[: admission["proposal_limit"]],
        "proposals_deferred_by_budget": max(0, len(proposals) - admission["proposal_limit"]),
        "promotion": "none; existing catalog, provenance, fixture and full CI gates still apply",
    }


def review_cycle(admission_path: Path, input_path: Path, *, as_of: date) -> dict[str, object]:
    """Record checked, unknown and deferred work without editing catalog dates."""
    admission = read_json(admission_path)
    if admission["catalog_digest"] != catalog_digest_sha256():
        raise ValueError("catalog changed since freshness admission")
    submitted = validated_json(input_path, REVIEW_SCHEMA)["reviews"]
    submitted.sort(key=lambda row: row["rule_id"])
    frozen = {row["rule_id"]: row for row in admission["rules"]}
    previous = _review_rows(admission_path.parent)
    seen = set()
    for row in submitted:
        identity = row["rule_id"]
        if identity not in frozen or identity in seen:
            raise ValueError("review rule is outside admission or repeated")
        _validate_review(row, frozen[identity], as_of)
        old = previous.get(identity)
        if old is not None and _resolved(old) and old != row:
            raise ValueError("checked review is frozen; declare a new recheck cycle")
        seen.add(identity)
    submission = {"schema_version": 1, "reviews": submitted}
    event = admission_path.parent / "reviews" / f"{canonical_json_digest(submission)}.json"
    if not event.exists() and len(list((admission_path.parent / "reviews").glob("*.json"))) >= 50:
        raise ValueError("freshness submission budget exhausted")
    write_private_event(event, submission, idempotent=True)
    combined = list(_review_rows(admission_path.parent).values())
    combined.sort(key=lambda row: row["rule_id"])
    return _review_result(admission, combined)


def skip_cycle(admission_path: Path, reason: str) -> dict[str, object]:
    if len(reason.strip()) < 10:
        raise ValueError("skipped cycle needs an explicit reason")
    admission = read_json(admission_path)
    rows = list(_review_rows(admission_path.parent).values())
    if len(rows) == len(admission["rules"]) and all(_resolved(row) for row in rows):
        raise ValueError("completed cycle cannot be relabeled skipped")
    result = {
        "schema_version": 1,
        "period": admission["period"],
        "status": "skipped",
        "reason": reason,
        "checked_count": sum(row["source_status"] == "checked" for row in rows),
        "promotion": "none",
    }
    write_private_event(admission_path.parent / "skip.json", result, idempotent=True)
    return result


def cycle_status(admission_path: Path, *, as_of: date) -> dict[str, object]:
    admission = read_json(admission_path)
    rows = sorted(_review_rows(admission_path.parent).values(), key=lambda row: row["rule_id"])
    result = _review_result(admission, rows)
    if not rows:
        result["status"] = admission["status"]
    skipped = admission_path.parent / "skip.json"
    if skipped.exists():
        result.update(read_json(skipped))
    period = date.fromisoformat(f"{admission['period'][:7]}-01")
    deadline = date(period.year, period.month, monthrange(period.year, period.month)[1])
    result["overdue"] = as_of > deadline and result["status"] not in {"completed", "no_change"}
    result["catalog_current"] = admission["catalog_digest"] == catalog_digest_sha256()
    return result


def claim_proposal(root: Path, proposal: dict[str, object]) -> tuple[bool, dict[str, object]]:
    """Reserve one proposal before an explicitly requested external PR write."""
    identity = proposal.get("proposal_id")
    if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise ValueError("proposal needs a stable SHA-256 identity")
    if identity != canonical_json_digest({key: value for key, value in proposal.items() if key != "proposal_id"}):
        raise ValueError("proposal identity differs from its contents")
    entity = proposal.get("rule_id")
    if not isinstance(entity, str) or not entity:
        raise ValueError("proposal needs a rule identity")
    directory = root / "proposals" / canonical_json_digest(entity)
    claims = sorted(directory.glob("claim-*.json"))
    if len(claims) >= 1000:
        raise ValueError("proposal history requires archival")
    for path in claims:
        previous = read_json(path)
        if previous["proposal"]["proposal_id"] == identity:
            return False, previous
    if claims and not (directory / f"resolved-{len(claims):06}.json").is_file():
        return False, read_json(claims[-1])
    slot = len(claims) + 1
    path = directory / f"claim-{slot:06}.json"
    claim = {
        "schema_version": 1,
        "status": "claimed; reconcile remote state before retrying publication",
        "proposal": proposal,
        "slot": slot,
    }
    try:
        write_private_event(path, claim)
    except ValueError as exc:
        if isinstance(exc.__cause__, FileExistsError):
            return False, read_json(path)
        raise
    return True, claim


def resolve_proposal(root: Path, claim: dict[str, object], *, pr_url: str, conclusion: str) -> None:
    """Record a checked remote conclusion; never perform a remote write."""
    if (
        conclusion not in {"merged", "closed"}
        or re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/pull/[1-9][0-9]*", pr_url) is None
    ):
        raise ValueError("proposal resolution needs a GitHub PR URL and merged/closed conclusion")
    directory = root / "proposals" / canonical_json_digest(claim["proposal"]["rule_id"])
    slot = claim["slot"]
    if type(slot) is not int or not 1 <= slot <= 1000:
        raise ValueError("invalid proposal claim slot")
    if read_json(directory / f"claim-{slot:06}.json") != claim:
        raise ValueError("proposal claim differs from the recorded admission")
    write_private_event(
        directory / f"resolved-{slot:06}.json",
        {
            "schema_version": 1,
            "pr_url": pr_url,
            "conclusion": conclusion,
            "proposal_id": claim["proposal"]["proposal_id"],
        },
        idempotent=True,
    )
