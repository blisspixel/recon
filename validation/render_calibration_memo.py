"""Render aggregate-only calibration memos from private validation runs.

The calibration harnesses read private apex lists, so the run outputs stay under
gitignored paths. This renderer is the publication boundary: it accepts only the
aggregate JSON emitted by those harnesses, applies disclosure checks, and writes
a memo that can be reviewed before any public copy is committed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

DOMAIN_RE = re.compile(r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,})+\b")

ALLOWED_DOMAINS = {
    "adventure-works.com",
    "contoso.com",
    "example.com",
    "example.net",
    "example.org",
    "fabrikam.com",
    "northwindtraders.com",
    "tailspintoys.com",
    "wideworldimporters.com",
    "wingtiptoys.com",
}

FORBIDDEN_TARGET_KEYS = {
    "apex",
    "apex_domain",
    "company",
    "company_name",
    "default_domain",
    "display_name",
    "domain",
    "domain_list",
    "domains",
    "host",
    "hostname",
    "input_domain",
    "organization",
    "organization_name",
    "queried_domain",
    "subdomain",
    "subdomains",
    "tenant_id",
    "tenant_ids",
}


def _is_allowed_domain(domain: str) -> bool:
    normalized = domain.lower().strip(".")
    if normalized.endswith((".test", ".invalid")):
        return True
    return normalized in ALLOWED_DOMAINS or any(normalized.endswith(f".{allowed}") for allowed in ALLOWED_DOMAINS)


def _payload_violations(value: object, *, path: str = "$") -> list[str]:
    violations: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            key_path = f"{path}.{key}"
            for match in DOMAIN_RE.finditer(key):
                domain = match.group(0)
                if not _is_allowed_domain(domain):
                    violations.append(f"{key_path}: target-looking domain key is not fictional or reserved")
            if key.lower() in FORBIDDEN_TARGET_KEYS:
                violations.append(f"{key_path}: target-identifying key is not publishable")
            violations.extend(_payload_violations(child, path=key_path))
        return violations
    if isinstance(value, str):
        for match in DOMAIN_RE.finditer(value):
            domain = match.group(0)
            if not _is_allowed_domain(domain):
                violations.append(f"{path}: target-looking domain value is not fictional or reserved")
    elif isinstance(value, Sequence):
        for index, child in enumerate(value):
            violations.extend(_payload_violations(child, path=f"{path}[{index}]"))
    return violations


def _small_cell_violations(value: object, *, threshold: int, path: str = "$") -> list[str]:
    violations: list[str] = []
    if isinstance(value, Mapping):
        min_cell = value.get("min_cell")
        if isinstance(min_cell, int | float) and int(min_cell) < threshold:
            violations.append(f"{path}.min_cell: minimum cell is below {threshold}")
        strata = value.get("strata")
        if isinstance(strata, Mapping):
            for name, summary in strata.items():
                stratum_path = f"{path}.strata.{name}"
                if isinstance(summary, Mapping):
                    n = summary.get("n")
                    suppressed = summary.get("suppressed") is True
                    if isinstance(n, int | float) and 0 < n < threshold and not suppressed:
                        violations.append(f"{stratum_path}: n={int(n)} is not suppressed")
        for raw_key, child in value.items():
            violations.extend(_small_cell_violations(child, threshold=threshold, path=f"{path}.{raw_key}"))
    elif isinstance(value, Sequence) and not isinstance(value, str):
        for index, child in enumerate(value):
            violations.extend(_small_cell_violations(child, threshold=threshold, path=f"{path}[{index}]"))
    return violations


def validate_public_payload(label: str, payload: Mapping[str, object], *, small_cell_threshold: int = 10) -> None:
    """Raise when a harness JSON payload is not safe for a public aggregate memo."""
    violations = [
        *_payload_violations(payload, path=f"${label}"),
        *_small_cell_violations(payload, threshold=small_cell_threshold, path=f"${label}"),
    ]
    if violations:
        rendered = "\n".join(f"  - {violation}" for violation in violations)
        raise ValueError(f"{label} payload is not publishable:\n{rendered}")


def validate_public_text(label: str, text: str) -> None:
    """Raise when free-form memo text contains target-looking domains."""
    violations = _payload_violations(text, path=f"${label}")
    if violations:
        rendered = "\n".join(f"  - {violation}" for violation in violations)
        raise ValueError(f"{label} text is not publishable:\n{rendered}")


def load_public_payload(path: Path, label: str, *, small_cell_threshold: int) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} payload is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{label} payload must be a JSON object")
    payload = dict(loaded)
    validate_public_payload(label, payload, small_cell_threshold=small_cell_threshold)
    return payload


def _as_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _fmt(value: object, *, digits: int = 4) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.{digits}f}".rstrip("0").rstrip(".")
    if isinstance(value, list | tuple):
        return ", ".join(_fmt(item, digits=digits) for item in value)
    return str(value)


def _calibration_row(name: str, summary: Mapping[str, object]) -> str:
    if summary.get("n") in (None, 0):
        return f"| {name} | 0 | | | | | |"
    return (
        f"| {name} | {_fmt(summary.get('n'))} | {_fmt(summary.get('log_score'))} | "
        f"{_fmt(summary.get('brier'))} | {_fmt(summary.get('ece'))} | "
        f"{_fmt(summary.get('agreement_rate'))} | {_fmt(summary.get('base_rate_enforcing'))} |"
    )


def _strata_lines(title: str, block: Mapping[str, object], label: str) -> list[str]:
    pooled = _as_mapping(block.get("pooled"))
    lines = [
        f"### {label}",
        "",
        "| Block | n | Log score | Brier | ECE | Agreement | Base rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
        _calibration_row("Pooled", pooled),
        "",
        "| Stratum | n | ECE | Agreement | Base rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, summary_raw in sorted(_as_mapping(block.get("strata")).items()):
        summary = _as_mapping(summary_raw)
        if summary.get("suppressed") is True:
            lines.append(f"| {name} | {_fmt(summary.get('n'))} | suppressed | suppressed | suppressed |")
        else:
            lines.append(
                f"| {name} | {_fmt(summary.get('n'))} | {_fmt(summary.get('ece'))} | "
                f"{_fmt(summary.get('agreement_rate'))} | {_fmt(summary.get('base_rate_enforcing'))} |"
            )
    lines.append("")
    if title:
        return [f"## {title}", "", *lines]
    return lines


def _render_calibration_block(title: str, payload: Mapping[str, object]) -> list[str]:
    lines = [f"## {title}", ""]
    if "strata" in payload and "pooled" in payload:
        return _strata_lines(title, payload, "Pooled and per-stratum")
    mode = payload.get("mode")
    if mode == "stratified":
        for block_name, label in (("full", "Full posterior"), ("held_out", "Held-out residual")):
            block = _as_mapping(payload.get(block_name))
            lines.extend(_strata_lines("", block, label))
        return lines
    lines.extend(
        [
            "| Block | n | Log score | Brier | ECE | Agreement | Base rate |",
            "|---|---:|---:|---:|---:|---:|---:|",
            _calibration_row("Full posterior", _as_mapping(payload.get("full"))),
            _calibration_row("Held-out residual", _as_mapping(payload.get("held_out"))),
            "",
        ]
    )
    return lines


def _render_tenancy_block(payload: Mapping[str, object]) -> list[str]:
    lines = ["## Tenancy Provider Corroboration", ""]
    counts = _as_mapping(payload.get("counts"))
    if counts:
        lines.extend(
            [
                "| Count | Value |",
                "|---|---:|",
                f"| Resolved | {_fmt(counts.get('resolved'))} |",
                f"| Resolve failed | {_fmt(counts.get('resolve_failed'))} |",
                f"| No DNS channel | {_fmt(counts.get('no_dns_channel'))} |",
                f"| M365 positive labels | {_fmt(counts.get('m365_positive'))} |",
                f"| M365 negative labels | {_fmt(counts.get('m365_negative'))} |",
                f"| M365 unlabeled | {_fmt(counts.get('m365_unlabeled'))} |",
                f"| M365 conflicts | {_fmt(counts.get('m365_conflict'))} |",
                f"| GWS attested positives | {_fmt(counts.get('gws_attested'))} |",
                "",
            ]
        )
    if payload.get("mode") == "stratified":
        lines.extend(
            _render_calibration_block(
                "M365 DNS-only Stratified Corroboration",
                _as_mapping(payload.get("m365_dns_only")),
            )
        )
    else:
        lines.extend(
            [
                "| Block | n | Log score | Brier | ECE | Agreement | Base rate |",
                "|---|---:|---:|---:|---:|---:|---:|",
                _calibration_row("M365 DNS-only", _as_mapping(payload.get("m365_dns_only"))),
                _calibration_row("M365 full pipeline", _as_mapping(payload.get("m365_full"))),
                "",
            ]
        )
    gws = _as_mapping(payload.get("gws_one_sided"))
    lines.extend(
        [
            "| GWS one-sided check | Value |",
            "|---|---:|",
            f"| Attested positives | {_fmt(gws.get('n'))} |",
            f"| Threshold | {_fmt(gws.get('threshold'))} |",
            f"| Recall | {_fmt(gws.get('recall'))} |",
            f"| Recall Wilson80 | {_fmt(gws.get('recall_wilson80'))} |",
            f"| Posterior quartiles | {_fmt(gws.get('posterior_quartiles'))} |",
            "",
        ]
    )
    return lines


def _render_conformal_block(payload: Mapping[str, object]) -> list[str]:
    summary = _as_mapping(payload.get("summary"))
    lines = ["## Conformal Coverage", ""]
    if summary.get("insufficient"):
        lines.extend([f"Only {_fmt(summary.get('n'))} labeled records were available; coverage was not reported.", ""])
        return lines
    lines.extend(
        [
            "| Metric | Value |",
            "|---|---:|",
            f"| Labeled records | {_fmt(summary.get('n'))} |",
            f"| Splits | {_fmt(summary.get('trials'))} |",
            f"| Target coverage | {_fmt(summary.get('target_coverage'))} |",
            f"| Mean coverage | {_fmt(summary.get('mean_coverage'))} |",
            f"| Worst split coverage | {_fmt(summary.get('min_coverage'))} |",
            f"| Mean set size | {_fmt(summary.get('mean_set_size'))} |",
            "",
        ]
    )
    return lines


def render_memo(
    *,
    title: str,
    reference: Mapping[str, object] | None = None,
    tenancy: Mapping[str, object] | None = None,
    conformal: Mapping[str, object] | None = None,
    small_cell_threshold: int = 10,
) -> str:
    validate_public_text("title", title)
    lines = [
        f"# {title}",
        "",
        "## Disclosure Controls",
        "",
        "- Source apex lists and per-domain outputs remain under gitignored private validation paths.",
        "- This memo is generated from aggregate JSON only.",
        "- No apexes, subdomains, organization names, tenant IDs, or per-domain rows are included.",
        f"- Strata below {small_cell_threshold} domains are suppressed or rejected before rendering.",
        "",
    ]
    if reference is not None:
        lines.extend(_render_calibration_block("Email Policy Reference Calibration", reference))
    if tenancy is not None:
        lines.extend(_render_tenancy_block(tenancy))
    if conformal is not None:
        lines.extend(_render_conformal_block(conformal))
    lines.extend(
        [
            "## Interpretation Guardrails",
            "",
            "- Full email-policy calibration overlaps the DMARC predictor and label by design.",
            "- The held-out residual masks the DMARC evidence unit, so predictor and label are disjoint.",
            "- M365 DNS-only tenancy corroboration splits predictor and provider-attested label by channel.",
            "- M365 full-pipeline tenancy agreement is a consistency check, not independent calibration.",
            "- GWS is one-sided recall on provider-attested positives, not two-class calibration.",
            "- Conformal coverage depends on exchangeability and is not claimed for adversarially hardened targets.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render an aggregate-only calibration validation memo.")
    parser.add_argument("--reference", type=Path, help="Aggregate JSON from validation.reference_calibration.")
    parser.add_argument("--tenancy", type=Path, help="Aggregate JSON from validation.tenancy_reference_calibration.")
    parser.add_argument("--conformal", type=Path, help="Aggregate JSON from validation.conformal_coverage.")
    parser.add_argument("--output", type=Path, help="Write the memo here. Defaults to stdout.")
    parser.add_argument("--title", default="Aggregate Calibration Validation Memo")
    parser.add_argument(
        "--small-cell-threshold",
        type=int,
        default=10,
        help="Reject unsuppressed strata below this count.",
    )
    args = parser.parse_args(argv)

    if args.reference is None and args.tenancy is None and args.conformal is None:
        print("FAIL: provide at least one of --reference, --tenancy, or --conformal")
        return 1

    try:
        reference = (
            load_public_payload(args.reference, "reference", small_cell_threshold=args.small_cell_threshold)
            if args.reference is not None
            else None
        )
        tenancy = (
            load_public_payload(args.tenancy, "tenancy", small_cell_threshold=args.small_cell_threshold)
            if args.tenancy is not None
            else None
        )
        conformal = (
            load_public_payload(args.conformal, "conformal", small_cell_threshold=args.small_cell_threshold)
            if args.conformal is not None
            else None
        )
        memo = render_memo(
            title=args.title,
            reference=reference,
            tenancy=tenancy,
            conformal=conformal,
            small_cell_threshold=args.small_cell_threshold,
        )
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    if args.output is None:
        print(memo)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{memo}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
