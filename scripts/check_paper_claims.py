#!/usr/bin/env python3
"""Check that the paper draft stays aligned with the claim map."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


SECTION6_ROWS: tuple[tuple[str, str], ...] = (
    ("Differential verification", "Exact inference matches a full-joint reference"),
    ("Adversarial add/remove perturbation", "Planted evidence can move posteriors across the decision boundary"),
    ("Interval coverage (synthetic)", "The 80 percent interval absorbs the CAL8 likelihood band"),
    ("Likelihood sensitivity", "Posteriors are stable under +/-20 percent likelihood perturbation"),
    ("Layer ablations (synthetic)", "The Bayesian and graph layers add value over simple matching"),
    ("Held-out residual", "DMARC-held-out residual fails as an independent predictor"),
    ("DMARC full posterior", "DMARC full posterior agrees strongly with the DMARC record"),
    ("Tenancy corroboration", "M365 tenancy DNS-only predictor corroborates provider attestation"),
    ("Conformal coverage", "Split conformal coverage is measured on labelable nodes"),
)

REQUIRED_BOUNDARIES: tuple[tuple[str, str], ...] = (
    ("draft", "not attacker prevalence"),
    ("draft", "CONSISTENCY, not calibration"),
    ("draft", "private-corpus rows are maintainer-reproducible aggregates only"),
    ("outline", "corroboration rather than calibration"),
    ("outline", "robustness checks rather than population rates"),
    ("claim-map", "not ground-truth frequentist coverage"),
    ("claim-map", "robustness checks rather than population rates"),
    ("claim-map", "Do not state attacker prevalence, exploitability, or real-world false-positive rate"),
    ("claim-map", "Do not state independent calibration"),
    ("artifact-review", "Private-corpus rows are aggregate evidence"),
    ("artifact-review", "robustness checks rather than population rates"),
    ("artifact-review", "corroboration rather than independent calibration"),
    ("external-plan", "adversarial-perturbation-paper-20260628"),
    ("external-plan", "final claim audit is complete"),
    ("external-plan", "public-list numbers as robustness checks rather than population rates"),
    ("external-plan", "M365 independent-instrument decision is closed"),
    ("roadmap", "Public-list numbers remain robustness checks rather than"),
    ("m365-decision", "Do not promote the M365 tenancy result to an independent calibration claim"),
    ("m365-decision", "No open-item table lists the M365 independent-instrument check"),
    ("data-policy", "Public-list checks may serve as robustness checks"),
)

LATEST_PUBLIC_PROOF_MEMO = "2026-06-29-scorecard-gate-claim-audit.md"

FORBIDDEN_M365_WORDING: tuple[tuple[str, str], ...] = (
    ("draft", "M365 and Google tenancy calibrations"),
    ("draft", "strongest genuinely-disjoint signal"),
    ("outline", "calibrated against Microsoft's own endpoint attestation"),
)


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _load_docs(root: Path) -> dict[str, str]:
    return {
        "draft": _read(root, "docs/paper-draft.md"),
        "outline": _read(root, "docs/paper-outline.md"),
        "claim-map": _read(root, "docs/paper-claim-map.md"),
        "artifact-review": _read(root, "docs/artifact-review.md"),
        "external-plan": _read(root, "docs/external-writeup-plan.md"),
        "roadmap": _read(root, "docs/roadmap.md"),
        "m365-decision": _read(root, "docs/m365-tenancy-decision.md"),
        "data-policy": _read(root, "docs/data-handling-policy.md"),
    }


def _section_issues(docs: dict[str, str]) -> list[str]:
    issues: list[str] = []

    for row_label, claim_label in SECTION6_ROWS:
        if row_label not in docs["draft"] and row_label not in docs["outline"]:
            issues.append(f"missing paper evaluation row: {row_label}")
        if claim_label not in docs["claim-map"]:
            issues.append(f"missing claim-map support row: {claim_label}")
    return issues


def _boundary_issues(docs: dict[str, str]) -> list[str]:
    issues: list[str] = []

    for doc_name, phrase in REQUIRED_BOUNDARIES:
        if phrase not in docs[doc_name]:
            issues.append(f"{doc_name} missing required boundary phrase: {phrase}")

    for doc_name, phrase in FORBIDDEN_M365_WORDING:
        if phrase in docs[doc_name]:
            issues.append(f"{doc_name} contains forbidden M365 calibration wording: {phrase}")
    return issues


def _latest_proof_issues(docs: dict[str, str]) -> list[str]:
    issues: list[str] = []
    for doc_name in ("claim-map", "artifact-review", "external-plan"):
        if LATEST_PUBLIC_PROOF_MEMO not in docs[doc_name]:
            issues.append(f"{doc_name} does not link latest public proof memo")
    return issues


def _submission_gate_issues(docs: dict[str, str]) -> list[str]:
    issues: list[str] = []

    if (
        "Requires further evidence" in docs["claim-map"]
        and "Claims marked as requiring further evidence" not in docs["claim-map"]
    ):
        issues.append("claim map names the further-evidence tier without the submission-gate handling rule")

    if "population rates" in docs["draft"] and "robustness checks" not in docs["draft"]:
        issues.append("draft mentions population rates without the public-list robustness boundary")

    if (
        "M365 independent-instrument check" in docs["draft"]
        and "corroboration rather than calibration" not in docs["draft"]
    ):
        issues.append("draft names the M365 instrument blocker without the corroboration boundary")

    for doc_name in ("draft", "outline"):
        if "Blocking open item" in docs[doc_name] and "M365 independent-instrument check" in docs[doc_name]:
            issues.append(f"{doc_name} still lists the M365 instrument decision as an open blocker")

    return issues


def collect_issues(root: Path = ROOT) -> list[str]:
    docs = _load_docs(root)
    issues: list[str] = []
    issues.extend(_section_issues(docs))
    issues.extend(_boundary_issues(docs))
    issues.extend(_latest_proof_issues(docs))
    issues.extend(_submission_gate_issues(docs))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check paper claim-map alignment.")
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root to check.")
    args = parser.parse_args(argv)

    issues = collect_issues(args.root)
    if issues:
        print("Paper claim audit failed:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    print("OK: paper draft, outline, claim map, reviewer guide, and write-up plan are aligned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
