#!/usr/bin/env python3
"""Generate and check the cross-surface parity matrix.

One record, rendered through every surface recon exposes, has to be the same
record. Four consecutive black-box rounds found defects where one renderer
carried a claim another dropped, or cut a list a note then miscounted. This
builds `docs/surface-parity.md` from a single maximal fixture rendered through
the panel, `--plain`, `--plain --full`, `--md`, `--md --full`, `--json`, the MCP
text surface, and the MCP JSON surface, and `--check` fails when a surface gains
or loses a claim, or a cut stops reconciling, without the committed table moving
in the same commit.

The fixture is deterministic and uses reserved `.invalid` names only. It is
maximal on purpose: a role split, a degraded source, a related list past the cut
with a wildcard and an `.onmicrosoft` name (which the selection filters but the
total counts), and an insight list past the cap with two lines the curator
drops. A fixture whose surfaces cannot disagree cannot guard against them
disagreeing, which is exactly how the 2.15.1 note bug passed its own test.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rich.console import Console  # noqa: E402

from recon_tool.formatter import (  # noqa: E402
    format_tenant_json,
    format_tenant_markdown,
    format_tenant_plain,
    render_tenant_panel,
)
from recon_tool.fusion_apply import apply_fusion  # noqa: E402
from recon_tool.models import CertSummary, ConfidenceLevel, EvidenceRecord, TenantInfo  # noqa: E402
from recon_tool.server.lookup import _format_lookup_tenant, _lookup_tenant_text  # noqa: E402

_OUTPUT = ROOT / "docs" / "surface-parity.md"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _fixture() -> TenantInfo:
    """A maximal, deterministic, reserved-namespace record."""
    related = (
        "login.beta.invalid",
        "sso.beta.invalid",
        "portal.beta.invalid",
        *(f"host{i}.beta.invalid" for i in range(20)),
        "*.beta.invalid",
        "beta.onmicrosoft.com",
    )
    insights = (
        "Email security: observed controls: DMARC reject, DKIM",
        "Federated identity observed; external IdP not identified",
        "Provider indicators co-observed: Microsoft 365, Google Workspace",  # curated away
        "MX gateway observed: Proofpoint",  # curated away
        "Certificate issuance concentrated at one issuer",
        "Legacy protocol indicator observed",
        "Tenant region reported as NA",
    )
    return TenantInfo(
        tenant_id="c7c08208-4f4d-45f1-83cd-5e2f491ab786",
        display_name="Synthetic Split Ltd",
        default_domain="beta.onmicrosoft.com",
        queried_domain="beta.invalid",
        region="NA",
        confidence=ConfidenceLevel.HIGH,
        sources=("oidc", "userrealm", "dns", "cert_transparency"),
        services=("Google Workspace", "Microsoft 365", "DKIM (Google Workspace)", "Proofpoint"),
        slugs=("google-workspace", "microsoft365", "dkim", "proofpoint"),
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=4,
        related_domains=related,
        insights=insights,
        degraded_sources=("crt.sh",),
        evidence=(
            EvidenceRecord("MX", "10 aspmx.l.google.example", "Google Workspace", "google-workspace"),
            EvidenceRecord("DKIM", "google._domainkey.beta.invalid", "DKIM (Google Workspace)", "dkim"),
            EvidenceRecord("HTTP", "tenant_id=c7c08208-4f4d-45f1-83cd-5e2f491ab786", "OIDC Discovery", "microsoft365"),
            EvidenceRecord("HTTP", "NameSpaceType=Federated", "GetUserRealm", "microsoft365"),
        ),
        cert_summary=CertSummary(
            cert_count=42,
            issuer_diversity=3,
            issuance_velocity=7,
            newest_cert_age_days=2,
            oldest_cert_age_days=365,
            top_issuers=("Let's Encrypt", "DigiCert"),
        ),
        evidence_confidence=ConfidenceLevel.HIGH,
        inference_confidence=ConfidenceLevel.HIGH,
    )


def _panel_text(info: TenantInfo) -> str:
    console = Console(file=io.StringIO(), width=100, no_color=True, legacy_windows=False)
    console.print(render_tenant_panel(info))
    return _ANSI.sub("", console.file.getvalue())


# The stable claims every surface is measured against, with a probe that answers
# "is this claim present in this rendering". Kept deliberately loose (substring /
# key membership) so the matrix tracks presence, not wording.
_CLAIMS: tuple[tuple[str, str], ...] = (
    ("queried_domain", "beta.invalid"),
    ("mail", "Google Workspace"),
    ("identity", "Microsoft 365"),
    ("provider", "provider"),
    ("tenant_id", "c7c08208"),
    ("auth_type", "Federated"),
    ("confidence", "high"),
    ("dmarc_policy", "reject"),
    ("related_domains", "login.beta.invalid"),
    ("insights", "Email security"),
    ("fusion", "posterior"),
)


_MORE = re.compile(r"(\d+)\s+more")


def _present_text(claim: str, probe: str, text: str) -> bool:
    # Escape-agnostic: --md backslash-escapes punctuation, so match on the
    # unescaped text. Presence, not exact wording, is what the matrix tracks.
    low = text.replace("\\", "").lower()
    if claim == "provider":
        return "provider:" in low or "provider " in low
    if claim == "fusion":
        return "posterior_observations" in low
    return probe.lower() in low


def _present_json(claim: str, probe: str, payload: dict[str, object]) -> bool:
    # A predicate per claim, so the JSON columns track the same claims the text
    # columns do. Membership for the parked/optional keys (mail, identity,
    # provider), truthiness for the lists and posteriors, an exact match for the
    # queried domain.
    checks = {
        "mail": lambda: "mail" in payload,
        "identity": lambda: "identity" in payload,
        "provider": lambda: "provider" in payload,
        "confidence": lambda: "confidence" in payload,
        "fusion": lambda: bool(payload.get("posterior_observations")),
        "related_domains": lambda: bool(payload.get("related_domains")),
        "insights": lambda: bool(payload.get("insights")),
        "tenant_id": lambda: bool(payload.get("tenant_id")),
        "auth_type": lambda: bool(payload.get("auth_type")),
        "dmarc_policy": lambda: bool(payload.get("dmarc_policy")),
        "queried_domain": lambda: payload.get("queried_domain") == "beta.invalid",
    }
    check = checks.get(claim)
    return check() if check is not None else False


def _cut_reconciles(shown: int, note_more: int | None, full: int) -> str:
    """One cell: does shown + withheld equal the surface's own --full count."""
    if note_more is None:
        return "= (no cut)" if shown == full else f"! {shown}/{full}"
    return "ok" if shown + note_more == full else f"! {shown}+{note_more}!={full}"


def _count_block(text: str, key: str) -> int:
    out, started = 0, False
    for line in text.splitlines():
        if re.match(rf"^\s*{re.escape(key)}:\s*$", line):
            started = True
            continue
        if started:
            if re.match(r"^\s+- ", line):
                out += 1
            else:
                break
    return out


def _note_more(text: str, key: str) -> int | None:
    for line in text.splitlines():
        if line.strip().startswith(f"{key}:"):
            match = _MORE.search(line)
            if match:
                return int(match.group(1))
    return None


def _render() -> str:
    info = _fixture()
    fused = apply_fusion(info)

    panel = _panel_text(info)
    plain = format_tenant_plain(info)
    plain_full = format_tenant_plain(info, full=True)
    md = format_tenant_markdown(info)
    md_full = format_tenant_markdown(info, full=True)
    cli_json = json.loads(format_tenant_json(fused))
    mcp_text = _lookup_tenant_text(info)
    mcp_json = json.loads(_format_lookup_tenant(info, [], "json", explain=False))

    text_surfaces: dict[str, str] = {
        "panel": panel,
        "--plain": plain,
        "--plain --full": plain_full,
        "--md": md,
        "--md --full": md_full,
        "mcp text": mcp_text,
    }
    json_surfaces: dict[str, dict[str, object]] = {"--json": cli_json, "mcp json": mcp_json}
    columns = [*text_surfaces, *json_surfaces]

    lines: list[str] = []
    lines.append("# Surface parity matrix")
    lines.append("")
    lines.append(
        "Generated by `scripts/generate_surface_parity.py` from one maximal, "
        "deterministic, reserved-namespace record. Do not edit by hand; run the "
        "script. The `surface-parity` gate in `scripts/check.py` fails when a "
        "surface gains or loses a claim, or a cut stops reconciling, without this "
        "file moving in the same commit."
    )
    lines.append("")
    lines.append("`+` present, `-` absent, `n/a` not applicable to the surface.")
    lines.append("")

    header = "| claim | " + " | ".join(columns) + " |"
    sep = "|---|" + "|".join("---" for _ in columns) + "|"
    lines.append(header)
    lines.append(sep)
    for claim, probe in _CLAIMS:
        cells: list[str] = []
        for text in text_surfaces.values():
            cells.append("+" if _present_text(claim, probe, text) else "-")
        for payload in json_surfaces.values():
            cells.append("+" if _present_json(claim, probe, payload) else "-")
        lines.append(f"| {claim} | " + " | ".join(cells) + " |")
    lines.append("")

    # Reconcile section: for the cutting surfaces, shown + withheld == full.
    lines.append("## Cut reconciliation")
    lines.append("")
    lines.append(
        "Each cutting surface shows a high-signal selection and a note. Shown plus "
        "the note's remainder must equal what that surface's own `--full` prints."
    )
    lines.append("")
    lines.append("| list | --plain vs --plain --full | --md vs --md --full |")
    lines.append("|---|---|---|")
    rel_full_plain = _count_block(plain_full, "related_domains")
    ins_full_plain = _count_block(plain_full, "insights")
    rel_shown_plain = _count_block(plain, "related_domains")
    ins_shown_plain = _count_block(plain, "insights")
    lines.append(
        "| related_domains | "
        + _cut_reconciles(rel_shown_plain, _note_more(plain, "related_domains_note"), rel_full_plain)
        + " | "
        + _md_reconcile(md, md_full, "Related Domains", "--md --full")
        + " |"
    )
    lines.append(
        "| insights | "
        + _cut_reconciles(ins_shown_plain, _note_more(plain, "insights_note"), ins_full_plain)
        + " | "
        + _md_reconcile(md, md_full, "Insights", "--md --full")
        + " |"
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def _md_section_items(md: str, header: str) -> tuple[int, int | None]:
    """Return (bullet count excluding the note, note remainder) for an md section."""
    items = 0
    note_more: int | None = None
    started = False
    for line in md.splitlines():
        if line.strip() == f"## {header}":
            started = True
            continue
        if started:
            if line.startswith(("## ", "---")):
                break
            stripped = line.strip()
            if stripped.startswith("- *") and "more, use" in stripped:
                match = _MORE.search(stripped)
                note_more = int(match.group(1)) if match else None
            elif stripped.startswith("- "):
                items += 1
    return items, note_more


def _md_reconcile(md: str, md_full: str, header: str, _cmd: str) -> str:
    shown, note_more = _md_section_items(md, header)
    full, _ = _md_section_items(md_full, header)
    return _cut_reconciles(shown, note_more, full)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the cross-surface parity matrix.")
    parser.add_argument("--write", action="store_true", help="Write the parity file.")
    parser.add_argument("--check", action="store_true", help="Fail if the parity file is stale.")
    args = parser.parse_args(argv)

    rendered = _render()
    if args.check:
        if not _OUTPUT.exists():
            print(f"parity matrix is missing: {_OUTPUT}", file=sys.stderr)
            print("run: uv run python scripts/generate_surface_parity.py --write", file=sys.stderr)
            return 1
        if _OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"parity matrix is out of date: {_OUTPUT}", file=sys.stderr)
            print("run: uv run python scripts/generate_surface_parity.py --write", file=sys.stderr)
            return 1
        # A reconcile failure is a hard fail even if the file is current.
        if "!" in rendered:
            print("parity matrix carries a reconcile failure (see the '!' cells).", file=sys.stderr)
            return 1
        return 0
    if args.write:
        _OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wrote {_OUTPUT}")
        return 0
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
