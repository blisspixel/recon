#!/usr/bin/env python3
"""Generate the deterministic synthetic terminal image embedded in README."""

from __future__ import annotations

import argparse
import io
import re
from pathlib import Path

from rich.console import Console
from rich.text import Text

from recon_tool.constants import SVC_DKIM, SVC_DMARC, SVC_MTA_STS, SVC_SPF_STRICT
from recon_tool.formatter import render_tenant_panel
from recon_tool.models import ConfidenceLevel, EvidenceRecord, TenantInfo

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "docs" / "assets" / "terminal-demo.svg"
DEFAULT_README = ROOT / "README.md"
_TERMINAL_WIDTH = 82
_FONT_FACE = re.compile(r"    @font-face \{.*?    \}\n", re.DOTALL)
_TRANSCRIPT_START = "<!-- terminal-demo-transcript:start -->"
_TRANSCRIPT_END = "<!-- terminal-demo-transcript:end -->"


def demo_tenant_info() -> TenantInfo:
    """Return a realistic public-output fixture using only reserved names.

    Globex is an obviously fictional demo company (not a real customer).
    The queried coordinate stays under the IETF reserved ``.invalid``
    namespace so the fixture never names a real registrable domain.
    """
    return TenantInfo(
        tenant_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        display_name="Globex Ltd",
        default_domain="globex.onmicrosoft.invalid",
        queried_domain="globex.invalid",
        confidence=ConfidenceLevel.HIGH,
        region="NA",
        sources=("dns_records", "oidc_discovery", "userrealm", "cert_transparency"),
        services=(
            "Microsoft 365",
            "Proofpoint",
            SVC_DMARC,
            SVC_DKIM,
            SVC_SPF_STRICT,
            SVC_MTA_STS,
            "Okta",
            "Slack",
            "Atlassian (Jira/Confluence)",
            "Cloudflare",
            "AWS Route 53",
            "Wiz",
        ),
        slugs=(
            "microsoft365",
            "proofpoint",
            "dmarc",
            "dkim",
            "spf-strict",
            "mta-sts",
            "okta",
            "slack",
            "atlassian",
            "cloudflare",
            "aws-route53",
            "wiz",
        ),
        auth_type="Federated",
        dmarc_policy="reject",
        domain_count=3,
        tenant_domains=(
            "globex.invalid",
            "globex.onmicrosoft.invalid",
            "globex-mail.invalid",
        ),
        related_domains=(
            "login.globex.invalid",
            "status.globex.invalid",
            "support.globex.invalid",
        ),
        insights=(
            "Federated identity observed; identity-vendor indicators: Okta",
            "Email security: observed controls: DMARC reject, DKIM, SPF strict, MTA-STS",
            "MX gateway observed: Proofpoint",
        ),
        evidence=(
            EvidenceRecord(
                "MX",
                "10 globex-invalid.mail.protection.outlook.invalid",
                "Microsoft 365",
                "microsoft365",
            ),
            EvidenceRecord("MX", "20 mx.proofpoint.invalid", "Proofpoint", "proofpoint"),
            EvidenceRecord("DMARC", "v=DMARC1; p=reject; pct=100", SVC_DMARC, "dmarc"),
            EvidenceRecord(
                "DKIM",
                "selector1._domainkey.globex.invalid",
                SVC_DKIM,
                "dkim",
            ),
            EvidenceRecord("SPF", "v=spf1 include:mail.invalid -all", SVC_SPF_STRICT, "spf-strict"),
            EvidenceRecord("MTA_STS_POLICY", "mode: enforce", SVC_MTA_STS, "mta-sts-enforce"),
            EvidenceRecord("CNAME", "login.globex.invalid -> login.vendor.invalid", "Okta", "okta"),
            EvidenceRecord("TXT", "slack-domain-verification=synthetic", "Slack", "slack"),
            EvidenceRecord(
                "CNAME",
                "status.globex.invalid -> status.vendor.invalid",
                "Atlassian (Jira/Confluence)",
                "atlassian",
            ),
            EvidenceRecord(
                "CNAME",
                "support.globex.invalid -> edge.vendor.invalid",
                "Cloudflare",
                "cloudflare",
            ),
            EvidenceRecord("NS", "ns-001.dns.invalid", "AWS Route 53", "aws-route53"),
            EvidenceRecord("TXT", "wiz-domain-verification=synthetic", "Wiz", "wiz"),
        ),
        evidence_confidence=ConfidenceLevel.HIGH,
        inference_confidence=ConfidenceLevel.HIGH,
        detection_scores=(
            ("microsoft365", "high"),
            ("proofpoint", "high"),
            ("okta", "medium"),
            ("cloudflare", "medium"),
        ),
        mta_sts_mode="enforce",
        primary_email_provider="Microsoft 365",
        email_gateway="Proofpoint",
        dmarc_pct=100,
        ct_provider_used="crt.sh",
        ct_subdomain_count=18,
    )


def _render_demo(console: Console) -> None:
    """Write the fixed command and real default panel to one console."""
    prompt = Text("$ ", style="bold green")
    prompt.append("recon ", style="bold white")
    prompt.append("globex.invalid", style="bold cyan")
    console.print(prompt)
    console.print(render_tenant_panel(demo_tenant_info()))


def render_terminal_demo_text() -> str:
    """Render the accessible plain-text equivalent of the terminal image."""
    stream = io.StringIO()
    console = Console(file=stream, width=_TERMINAL_WIDTH, no_color=True, legacy_windows=False)
    _render_demo(console)
    return stream.getvalue()


def render_terminal_demo_svg() -> str:
    """Render the real default panel into a self-contained deterministic SVG."""
    stream = io.StringIO()
    console = Console(
        file=stream,
        width=_TERMINAL_WIDTH,
        record=True,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    _render_demo(console)
    svg = console.export_svg(title="recon synthetic demo", unique_id="recon-demo")
    svg = svg.replace("    <!-- Generated with Rich https://www.textualize.io -->\n", "")
    svg = _FONT_FACE.sub("", svg)
    svg = svg.replace(
        "font-family: Fira Code, monospace;",
        "font-family: ui-monospace, SFMono-Regular, Consolas, Liberation Mono, monospace;",
    )
    svg = svg.replace(
        '<svg class="rich-terminal"',
        '<svg class="rich-terminal" role="img" '
        'aria-labelledby="recon-demo-accessible-title recon-demo-accessible-description"',
        1,
    )
    svg = svg.replace(
        "    <style>\n",
        '    <title id="recon-demo-accessible-title">recon synthetic terminal demo</title>\n'
        '    <desc id="recon-demo-accessible-description">Synthetic output for Globex Ltd '
        "(globex.invalid) showing public email, identity, cloud, security, collaboration, "
        "related-domain, and insight observations.</desc>\n"
        "    <style>\n",
        1,
    )
    normalized = svg.replace("\r\n", "\n")
    return "\n".join(line.rstrip() for line in normalized.splitlines()) + "\n"


def _readme_with_current_transcript(readme: str) -> str:
    """Replace the single marked README transcript with current plain output."""
    if readme.count(_TRANSCRIPT_START) != 1 or readme.count(_TRANSCRIPT_END) != 1:
        raise ValueError("README must contain exactly one terminal demo transcript region")
    start = readme.index(_TRANSCRIPT_START)
    end = readme.index(_TRANSCRIPT_END, start) + len(_TRANSCRIPT_END)
    transcript = render_terminal_demo_text()
    replacement = (
        f"{_TRANSCRIPT_START}\n"
        "<details>\n"
        "<summary>Accessible text transcript</summary>\n\n"
        f"```text\n{transcript}```\n\n"
        "</details>\n"
        f"{_TRANSCRIPT_END}"
    )
    return readme[:start] + replacement + readme[end:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail when the committed image differs.")
    args = parser.parse_args(argv)

    expected = render_terminal_demo_svg()
    updates_default_asset = args.output.resolve() == DEFAULT_OUTPUT.resolve()
    readme_bytes = DEFAULT_README.read_bytes() if updates_default_asset else b""
    readme = readme_bytes.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    expected_readme = _readme_with_current_transcript(readme) if updates_default_asset else ""
    if args.check:
        stale_asset = not args.output.is_file() or args.output.read_bytes() != expected.encode("utf-8")
        stale_readme = updates_default_asset and readme_bytes != expected_readme.encode("utf-8")
        if stale_asset or stale_readme:
            stale = [str(args.output)] if stale_asset else []
            if stale_readme:
                stale.append(str(DEFAULT_README))
            print(f"FAIL: {', '.join(stale)} differs from the deterministic terminal demo.")
            return 1
        print(f"PASS: {args.output} and its README transcript are current.")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8", newline="\n")
    if updates_default_asset:
        DEFAULT_README.write_text(expected_readme, encoding="utf-8", newline="\n")
    print(f"Wrote {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
