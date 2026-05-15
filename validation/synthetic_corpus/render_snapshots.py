"""Render v1.9.9-panel snapshots for the synthetic corpus and the
v1.9.2 agentic-UX fixtures.

The agentic-UX harness at ``validation/agentic_ux/run.py`` requires
an LLM provider with an API key. This script does NOT call any LLM.
It only renders the panel through the v1.9.9 ``render_tenant_panel``
function and writes the rendered text to a markdown report.

The result is the operator-facing panel that an agent would read
when querying any of the fixtures via the MCP server. The maintainer
can then run the agentic-UX harness against this same set of fixtures
locally (with whatever API key they have) and compare the agent's
behaviour on the v1.9.9 panels to the v1.9.2 baseline.

Usage::

    python validation/synthetic_corpus/render_snapshots.py \\
        --output validation/synthetic_corpus/render_snapshots.md
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

from recon_tool.cache import tenant_info_from_dict  # noqa: E402
from recon_tool.formatter import render_tenant_panel  # noqa: E402


def _render(info) -> str:
    console = Console(no_color=True, record=True, width=120, file=io.StringIO())
    rendered = render_tenant_panel(info)
    console.print(rendered)
    return console.export_text()


def _fixture_paths() -> list[tuple[str, Path]]:
    """Find both the v1.9.2 agentic-UX fixtures and the synthetic
    corpus fixtures. Returns ``(label, path)`` pairs in a stable
    order: v1.9.2 fixtures first (they anchor the comparison),
    synthetic corpus fixtures alphabetical second."""
    pairs: list[tuple[str, Path]] = []
    agentic_dir = REPO_ROOT / "validation" / "agentic_ux" / "fixtures"
    for name in ("contoso-dense.json", "hardened-sparse.json"):
        path = agentic_dir / name
        if path.exists():
            pairs.append((f"v1.9.2: {path.stem}", path))

    synth_dir = REPO_ROOT / "validation" / "synthetic_corpus" / "fixtures"
    if synth_dir.exists():
        for path in sorted(synth_dir.glob("*.json")):
            pairs.append((f"synth: {path.stem}", path))

    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render v1.9.9 panel snapshots for all fixtures")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "validation" / "synthetic_corpus" / "render_snapshots.md",
    )
    args = parser.parse_args(argv)

    lines = [
        "# v1.9.9 panel render snapshots",
        "",
        "Renders each fixture through the v1.9.9 ``render_tenant_panel``",
        "function and captures the operator-facing output as plain",
        "text. The agentic-UX harness (``validation/agentic_ux/run.py``)",
        "can be pointed at these same fixtures to validate how an AI",
        "agent reads the v1.9.9 panel; this report is the panel-shape",
        "evidence that precedes the agent run.",
        "",
        "Look for:",
        "",
        "- ``Multi-cloud`` rows on multi-vendor fixtures.",
        "- ``Passive-DNS ceiling`` blocks on sparse multi-domain fixtures.",
        "- Per-vendor canonicalization (AWS-family collapses; Firebase",
        "  rolls under GCP; Replit / Glitch excluded).",
        "- No regression on pre-existing surfaces (Services, Confidence,",
        "  External surface).",
        "",
        "---",
        "",
    ]

    pairs = _fixture_paths()
    for label, path in pairs:
        data = json.loads(path.read_text(encoding="utf-8"))
        try:
            info = tenant_info_from_dict(data)
        except Exception as exc:
            lines.append(f"## {label}")
            lines.append("")
            lines.append(f"`{path.name}` failed to load: {exc}")
            lines.append("")
            continue

        rendered = _render(info)
        lines.append(f"## {label}")
        lines.append("")
        lines.append(f"Source: `{path.relative_to(REPO_ROOT).as_posix()}`")
        lines.append("")
        lines.append("```")
        lines.append(rendered.rstrip())
        lines.append("```")
        lines.append("")

        # Surface fire / suppress summary for at-a-glance scan
        mc = "fires" if "Multi-cloud" in rendered else "suppressed"
        ceiling = "fires" if "Passive-DNS ceiling" in rendered else "suppressed"
        lines.append(f"- Multi-cloud rollup: **{mc}**")
        lines.append(f"- Passive-DNS ceiling: **{ceiling}**")
        lines.append("")

    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.output} ({len(pairs)} fixtures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
