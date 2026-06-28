#!/usr/bin/env python3
"""Generate aggregate-safe SVG figures for the external paper package."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from xml.sax.saxutils import escape

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "assets" / "paper"
NETWORK_PATH = ROOT / "src" / "recon_tool" / "data" / "bayesian_network.yaml"

NODE_ORDER = (
    "m365_tenant",
    "google_workspace_tenant",
    "federated_identity",
    "okta_idp",
    "email_gateway_present",
    "email_security_modern_provider",
    "email_security_policy_enforcing",
    "cdn_fronting",
    "aws_hosting",
)

FIGURE_NAMES = (
    "assurance-architecture.svg",
    "bayesian-dag.svg",
    "calibration-reliability.svg",
    "interval-width-vs-evidence.svg",
)

COLORS = {
    "ink": "#111827",
    "muted": "#4b5563",
    "grid": "#d1d5db",
    "panel": "#f8fafc",
    "blue": "#2563eb",
    "cyan": "#0891b2",
    "green": "#059669",
    "amber": "#d97706",
    "purple": "#7c3aed",
    "red": "#dc2626",
    "white": "#ffffff",
}

Point = tuple[float, float]
BoxSize = tuple[float, float]
ChartFrame = tuple[float, float, float, float]


def _tag(name: str, attrs: Mapping[str, object], content: str | None = None) -> str:
    rendered = " ".join(f'{key}="{escape(str(value))}"' for key, value in attrs.items())
    if content is None:
        return f"<{name} {rendered} />"
    return f"<{name} {rendered}>{content}</{name}>"


def _text(pos: Point, value: str, **style: object) -> str:
    x, y = pos
    attrs = {
        "x": round(x, 2),
        "y": round(y, 2),
        "font-family": "Inter, Segoe UI, Arial, sans-serif",
        "font-size": int(style.get("size", 16)),
        "font-weight": int(style.get("weight", 400)),
        "fill": str(style.get("fill", COLORS["ink"])),
        "text-anchor": str(style.get("anchor", "start")),
    }
    return _tag("text", attrs, escape(value))


def _rect(pos: Point, size: BoxSize, fill: str, stroke: str = COLORS["grid"]) -> str:
    x, y = pos
    width, height = size
    return _tag(
        "rect",
        {
            "x": round(x, 2),
            "y": round(y, 2),
            "width": round(width, 2),
            "height": round(height, 2),
            "rx": 8,
            "fill": fill,
            "stroke": stroke,
            "stroke-width": 1.2,
        },
    )


def _line(start: Point, end: Point, stroke: str, *, width: float = 2.0) -> str:
    x1, y1 = start
    x2, y2 = end
    return _tag(
        "line",
        {
            "x1": round(x1, 2),
            "y1": round(y1, 2),
            "x2": round(x2, 2),
            "y2": round(y2, 2),
            "stroke": stroke,
            "stroke-width": width,
            "stroke-linecap": "round",
        },
    )


def _circle(cx: float, cy: float, radius: float, fill: str, stroke: str = COLORS["white"]) -> str:
    return _tag(
        "circle",
        {
            "cx": round(cx, 2),
            "cy": round(cy, 2),
            "r": round(radius, 2),
            "fill": fill,
            "stroke": stroke,
            "stroke-width": 2,
        },
    )


def _svg(width: int, height: int, body: list[str], *, title: str) -> str:
    defs = """
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">
      <path d="M0,0 L10,4 L0,8 Z" fill="#4b5563" />
    </marker>
  </defs>""".strip()
    body_text = "\n  ".join([defs, *body])
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">\n'
        f"  <title id=\"title\">{escape(title)}</title>\n"
        "  <desc id=\"desc\">Aggregate-safe paper figure generated from committed recon artifacts.</desc>\n"
        f"  {_rect((0, 0), (width, height), COLORS['white'], COLORS['white'])}\n"
        f"  {body_text}\n"
        "</svg>\n"
    )


def _load_network() -> dict[str, dict[str, object]]:
    raw = yaml.safe_load(NETWORK_PATH.read_text(encoding="utf-8"))
    nodes = {str(node["name"]): dict(node) for node in raw["nodes"]}
    if set(nodes) != set(NODE_ORDER):
        missing = sorted(set(NODE_ORDER) - set(nodes))
        extra = sorted(set(nodes) - set(NODE_ORDER))
        raise RuntimeError(f"Bayesian network figure layout drifted: missing={missing}, extra={extra}")
    return nodes


def _wrap(lines: list[str], x: float, y: float, *, size: int = 14, step: int = 20) -> list[str]:
    return [_text((x, y + index * step), line, size=size, fill=COLORS["muted"]) for index, line in enumerate(lines)]


def render_assurance_architecture() -> str:
    body: list[str] = [_text((40, 45), "Figure 1. Assurance architecture and evidence tiers", size=24, weight=700)]
    stages = [
        ("Public observations", ["DNS, CT, identity endpoints", "No credentials or active scan"], COLORS["blue"]),
        ("Evidence DAG", ["Records to slugs to rules", "Every conclusion traceable"], COLORS["cyan"]),
        ("Nine-node inference", ["Exact variable elimination", "Intervals widen on sparse evidence"], COLORS["purple"]),
        ("Hedged output", ["Observation, not verdict", "Sparse means cannot tell"], COLORS["green"]),
    ]
    x = 40
    for index, (title, lines, color) in enumerate(stages):
        body.append(_rect((x, 90), (210, 125), COLORS["panel"], color))
        body.append(_text((x + 18, 122), title, size=17, weight=700, fill=color))
        body.extend(_wrap(lines, x + 18, 152, size=13, step=18))
        if index < len(stages) - 1:
            body.append(
                _tag(
                    "line",
                    {
                        "x1": x + 214,
                        "y1": 152,
                        "x2": x + 260,
                        "y2": 152,
                        "stroke": COLORS["muted"],
                        "stroke-width": 2.2,
                        "marker-end": "url(#arrow)",
                    },
                )
            )
        x += 260

    tiers = [
        ("Provider attested", "M365 channel split, GWS one-sided", COLORS["blue"]),
        ("Public declaration", "DMARC policy consistency plus residual negative", COLORS["green"]),
        ("Hideable", "Structural guarantees only", COLORS["amber"]),
    ]
    body.append(_text((40, 280), "Validation tiering by who controls the evidence", size=19, weight=700))
    for index, (title, detail, color) in enumerate(tiers):
        y = 315 + index * 78
        body.append(_rect((60, y), (900, 52), COLORS["white"], color))
        body.append(_text((82, y + 33), title, size=16, weight=700, fill=color))
        body.append(_text((300, y + 33), detail, size=15, fill=COLORS["ink"]))
    body.extend(
        _wrap(
            [
                "Publication boundary: public and synthetic proof rows are reproducible by reviewers.",
                "Private-corpus rows are committed only as aggregate memos with small-cell suppression.",
            ],
            60,
            585,
            size=14,
        )
    )
    return _svg(1080, 650, body, title="Assurance architecture")


def _node_color(name: str) -> str:
    if name in {"m365_tenant", "google_workspace_tenant"}:
        return COLORS["blue"]
    if name == "email_security_policy_enforcing":
        return COLORS["green"]
    if name == "email_security_modern_provider":
        return COLORS["purple"]
    return COLORS["amber"]


def render_bayesian_dag() -> str:
    nodes = _load_network()
    positions = {
        "m365_tenant": (90, 110),
        "google_workspace_tenant": (330, 110),
        "federated_identity": (210, 255),
        "okta_idp": (210, 410),
        "email_gateway_present": (570, 110),
        "email_security_modern_provider": (450, 310),
        "email_security_policy_enforcing": (780, 110),
        "cdn_fronting": (800, 300),
        "aws_hosting": (800, 455),
    }
    labels = {
        "m365_tenant": "M365 tenant",
        "google_workspace_tenant": "Google Workspace",
        "federated_identity": "Federated identity",
        "okta_idp": "Okta IdP",
        "email_gateway_present": "Email gateway",
        "email_security_modern_provider": "Modern mail provider",
        "email_security_policy_enforcing": "Enforcing mail policy",
        "cdn_fronting": "CDN fronting",
        "aws_hosting": "AWS hosting",
    }
    body = [_text((40, 45), "Figure 2. Nine-node Bayesian network", size=24, weight=700)]
    for child, node in nodes.items():
        for parent in node.get("parents", []):
            px, py = positions[str(parent)]
            cx, cy = positions[child]
            body.append(
                _tag(
                    "line",
                    {
                        "x1": px + 80,
                        "y1": py + 32,
                        "x2": cx + 80,
                        "y2": cy - 6,
                        "stroke": COLORS["muted"],
                        "stroke-width": 2,
                        "marker-end": "url(#arrow)",
                    },
                )
            )
    for name in NODE_ORDER:
        x, y = positions[name]
        color = _node_color(name)
        body.append(_rect((x, y), (170, 64), COLORS["panel"], color))
        body.append(_text((x + 85, y + 38), labels[name], size=14, weight=700, fill=color, anchor="middle"))
    legend = [
        ("Provider attested", COLORS["blue"]),
        ("Public declaration", COLORS["green"]),
        ("Hideable or operator controlled", COLORS["amber"]),
        ("Derived provider claim", COLORS["purple"]),
    ]
    for index, (label, color) in enumerate(legend):
        x = 70 + index * 245
        body.append(_rect((x, 545), (20, 20), color, color))
        body.append(_text((x + 30, 562), label, size=13, fill=COLORS["muted"]))
    return _svg(1010, 600, body, title="Bayesian DAG")


def _chart_xy(point: Point, frame: ChartFrame) -> tuple[float, float]:
    x, y = point
    left, top, width, height = frame
    return left + x * width, top + (1.0 - y) * height


def render_calibration_reliability() -> str:
    left, top, width, height = 90.0, 95.0, 520.0, 390.0
    frame = (left, top, width, height)
    body = [_text((40, 45), "Figure 3. Public-list reliability bins with posterior histogram", size=24, weight=700)]
    for tick in range(6):
        value = tick / 5
        x, y = _chart_xy((value, value), frame)
        body.append(_line((left, y), (left + width, y), COLORS["grid"], width=1))
        body.append(_line((x, top), (x, top + height), COLORS["grid"], width=1))
        body.append(_text((left - 18, y + 5), f"{value:.1f}", size=12, fill=COLORS["muted"], anchor="end"))
        body.append(_text((x, top + height + 26), f"{value:.1f}", size=12, fill=COLORS["muted"], anchor="middle"))
    body.append(_line((left, top + height), (left + width, top + height), COLORS["ink"], width=1.8))
    body.append(_line((left, top), (left, top + height), COLORS["ink"], width=1.8))
    x0, y0 = _chart_xy((0.0, 0.0), frame)
    x1, y1 = _chart_xy((1.0, 1.0), frame)
    body.append(
        _tag(
            "line",
            {
                "x1": x0,
                "y1": y0,
                "x2": x1,
                "y2": y1,
                "stroke": "#6b7280",
                "stroke-dasharray": "6 5",
                "stroke-width": 1.6,
            },
        )
    )

    series = [
        ("DMARC public-list bins", COLORS["green"], [(0.05, 0.0, 78), (0.85, 1.0, 88), (0.95, 1.0, 399)]),
        (
            "M365 DNS-only bins",
            COLORS["purple"],
            [(0.25, 0.611, 18), (0.25, 0.667, 27), (0.95, 0.995, 186), (0.95, 0.993, 145)],
        ),
    ]
    for _label, color, points in series:
        for predicted, observed, count in points:
            cx, cy = _chart_xy((predicted, observed), frame)
            radius = min(18, 5 + count**0.5 / 2.0)
            body.append(_circle(cx, cy, radius, color))
            body.append(_text((cx, cy - radius - 7), f"n={count}", size=11, fill=color, anchor="middle"))
            bar_height = min(86, count / 4.6)
            body.append(_rect((cx - 10, top + height + 55 - bar_height), (20, bar_height), color, color))

    body.append(_text((left + width / 2, top + height + 52), "Predicted posterior bin", size=14, anchor="middle"))
    body.append(_text((18, top + height / 2), "Observed rate", size=14, anchor="middle"))
    body.append(_text((690, 135), "Source data", size=18, weight=700))
    body.extend(
        _wrap(
            [
                "Public-list aggregates only.",
                "Circle and bar size show posterior-bin count.",
                "DMARC bins pool Lists A, B, and C.",
                "M365 bins show the published A and B low and high bins.",
                "Diagonal line is perfect reliability.",
            ],
            690,
            170,
            size=14,
            step=24,
        )
    )
    body.append(_rect((690, 330), (22, 22), COLORS["green"], COLORS["green"]))
    body.append(_text((724, 347), "DMARC full posterior", size=14))
    body.append(_rect((690, 365), (22, 22), COLORS["purple"], COLORS["purple"]))
    body.append(_text((724, 382), "M365 DNS-only predictor", size=14))
    return _svg(980, 610, body, title="Calibration reliability bins")


def render_interval_width() -> str:
    body = [_text((40, 45), "Figure 4. Interval width falls as effective evidence rises", size=24, weight=700)]
    left, top, width, height = 95.0, 95.0, 650.0, 380.0
    buckets = ["ceiling", "5-6", "7-9"]
    grouped = [0.552, 0.193, 0.050]
    ungrouped = [0.452, 0.175, None]
    max_y = 0.60
    for tick in range(5):
        value = tick * 0.15
        y = top + height - (value / max_y) * height
        body.append(_line((left, y), (left + width, y), COLORS["grid"], width=1))
        body.append(_text((left - 16, y + 5), f"{value:.2f}", size=12, fill=COLORS["muted"], anchor="end"))
    body.append(_line((left, top + height), (left + width, top + height), COLORS["ink"], width=1.8))
    body.append(_line((left, top), (left, top + height), COLORS["ink"], width=1.8))

    def point(index: int, value: float) -> tuple[float, float]:
        x = left + 90 + index * 230
        y = top + height - (value / max_y) * height
        return x, y

    grouped_points = [point(index, value) for index, value in enumerate(grouped)]
    ungrouped_points = [point(index, value) for index, value in enumerate(ungrouped) if value is not None]
    for start, end in pairwise(grouped_points):
        body.append(_line(start, end, COLORS["blue"], width=2.8))
    for start, end in pairwise(ungrouped_points):
        body.append(_line(start, end, COLORS["amber"], width=2.8))
    for index, value in enumerate(grouped):
        x, y = point(index, value)
        body.append(_circle(x, y, 9, COLORS["blue"]))
        body.append(_text((x, y - 16), f"{value:.3f}", size=12, fill=COLORS["blue"], anchor="middle"))
    for index, value in enumerate(ungrouped):
        if value is None:
            continue
        x, y = point(index, value)
        body.append(_circle(x, y, 9, COLORS["amber"]))
        body.append(_text((x, y + 28), f"{value:.3f}", size=12, fill=COLORS["amber"], anchor="middle"))
    for index, label in enumerate(buckets):
        x = left + 90 + index * 230
        body.append(_text((x, top + height + 32), label, size=14, anchor="middle"))
    body.append(_text((left + width / 2, top + height + 62), "Effective evidence bucket", size=14, anchor="middle"))
    body.append(_text((28, top + height / 2), "Mean 80% interval width", size=14, anchor="middle"))
    body.append(_rect((805, 145), (22, 22), COLORS["blue"], COLORS["blue"]))
    body.append(_text((840, 162), "Grouped nodes", size=14))
    body.append(_rect((805, 180), (22, 22), COLORS["amber"], COLORS["amber"]))
    body.append(_text((840, 197), "Ungrouped nodes", size=14))
    body.extend(
        _wrap(
            [
                "Values are means across public Lists A, B, and C.",
                "Grouped nodes stay wider at matched low evidence.",
                "The 7-9 ungrouped bucket is empty in the public lists.",
            ],
            805,
            245,
            size=14,
            step=24,
        )
    )
    return _svg(1060, 590, body, title="Interval width vs effective evidence")


def build_assets() -> dict[str, str]:
    return {
        "assurance-architecture.svg": render_assurance_architecture(),
        "bayesian-dag.svg": render_bayesian_dag(),
        "calibration-reliability.svg": render_calibration_reliability(),
        "interval-width-vs-evidence.svg": render_interval_width(),
    }


def write_assets(output_dir: Path, *, check: bool) -> int:
    assets = build_assets()
    output_dir.mkdir(parents=True, exist_ok=True)
    mismatches: list[str] = []
    for name, content in assets.items():
        path = output_dir / name
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                mismatches.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(content, encoding="utf-8")
    if mismatches:
        print("Paper figure assets are stale:")
        for path in mismatches:
            print(f"  {path}")
        print("Regenerate with: uv run python scripts/generate_paper_figures.py")
        return 1
    if not check:
        print(f"Wrote {len(assets)} paper figure assets to {output_dir.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUT_DIR)
    parser.add_argument("--check", action="store_true", help="Fail if committed assets differ from generated SVGs.")
    args = parser.parse_args(argv)
    output_dir = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    return write_assets(output_dir, check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
