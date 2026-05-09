"""LLM-assisted triage of candidates.json into proposed surface.yaml stanzas.

Reads a ``candidates.json`` produced by ``triage_candidates.py``, sends
the entries to an Anthropic chat model in a single batched call along
with the project's triage rubric, and parses the structured response
into:

  * a markdown triage report (verdict per candidate, kept local because
    the report includes the original sample subdomains, which may name
    real companies);
  * a proposed YAML diff for ``recon_tool/data/fingerprints/surface.yaml``
    containing only generic patterns + slug + display name (safe to
    commit per the no-real-company-data invariant).

Usage::

    python validation/triage_llm.py \\
        --candidates validation/runs-private/<stamp>/candidates.json \\
        --report     validation/runs-private/<stamp>/triage-llm.md \\
        --yaml       validation/runs-private/<stamp>/proposed-stanzas.yaml \\
        --model      claude-sonnet-4-6

The script is dev-only and is not exercised by ``recon`` itself. End
users do not need an LLM API key for any recon CLI surface.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_RUBRIC_PATH = (
    REPO_ROOT / "agents" / "claude-code" / "skills" / "recon-fingerprint-triage" / "SKILL.md"
)
FINGERPRINTS_DIR = REPO_ROOT / "recon_tool" / "data" / "fingerprints"


def _load_existing_slugs() -> dict[str, str]:
    """Return slug -> display name from every committed fingerprint YAML."""
    slugs: dict[str, str] = {}
    for path in FINGERPRINTS_DIR.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        current_name: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- name:"):
                current_name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("slug:") and current_name is not None:
                slug = stripped.split(":", 1)[1].strip()
                slugs.setdefault(slug, current_name)
    return slugs


def _build_system_prompt(existing_slugs: dict[str, str]) -> str:
    rubric = SKILL_RUBRIC_PATH.read_text(encoding="utf-8")
    slug_lines = "\n".join(f"- {slug}: {name}" for slug, name in sorted(existing_slugs.items()))
    return (
        "You are the recon-fingerprint-triage skill, applied programmatically.\n\n"
        "Below is the full triage skill specification. Apply its rubric to every "
        "candidate the user sends you. **Output a single JSON document only**, "
        "no prose, no code fence, with this top-level shape:\n\n"
        "{\n"
        '  "triage": [\n'
        '    {\n'
        '      "suffix": "<the candidate suffix verbatim>",\n'
        '      "verdict": "real_saas" | "infrastructure" | "intra_org" | "niche" '
        '| "unclear" | "already_covered",\n'
        '      "reason": "<one sentence>",\n'
        '      "stanza": null | { "name": "...", "slug": "...", "category": "...", '
        '"pattern": "...", "tier": "application" | "infrastructure", '
        '"description": "...", "reference": null | "https://..." },\n'
        '      "category_mapping": null | "<formatter category if new slug>"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "1. Emit exactly one entry per input suffix; preserve the verbatim suffix.\n"
        "2. `stanza` is null whenever `verdict` is intra_org / niche / unclear / already_covered.\n"
        "3. If `verdict` is real_saas or infrastructure, `stanza` MUST be populated.\n"
        "4. `slug` MUST be lowercase-kebab and unique. If the candidate maps to an "
        "existing slug listed below, reuse the slug AND the existing display name verbatim.\n"
        "5. `pattern` is the most specific substring uniquely identifying the service. "
        "Avoid over-broad patterns like `amazonaws.com`. Prefer service-specific subzones.\n"
        "6. `category` is one of: Email & Communication, Identity, Infrastructure, "
        "Security, Productivity & Collaboration, Marketing, Business Apps, Commerce, "
        "AI & Generative.\n"
        "7. `category_mapping` is the formatter._CATEGORY_BY_SLUG bucket "
        "(Email | Identity | Cloud | Security | AI | Collaboration | Business Apps). "
        "Set it ONLY when proposing a new slug. Reuse existing-slug mappings.\n"
        "8. Niche / one-off / unclear candidates: `verdict` set, `stanza` null, "
        "explain in `reason` for human review.\n"
        "9. Be conservative: when in doubt, mark `unclear`, do not invent a slug.\n\n"
        "EXISTING SLUGS (do not duplicate; reuse name verbatim if the candidate maps "
        f"to one):\n{slug_lines}\n\n"
        "TRIAGE SKILL RUBRIC (full specification follows):\n\n"
        f"{rubric}\n"
    )


def _build_user_prompt(candidates: list[dict[str, Any]]) -> str:
    body = json.dumps(candidates, indent=2, ensure_ascii=False)
    return (
        "Triage these candidates against the rubric in your system prompt. "
        f"There are {len(candidates)} candidates. Output JSON only, exactly one "
        "entry per suffix.\n\n"
        f"```json\n{body}\n```"
    )


def _call_model(
    system: str,
    user: str,
    *,
    model: str,
    api_key: str,
    max_tokens: int,
) -> dict[str, Any]:
    import anthropic  # type: ignore[import-not-found]

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        max_tokens=max_tokens,
    )
    text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
    usage = response.usage
    in_tok = int(getattr(usage, "input_tokens", 0))
    out_tok = int(getattr(usage, "output_tokens", 0))
    # Anthropic Sonnet 4.6 list price: $3 / $15 per Mtok
    cost = (in_tok * 3.0 + out_tok * 15.0) / 1_000_000
    print(
        f"  call complete: {in_tok:,} in / {out_tok:,} out — cost ${cost:.4f}",
        file=sys.stderr,
    )
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
    return json.loads(cleaned)


def _format_yaml(entries: list[dict[str, Any]]) -> str:
    """Render proposed stanzas in surface.yaml-compatible YAML."""
    lines: list[str] = [
        "# v1.9.x catalog growth: LLM-triaged candidates from the v1.9.2-pre-release scan.",
        "# Generated by validation/triage_llm.py; reviewed by hand before merge.",
        "",
    ]
    seen_slugs: set[str] = set()
    for entry in entries:
        if not entry.get("stanza"):
            continue
        s = entry["stanza"]
        slug = s["slug"]
        if slug in seen_slugs:
            # multiple candidates rolled into the same slug — emit a continuation
            # detection only.
            lines.append("  # additional pattern for the existing stanza above (same slug):")
            lines.append(f"  # - cname_target pattern: {s['pattern']}")
            continue
        seen_slugs.add(slug)
        lines.append(f"- name: {s['name']}")
        lines.append(f"  slug: {slug}")
        lines.append(f"  category: {s['category']}")
        lines.append("  confidence: high")
        lines.append("  detections:")
        lines.append("  - type: cname_target")
        lines.append(f"    pattern: {s['pattern']}")
        lines.append(f"    tier: {s['tier']}")
        desc = s.get("description") or "(add description)"
        lines.append(f"    description: {desc}")
        ref = s.get("reference")
        if ref:
            lines.append(f"    reference: {ref}")
        lines.append("")
    return "\n".join(lines)


def _format_report(entries: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> str:
    by_suffix = {c["suffix"]: c for c in candidates}
    lines: list[str] = []
    lines.append("# LLM-triage report")
    lines.append("")
    lines.append(f"Total candidates: **{len(entries)}**")
    verdicts = sorted({e.get("verdict", "?") for e in entries})
    counts = {v: sum(1 for e in entries if e.get("verdict") == v) for v in verdicts}
    for v in verdicts:
        lines.append(f"- {v}: {counts[v]}")
    lines.append("")
    lines.append("## Per-candidate verdicts")
    lines.append("")
    lines.append("| Suffix | Count | Verdict | Slug | Reason |")
    lines.append("|---|---|---|---|---|")
    entries_sorted = sorted(entries, key=lambda e: -by_suffix.get(e["suffix"], {}).get("count", 0))
    for entry in entries_sorted:
        suffix = entry["suffix"]
        count = by_suffix.get(suffix, {}).get("count", "?")
        verdict = entry.get("verdict", "?")
        slug = (entry.get("stanza") or {}).get("slug", "—")
        reason = (entry.get("reason") or "").replace("|", "\\|")
        lines.append(f"| `{suffix}` | {count} | {verdict} | {slug} | {reason} |")
    lines.append("")
    lines.append("## New formatter category mappings")
    lines.append("")
    cats: dict[str, str] = {}
    for entry in entries:
        slug = (entry.get("stanza") or {}).get("slug")
        cm = entry.get("category_mapping")
        if slug and cm:
            cats.setdefault(slug, cm)
    if cats:
        lines.append("```python")
        for slug, cat in sorted(cats.items()):
            lines.append(f'    "{slug}": "{cat}",')
        lines.append("```")
    else:
        lines.append("(none)")
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--yaml", required=True, type=Path, dest="yaml_path")
    parser.add_argument("--raw", type=Path, default=None, help="Optional path to also dump raw LLM JSON.")
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--max-tokens", type=int, default=20_000)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args(argv)

    candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
    print(f"Loaded {len(candidates)} candidates from {args.candidates}", file=sys.stderr)

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("error: ANTHROPIC_API_KEY not set and --api-key not given", file=sys.stderr)
        return 2

    existing = _load_existing_slugs()
    print(f"Existing catalog: {len(existing)} slugs", file=sys.stderr)

    system = _build_system_prompt(existing)
    user = _build_user_prompt(candidates)

    print(f"Calling {args.model}...", file=sys.stderr)
    payload = _call_model(
        system,
        user,
        model=args.model,
        api_key=api_key,
        max_tokens=args.max_tokens,
    )

    entries = payload.get("triage", [])
    if len(entries) != len(candidates):
        print(
            f"warning: model returned {len(entries)} entries for {len(candidates)} candidates",
            file=sys.stderr,
        )

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(_format_report(entries, candidates), encoding="utf-8")
    args.yaml_path.parent.mkdir(parents=True, exist_ok=True)
    args.yaml_path.write_text(_format_yaml(entries), encoding="utf-8")
    if args.raw:
        args.raw.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"wrote {args.report}", file=sys.stderr)
    print(f"wrote {args.yaml_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
