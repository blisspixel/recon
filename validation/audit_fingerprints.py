"""Audit multi-detection fingerprints for match-mode hardening.

Run from the repository root:
    python -m validation.audit_fingerprints --markdown-output validation/live_runs/<run>/fingerprint_audit.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from recon_tool.fingerprint_audit import (
    audit_multi_detection_fingerprints,
    format_fingerprint_audit_dict,
    render_fingerprint_audit_markdown,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit multi-detection fingerprints for match-mode decisions.")
    parser.add_argument("--json-output", type=Path, default=None, help="Optional path for JSON audit output.")
    parser.add_argument("--markdown-output", type=Path, default=None, help="Optional path for Markdown audit output.")
    args = parser.parse_args()

    entries = audit_multi_detection_fingerprints()
    json_payload = json.dumps(format_fingerprint_audit_dict(entries), indent=2)
    markdown = render_fingerprint_audit_markdown(entries)

    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json_payload, encoding="utf-8")
    if args.markdown_output is not None:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(markdown, encoding="utf-8")

    if args.json_output is None and args.markdown_output is None:
        print(markdown)
    else:
        if args.json_output is not None:
            print(f"wrote {args.json_output}")
        if args.markdown_output is not None:
            print(f"wrote {args.markdown_output}")


if __name__ == "__main__":
    main()
