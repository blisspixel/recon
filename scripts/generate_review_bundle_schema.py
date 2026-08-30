#!/usr/bin/env python3
"""Generate and verify the self-contained ReviewBundle v1 JSON Schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from recon_tool.review_bundle_schema import build_review_bundle_schema  # noqa: E402

_LOOKUP_SCHEMA = _ROOT / "docs" / "recon-schema.json"
_DOCS_SCHEMA = _ROOT / "docs" / "review-bundle-schema.json"
_PACKAGED_SCHEMA = _ROOT / "src" / "recon_tool" / "data" / "review-bundle-schema.json"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def render_schema(lookup_schema_path: Path = _LOOKUP_SCHEMA) -> str:
    """Return canonical generated schema text using the current lookup schema."""
    schema = build_review_bundle_schema(_load_object(lookup_schema_path))
    return json.dumps(schema, indent=2, ensure_ascii=True) + "\n"


def _write_if_changed(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def _check(path: Path, expected: str) -> bool:
    try:
        display = path.relative_to(_ROOT)
    except ValueError:
        display = path
    if not path.exists():
        print(f"missing generated ReviewBundle schema: {display}", file=sys.stderr)
        return False
    if path.read_text(encoding="utf-8") != expected:
        print(
            f"generated ReviewBundle schema is stale: {display}; "
            "run python scripts/generate_review_bundle_schema.py --write",
            file=sys.stderr,
        )
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Fail if either generated copy has drifted.")
    mode.add_argument("--write", action="store_true", help="Write both generated schema copies.")
    mode.add_argument("--stdout", action="store_true", help="Print the generated schema.")
    parser.add_argument("--lookup-schema", type=Path, default=_LOOKUP_SCHEMA)
    parser.add_argument("--docs-schema", type=Path, default=_DOCS_SCHEMA)
    parser.add_argument("--packaged-schema", type=Path, default=_PACKAGED_SCHEMA)
    args = parser.parse_args(argv)

    rendered = render_schema(args.lookup_schema)
    if args.stdout:
        print(rendered, end="")
        return 0
    if args.write:
        changed = [path for path in (args.docs_schema, args.packaged_schema) if _write_if_changed(path, rendered)]
        for path in changed:
            try:
                display = path.relative_to(_ROOT)
            except ValueError:
                display = path
            print(f"wrote {display}")
        if not changed:
            print("ReviewBundle schema copies are current")
        return 0
    return 0 if all(_check(path, rendered) for path in (args.docs_schema, args.packaged_schema)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
