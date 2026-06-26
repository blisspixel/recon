#!/usr/bin/env python3
"""Generate the published JSON Schema from code-owned schema metadata.

The top-level contract has two code-owned inputs:

* ``REQUIRED_TOP_LEVEL_FIELDS`` in ``recon_tool.schema_contract``.
* The explicit conditional fields below, which are emitted only in certain
  modes or behind opt-in flags.

The existing schema file remains the source for human-written descriptions,
constraints, and nested ``$defs`` fragments. This script rebuilds the schema
from those fragments plus the code-owned field sets, then prints, writes, or
checks both published copies.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from recon_tool.schema_contract import REQUIRED_TOP_LEVEL_FIELDS

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from check_schema_sources import audit_schema_sources, tenant_info_fields  # noqa: E402

_DOCS_SCHEMA = _ROOT / "docs" / "recon-schema.json"
_PACKAGED_SCHEMA = _ROOT / "src" / "recon_tool" / "data" / "recon-schema.json"

# Top-level properties that are intentionally conditional or mode-specific.
# Required fields come from recon_tool.schema_contract.
CONDITIONAL_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "ct_provider_used",
    "ct_cache_age_days",
    "ct_attempt_outcome",
    "evidence",
    "explanation_dag",
    "shared_display_name",
    "shared_tenant",
    "shared_verification_tokens",
    "unclassified_cname_chains",
)


def generated_top_level_fields() -> tuple[str, ...]:
    """Return the generated top-level schema property names."""
    fields = (*REQUIRED_TOP_LEVEL_FIELDS, *CONDITIONAL_TOP_LEVEL_FIELDS)
    if len(fields) != len(set(fields)):
        raise ValueError("generated top-level schema fields contain duplicates")
    return fields


def load_schema(path: Path) -> dict[str, Any]:
    """Load a schema object from ``path``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _properties(schema: Mapping[str, Any]) -> Mapping[str, Any]:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("schema properties must be an object")
    return properties


def _ordered_required(template: Mapping[str, Any]) -> list[str]:
    required = template.get("required")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise ValueError("schema required must be a string array")
    required_set = frozenset(REQUIRED_TOP_LEVEL_FIELDS)
    template_set = frozenset(required)
    missing_required = tuple(field for field in REQUIRED_TOP_LEVEL_FIELDS if field not in template_set)
    stale_required = tuple(sorted(template_set - required_set))
    if stale_required:
        raise ValueError(f"stale required fields: {', '.join(stale_required)}")
    return [field for field in required if field in required_set] + list(missing_required)


def build_schema(template: Mapping[str, Any]) -> dict[str, Any]:
    """Build the generated schema from a template schema's detailed fragments."""
    template_properties = _properties(template)
    generated_fields = generated_top_level_fields()
    generated_set = frozenset(generated_fields)
    template_set = frozenset(str(key) for key in template_properties)

    missing_fragments = tuple(sorted(generated_set - template_set))
    stale_fragments = tuple(sorted(template_set - generated_set))
    if missing_fragments or stale_fragments:
        details = []
        if missing_fragments:
            details.append(f"missing property fragments: {', '.join(missing_fragments)}")
        if stale_fragments:
            details.append(f"stale property fragments: {', '.join(stale_fragments)}")
        raise ValueError("; ".join(details))

    audit = audit_schema_sources(generated_fields, tenant_info_fields())
    if not audit.ok:
        details = []
        if audit.untraced_schema_properties:
            details.append(f"untraced properties: {', '.join(audit.untraced_schema_properties)}")
        if audit.stale_special_sources:
            details.append(f"stale special sources: {', '.join(audit.stale_special_sources)}")
        if audit.unrepresented_tenant_fields:
            details.append(f"unrepresented TenantInfo fields: {', '.join(audit.unrepresented_tenant_fields)}")
        raise ValueError("; ".join(details))

    generated = dict(template)
    generated["required"] = _ordered_required(template)
    generated["properties"] = {str(key): template_properties[key] for key in template_properties}
    return generated


def dumps_schema(schema: Mapping[str, Any]) -> str:
    """Return the canonical serialized schema form."""
    return json.dumps(schema, indent=2, ensure_ascii=True) + "\n"


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(_ROOT))
    except ValueError:
        return str(path)


def _check_target(path: Path, generated_text: str) -> bool:
    current = load_schema(path)
    generated = json.loads(generated_text)
    if current == generated:
        print(f"PASS {_display_path(path)} is current.")
        return True
    print(f"FAIL {_display_path(path)} is stale; run scripts/generate_schema.py.", file=sys.stderr)
    return False


def _write_if_changed(path: Path, generated_text: str) -> bool:
    if path.read_text(encoding="utf-8") == generated_text:
        print(f"{_display_path(path)} already current.")
        return False
    path.write_text(generated_text, encoding="utf-8")
    print(f"Updated {_display_path(path)}.")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/recon-schema.json from code-owned metadata.")
    parser.add_argument("--schema", type=Path, default=_DOCS_SCHEMA, help="Template and docs schema path.")
    parser.add_argument(
        "--packaged-schema",
        type=Path,
        default=_PACKAGED_SCHEMA,
        help="Packaged schema copy to write or check.",
    )
    parser.add_argument("--check", action="store_true", help="Fail if either schema copy is stale.")
    parser.add_argument("--write", action="store_true", help="Write both schema copies.")
    parser.add_argument("--stdout", action="store_true", help="Print the generated schema instead of writing files.")
    args = parser.parse_args(argv)

    selected_modes = sum((args.check, args.write, args.stdout))
    if selected_modes > 1:
        parser.error("--check, --write, and --stdout are mutually exclusive")

    generated = build_schema(load_schema(args.schema))
    generated_text = dumps_schema(generated)

    if args.stdout or selected_modes == 0:
        print(generated_text, end="")
        return 0
    if args.check:
        docs_ok = _check_target(args.schema, generated_text)
        packaged_ok = _check_target(args.packaged_schema, generated_text)
        return 0 if docs_ok and packaged_ok else 1
    changed = _write_if_changed(args.schema, generated_text)
    changed = _write_if_changed(args.packaged_schema, generated_text) or changed
    if not changed:
        print("Schema files already current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
