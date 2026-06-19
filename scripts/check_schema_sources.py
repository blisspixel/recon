#!/usr/bin/env python3
"""Check that every top-level JSON Schema field has an implementation source."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path

from recon_tool.models import TenantInfo

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "docs" / "recon-schema.json"

SPECIAL_SCHEMA_SOURCES: Mapping[str, str] = {
    "email_security_score": "formatter-derived email control count",
    "evidence_conflicts": "formatter serialization of TenantInfo.merge_conflicts",
    "explanation_dag": "explain-mode extension",
    "fingerprint_metadata": "formatter-derived relationship metadata from detected slugs",
    "fusion_enabled": "formatter-derived posterior-observation envelope flag",
    "partial": "formatter-derived core-source degradation flag",
    "provider": "formatter-derived provider summary",
    "record_type": "static formatter envelope discriminator",
    "schema_version": "static formatter envelope version",
    "shared_display_name": "batch-mode extension",
    "shared_tenant": "batch-mode extension",
}

INTENTIONAL_TENANTINFO_OMISSIONS: Mapping[str, str] = {
    "cached_at": "cache metadata, not emitted by the lookup JSON formatter",
    "merge_conflicts": "serialized as top-level evidence_conflicts",
    "resolved_at": "cache metadata, not emitted by the lookup JSON formatter",
}


@dataclass(frozen=True)
class SchemaSourceAudit:
    """Result of comparing schema properties with implementation sources."""

    schema_property_count: int
    tenant_field_count: int
    untraced_schema_properties: tuple[str, ...]
    stale_special_sources: tuple[str, ...]
    unrepresented_tenant_fields: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (
            self.untraced_schema_properties or self.stale_special_sources or self.unrepresented_tenant_fields
        )


def load_schema_properties(path: Path = _SCHEMA_PATH) -> frozenset[str]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("schema properties must be an object")
    return frozenset(str(key) for key in properties)


def tenant_info_fields() -> frozenset[str]:
    return frozenset(field.name for field in fields(TenantInfo))


def audit_schema_sources(
    schema_properties: Iterable[str],
    tenant_fields: Iterable[str],
) -> SchemaSourceAudit:
    schema_set = frozenset(schema_properties)
    tenant_set = frozenset(tenant_fields)
    special_set = frozenset(SPECIAL_SCHEMA_SOURCES)
    omission_set = frozenset(INTENTIONAL_TENANTINFO_OMISSIONS)
    return SchemaSourceAudit(
        schema_property_count=len(schema_set),
        tenant_field_count=len(tenant_set),
        untraced_schema_properties=tuple(sorted(schema_set - tenant_set - special_set)),
        stale_special_sources=tuple(sorted(special_set - schema_set)),
        unrepresented_tenant_fields=tuple(sorted(tenant_set - schema_set - omission_set)),
    )


def _print_problem(label: str, values: tuple[str, ...]) -> None:
    if values:
        print(f"FAIL {label}: {', '.join(values)}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that top-level docs/recon-schema.json fields have declared implementation sources."
    )
    parser.add_argument("--schema", type=Path, default=_SCHEMA_PATH, help="Schema file to inspect.")
    args = parser.parse_args(argv)

    audit = audit_schema_sources(load_schema_properties(args.schema), tenant_info_fields())
    if not audit.ok:
        _print_problem("untraced schema properties", audit.untraced_schema_properties)
        _print_problem("stale special schema sources", audit.stale_special_sources)
        _print_problem("unrepresented TenantInfo fields", audit.unrepresented_tenant_fields)
        return 1
    print(
        "OK: "
        f"{audit.schema_property_count} schema properties traced to TenantInfo fields "
        f"or explicit formatter/mode sources; {audit.tenant_field_count} TenantInfo fields checked."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
