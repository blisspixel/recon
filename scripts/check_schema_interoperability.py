#!/usr/bin/env python3
"""Validate the published JSON contract with an independent Draft 2020-12 engine.

The schema generator and source-drift gates prove that recon's two committed
schema copies match the implementation. This gate answers a different
question: can a standards-based consumer load the detached public artifact,
resolve it without network access, and validate a representative wire record
within explicit resource bounds?

``jsonschema`` is intentionally used without a ``FormatChecker``. JSON Schema
``format`` vocabularies are not a portable substitute for recon's domain and
semantic validation rules.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from recon_tool.formatter import format_tenant_dict
from recon_tool.models import TenantInfo

_ROOT = Path(__file__).resolve().parents[1]
_DOCS_SCHEMA = _ROOT / "docs" / "recon-schema.json"
_PACKAGED_SCHEMA = _ROOT / "src" / "recon_tool" / "data" / "recon-schema.json"

# These caps are deliberately far above the current artifact. They prevent an
# accidental schema expansion from turning a CI or client-side validation step
# into unbounded work while leaving ample room for additive v2 fields.
MAX_SCHEMA_BYTES = 262_144
MAX_SCHEMA_DEPTH = 64
MAX_SCHEMA_NODES = 20_000
MAX_LOCAL_REFS = 5_000
MAX_VALIDATION_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class SchemaInteroperabilityReport:
    """Stable, aggregate-only result from the interoperability check."""

    ok: bool
    draft: str
    schema_sha256: str
    schema_bytes: int
    schema_nodes: int
    maximum_depth: int
    local_ref_count: int
    format_keyword_count: int
    representative_payload_bytes: int
    validation_seconds: float
    external_ref_count: int
    unresolved_local_refs: tuple[str, ...]


def _walk_json(value: object) -> tuple[int, int, list[str], int]:
    """Return node count, maximum depth, refs, and ``format`` keyword count."""
    nodes = 0
    maximum_depth = 0
    refs: list[str] = []
    format_keywords = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        maximum_depth = max(maximum_depth, depth)
        if isinstance(current, dict):
            ref = current.get("$ref")
            if isinstance(ref, str):
                refs.append(ref)
            if "format" in current:
                format_keywords += 1
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return nodes, maximum_depth, refs, format_keywords


def _decode_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _resolve_local_pointer(document: object, ref: str) -> object:
    """Resolve one RFC 6901 fragment pointer without fetching anything."""
    if ref == "#":
        return document
    if not ref.startswith("#/"):
        raise ValueError(f"not a local JSON Pointer: {ref}")
    current = document
    for raw_token in ref[2:].split("/"):
        token = _decode_pointer_token(raw_token)
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdecimal() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise KeyError(ref)
    return current


def _representative_payload() -> dict[str, Any]:
    """Build one deterministic valid record through the production formatter."""
    info = TenantInfo(
        tenant_id=None,
        display_name="Schema Interoperability Fixture",
        default_domain="schema.invalid",
        queried_domain="schema.invalid",
        sources=("schema_fixture",),
        degraded_sources=("oidc_discovery",),
    )
    return format_tenant_dict(info)


def _load_matching_schema(docs_schema_path: Path, packaged_schema_path: Path) -> tuple[dict[str, Any], bytes]:
    """Load the portable text artifact and enforce its top-level contract."""
    docs_text = docs_schema_path.read_text(encoding="utf-8")
    packaged_text = packaged_schema_path.read_text(encoding="utf-8")
    if docs_text != packaged_text:
        raise ValueError("docs and packaged schema copies are not content-identical")
    canonical_bytes = docs_text.encode("utf-8")
    if len(canonical_bytes) > MAX_SCHEMA_BYTES:
        raise ValueError(f"schema is {len(canonical_bytes)} bytes; cap is {MAX_SCHEMA_BYTES}")
    schema = json.loads(docs_text)
    if not isinstance(schema, dict):
        raise TypeError("published schema root must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("published schema does not declare Draft 2020-12")
    return schema, canonical_bytes


def _bounded_schema_shape(
    schema: dict[str, Any],
) -> tuple[int, int, tuple[str, ...], int, tuple[str, ...], tuple[str, ...]]:
    """Return bounded structure plus external and unresolved references."""
    nodes, maximum_depth, refs, format_keywords = _walk_json(schema)
    if nodes > MAX_SCHEMA_NODES:
        raise ValueError(f"schema has {nodes} nodes; cap is {MAX_SCHEMA_NODES}")
    if maximum_depth > MAX_SCHEMA_DEPTH:
        raise ValueError(f"schema depth is {maximum_depth}; cap is {MAX_SCHEMA_DEPTH}")
    external_refs = tuple(sorted({ref for ref in refs if not ref.startswith("#")}))
    local_refs = tuple(ref for ref in refs if ref.startswith("#"))
    if len(local_refs) > MAX_LOCAL_REFS:
        raise ValueError(f"schema has {len(local_refs)} local refs; cap is {MAX_LOCAL_REFS}")
    unresolved: list[str] = []
    for ref in sorted(set(local_refs)):
        with contextlib.suppress(KeyError, ValueError):
            _resolve_local_pointer(schema, ref)
            continue
        unresolved.append(ref)
    return nodes, maximum_depth, local_refs, format_keywords, external_refs, tuple(unresolved)


def characterize_schema(
    docs_schema_path: Path = _DOCS_SCHEMA,
    packaged_schema_path: Path = _PACKAGED_SCHEMA,
) -> SchemaInteroperabilityReport:
    """Validate both artifact copies, local references, bounds, and one record."""
    schema, canonical_bytes = _load_matching_schema(docs_schema_path, packaged_schema_path)
    nodes, maximum_depth, local_refs, format_keywords, external_refs, unresolved = _bounded_schema_shape(schema)

    payload = _representative_payload()
    payload_bytes = len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    if external_refs or unresolved:
        return SchemaInteroperabilityReport(
            ok=False,
            draft="2020-12",
            schema_sha256=hashlib.sha256(canonical_bytes).hexdigest(),
            schema_bytes=len(canonical_bytes),
            schema_nodes=nodes,
            maximum_depth=maximum_depth,
            local_ref_count=len(local_refs),
            format_keyword_count=format_keywords,
            representative_payload_bytes=payload_bytes,
            validation_seconds=0.0,
            external_ref_count=len(external_refs),
            unresolved_local_refs=tuple(unresolved),
        )

    started = time.perf_counter()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    invalid_payload = dict(payload)
    invalid_payload.pop("queried_domain")
    rejected_control = bool(tuple(validator.iter_errors(invalid_payload)))
    elapsed = time.perf_counter() - started

    if errors:
        locations = ["/".join(str(part) for part in error.absolute_path) or "<root>" for error in errors]
        raise ValueError(f"representative payload failed validation at {locations!r}")
    if not rejected_control:
        raise ValueError("independent validator accepted a control missing queried_domain")
    if elapsed > MAX_VALIDATION_SECONDS:
        raise ValueError(f"schema validation took {elapsed:.3f}s; cap is {MAX_VALIDATION_SECONDS:.3f}s")

    ok = not external_refs and not unresolved
    return SchemaInteroperabilityReport(
        ok=ok,
        draft="2020-12",
        schema_sha256=hashlib.sha256(canonical_bytes).hexdigest(),
        schema_bytes=len(canonical_bytes),
        schema_nodes=nodes,
        maximum_depth=maximum_depth,
        local_ref_count=len(local_refs),
        format_keyword_count=format_keywords,
        representative_payload_bytes=payload_bytes,
        validation_seconds=round(elapsed, 6),
        external_ref_count=len(external_refs),
        unresolved_local_refs=tuple(unresolved),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit the bounded machine-readable report.")
    args = parser.parse_args(argv)
    try:
        report = characterize_schema()
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Schema interoperability: FAIL: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(asdict(report), indent=2, sort_keys=True))
    else:
        status = "PASS" if report.ok else "FAIL"
        print(
            f"Schema interoperability: {status} "
            f"(Draft {report.draft}, {report.schema_bytes} bytes, "
            f"{report.local_ref_count} local refs, {report.validation_seconds:.6f}s)"
        )
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
