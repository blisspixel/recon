"""Freeze a provider-labeled vendor-seed round without target collection.

The private dossier names provider-controlled source pages and the customer
domains they support. This preparer verifies archived source bytes, excludes
every prior development or observation frame, requires disclosure-safe stratum
sizes, and emits the generic catalog-round plan, frame, and manifest consumed
by ``validation.scan``. It performs no network requests and prints no target
identifier.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, cast
from urllib.parse import urlsplit

from recon_tool.fingerprints import load_builtin_fingerprints
from recon_tool.validator import validate_domain
from validation.archive_vendor_seed_sources import load_source_receipt
from validation.prepare_catalog_round import (
    REPO_ROOT,
    canonical_json_digest,
    prepare_catalog_round,
)
from validation.prepare_catalog_round import SCHEMA_VERSION as ROUND_SCHEMA_VERSION
from validation.ranked_sampling import bounded_stable_read
from validation.run_path_safety import validate_private_output_root

PRIVATE_ROOTS = (
    REPO_ROOT / "validation" / "corpus-private",
    REPO_ROOT / "validation" / "runs-private",
    REPO_ROOT / "validation" / "local",
)
SCHEMA_VERSION = 2
LABEL_BASIS = "provider-relationship"
METRIC = "provider-relationship corroboration rate"
MIN_PROVIDER_ROWS = 20
MAX_DOSSIER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXCLUSION_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_EXCLUSION_BYTES = 128 * 1024 * 1024
MAX_PROVIDERS = 25
MAX_EXCLUSIONS = 100
MAX_SOURCES_PER_PROVIDER = 100
MAX_MEMBERS_PER_PROVIDER = 10_000
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,79}$")
_DOSSIER_KEYS = frozenset(
    {
        "schema_version",
        "private",
        "round_id",
        "question",
        "source_name",
        "source_revision",
        "source_receipt",
        "providers",
        "exclusions",
        "collection",
        "thresholds",
        "promotion_budget",
    }
)


@dataclass(frozen=True, slots=True)
class PreparedVendorSeed:
    """All bytes needed for one immutable private vendor-seed contract."""

    round_plan: bytes
    source_contract: bytes
    provider_sources: tuple[tuple[str, bytes], ...]
    frame: bytes
    round_manifest: dict[str, object]


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _strict_object(value: object, *, name: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{name} must be an object")
    actual = frozenset(value)
    missing = sorted(keys - actual)
    extra = sorted(actual - keys)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        _fail(f"{name} has invalid fields: {'; '.join(details)}")
    return value


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            _fail(f"vendor-seed dossier contains duplicate field: {key}")
        value[key] = child
    return value


def _identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{name} must be a lowercase identifier")
    return value


def _text(value: object, *, name: str, minimum: int = 3) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    normalized = " ".join(value.split())
    if len(normalized) < minimum or normalized.casefold() in {"n/a", "none", "tbd", "unknown", "latest"}:
        _fail(f"{name} must be meaningful and at least {minimum} characters")
    return normalized


def _private_path(base: Path, value: object, *, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{name} must be a non-empty path")
    supplied = Path(value)
    path = supplied if supplied.is_absolute() else base / supplied
    resolved = path.resolve(strict=False)
    validate_private_output_root(resolved.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    return resolved


def _read_json(path: Path) -> tuple[dict[str, object], bytes]:
    raw = bounded_stable_read(path, maximum_bytes=MAX_DOSSIER_BYTES, kind="vendor-seed dossier")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("vendor-seed dossier must be valid UTF-8 JSON") from exc
    return _strict_object(value, name="vendor-seed dossier", keys=_DOSSIER_KEYS), raw


def _source_url(value: object, *, name: str) -> str:
    url = _text(value, name=name, minimum=12)
    if len(url) > 2048:
        _fail(f"{name} exceeds 2048 characters")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        _fail(f"{name} must be an HTTPS URL without credentials or a fragment")
    return url


def _utc_timestamp(value: object, *, name: str) -> str:
    timestamp = _text(value, name=name, minimum=10)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        _fail(f"{name} must carry the UTC timezone")
    return timestamp


def _domain(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a domain string")
    try:
        return validate_domain(value)
    except ValueError as exc:
        raise ValueError(f"{name} is malformed") from exc


def _catalog_contract() -> dict[str, dict[str, object]]:
    by_slug: dict[str, dict[str, object]] = {}
    for fingerprint in load_builtin_fingerprints():
        row = by_slug.setdefault(fingerprint.slug, {"names": set(), "record_types": set()})
        cast(set[str], row["names"]).add(fingerprint.name)
        cast(set[str], row["record_types"]).update(rule.type for rule in fingerprint.detections)
    return by_slug


def _exclusion_union(dossier: Mapping[str, object], *, base: Path) -> tuple[set[str], list[dict[str, object]]]:
    raw_exclusions = dossier["exclusions"]
    if not isinstance(raw_exclusions, list) or not raw_exclusions or len(raw_exclusions) > MAX_EXCLUSIONS:
        _fail(f"exclusions must contain between 1 and {MAX_EXCLUSIONS} entries")
    union: set[str] = set()
    rows: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    total_bytes = 0
    for index, raw_exclusion in enumerate(raw_exclusions):
        exclusion = _strict_object(
            raw_exclusion,
            name=f"exclusions[{index}]",
            keys=frozenset({"id", "input"}),
        )
        exclusion_id = _identifier(exclusion["id"], name=f"exclusions[{index}].id")
        if exclusion_id in seen_ids:
            _fail(f"duplicate exclusion id: {exclusion_id}")
        seen_ids.add(exclusion_id)
        path = _private_path(base, exclusion["input"], name=f"exclusions[{index}].input")
        raw = bounded_stable_read(path, maximum_bytes=MAX_EXCLUSION_BYTES, kind=f"exclusion {exclusion_id}")
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_EXCLUSION_BYTES:
            _fail(f"exclusion sources exceed the {MAX_TOTAL_EXCLUSION_BYTES}-byte aggregate limit")
        try:
            lines = raw.decode("utf-8-sig").splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError(f"exclusion {exclusion_id} must be UTF-8") from exc
        domains: set[str] = set()
        for line_number, line in enumerate(lines, start=1):
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            domains.add(_domain(candidate, name=f"exclusion {exclusion_id} row {line_number}"))
        if not domains:
            _fail(f"exclusion {exclusion_id} has no valid domains")
        union.update(domains)
        rows.append(
            {
                "id": exclusion_id,
                "raw_digest_sha256": hashlib.sha256(raw).hexdigest(),
                "canonical_count": len(domains),
                "canonical_digest_sha256": hashlib.sha256(
                    ("\n".join(sorted(domains)) + "\n").encode("ascii")
                ).hexdigest(),
            }
        )
    return union, rows


def _positive_int(value: object, *, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(f"{name} must be a positive integer")
    return value


def _bounded_rate(value: object, *, name: str, positive: bool) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        _fail(f"{name} must be a number")
    result = float(value)
    if result > 1 or (result <= 0 if positive else result < 0):
        _fail(f"{name} must be within {'(0, 1]' if positive else '[0, 1]'}")
    return result


def _generic_settings(dossier: Mapping[str, object]) -> dict[str, object]:
    collection = _strict_object(
        dossier["collection"],
        name="collection",
        keys=frozenset({"ct_enabled", "direct_probes_enabled"}),
    )
    if not isinstance(collection["ct_enabled"], bool):
        _fail("collection.ct_enabled must be a boolean")
    if collection["direct_probes_enabled"] is not False:
        _fail("collection.direct_probes_enabled must be false")
    thresholds = _strict_object(
        dossier["thresholds"],
        name="thresholds",
        keys=frozenset({"minimum_occurrences", "minimum_distinct_namespaces"}),
    )
    minimum_occurrences = _positive_int(thresholds["minimum_occurrences"], name="thresholds.minimum_occurrences")
    minimum_namespaces = _positive_int(
        thresholds["minimum_distinct_namespaces"], name="thresholds.minimum_distinct_namespaces"
    )
    budget = _strict_object(
        dossier["promotion_budget"],
        name="promotion_budget",
        keys=frozenset({"metric", "minimum_improvement", "maximum_regression", "decision_rule"}),
    )
    if budget["metric"] != METRIC:
        _fail(f"promotion_budget.metric must be {METRIC!r}")
    return {
        "collection": {"ct_enabled": collection["ct_enabled"], "direct_probes_enabled": False},
        "thresholds": {
            "minimum_occurrences": minimum_occurrences,
            "minimum_distinct_namespaces": minimum_namespaces,
        },
        "promotion_budget": {
            "metric": METRIC,
            "minimum_improvement": _bounded_rate(
                budget["minimum_improvement"], name="promotion_budget.minimum_improvement", positive=True
            ),
            "maximum_regression": _bounded_rate(
                budget["maximum_regression"], name="promotion_budget.maximum_regression", positive=False
            ),
            "decision_rule": _text(budget["decision_rule"], name="promotion_budget.decision_rule", minimum=30),
        },
    }


def _provider_sources(
    provider: Mapping[str, object],
    *,
    slug: str,
    base: Path,
    receipt_sources: Mapping[tuple[str, str], Mapping[str, object]],
) -> tuple[list[dict[str, object]], set[str], int, set[tuple[str, str]]]:
    raw_sources = provider["sources"]
    if not isinstance(raw_sources, list) or not raw_sources or len(raw_sources) > MAX_SOURCES_PER_PROVIDER:
        _fail(f"provider {slug} must contain 1-{MAX_SOURCES_PER_PROVIDER} sources")
    sources: list[dict[str, object]] = []
    source_ids: set[str] = set()
    source_urls: set[str] = set()
    used_receipt_sources: set[tuple[str, str]] = set()
    total_archive_bytes = 0
    for source_index, raw_source in enumerate(raw_sources):
        source = _strict_object(
            raw_source,
            name=f"provider {slug} sources[{source_index}]",
            keys=frozenset({"id", "url", "retrieved_at", "archive"}),
        )
        source_id = _identifier(source["id"], name=f"provider {slug} sources[{source_index}].id")
        if source_id in source_ids:
            _fail(f"provider {slug} has duplicate source id: {source_id}")
        source_ids.add(source_id)
        url = _source_url(source["url"], name=f"provider {slug} sources[{source_index}].url")
        if url in source_urls:
            _fail(f"provider {slug} has a duplicate source URL")
        source_urls.add(url)
        archive_path = _private_path(base, source["archive"], name=f"provider {slug} source archive")
        receipt_source = receipt_sources.get((slug, source_id))
        if receipt_source is None:
            _fail(f"provider {slug} source is absent from the frozen source receipt")
        receipt_archive = cast(Path, receipt_source["archive_path"])
        retrieved_at = _utc_timestamp(
            source["retrieved_at"], name=f"provider {slug} sources[{source_index}].retrieved_at"
        )
        if (
            url != receipt_source["url"]
            or retrieved_at != receipt_source["retrieved_at"]
            or archive_path != receipt_archive
        ):
            _fail(f"provider {slug} source metadata does not match the frozen source receipt")
        archive = bounded_stable_read(
            archive_path,
            maximum_bytes=MAX_ARCHIVE_BYTES,
            kind=f"provider {slug} source archive",
        )
        if (
            len(archive) != receipt_source["archive_bytes"]
            or hashlib.sha256(archive).hexdigest() != receipt_source["archive_digest_sha256"]
        ):
            _fail(f"provider {slug} source archive does not match the frozen source receipt")
        total_archive_bytes += len(archive)
        used_receipt_sources.add((slug, source_id))
        sources.append(
            {
                "id": source_id,
                "url": url,
                "retrieved_at": retrieved_at,
                "archive_digest_sha256": hashlib.sha256(archive).hexdigest(),
                "archive_bytes": len(archive),
            }
        )
    return sources, source_ids, total_archive_bytes, used_receipt_sources


def _provider_members(
    provider: Mapping[str, object],
    *,
    slug: str,
    source_ids: set[str],
    exclusions: set[str],
    assigned: set[str],
) -> tuple[set[str], defaultdict[str, int]]:
    raw_members = provider["members"]
    if not isinstance(raw_members, list) or not raw_members or len(raw_members) > MAX_MEMBERS_PER_PROVIDER:
        _fail(f"provider {slug} must contain 1-{MAX_MEMBERS_PER_PROVIDER} members")
    domains: set[str] = set()
    source_use: defaultdict[str, int] = defaultdict(int)
    for member_index, raw_member in enumerate(raw_members):
        member = _strict_object(
            raw_member,
            name=f"provider {slug} members[{member_index}]",
            keys=frozenset({"domain", "source_id"}),
        )
        source_id = _identifier(member["source_id"], name=f"provider {slug} members[{member_index}].source_id")
        if source_id not in source_ids:
            _fail(f"provider {slug} member references an unknown source id")
        domain = _domain(member["domain"], name=f"provider {slug} member {member_index + 1}")
        if domain in exclusions:
            _fail(f"provider {slug} member overlaps a frozen exclusion")
        if domain in assigned:
            _fail("one vendor-seed namespace appears in multiple provider strata")
        if domain in domains:
            _fail(f"provider {slug} contains a duplicate canonical member")
        domains.add(domain)
        source_use[source_id] += 1
    return domains, source_use


def _provider_contracts(
    dossier: Mapping[str, object],
    *,
    base: Path,
    exclusions: set[str],
    receipt_sources: Mapping[tuple[str, str], Mapping[str, object]],
) -> tuple[list[dict[str, object]], tuple[tuple[str, bytes], ...]]:
    raw_providers = dossier["providers"]
    if not isinstance(raw_providers, list) or not raw_providers or len(raw_providers) > MAX_PROVIDERS:
        _fail(f"providers must contain between 1 and {MAX_PROVIDERS} entries")
    catalog = _catalog_contract()
    seen_slugs: set[str] = set()
    assigned: set[str] = set()
    contracts: list[dict[str, object]] = []
    provider_sources: list[tuple[str, bytes]] = []
    total_archive_bytes = 0
    used_receipt_sources: set[tuple[str, str]] = set()
    for provider_index, raw_provider in enumerate(raw_providers):
        provider = _strict_object(
            raw_provider,
            name=f"providers[{provider_index}]",
            keys=frozenset({"slug", "label_basis", "sources", "members"}),
        )
        slug = _identifier(provider["slug"], name=f"providers[{provider_index}].slug")
        if slug in seen_slugs:
            _fail(f"duplicate provider slug: {slug}")
        seen_slugs.add(slug)
        catalog_row = catalog.get(slug)
        if catalog_row is None:
            _fail(f"provider slug is absent from the current catalog: {slug}")
        if provider["label_basis"] != LABEL_BASIS:
            _fail(f"provider {slug} label_basis must be {LABEL_BASIS!r}")
        sources, source_ids, archive_bytes, provider_receipt_sources = _provider_sources(
            provider,
            slug=slug,
            base=base,
            receipt_sources=receipt_sources,
        )
        used_receipt_sources.update(provider_receipt_sources)
        total_archive_bytes += archive_bytes
        if total_archive_bytes > MAX_TOTAL_ARCHIVE_BYTES:
            _fail(f"provider source archives exceed the {MAX_TOTAL_ARCHIVE_BYTES}-byte aggregate limit")
        domains, source_use = _provider_members(
            provider,
            slug=slug,
            source_ids=source_ids,
            exclusions=exclusions,
            assigned=assigned,
        )
        if len(domains) < MIN_PROVIDER_ROWS:
            _fail(f"provider {slug} has {len(domains)} canonical rows; at least {MIN_PROVIDER_ROWS} are required")
        unused_sources = sorted(source_ids - set(source_use))
        if unused_sources:
            _fail(f"provider {slug} has sources with no members: {', '.join(unused_sources)}")
        assigned.update(domains)
        rendered = ("\n".join(sorted(domains)) + "\n").encode("ascii")
        provider_sources.append((slug, rendered))
        names = sorted(cast(set[str], catalog_row["names"]))
        contracts.append(
            {
                "slug": slug,
                "catalog_names": names,
                "label_basis": LABEL_BASIS,
                "record_types": sorted(cast(set[str], catalog_row["record_types"])),
                "sources": sources,
                "member_count": len(domains),
                "member_digest_sha256": hashlib.sha256(rendered).hexdigest(),
            }
        )
    if used_receipt_sources != set(receipt_sources):
        _fail("vendor-seed dossier must use every source in the frozen source receipt exactly once")
    return contracts, tuple(provider_sources)


def _receipt_source_index(
    receipt: Mapping[str, object],
    *,
    receipt_path: Path,
) -> dict[tuple[str, str], dict[str, object]]:
    sources: dict[tuple[str, str], dict[str, object]] = {}
    for raw_provider in cast(list[dict[str, object]], receipt["providers"]):
        slug = cast(str, raw_provider["slug"])
        for raw_source in cast(list[dict[str, object]], raw_provider["sources"]):
            source_id = cast(str, raw_source["id"])
            archive_path = _private_path(
                receipt_path.parent,
                raw_source["archive"],
                name=f"source receipt archive for {slug}",
            )
            sources[(slug, source_id)] = {
                "url": raw_source["url"],
                "retrieved_at": raw_source["retrieved_at"],
                "archive_path": archive_path,
                "archive_bytes": raw_source["archive_bytes"],
                "archive_digest_sha256": raw_source["archive_digest_sha256"],
            }
    return sources


def prepare_vendor_seed_round(
    dossier_path: Path,
    output_dir: Path,
    *,
    prepared_at: str | None = None,
) -> PreparedVendorSeed:
    """Validate one private dossier and return its frozen round artifacts."""
    resolved_dossier = dossier_path.resolve(strict=False)
    validate_private_output_root(resolved_dossier.parent, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    resolved_output = output_dir.resolve(strict=False)
    validate_private_output_root(resolved_output, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    if resolved_output.exists():
        _fail("vendor-seed output directory already exists; refusing to replace it")
    dossier, dossier_raw = _read_json(resolved_dossier)
    if dossier["schema_version"] != SCHEMA_VERSION or dossier["private"] is not True:
        _fail(f"vendor-seed dossier must use private schema version {SCHEMA_VERSION}")
    round_id = _identifier(dossier["round_id"], name="round_id")
    question = _text(dossier["question"], name="question", minimum=30)
    source_name = _text(dossier["source_name"], name="source_name", minimum=8)
    source_revision = _text(dossier["source_revision"], name="source_revision", minimum=8)
    source_receipt_path = _private_path(
        resolved_dossier.parent,
        dossier["source_receipt"],
        name="source_receipt",
    )
    source_receipt, source_receipt_raw = load_source_receipt(source_receipt_path)
    source_receipt_digest = cast(str, source_receipt["receipt_digest_sha256"])
    receipt_sources = _receipt_source_index(source_receipt, receipt_path=source_receipt_path)
    settings = _generic_settings(dossier)
    exclusions, exclusion_contracts = _exclusion_union(dossier, base=resolved_dossier.parent)
    providers, provider_sources = _provider_contracts(
        dossier,
        base=resolved_dossier.parent,
        exclusions=exclusions,
        receipt_sources=receipt_sources,
    )
    exclusion_union_raw = ("\n".join(sorted(exclusions)) + "\n").encode("ascii")
    source_contract: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "private": True,
        "label_basis": LABEL_BASIS,
        "metric": METRIC,
        "dossier_digest_sha256": hashlib.sha256(dossier_raw).hexdigest(),
        "source_receipt_digest_sha256": source_receipt_digest,
        "source_receipt_bytes_sha256": hashlib.sha256(source_receipt_raw).hexdigest(),
        "source_set_id": source_receipt["source_set_id"],
        "source_name": source_name,
        "source_revision": source_revision,
        "exclusions": exclusion_contracts,
        "exclusion_union_count": len(exclusions),
        "exclusion_union_digest_sha256": hashlib.sha256(exclusion_union_raw).hexdigest(),
        "providers": providers,
        "target_network_requests": 0,
    }
    source_contract_digest = canonical_json_digest(source_contract)
    source_contract["contract_digest_sha256"] = source_contract_digest
    source_contract_raw = json.dumps(source_contract, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    plan: dict[str, object] = {
        "schema_version": ROUND_SCHEMA_VERSION,
        "private": True,
        "round_id": round_id,
        "round_kind": "vendor-seed",
        "question": question,
        "source": {
            "name": source_name,
            "revision": (
                f"{source_revision}; source-receipt-sha256={source_receipt_digest}; "
                f"source-contract-sha256={source_contract_digest}"
            ),
        },
        "strata": [
            {
                "id": contract["slug"],
                "label": cast(list[str], contract["catalog_names"])[0],
                "input": f"sources/{contract['slug']}.txt",
            }
            for contract in providers
        ],
        "policies": {
            "exclusions": (
                "Reject all development, prior observation, prior case-study, and cross-provider overlaps; "
                f"frozen exclusion union contains {len(exclusions)} canonical namespaces."
            ),
            "overlap": "reject",
        },
        "collection": settings["collection"],
        "thresholds": settings["thresholds"],
        "promotion_budget": settings["promotion_budget"],
    }
    plan_raw = json.dumps(plan, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    with tempfile.TemporaryDirectory(prefix="recon-vendor-seed-") as staging_value:
        staging = Path(staging_value)
        virtual_plan_path = staging / "round-plan.json"
        virtual_sources = staging / "sources"
        virtual_sources.mkdir()
        for slug, raw in provider_sources:
            path = virtual_sources / f"{slug}.txt"
            path.write_bytes(raw)
        virtual_plan_path.write_bytes(plan_raw)
        frame_path = resolved_output / "frame.txt"
        frame, manifest = prepare_catalog_round(virtual_plan_path, frame_path, prepared_at=prepared_at)
    return PreparedVendorSeed(
        round_plan=plan_raw,
        source_contract=source_contract_raw,
        provider_sources=provider_sources,
        frame=frame,
        round_manifest=manifest,
    )


def _reserve(path: Path) -> int:
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("vendor-seed output already exists; refusing to replace it") from exc


def write_vendor_seed_round(dossier_path: Path, output_dir: Path) -> dict[str, object]:
    """Exclusively write a complete private vendor-seed contract."""
    root = output_dir.resolve(strict=False)
    validate_private_output_root(root, repo_root=REPO_ROOT, allowed_roots=PRIVATE_ROOTS)
    if root.exists():
        _fail("vendor-seed output directory already exists; refusing to replace it")
    prepared = prepare_vendor_seed_round(dossier_path, root)
    outputs: dict[Path, bytes] = {
        root / "round-plan.json": prepared.round_plan,
        root / "source-contract.json": prepared.source_contract,
        root / "frame.txt": prepared.frame,
        root / "round-manifest.json": json.dumps(prepared.round_manifest, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
        **{root / "sources" / f"{slug}.txt": raw for slug, raw in prepared.provider_sources},
    }
    descriptors: dict[Path, int] = {}
    owned: list[Path] = []
    directories: list[Path] = []
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(exist_ok=False)
        directories.append(root)
        sources_directory = root / "sources"
        sources_directory.mkdir(exist_ok=False)
        directories.append(sources_directory)
        for path in outputs:
            descriptors[path] = _reserve(path)
            owned.append(path)
        for path, raw in outputs.items():
            descriptor = descriptors.pop(path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        for path in reversed(owned):
            with contextlib.suppress(OSError):
                path.unlink()
        for directory in reversed(directories):
            with contextlib.suppress(OSError):
                directory.rmdir()
        raise
    return prepared.round_manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dossier", required=True, type=Path, help="Strict ignored private vendor source dossier.")
    parser.add_argument("--output-dir", required=True, type=Path, help="New ignored private contract directory.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = write_vendor_seed_round(args.dossier, args.output_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    source = cast(dict[str, object], manifest["source"])
    frame = cast(dict[str, object], manifest["frame"])
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "round_kind": "vendor-seed",
                "provider_count": len(cast(list[object], manifest["strata"])),
                "frame_count": frame["count"],
                "frame_digest_sha256": frame["digest_sha256"],
                "source_digest_sha256": source["digest_sha256"],
                "manifest_digest_sha256": manifest["manifest_digest_sha256"],
                "identifiers_printed": 0,
                "network_requests": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
